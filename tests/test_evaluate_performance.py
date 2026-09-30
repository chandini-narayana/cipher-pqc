"""Unit tests for evaluate_performance.py — the Phase 2C controlled offline
benchmark runner.

FAST BY CONSTRUCTION. Every test passes tiny repetition counts and skips both
startup timing (which launches run_demo.py as a subprocess) and the optional
sustained run. No test asserts an exact duration: timings are not reproducible
across machines or runs. What is asserted is structure, counts, unit
conversions, relationships guaranteed by construction, and that the runner
never writes outside a temporary directory.
"""
from __future__ import annotations

import ast
import csv
import json
from pathlib import Path

import pytest

import evaluate_performance

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def packets() -> list:
    return evaluate_performance.load_prepared_packets()


@pytest.fixture(scope="module")
def detector_and_metadata():
    return evaluate_performance.build_in_memory_detector()


@pytest.fixture(scope="module")
def small_report(packets, detector_and_metadata) -> dict:
    """One shared benchmark run with minimal repetitions — startup and report
    generation are exercised separately so this stays quick."""
    detector, metadata = detector_and_metadata
    return evaluate_performance.build_performance_report(
        packets,
        detector,
        metadata,
        latency_reps=2,
        throughput_passes=1,
        report_reps=1,
        include_startup=False,
        include_report_generation=False,
    )


# --- dataset loading -----------------------------------------------------


def test_packets_are_loaded_from_the_controlled_dataset(packets) -> None:
    assert len(packets) == 30
    for prepared in packets:
        assert prepared.raw_packet.payload
        assert prepared.device.ip == prepared.raw_packet.src_ip
        assert prepared.port_risk >= 0


def test_missing_fixture_raises_with_an_actionable_message(tmp_path) -> None:
    with pytest.raises(FileNotFoundError) as error:
        evaluate_performance.load_prepared_packets(tmp_path / "absent.pcap")
    assert (
        "python -m tests.fixtures.generate_labelled_evaluation_fixtures"
        in str(error.value)
    )


def test_packets_are_prepared_before_timing_so_io_is_excluded() -> None:
    """Device resolution and port-risk lookup happen in PreparedPacket's
    constructor, outside every timed region."""
    source = (REPO_ROOT / "evaluate_performance.py").read_text(encoding="utf-8")
    assert "read from disk ONCE before" in source or "read from disk ONCE" in source
    assert "OfflinePcapSource" in source


# --- latency benchmarks --------------------------------------------------


def test_qrs_only_benchmark_produces_one_sample_per_packet_repetition(packets) -> None:
    samples = evaluate_performance.measure_assessment_latency(
        packets, None, repetitions=3, warmup=0
    )
    assert len(samples) == 3 * len(packets)
    assert all(value >= 0 for value in samples)


def test_qrs_plus_isolation_forest_benchmark_produces_matching_sample_count(
    packets, detector_and_metadata
) -> None:
    detector, _metadata = detector_and_metadata
    samples = evaluate_performance.measure_assessment_latency(
        packets, detector, repetitions=2, warmup=0
    )
    assert len(samples) == 2 * len(packets)
    assert all(value >= 0 for value in samples)


def test_paired_sample_sequences_are_positionally_aligned(
    packets, detector_and_metadata
) -> None:
    """The ML overhead is a paired per-observation difference, so the two runs
    must produce equal-length sequences in the same packet order."""
    detector, _metadata = detector_and_metadata
    baseline = evaluate_performance.measure_assessment_latency(
        packets, None, repetitions=2, warmup=0
    )
    treatment = evaluate_performance.measure_assessment_latency(
        packets, detector, repetitions=2, warmup=0
    )
    assert len(baseline) == len(treatment)

    overhead = evaluate_performance.paired_difference_statistics(baseline, treatment)
    assert overhead["pairs"] == len(baseline)


def test_ml_overhead_is_positive_because_the_model_adds_work(small_report) -> None:
    """A relationship guaranteed by construction: QRS+IF performs strictly more
    work than QRS-only on the same packet, so the mean paired difference cannot
    be negative. The magnitude is machine-dependent and not asserted."""
    overhead = small_report["incremental_ml_overhead"]
    assert overhead["mean_ms"] > 0
    assert overhead["pairs_slower"] > 0

    qrs_only = small_report["qrs_only_assessment_latency"]["mean_ms"]
    with_ml = small_report["qrs_plus_isolation_forest_assessment_latency"]["mean_ms"]
    assert with_ml > qrs_only


def test_full_pipeline_benchmark_reports_both_variants_and_a_definition(
    small_report,
) -> None:
    pipeline = small_report["full_pipeline_latency"]
    assert "fingerprint_packet" in pipeline["definition"]
    assert "should_isolate" in pipeline["definition"]
    for variant in ("qrs_only", "with_isolation_forest"):
        assert pipeline[variant]["n"] > 0
        assert pipeline[variant]["mean_ms"] >= 0
    assert pipeline["incremental_ml_overhead"]["pairs"] > 0


def test_full_pipeline_is_at_least_as_slow_as_assessment_alone(small_report) -> None:
    """It contains the assessment plus fingerprinting, port-risk lookup and the
    isolation decision, so its mean cannot be meaningfully lower. Compared with
    generous tolerance because both are sub-millisecond and noisy."""
    assessment = small_report["qrs_only_assessment_latency"]["median_ms"]
    pipeline = small_report["full_pipeline_latency"]["qrs_only"]["median_ms"]
    assert pipeline >= assessment * 0.5


def test_enforcement_decision_latency_is_labelled_software_only(small_report) -> None:
    payload = small_report["software_enforcement_decision_latency"]
    assert payload["n"] > 0
    assert "SOFTWARE" in payload["scope"]
    assert "UNMEASURED" in payload["scope"]


# --- throughput and CPU --------------------------------------------------


def test_throughput_computation_is_consistent_with_its_counts(packets) -> None:
    result = evaluate_performance.measure_throughput_and_cpu(
        packets, None, passes=1, min_wall_seconds=0.0
    )
    assert result["assessments"] == result["passes"] * len(packets)
    assert result["wall_seconds"] > 0
    assert result["assessments_per_second"] == pytest.approx(
        result["assessments"] / result["wall_seconds"]
    )


def test_throughput_extends_the_interval_to_reach_the_cpu_floor(packets) -> None:
    """The floor exists so the CPU ratio is not built from clock quantization."""
    result = evaluate_performance.measure_throughput_and_cpu(
        packets, None, passes=1, min_wall_seconds=0.3
    )
    assert result["wall_seconds"] >= 0.3
    assert result["passes"] > result["requested_passes"]
    assert result["cpu"]["reliable"] is True


def test_throughput_is_labelled_single_threaded_and_offline(small_report) -> None:
    for variant in ("qrs_only", "with_isolation_forest"):
        throughput = small_report["throughput"][variant]
        assert throughput["label"] == "single-threaded controlled offline throughput"
        assert "NOT network throughput" in throughput["definition"]
        assert throughput["assessments_per_second"] > 0


def test_qrs_only_throughput_exceeds_throughput_with_the_model(small_report) -> None:
    """Guaranteed by construction: the model adds per-packet work."""
    qrs_only = small_report["throughput"]["qrs_only"]["assessments_per_second"]
    with_ml = small_report["throughput"]["with_isolation_forest"][
        "assessments_per_second"
    ]
    assert qrs_only > with_ml


def test_cpu_is_reported_as_process_utilization_not_system_usage(small_report) -> None:
    for variant in ("qrs_only", "with_isolation_forest"):
        cpu = small_report["throughput"][variant]["cpu"]
        assert cpu["cpu_ratio"] is not None
        assert cpu["cpu_ratio"] >= 0
        assert "Not whole-system CPU usage" in cpu["interpretation"]
        assert cpu["process_cpu_utilization_percent"] == pytest.approx(
            cpu["cpu_ratio"] * 100.0
        )


# --- memory --------------------------------------------------------------


def test_memory_section_reports_rss_and_python_heap_separately(small_report) -> None:
    memory = small_report["memory"]
    rss = memory["peak_rss"]
    heap = memory["python_heap"]

    assert "process lifetime" in rss["scope"]
    assert isinstance(rss["available"], bool)
    if not rss["available"]:
        assert rss["peak_rss_bytes"] is None
        assert rss["reason"]

    assert heap["python_heap_peak_bytes"] > 0
    assert "separate pass" in heap["note"]


# --- report generation ---------------------------------------------------


def test_report_generation_benchmark_uses_a_temporary_directory(packets) -> None:
    """Must never touch the real data/reports/ directory."""
    real_reports = REPO_ROOT / "data" / "reports"
    before = (
        sorted(path.name for path in real_reports.glob("*.pdf"))
        if real_reports.exists()
        else []
    )

    payload = evaluate_performance.measure_report_generation_latency(
        packets, repetitions=2
    )

    after = (
        sorted(path.name for path in real_reports.glob("*.pdf"))
        if real_reports.exists()
        else []
    )
    assert after == before

    assert payload["n"] == 2
    assert payload["mean_ms"] > 0
    assert "temporary directory" in payload["scope"]
    assert "excludes any download" in payload["scope"]
    assert payload["final_category"] in {"MEDIUM", "HIGH"}


def test_report_generation_benchmark_names_the_flagged_device(packets) -> None:
    payload = evaluate_performance.measure_report_generation_latency(
        packets, repetitions=1
    )
    assert payload["device_ip"]


# --- optional sustained run ----------------------------------------------


def test_stability_benchmark_runs_a_bounded_iteration_count(
    packets, detector_and_metadata
) -> None:
    """Exercised with a tiny count only; long runs never happen in pytest."""
    detector, _metadata = detector_and_metadata
    payload = evaluate_performance.run_stability_benchmark(
        packets, None, iterations=2
    )
    assert payload["completed_passes"] == 2
    assert payload["assessments"] == 2 * len(packets)
    assert payload["mode"] == "iterations"
    assert payload["per_pass_latency"]["n"] == 2
    assert payload["assessments_per_second"] > 0
    assert payload["drift"]["first_window_mean_ms"] is not None


def test_stability_benchmark_supports_a_duration_bound(packets) -> None:
    payload = evaluate_performance.run_stability_benchmark(
        packets, None, duration_seconds=0.2
    )
    assert payload["mode"] == "duration_seconds"
    assert payload["completed_passes"] >= 1
    assert payload["wall_seconds"] >= 0.2


def test_stability_benchmark_requires_exactly_one_bound(packets) -> None:
    with pytest.raises(ValueError, match="exactly one of iterations or duration"):
        evaluate_performance.run_stability_benchmark(packets, None)
    with pytest.raises(ValueError, match="exactly one of iterations or duration"):
        evaluate_performance.run_stability_benchmark(
            packets, None, iterations=1, duration_seconds=1.0
        )


@pytest.mark.parametrize(
    "kwargs", [{"iterations": 0}, {"iterations": -1}, {"duration_seconds": 0.0}]
)
def test_stability_benchmark_rejects_non_positive_bounds(packets, kwargs) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        evaluate_performance.run_stability_benchmark(packets, None, **kwargs)


def test_stability_benchmark_is_not_part_of_the_default_report(small_report) -> None:
    assert "sustained_controlled_run" not in small_report


# --- platform metadata ---------------------------------------------------


def test_report_records_platform_metadata_for_later_comparison(small_report) -> None:
    """Windows and Raspberry Pi outputs must be distinguishable after the fact."""
    system = small_report["system"]
    for key in (
        "python_version",
        "system",
        "machine",
        "architecture",
        "platform",
        "sklearn_version",
        "numpy_version",
    ):
        assert system[key], key


def test_no_platform_specific_value_is_hard_coded() -> None:
    """Must run unchanged on Raspberry Pi: no Windows or Pi path, CPU model or
    interface name baked in."""
    source = (REPO_ROOT / "evaluate_performance.py").read_text(encoding="utf-8")
    for forbidden in (
        "C:\\",
        "/home/pi",
        "raspberrypi",
        "AMD64",
        "aarch64",
        "wlan0",
        "eth0",
        "Intel",
    ):
        assert forbidden not in source, forbidden


# --- output schema -------------------------------------------------------


def test_report_has_every_required_benchmark_section(small_report) -> None:
    for key in (
        "timestamp",
        "phase",
        "system",
        "dataset",
        "configuration",
        "qrs_only_assessment_latency",
        "qrs_plus_isolation_forest_assessment_latency",
        "incremental_ml_overhead",
        "full_pipeline_latency",
        "software_enforcement_decision_latency",
        "throughput",
        "memory",
        "notes",
    ):
        assert key in small_report, key
    assert small_report["phase"] == "Phase 2C"


def test_every_timing_section_carries_the_documented_statistics(small_report) -> None:
    for payload in (
        small_report["qrs_only_assessment_latency"],
        small_report["qrs_plus_isolation_forest_assessment_latency"],
        small_report["full_pipeline_latency"]["qrs_only"],
        small_report["software_enforcement_decision_latency"],
    ):
        for key in ("n", "mean_ms", "median_ms", "p95_ms", "min_ms", "max_ms", "unit"):
            assert key in payload, key
        assert payload["unit"] == "milliseconds"


def test_write_outputs_produces_json_and_csv(tmp_path, small_report) -> None:
    json_path, csv_path = evaluate_performance.write_performance_outputs(
        small_report, tmp_path
    )
    assert json_path.name == "latest_performance.json"
    assert csv_path.name == "performance_metrics.csv"

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["phase"] == "Phase 2C"

    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    assert rows
    assert set(rows[0]) == {"benchmark", "metric", "value", "unit"}

    benchmarks = {row["benchmark"] for row in rows}
    assert "qrs_only_assessment_latency" in benchmarks
    assert "incremental_ml_overhead" in benchmarks
    assert "throughput_qrs_only" in benchmarks
    assert "memory" in benchmarks
    assert "platform" in benchmarks


def test_csv_records_platform_rows_so_runs_can_be_compared(tmp_path, small_report) -> None:
    _json_path, csv_path = evaluate_performance.write_performance_outputs(
        small_report, tmp_path
    )
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    platform_rows = {
        row["metric"]: row["value"] for row in rows if row["benchmark"] == "platform"
    }
    assert {"system", "machine", "architecture", "python_version"} <= set(platform_rows)


def test_notes_avoid_overclaiming(small_report) -> None:
    notes = small_report["notes"].lower()
    assert "controlled offline benchmark" in notes
    assert "this machine" in notes
    assert "single-threaded" in notes
    assert "never network throughput" in notes
    assert "physical isolation latency remains unmeasured" in notes


def test_no_forbidden_performance_claim_appears_unnegated() -> None:
    """The approved wording constraints for this phase."""
    source = (REPO_ROOT / "evaluate_performance.py").read_text(encoding="utf-8").lower()
    for phrase in (
        "line-rate",
        "production capacity",
        "whole-system cpu",
        "network throughput",
    ):
        index = source.find(phrase)
        while index != -1:
            window = source[max(0, index - 220) : index]
            assert any(
                marker in window for marker in ("not", "never", "neither", "nor")
            ), (phrase, window[-80:])
            index = source.find(phrase, index + 1)


# --- CLI -----------------------------------------------------------------


def test_argument_parser_exposes_the_documented_flags() -> None:
    parser = evaluate_performance.build_argument_parser()
    args = parser.parse_args([])
    assert args.latency_reps == evaluate_performance.DEFAULT_LATENCY_REPS
    assert args.stability_iterations is None
    assert args.duration_seconds is None
    assert args.skip_startup is False


def test_argument_parser_accepts_the_stability_flags() -> None:
    parser = evaluate_performance.build_argument_parser()
    assert parser.parse_args(["--stability-iterations", "50"]).stability_iterations == 50
    assert parser.parse_args(["--duration-seconds", "30"]).duration_seconds == 30.0
    assert parser.parse_args(["--skip-startup"]).skip_startup is True


def test_main_runs_end_to_end_without_startup_or_reports(tmp_path, capsys) -> None:
    exit_code = evaluate_performance.main(
        [
            "--latency-reps",
            "1",
            "--throughput-passes",
            "1",
            "--skip-startup",
            "--skip-report-generation",
            "--results-dir",
            str(tmp_path),
        ]
    )
    assert exit_code == 0
    assert (tmp_path / "latest_performance.json").exists()
    assert (tmp_path / "performance_metrics.csv").exists()

    output = capsys.readouterr().out
    for heading in (
        "SYSTEM INFORMATION",
        "QRS-ONLY LATENCY",
        "QRS + ISOLATION FOREST LATENCY",
        "ML OVERHEAD",
        "FULL PIPELINE LATENCY",
        "THROUGHPUT",
        "PROCESS CPU",
        "MEMORY",
    ):
        assert heading in output, heading

    payload = json.loads((tmp_path / "latest_performance.json").read_text(encoding="utf-8"))
    assert "startup" not in payload
    assert "report_generation_latency" not in payload


def test_main_rejects_both_stability_bounds(tmp_path) -> None:
    with pytest.raises(SystemExit):
        evaluate_performance.main(
            [
                "--stability-iterations",
                "5",
                "--duration-seconds",
                "5",
                "--results-dir",
                str(tmp_path),
            ]
        )


def test_main_does_not_write_into_the_real_results_directory(tmp_path) -> None:
    real_json = (
        evaluate_performance.DEFAULT_RESULTS_DIR
        / evaluate_performance.PERFORMANCE_JSON_FILENAME
    )
    before = real_json.read_bytes() if real_json.exists() else None

    evaluate_performance.main(
        [
            "--latency-reps",
            "1",
            "--throughput-passes",
            "1",
            "--skip-startup",
            "--skip-report-generation",
            "--results-dir",
            str(tmp_path),
        ]
    )

    after = real_json.read_bytes() if real_json.exists() else None
    assert after == before


# --- startup boundary ----------------------------------------------------


def test_startup_reuses_the_existing_measurement_module() -> None:
    """The startup boundary must not be redefined here: this phase reuses
    measure_startup.measure_startup() unchanged, so the figure stays comparable
    with the project's existing startup reporting."""
    tree = ast.parse((REPO_ROOT / "evaluate_performance.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert "measure_startup" in imported

    source = (REPO_ROOT / "evaluate_performance.py").read_text(encoding="utf-8")
    assert "measure_startup.measure_startup()" in source

    # No second, competing implementation of the startup boundary. Checked on
    # parsed imports, not raw text: the docstring quotes measure_startup.py's
    # boundary (including its health endpoint) precisely so a reader knows what
    # the timing covers, and a substring scan would flag that explanation.
    for module_name in ("urllib", "subprocess", "http", "socket", "requests"):
        assert module_name not in imported, module_name
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert not node.module.startswith(
                ("urllib", "http", "subprocess", "socket")
            ), node.module


def test_startup_payload_documents_what_it_includes(monkeypatch) -> None:
    """Exercised with a stub rather than real subprocess launches, so this stays
    fast; the real measurement runs only from the command line."""
    monkeypatch.setattr(
        evaluate_performance.measure_startup, "measure_startup", lambda: 4.25
    )
    payload = evaluate_performance.measure_startup_times(2)

    assert payload["n"] == 2
    assert payload["mean_seconds"] == pytest.approx(4.25)
    assert payload["max_seconds"] == pytest.approx(4.25)
    assert payload["p95_seconds"] == pytest.approx(4.25)
    assert payload["error"] is None
    assert "subprocess launch of run_demo.py" in payload["boundary"]
    assert "health" in payload["boundary"]


def test_startup_failure_is_reported_without_aborting_the_benchmark(monkeypatch) -> None:
    def _fail() -> float:
        raise TimeoutError("did not respond")

    monkeypatch.setattr(
        evaluate_performance.measure_startup, "measure_startup", _fail
    )
    payload = evaluate_performance.measure_startup_times(2)
    assert payload["error"] == "did not respond"
    assert payload["n"] == 0
    assert payload["mean_seconds"] is None
