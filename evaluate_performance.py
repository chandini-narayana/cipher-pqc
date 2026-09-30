"""evaluate_performance.py — Phase 2C controlled offline performance
benchmark (docs/SDD.md's Phase 2C addendum).

    python evaluate_performance.py
    python evaluate_performance.py --latency-reps 50 --skip-startup
    python evaluate_performance.py --stability-iterations 500
    python evaluate_performance.py --duration-seconds 120

PERFORMANCE ONLY. Nothing here changes the Quantum Risk Score, the Isolation
Forest, the fusion rule, feature extraction, packet parsing, any threshold,
enforcement, or report content. It imports the frozen modules and times
them.

A SEPARATE ENTRY POINT FROM evaluate_research.py, deliberately.
evaluate_research.py answers "is the output correct" and must stay cheap,
deterministic and safe to run anywhere. This script answers "how fast is it
on this machine", which needs repetition counts, a warm-up discipline,
subprocess launches for startup timing, an optional long-running stability
mode, and a command-line interface for all of that. Merging the two would
force every correctness run to carry benchmark machinery it does not need.

WHAT IS MEASURED, AND ON WHAT. Every benchmark runs against the Phase 2A
controlled labelled dataset — 30 deterministic offline packets
(tests/fixtures/evaluation_labelled_set.pcap). Packets are read from disk
ONCE, before any timing starts, so no latency figure includes file I/O or
pcap parsing; the one exception is startup time, which is a subprocess
measurement and documents its own boundary.

WORDING THAT MATTERS. Throughput here is SINGLE-THREADED CONTROLLED OFFLINE
throughput: sequential in-process assessments of already-loaded packets per
wall-clock second. It is not network throughput, not line-rate performance
and not production capacity. CPU figures are PROCESS CPU UTILIZATION, where
1.0 is approximately one logical core fully busy, never whole-system CPU
usage. Memory is PEAK RSS (process lifetime) and PYTHON HEAP PEAK, measured
separately. Physical isolation latency remains UNMEASURED: no hardware
enforcement backend exists (see docs/SDD.md's Phase 14 addendum), and the
enforcement figure below times only the software decision.

RASPBERRY PI. This script runs unchanged on Raspberry Pi OS / ARM64 under
Python 3.13.x. No path, CPU model, core count or interface name is
hard-coded; every platform value is read from the running system and
recorded in the results JSON so Windows and Pi outputs can be told apart
later. No new dependency is introduced: CPU comes from time.process_time(),
memory from resource.getrusage() where the platform provides it and
tracemalloc for the Python heap.
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np
import sklearn

import measure_startup
from capture.offline_source import OfflinePcapSource
from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD
from enforcement.backends import NoOpIsolationBackend
from enforcement.decision import should_isolate
from evaluation.benchmark import (
    cpu_utilization,
    measure_calls,
    paired_difference_statistics,
    peak_rss_bytes,
    platform_metadata,
    throughput_per_second,
    timing_statistics,
    tracemalloc_peak,
)
from evaluate_research import build_in_memory_detector
from fingerprint.protocol import fingerprint_packet
from models.device import Device
from pipeline.assessment_pipeline import assess_packet
from reports.pdf_generator import generate_report, is_flagged_device
from risk.port_risk import port_risk_for_protocol
from signing import generate_keypair
from tests.fixtures.labelled_evaluation_manifest import LABELLED_SET_PCAP_PATH

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_RESULTS_DIR = REPO_ROOT / "data" / "evaluation" / "research"
PERFORMANCE_JSON_FILENAME = "latest_performance.json"
PERFORMANCE_CSV_FILENAME = "performance_metrics.csv"

DEFAULT_LATENCY_REPS = 30
DEFAULT_THROUGHPUT_REPS = 20
DEFAULT_REPORT_REPS = 20
DEFAULT_STARTUP_REPS = 3
DEFAULT_WARMUP = 2

# Minimum wall-clock span for the combined throughput/CPU interval, so the
# CPU ratio is not dominated by process_time clock quantization. See
# measure_throughput_and_cpu.
DEFAULT_MIN_THROUGHPUT_SECONDS = 1.0

MISSING_FIXTURE_MESSAGE = (
    "CIPHER controlled benchmark data is missing.\n"
    f"Expected: {LABELLED_SET_PCAP_PATH}\n"
    "Generate it first (it is deliberately gitignored, like every other "
    "evaluation fixture):\n"
    "    python -m tests.fixtures.generate_labelled_evaluation_fixtures"
)

THROUGHPUT_LABEL = "single-threaded controlled offline throughput"
THROUGHPUT_DEFINITION = (
    "Sequential in-process assessments of already-loaded packets divided by "
    "wall-clock seconds. Packets are read from disk before timing begins, so "
    "this excludes file I/O and pcap parsing. It is NOT network throughput, "
    "line-rate performance or production capacity."
)

FULL_PIPELINE_DEFINITION = (
    "fingerprint_packet -> port_risk_for_protocol -> assess_packet (entropy, "
    "Quantum Risk Score, optional Isolation Forest, fusion) -> should_isolate. "
    "These are the same per-packet stages pipeline.runner._process_packet "
    "performs, excluding device-identity bookkeeping and report generation, "
    "which are timed separately or not at all."
)


class PreparedPacket:
    """One already-loaded packet plus the inputs the pipeline needs, prepared
    BEFORE timing so no latency sample includes pcap reading."""

    def __init__(self, raw_packet) -> None:
        self.raw_packet = raw_packet
        self.device = Device.first_contact(raw_packet.src_ip, raw_packet.timestamp)
        self.port_risk = port_risk_for_protocol(
            fingerprint_packet(raw_packet.payload).protocol
        )


def load_prepared_packets(
    pcap_path: Path = LABELLED_SET_PCAP_PATH,
) -> List[PreparedPacket]:
    """Read the controlled dataset once, up front.

    Raises:
        FileNotFoundError: if the gitignored fixture has not been generated,
            with the exact command that generates it.
    """
    if not Path(pcap_path).exists():
        raise FileNotFoundError(MISSING_FIXTURE_MESSAGE)
    return [
        PreparedPacket(raw_packet)
        for raw_packet in OfflinePcapSource(pcap_path).read_packets()
    ]


# --- latency benchmarks ---------------------------------------------------


def _assess_once(prepared: PreparedPacket, detector) -> None:
    assess_packet(
        prepared.raw_packet, prepared.device, prepared.port_risk, detector
    )


def _full_pipeline_once(prepared: PreparedPacket, detector) -> None:
    """Every per-packet stage the production runner performs, in its order."""
    fingerprint = fingerprint_packet(prepared.raw_packet.payload)
    port_risk = port_risk_for_protocol(fingerprint.protocol)
    assessment = assess_packet(
        prepared.raw_packet, prepared.device, port_risk, detector
    )
    should_isolate(assessment, DEFAULT_RISK_ISOLATION_THRESHOLD)


def measure_assessment_latency(
    packets: List[PreparedPacket],
    detector,
    repetitions: int,
    warmup: int = DEFAULT_WARMUP,
) -> List[int]:
    """One nanosecond sample per (packet, repetition), so every observation
    contributes equally and the sample order stays paired with any other run
    over the same packet list."""
    samples: List[int] = []
    for prepared in packets:
        samples.extend(
            measure_calls(
                lambda prepared=prepared: _assess_once(prepared, detector),
                repetitions=repetitions,
                warmup=warmup,
            )
        )
    return samples


def measure_full_pipeline_latency(
    packets: List[PreparedPacket],
    detector,
    repetitions: int,
    warmup: int = DEFAULT_WARMUP,
) -> List[int]:
    samples: List[int] = []
    for prepared in packets:
        samples.extend(
            measure_calls(
                lambda prepared=prepared: _full_pipeline_once(prepared, detector),
                repetitions=repetitions,
                warmup=warmup,
            )
        )
    return samples


def measure_enforcement_decision_latency(
    packets: List[PreparedPacket], repetitions: int
) -> List[int]:
    """Times should_isolate() plus the NoOp backend call.

    SOFTWARE DECISION ONLY. There is no hardware enforcement backend in this
    project, so this is never physical network isolation latency, which
    remains unmeasured."""
    backend = NoOpIsolationBackend()
    assessments = [
        assess_packet(p.raw_packet, p.device, p.port_risk, None) for p in packets
    ]

    import logging

    backend_logger = logging.getLogger("enforcement.backends")
    previous_level = backend_logger.level
    backend_logger.setLevel(logging.ERROR)
    try:
        samples: List[int] = []
        for assessment in assessments:
            def work(assessment=assessment) -> None:
                if should_isolate(assessment, DEFAULT_RISK_ISOLATION_THRESHOLD):
                    backend.isolate(
                        assessment.device.ip, assessment.risk_assessment.risk_score
                    )

            samples.extend(measure_calls(work, repetitions=repetitions, warmup=1))
        return samples
    finally:
        backend_logger.setLevel(previous_level)


# --- throughput and CPU ---------------------------------------------------


def measure_throughput_and_cpu(
    packets: List[PreparedPacket],
    detector,
    passes: int,
    min_wall_seconds: float = DEFAULT_MIN_THROUGHPUT_SECONDS,
) -> Dict[str, Any]:
    """Process the whole packet set sequentially, measuring wall time and
    process CPU time across the run.

    CPU and throughput come from the SAME interval deliberately, so the
    reported utilization belongs to exactly the work the throughput figure
    counts.

    Runs AT LEAST `passes` passes, then keeps going until the interval reaches
    `min_wall_seconds`. That floor exists for the CPU figure, not the
    throughput one: `time.process_time()` has ~15.6 ms resolution on Windows,
    so a QRS-only run over 30 packets finishes in ~20 ms and would yield a
    ratio built almost entirely from clock quantization (it can even exceed
    1.0 for single-threaded work). Extending the interval is the honest fix;
    the actual pass count is reported."""
    # One untimed pass so the measured interval excludes first-call warm-up.
    for prepared in packets:
        _assess_once(prepared, detector)

    wall_start = time.perf_counter()
    process_start = time.process_time()
    completed = 0
    while completed < passes or (time.perf_counter() - wall_start) < min_wall_seconds:
        for prepared in packets:
            _assess_once(prepared, detector)
        completed += 1
    wall_elapsed = time.perf_counter() - wall_start
    process_elapsed = time.process_time() - process_start

    assessments = completed * len(packets)
    return {
        "label": THROUGHPUT_LABEL,
        "definition": THROUGHPUT_DEFINITION,
        "packets_per_pass": len(packets),
        "requested_passes": passes,
        "passes": completed,
        "minimum_wall_seconds": min_wall_seconds,
        "assessments": assessments,
        "wall_seconds": wall_elapsed,
        "assessments_per_second": throughput_per_second(assessments, wall_elapsed),
        "mean_seconds_per_assessment": (
            wall_elapsed / assessments if assessments else None
        ),
        "cpu": cpu_utilization(process_elapsed, wall_elapsed),
    }


# --- memory ---------------------------------------------------------------


def measure_python_heap(packets: List[PreparedPacket], detector) -> Dict[str, Any]:
    """Python heap peak for one pass over the packet set, in a separate pass
    under tracemalloc (which slows execution, so it yields no timing)."""

    def work() -> None:
        for prepared in packets:
            _assess_once(prepared, detector)

    return tracemalloc_peak(work)


# --- report generation ----------------------------------------------------


def measure_report_generation_latency(
    packets: List[PreparedPacket], repetitions: int
) -> Dict[str, Any]:
    """Time one signed PDF report per repetition, into a TEMPORARY directory.

    Never writes to data/reports/, so a user's real reports are never
    overwritten. Uses an ephemeral keypair. A distinct report_id per
    repetition keeps each write an independent new file rather than repeatedly
    truncating one. Excludes any download or browser activity — this is
    generation only, inside the process."""
    flagged = None
    for prepared in packets:
        assessment = assess_packet(
            prepared.raw_packet, prepared.device, prepared.port_risk, None
        )
        if is_flagged_device(assessment):
            flagged = assessment
            break
    if flagged is None:
        raise RuntimeError(
            "no flagged assessment available in the controlled dataset; cannot "
            "benchmark report generation"
        )

    public_key, secret_key = generate_keypair()
    generated_at = datetime(2026, 1, 1, tzinfo=timezone.utc)

    with tempfile.TemporaryDirectory(prefix="cipher-report-benchmark-") as tmp_dir:
        counter = {"index": 0}

        def work() -> None:
            counter["index"] += 1
            generate_report(
                flagged,
                secret_key,
                public_key,
                output_dir=tmp_dir,
                report_id=f"CIPHER-BENCHMARK-{counter['index']:06d}",
                generated_at=generated_at,
            )

        samples = measure_calls(work, repetitions=repetitions, warmup=1)

    payload = timing_statistics(samples)
    payload["scope"] = (
        "one signed 3-page PDF per repetition, written to a temporary directory; "
        "excludes any download or browser activity"
    )
    payload["device_ip"] = flagged.device.ip
    payload["final_category"] = flagged.final_category.value
    return payload


# --- startup --------------------------------------------------------------


def measure_startup_times(repetitions: int) -> Dict[str, Any]:
    """Reuse measure_startup.measure_startup() unchanged, so the startup
    boundary is not redefined here.

    WHAT THE TIMING INCLUDES (measure_startup.py's own definition): launching
    `python run_demo.py` as a real SUBPROCESS on port 5099 with a temporary
    cwd, and polling GET /api/health until it first answers 200 OK. That
    covers interpreter start, every import, model/key loading, pcap
    processing and Flask binding the port — it is deliberately a whole
    cold-start measurement, not an in-process one, and it therefore also
    includes the ~0.1s health-poll granularity.

    Returns a payload whose `error` field is set, rather than raising, if the
    subprocess never answers — a benchmark run should still report everything
    else it measured."""
    samples_seconds: List[float] = []
    error: Optional[str] = None
    for _ in range(repetitions):
        try:
            samples_seconds.append(measure_startup.measure_startup())
        except (RuntimeError, TimeoutError) as exc:
            error = str(exc)
            break

    samples_ns = [int(value * 1_000_000_000) for value in samples_seconds]
    payload = timing_statistics(samples_ns)
    payload["boundary"] = (
        "subprocess launch of run_demo.py until GET /api/health first returns "
        "200 OK (measure_startup.py, unchanged); includes interpreter start, "
        "imports, key/model loading, pcap processing and Flask port binding, "
        "plus the 0.1s health-poll interval"
    )
    payload["port"] = measure_startup.DEFAULT_PORT
    payload["target_seconds"] = measure_startup.STARTUP_TARGET_SECONDS
    payload["mean_seconds"] = (
        None if payload["mean_ms"] is None else payload["mean_ms"] / 1000.0
    )
    payload["max_seconds"] = (
        None if payload["max_ms"] is None else payload["max_ms"] / 1000.0
    )
    payload["p95_seconds"] = (
        None if payload["p95_ms"] is None else payload["p95_ms"] / 1000.0
    )
    payload["error"] = error
    return payload


# --- optional sustained/stability run ------------------------------------


def run_stability_benchmark(
    packets: List[PreparedPacket],
    detector,
    iterations: Optional[int] = None,
    duration_seconds: Optional[float] = None,
    sample_every: int = 25,
) -> Dict[str, Any]:
    """OPTIONAL sustained run: repeatedly process the deterministic packet set,
    recording per-pass wall time so drift or degradation over a long run is
    visible.

    Never invoked by the default benchmark and never by pytest — it exists to
    support Raspberry Pi stability measurement later, where the question is
    whether throughput holds up over minutes under thermal load.

    Exactly one of `iterations` or `duration_seconds` must be given.

    Raises:
        ValueError: if neither or both bounds are supplied, or a bound is not
            positive.
    """
    if (iterations is None) == (duration_seconds is None):
        raise ValueError(
            "supply exactly one of iterations or duration_seconds"
        )
    if iterations is not None and iterations <= 0:
        raise ValueError(f"iterations must be positive, got {iterations}")
    if duration_seconds is not None and duration_seconds <= 0:
        raise ValueError(
            f"duration_seconds must be positive, got {duration_seconds}"
        )

    pass_times_ns: List[int] = []
    wall_start = time.perf_counter()
    process_start = time.process_time()
    deadline = None if duration_seconds is None else wall_start + duration_seconds

    completed = 0
    while True:
        if iterations is not None and completed >= iterations:
            break
        if deadline is not None and time.perf_counter() >= deadline:
            break

        start = time.perf_counter_ns()
        for prepared in packets:
            _assess_once(prepared, detector)
        pass_times_ns.append(time.perf_counter_ns() - start)
        completed += 1

    wall_elapsed = time.perf_counter() - wall_start
    process_elapsed = time.process_time() - process_start

    per_pass = timing_statistics(pass_times_ns)
    # First-versus-last comparison, which is what exposes drift that a mean
    # over the whole run would average away.
    window = max(1, len(pass_times_ns) // 10)
    first_window = pass_times_ns[:window]
    last_window = pass_times_ns[-window:]

    assessments = completed * len(packets)
    return {
        "mode": "iterations" if iterations is not None else "duration_seconds",
        "requested_iterations": iterations,
        "requested_duration_seconds": duration_seconds,
        "completed_passes": completed,
        "packets_per_pass": len(packets),
        "assessments": assessments,
        "wall_seconds": wall_elapsed,
        "assessments_per_second": throughput_per_second(assessments, wall_elapsed),
        "per_pass_latency": per_pass,
        "cpu": cpu_utilization(process_elapsed, wall_elapsed),
        "drift": {
            "window_passes": window,
            "first_window_mean_ms": (
                statistics.fmean(first_window) / 1_000_000 if first_window else None
            ),
            "last_window_mean_ms": (
                statistics.fmean(last_window) / 1_000_000 if last_window else None
            ),
            "interpretation": (
                "mean per-pass latency over the first and last tenth of the run; a "
                "materially higher last window suggests thermal throttling or "
                "resource growth"
            ),
        },
        "memory": peak_rss_bytes(),
        "label": "sustained controlled offline run on this machine",
    }


# --- report assembly ------------------------------------------------------


def build_performance_report(
    packets: List[PreparedPacket],
    detector,
    detector_metadata: Dict[str, Any],
    latency_reps: int = DEFAULT_LATENCY_REPS,
    throughput_passes: int = DEFAULT_THROUGHPUT_REPS,
    report_reps: int = DEFAULT_REPORT_REPS,
    startup_reps: int = DEFAULT_STARTUP_REPS,
    include_startup: bool = True,
    include_report_generation: bool = True,
) -> Dict[str, Any]:
    """Run every benchmark and assemble the results.

    QRS-only and QRS+Isolation Forest latency are measured over the SAME
    packet list in the SAME sample order, so the two sample sequences are
    positionally paired and the ML overhead can be differenced per
    observation rather than as a difference of independent means."""
    system = platform_metadata()
    system["sklearn_version"] = sklearn.__version__
    system["numpy_version"] = np.__version__

    qrs_only_samples = measure_assessment_latency(packets, None, latency_reps)
    qrs_plus_ml_samples = measure_assessment_latency(packets, detector, latency_reps)

    full_pipeline_qrs_only = measure_full_pipeline_latency(packets, None, latency_reps)
    full_pipeline_with_ml = measure_full_pipeline_latency(
        packets, detector, latency_reps
    )

    enforcement_samples = measure_enforcement_decision_latency(packets, latency_reps)

    throughput_qrs_only = measure_throughput_and_cpu(packets, None, throughput_passes)
    throughput_with_ml = measure_throughput_and_cpu(
        packets, detector, throughput_passes
    )

    report: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": "Phase 2C",
        "benchmark_mode": "controlled offline benchmark on this machine",
        "system": system,
        "model": {
            "contamination": detector_metadata["contamination"],
            "random_state": detector_metadata["random_state"],
            "training_matrix_shape": detector_metadata["training_matrix_shape"],
            "fitted": detector_metadata["fitted"],
        },
        "dataset": {
            "pcap_path": str(LABELLED_SET_PCAP_PATH),
            "packets": len(packets),
            "note": (
                "Phase 2A controlled labelled dataset, read from disk ONCE before "
                "any timing began; no latency figure includes file I/O or pcap "
                "parsing."
            ),
        },
        "configuration": {
            "latency_repetitions_per_packet": latency_reps,
            "throughput_passes": throughput_passes,
            "report_repetitions": report_reps,
            "startup_repetitions": startup_reps if include_startup else 0,
            "warmup_calls_per_packet": DEFAULT_WARMUP,
            "clock": "time.perf_counter_ns",
        },
        "qrs_only_assessment_latency": timing_statistics(qrs_only_samples),
        "qrs_plus_isolation_forest_assessment_latency": timing_statistics(
            qrs_plus_ml_samples
        ),
        "incremental_ml_overhead": paired_difference_statistics(
            qrs_only_samples, qrs_plus_ml_samples
        ),
        "full_pipeline_latency": {
            "definition": FULL_PIPELINE_DEFINITION,
            "qrs_only": timing_statistics(full_pipeline_qrs_only),
            "with_isolation_forest": timing_statistics(full_pipeline_with_ml),
            "incremental_ml_overhead": paired_difference_statistics(
                full_pipeline_qrs_only, full_pipeline_with_ml
            ),
        },
        "software_enforcement_decision_latency": {
            **timing_statistics(enforcement_samples),
            "scope": (
                "should_isolate() plus NoOpIsolationBackend.isolate(). SOFTWARE "
                "DECISION ONLY — physical network isolation latency remains "
                "UNMEASURED, as no hardware enforcement backend exists."
            ),
        },
        "throughput": {
            "qrs_only": throughput_qrs_only,
            "with_isolation_forest": throughput_with_ml,
        },
        "memory": {
            "peak_rss": peak_rss_bytes(),
            "python_heap": measure_python_heap(packets, detector),
        },
        "notes": (
            "Controlled offline benchmark measured on THIS machine, "
            "single-threaded, on deterministic synthetic/offline packets. "
            "Throughput is single-threaded controlled offline throughput, never "
            "network throughput, line-rate performance or production capacity. CPU "
            "figures are process CPU utilization (1.0 is approximately one logical "
            "core fully busy), never whole-system CPU usage. Physical isolation "
            "latency remains unmeasured. No scoring, model, fusion, threshold, "
            "parsing or report behavior was changed for this phase."
        ),
    }

    if include_report_generation:
        report["report_generation_latency"] = measure_report_generation_latency(
            packets, report_reps
        )
    if include_startup:
        report["startup"] = measure_startup_times(startup_reps)

    return report


PERFORMANCE_CSV_COLUMNS = ["benchmark", "metric", "value", "unit"]


def _flatten_timing(benchmark: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for key in ("n", "mean_ms", "median_ms", "p95_ms", "p99_ms", "min_ms", "max_ms", "stdev_ms"):
        if key not in payload:
            continue
        rows.append(
            {
                "benchmark": benchmark,
                "metric": key,
                "value": payload[key],
                "unit": "count" if key == "n" else "milliseconds",
            }
        )
    return rows


def write_performance_outputs(
    report: Dict[str, Any], results_dir: Path
) -> Tuple[Path, Path]:
    """Write the JSON report and a flat metric CSV (one metric per row, so a
    Windows run and a Pi run can be concatenated and compared directly)."""
    results_dir.mkdir(parents=True, exist_ok=True)

    json_path = results_dir / PERFORMANCE_JSON_FILENAME
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    rows: List[Dict[str, Any]] = []
    rows.extend(
        _flatten_timing("qrs_only_assessment_latency", report["qrs_only_assessment_latency"])
    )
    rows.extend(
        _flatten_timing(
            "qrs_plus_isolation_forest_assessment_latency",
            report["qrs_plus_isolation_forest_assessment_latency"],
        )
    )
    rows.extend(_flatten_timing("incremental_ml_overhead", report["incremental_ml_overhead"]))
    rows.extend(
        _flatten_timing(
            "full_pipeline_latency_qrs_only", report["full_pipeline_latency"]["qrs_only"]
        )
    )
    rows.extend(
        _flatten_timing(
            "full_pipeline_latency_with_isolation_forest",
            report["full_pipeline_latency"]["with_isolation_forest"],
        )
    )
    rows.extend(
        _flatten_timing(
            "software_enforcement_decision_latency",
            report["software_enforcement_decision_latency"],
        )
    )
    if "report_generation_latency" in report:
        rows.extend(
            _flatten_timing("report_generation_latency", report["report_generation_latency"])
        )
    if "startup" in report:
        rows.extend(_flatten_timing("startup", report["startup"]))

    for variant in ("qrs_only", "with_isolation_forest"):
        throughput = report["throughput"][variant]
        rows.append(
            {
                "benchmark": f"throughput_{variant}",
                "metric": "assessments_per_second",
                "value": throughput["assessments_per_second"],
                "unit": "assessments/second",
            }
        )
        rows.append(
            {
                "benchmark": f"throughput_{variant}",
                "metric": "process_cpu_utilization_percent",
                "value": throughput["cpu"]["process_cpu_utilization_percent"],
                "unit": "percent of one logical core",
            }
        )

    rows.append(
        {
            "benchmark": "memory",
            "metric": "peak_rss_bytes",
            "value": report["memory"]["peak_rss"]["peak_rss_bytes"],
            "unit": "bytes",
        }
    )
    rows.append(
        {
            "benchmark": "memory",
            "metric": "python_heap_peak_bytes",
            "value": report["memory"]["python_heap"]["python_heap_peak_bytes"],
            "unit": "bytes",
        }
    )
    for key in ("system", "machine", "architecture", "python_version"):
        rows.append(
            {
                "benchmark": "platform",
                "metric": key,
                "value": report["system"][key],
                "unit": "metadata",
            }
        )

    csv_path = results_dir / PERFORMANCE_CSV_FILENAME
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=PERFORMANCE_CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    return json_path, csv_path


# --- console output -------------------------------------------------------


def _format_ms(value: Optional[float]) -> str:
    return "not available" if value is None else f"{value:.4f}ms"


def _print_timing(title: str, payload: Dict[str, Any], indent: str = "  ") -> None:
    print(f"{indent}{title}")
    print(
        f"{indent}  n={payload['n']}  mean={_format_ms(payload['mean_ms'])}  "
        f"median={_format_ms(payload['median_ms'])}"
    )
    print(
        f"{indent}  p95={_format_ms(payload['p95_ms'])}  "
        f"p99={_format_ms(payload['p99_ms'])}  "
        f"min={_format_ms(payload['min_ms'])}  max={_format_ms(payload['max_ms'])}  "
        f"stdev={_format_ms(payload['stdev_ms'])}"
    )


def print_performance_report(report: Dict[str, Any]) -> None:
    system = report["system"]
    print("=" * 78)
    print("CIPHER Phase 2C — Controlled offline performance benchmark")
    print("=" * 78)
    print(
        "\nPerformance only: no scoring, model, fusion, threshold, parsing or "
        "report behavior was changed. Every figure is measured on THIS machine, "
        "single-threaded, over deterministic offline packets.\n"
    )

    print("SYSTEM INFORMATION")
    print(f"  Python:        {system['python_version']} ({system['python_implementation']})")
    print(f"  Platform:      {system['platform']}")
    print(f"  System:        {system['system']} {system['release']}")
    print(f"  Machine:       {system['machine']}   architecture: {system['architecture']}")
    print(f"  Processor:     {system['processor'] or 'not reported by platform'}")
    print(f"  scikit-learn:  {system['sklearn_version']}")
    print(f"  numpy:         {system['numpy_version']}")
    dataset = report["dataset"]
    configuration = report["configuration"]
    print(
        f"  Dataset:       {dataset['packets']} deterministic offline packets, "
        f"{configuration['latency_repetitions_per_packet']} repetitions each"
    )
    print(f"  Clock:         {configuration['clock']}")
    print()

    print("QRS-ONLY LATENCY (deterministic assessment path, no ML)")
    _print_timing("assess_packet(anomaly_detector=None)", report["qrs_only_assessment_latency"])
    print()

    print("QRS + ISOLATION FOREST LATENCY (same packets, model attached)")
    _print_timing(
        "assess_packet(anomaly_detector=<fitted model>)",
        report["qrs_plus_isolation_forest_assessment_latency"],
    )
    print()

    print("ML OVERHEAD (paired per-observation difference)")
    overhead = report["incremental_ml_overhead"]
    _print_timing("QRS+IF minus QRS-only", overhead)
    print(
        f"    pairs={overhead['pairs']}  slower in "
        f"{overhead['pairs_slower']}/{overhead['pairs']} pairs"
    )
    print()

    print("FULL PIPELINE LATENCY")
    print(f"  definition: {report['full_pipeline_latency']['definition']}")
    _print_timing("QRS-only", report["full_pipeline_latency"]["qrs_only"])
    _print_timing(
        "with Isolation Forest", report["full_pipeline_latency"]["with_isolation_forest"]
    )
    print()

    print("SOFTWARE ENFORCEMENT DECISION LATENCY")
    _print_timing(
        "should_isolate + NoOp backend", report["software_enforcement_decision_latency"]
    )
    print(f"    {report['software_enforcement_decision_latency']['scope']}")
    print()

    print(f"THROUGHPUT ({THROUGHPUT_LABEL})")
    for variant, title in (
        ("qrs_only", "QRS-only"),
        ("with_isolation_forest", "with Isolation Forest"),
    ):
        throughput = report["throughput"][variant]
        rate = throughput["assessments_per_second"]
        print(
            f"  {title:<24} {rate:,.1f} assessments/s "
            f"({throughput['assessments']} assessments in "
            f"{throughput['wall_seconds']:.3f}s)"
        )
    print(f"  NOT network throughput or line-rate performance.")
    print()

    print("PROCESS CPU")
    for variant, title in (
        ("qrs_only", "QRS-only"),
        ("with_isolation_forest", "with Isolation Forest"),
    ):
        cpu = report["throughput"][variant]["cpu"]
        ratio = cpu["cpu_ratio"]
        percent = cpu["process_cpu_utilization_percent"]
        flag = "" if cpu["reliable"] else "  [indicative only — interval too short]"
        print(
            f"  {title:<24} ratio={ratio:.3f}  "
            f"process CPU utilization={percent:.1f}% of one logical core{flag}"
        )
    print("  1.0 is approximately one logical core fully busy BY THIS PROCESS;")
    print("  this is not whole-system CPU usage.")
    resolution = report["throughput"]["qrs_only"]["cpu"][
        "process_time_clock_resolution_seconds"
    ]
    print(f"  process_time clock resolution on this platform: {resolution * 1000:.2f}ms")
    print()

    print("MEMORY")
    rss = report["memory"]["peak_rss"]
    if rss["available"]:
        print(
            f"  Peak RSS (process lifetime):  {rss['peak_rss_mib']:.1f} MiB "
            f"(via {rss['source']})"
        )
    else:
        print(f"  Peak RSS (process lifetime):  not available — {rss['reason']}")
    heap = report["memory"]["python_heap"]
    print(
        f"  Python heap peak:             {heap['python_heap_peak_mib']:.3f} MiB "
        f"(tracemalloc, separate pass)"
    )
    print(f"  {heap['scope']}")
    print()

    if "startup" in report:
        startup = report["startup"]
        print("STARTUP")
        if startup["error"]:
            print(f"  measurement failed: {startup['error']}")
        else:
            print(
                f"  n={startup['n']}  mean={startup['mean_seconds']:.3f}s  "
                f"p95={startup['p95_seconds']:.3f}s  max={startup['max_seconds']:.3f}s  "
                f"(target < {startup['target_seconds']:.0f}s)"
            )
        print(f"  boundary: {startup['boundary']}")
        print()

    if "report_generation_latency" in report:
        print("REPORT GENERATION")
        _print_timing("one signed 3-page PDF", report["report_generation_latency"])
        print(f"    {report['report_generation_latency']['scope']}")
        print()


def print_stability_report(payload: Dict[str, Any]) -> None:
    print("SUSTAINED CONTROLLED RUN (optional)")
    print(
        f"  completed {payload['completed_passes']} passes "
        f"({payload['assessments']} assessments) in {payload['wall_seconds']:.2f}s"
    )
    rate = payload["assessments_per_second"]
    print(f"  {rate:,.1f} assessments/s sustained")
    _print_timing("per-pass latency", payload["per_pass_latency"])
    drift = payload["drift"]
    print(
        f"  drift: first {drift['window_passes']} passes mean "
        f"{drift['first_window_mean_ms']:.3f}ms vs last "
        f"{drift['last_window_mean_ms']:.3f}ms"
    )
    cpu = payload["cpu"]
    print(
        f"  process CPU utilization={cpu['process_cpu_utilization_percent']:.1f}% "
        f"of one logical core"
    )
    print()


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "CIPHER Phase 2C controlled offline performance benchmark. "
            "Measures only; changes no scoring, model or threshold behavior."
        )
    )
    parser.add_argument(
        "--latency-reps",
        type=int,
        default=DEFAULT_LATENCY_REPS,
        help="timed repetitions per packet for each latency benchmark",
    )
    parser.add_argument(
        "--throughput-passes",
        type=int,
        default=DEFAULT_THROUGHPUT_REPS,
        help="sequential passes over the packet set for the throughput benchmark",
    )
    parser.add_argument(
        "--report-reps",
        type=int,
        default=DEFAULT_REPORT_REPS,
        help="signed PDF reports to generate for the report-latency benchmark",
    )
    parser.add_argument(
        "--startup-reps",
        type=int,
        default=DEFAULT_STARTUP_REPS,
        help="subprocess startup measurements to take",
    )
    parser.add_argument(
        "--skip-startup",
        action="store_true",
        help="skip startup timing (it launches run_demo.py as a subprocess)",
    )
    parser.add_argument(
        "--skip-report-generation",
        action="store_true",
        help="skip the signed-PDF generation benchmark",
    )
    parser.add_argument(
        "--stability-iterations",
        type=int,
        default=None,
        help=(
            "OPTIONAL sustained run: process the packet set this many times, "
            "reporting drift. Not part of the default benchmark."
        ),
    )
    parser.add_argument(
        "--duration-seconds",
        type=float,
        default=None,
        help=(
            "OPTIONAL sustained run bounded by wall-clock seconds instead of "
            "iterations. Not part of the default benchmark."
        ),
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=DEFAULT_RESULTS_DIR,
        help="directory for latest_performance.json and performance_metrics.csv",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if args.stability_iterations is not None and args.duration_seconds is not None:
        parser.error("use either --stability-iterations or --duration-seconds, not both")

    try:
        packets = load_prepared_packets()
    except FileNotFoundError as error:
        print(str(error), file=sys.stderr)
        return 1

    detector, detector_metadata = build_in_memory_detector()

    report = build_performance_report(
        packets,
        detector,
        detector_metadata,
        latency_reps=args.latency_reps,
        throughput_passes=args.throughput_passes,
        report_reps=args.report_reps,
        startup_reps=args.startup_reps,
        include_startup=not args.skip_startup,
        include_report_generation=not args.skip_report_generation,
    )

    print_performance_report(report)

    if args.stability_iterations is not None or args.duration_seconds is not None:
        stability = run_stability_benchmark(
            packets,
            detector,
            iterations=args.stability_iterations,
            duration_seconds=args.duration_seconds,
        )
        report["sustained_controlled_run"] = stability
        print_stability_report(stability)

    json_path, csv_path = write_performance_outputs(report, args.results_dir)
    print("=" * 78)
    print(f"Performance JSON written to {json_path}")
    print(f"Performance metric CSV written to {csv_path}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
