"""Unit tests for evaluation/benchmark.py — the Phase 2C measurement
primitives.

No test asserts an exact timing: wall-clock durations are not reproducible
across machines or runs. What is asserted instead is arithmetic that must
hold (percentile positions, paired differences, unit conversions), structural
correctness (field presence, counts), relationships guaranteed by
construction, and the undefined-is-not-zero rule.
"""
from __future__ import annotations

import platform

import pytest

from evaluation.benchmark import (
    ABSOLUTE_MIN_CPU_INTERVAL_SECONDS,
    NANOSECONDS_PER_MILLISECOND,
    P99_MINIMUM_SAMPLES,
    cpu_utilization,
    measure_calls,
    paired_difference_statistics,
    peak_rss_bytes,
    percentile,
    platform_metadata,
    ru_maxrss_to_bytes,
    throughput_per_second,
    timing_statistics,
    tracemalloc_peak,
)

_MS = NANOSECONDS_PER_MILLISECOND


# --- percentile ----------------------------------------------------------


def test_percentile_hand_computed_positions() -> None:
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert percentile(values, 0) == 1.0
    assert percentile(values, 50) == 3.0
    assert percentile(values, 100) == 5.0


def test_percentile_sorts_unsorted_input() -> None:
    assert percentile([5.0, 1.0, 3.0, 2.0, 4.0], 50) == 3.0


def test_percentile_nearest_rank_matches_the_documented_formula() -> None:
    """index = round(pct/100 * (n-1)); for n=10 and p95 that is index 9."""
    values = [float(value) for value in range(10)]
    assert percentile(values, 95) == 9.0
    assert percentile(values, 90) == 8.0


def test_percentile_single_value() -> None:
    assert percentile([7.5], 95) == 7.5


def test_percentile_empty_input_is_none_not_zero() -> None:
    assert percentile([], 95) is None


@pytest.mark.parametrize("bad_pct", [-1, 101, 150])
def test_percentile_rejects_out_of_range_percentile(bad_pct) -> None:
    with pytest.raises(ValueError, match=r"pct must be within \[0, 100\]"):
        percentile([1.0], bad_pct)


# --- timing statistics ---------------------------------------------------


def test_timing_statistics_hand_computed() -> None:
    """Samples of 1, 2, 3, 4 ms."""
    stats = timing_statistics([1 * _MS, 2 * _MS, 3 * _MS, 4 * _MS])
    assert stats["n"] == 4
    assert stats["unit"] == "milliseconds"
    assert stats["mean_ms"] == pytest.approx(2.5)
    assert stats["median_ms"] == pytest.approx(2.5)
    assert stats["min_ms"] == pytest.approx(1.0)
    assert stats["max_ms"] == pytest.approx(4.0)
    assert stats["total_seconds"] == pytest.approx(0.010)


def test_timing_statistics_converts_nanoseconds_to_milliseconds() -> None:
    stats = timing_statistics([5_000_000])
    assert stats["mean_ms"] == pytest.approx(5.0)


def test_timing_statistics_stdev_undefined_for_one_sample() -> None:
    stats = timing_statistics([3 * _MS])
    assert stats["n"] == 1
    assert stats["stdev_ms"] is None
    assert stats["mean_ms"] == pytest.approx(3.0)


def test_timing_statistics_stdev_defined_from_two_samples() -> None:
    stats = timing_statistics([1 * _MS, 3 * _MS])
    assert stats["stdev_ms"] == pytest.approx(1.4142135, rel=1e-5)


def test_timing_statistics_withholds_p99_below_the_minimum_sample_count() -> None:
    """A nearest-rank p99 on a small sample is just the maximum, which would
    misrepresent one outlier as a percentile."""
    stats = timing_statistics([value * _MS for value in range(P99_MINIMUM_SAMPLES - 1)])
    assert stats["p99_ms"] is None
    assert stats["p95_ms"] is not None


def test_timing_statistics_reports_p99_at_the_minimum_sample_count() -> None:
    stats = timing_statistics([value * _MS for value in range(P99_MINIMUM_SAMPLES)])
    assert stats["p99_ms"] is not None


def test_timing_statistics_empty_input_is_all_none_not_zero() -> None:
    stats = timing_statistics([])
    assert stats["n"] == 0
    for key in ("mean_ms", "median_ms", "p95_ms", "p99_ms", "min_ms", "max_ms", "stdev_ms"):
        assert stats[key] is None, key
    assert stats["total_seconds"] == 0.0


def test_timing_statistics_ordering_relationships_hold() -> None:
    stats = timing_statistics([value * _MS for value in range(1, 201)])
    assert stats["min_ms"] <= stats["median_ms"] <= stats["max_ms"]
    assert stats["min_ms"] <= stats["mean_ms"] <= stats["max_ms"]
    assert stats["min_ms"] <= stats["p95_ms"] <= stats["max_ms"]
    assert stats["p95_ms"] <= stats["p99_ms"] <= stats["max_ms"]


# --- paired differences --------------------------------------------------


def test_paired_difference_statistics_hand_computed() -> None:
    """Baseline 1,1,1 ms against treatment 3,2,4 ms -> differences 2,1,3 ms."""
    stats = paired_difference_statistics(
        [1 * _MS, 1 * _MS, 1 * _MS], [3 * _MS, 2 * _MS, 4 * _MS]
    )
    assert stats["pairs"] == 3
    assert stats["mean_ms"] == pytest.approx(2.0)
    assert stats["median_ms"] == pytest.approx(2.0)
    assert stats["pairs_slower"] == 3
    assert stats["fraction_slower"] == pytest.approx(1.0)


def test_paired_difference_statistics_handles_a_faster_treatment() -> None:
    stats = paired_difference_statistics([5 * _MS, 5 * _MS], [2 * _MS, 8 * _MS])
    assert stats["mean_ms"] == pytest.approx(0.0)
    assert stats["pairs_slower"] == 1
    assert stats["fraction_slower"] == pytest.approx(0.5)
    assert stats["min_ms"] == pytest.approx(-3.0)


def test_paired_difference_statistics_rejects_unequal_lengths() -> None:
    with pytest.raises(ValueError, match="equal length"):
        paired_difference_statistics([1 * _MS], [1 * _MS, 2 * _MS])


def test_paired_difference_statistics_documents_its_direction() -> None:
    stats = paired_difference_statistics([1 * _MS], [2 * _MS])
    assert "treatment minus baseline" in stats["interpretation"]


def test_paired_difference_statistics_empty_input() -> None:
    stats = paired_difference_statistics([], [])
    assert stats["pairs"] == 0
    assert stats["fraction_slower"] is None
    assert stats["mean_ms"] is None


# --- CPU utilization ----------------------------------------------------


def test_cpu_ratio_hand_computed() -> None:
    result = cpu_utilization(process_time_delta_seconds=0.5, wall_time_delta_seconds=1.0)
    assert result["cpu_ratio"] == pytest.approx(0.5)
    assert result["process_cpu_utilization_percent"] == pytest.approx(50.0)


def test_cpu_ratio_of_one_is_one_core_fully_busy() -> None:
    result = cpu_utilization(2.0, 2.0)
    assert result["cpu_ratio"] == pytest.approx(1.0)
    assert result["process_cpu_utilization_percent"] == pytest.approx(100.0)
    assert "one logical CPU core" in result["interpretation"]
    assert "Not whole-system CPU usage" in result["interpretation"]


def test_cpu_ratio_is_undefined_for_a_non_positive_interval() -> None:
    for wall in (0.0, -1.0):
        result = cpu_utilization(0.5, wall)
        assert result["cpu_ratio"] is None
        assert result["process_cpu_utilization_percent"] is None
        assert result["reliable"] is False


def test_cpu_measurement_is_flagged_unreliable_for_a_short_interval() -> None:
    """The observed Windows failure mode: a 23 ms interval produced a ratio of
    1.387 for single-threaded work. Such an interval must be marked."""
    result = cpu_utilization(0.031, 0.023)
    assert result["reliable"] is False
    assert result["reliability_note"] is not None
    assert "too short" in result["reliability_note"]


def test_cpu_measurement_is_reliable_for_a_long_enough_interval() -> None:
    result = cpu_utilization(1.0, ABSOLUTE_MIN_CPU_INTERVAL_SECONDS + 1.0)
    assert result["reliable"] is True
    assert result["reliability_note"] is None


def test_cpu_payload_records_the_clock_resolution_and_threshold() -> None:
    result = cpu_utilization(1.0, 2.0)
    assert result["process_time_clock_resolution_seconds"] > 0
    assert result["minimum_reliable_interval_seconds"] >= (
        ABSOLUTE_MIN_CPU_INTERVAL_SECONDS
    )


# --- throughput ----------------------------------------------------------


def test_throughput_hand_computed() -> None:
    assert throughput_per_second(150, 3.0) == pytest.approx(50.0)


def test_throughput_is_undefined_for_a_non_positive_interval() -> None:
    assert throughput_per_second(150, 0.0) is None
    assert throughput_per_second(150, -1.0) is None


def test_throughput_of_zero_operations_is_zero_not_none() -> None:
    """Zero work in a positive interval genuinely is a rate of 0."""
    assert throughput_per_second(0, 2.0) == 0.0


# --- memory --------------------------------------------------------------


def test_ru_maxrss_linux_is_converted_from_kibibytes() -> None:
    """Getting this wrong misreports memory by three orders of magnitude."""
    assert ru_maxrss_to_bytes(2048, "Linux") == 2048 * 1024
    assert ru_maxrss_to_bytes(2048, "linux") == 2_097_152


def test_ru_maxrss_darwin_is_already_bytes() -> None:
    assert ru_maxrss_to_bytes(2048, "Darwin") == 2048


def test_ru_maxrss_unknown_platform_is_none_not_a_guess() -> None:
    assert ru_maxrss_to_bytes(2048, "Windows") is None
    assert ru_maxrss_to_bytes(2048, "SomeFutureOS") is None


def test_ru_maxrss_defaults_to_the_running_platform() -> None:
    expected = ru_maxrss_to_bytes(1024, platform.system())
    assert ru_maxrss_to_bytes(1024) == expected


def test_peak_rss_reports_availability_honestly() -> None:
    result = peak_rss_bytes()
    assert set(result) >= {"peak_rss_bytes", "available", "scope", "reason"}
    assert "process lifetime" in result["scope"]

    if result["available"]:
        assert result["peak_rss_bytes"] > 0
        assert result["peak_rss_mib"] > 0
        assert result["reason"] is None
    else:
        # Windows: no stdlib RSS, so None plus a stated reason — never a guess.
        assert result["peak_rss_bytes"] is None
        assert result["reason"]


def test_tracemalloc_peak_measures_a_known_allocation() -> None:
    """Allocating ~4 MB of bytes must show a peak of at least that."""
    holder = {}

    def work() -> None:
        holder["data"] = bytearray(4 * 1024 * 1024)

    result = tracemalloc_peak(work)
    assert result["python_heap_peak_bytes"] >= 4 * 1024 * 1024
    assert result["python_heap_peak_mib"] >= 4.0
    assert result["source"] == "tracemalloc"
    assert "Python-managed heap only" in result["scope"]


def test_tracemalloc_is_stopped_afterwards() -> None:
    import tracemalloc

    assert not tracemalloc.is_tracing()
    tracemalloc_peak(lambda: bytearray(1024))
    assert not tracemalloc.is_tracing()


def test_tracemalloc_is_stopped_even_when_the_work_raises() -> None:
    import tracemalloc

    def failing() -> None:
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        tracemalloc_peak(failing)
    assert not tracemalloc.is_tracing()


# --- platform metadata ---------------------------------------------------


def test_platform_metadata_records_what_distinguishes_windows_from_a_pi() -> None:
    metadata = platform_metadata()
    for key in (
        "python_version",
        "python_implementation",
        "system",
        "release",
        "machine",
        "architecture",
        "platform",
    ):
        assert metadata[key], key
    assert metadata["system"] == platform.system()
    assert metadata["machine"] == platform.machine()
    assert metadata["python_version"] == platform.python_version()


def test_platform_metadata_tolerates_an_unreported_processor() -> None:
    """platform.processor() is empty on some Linux builds, including Raspberry
    Pi OS — that must surface as None, not an empty string."""
    metadata = platform_metadata()
    assert metadata["processor"] is None or isinstance(metadata["processor"], str)
    assert metadata["processor"] != ""


def test_platform_metadata_does_not_leak_the_hostname() -> None:
    """The node name is recorded only as a boolean: a machine identifier is not
    needed to tell a Windows run from a Pi run."""
    metadata = platform_metadata()
    assert isinstance(metadata["node_reported"], bool)
    assert "node" not in {key for key in metadata if key != "node_reported"}

    hostname = platform.node()
    if hostname:
        assert not any(
            isinstance(value, str) and hostname in value for value in metadata.values()
        )


# --- measure_calls -------------------------------------------------------


def test_measure_calls_returns_one_sample_per_repetition() -> None:
    samples = measure_calls(lambda: sum(range(50)), repetitions=7, warmup=0)
    assert len(samples) == 7
    assert all(value >= 0 for value in samples)


def test_measure_calls_runs_warmup_calls_untimed() -> None:
    calls = {"count": 0}

    def work() -> None:
        calls["count"] += 1

    samples = measure_calls(work, repetitions=4, warmup=3)
    assert len(samples) == 4
    assert calls["count"] == 7  # 3 warmup + 4 timed


def test_measure_calls_rejects_non_positive_repetitions() -> None:
    with pytest.raises(ValueError, match="repetitions must be positive"):
        measure_calls(lambda: None, repetitions=0)


def test_measure_calls_rejects_negative_warmup() -> None:
    with pytest.raises(ValueError, match="warmup cannot be negative"):
        measure_calls(lambda: None, repetitions=1, warmup=-1)


# --- module hygiene ------------------------------------------------------


def test_benchmark_module_imports_only_the_standard_library() -> None:
    """Keeps the primitives Raspberry Pi-safe and dependency-free: notably no
    psutil, and no CIPHER domain module."""
    import ast
    from pathlib import Path

    import evaluation.benchmark as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    allowed = {
        "platform",
        "statistics",
        "sys",
        "time",
        "tracemalloc",
        "resource",
        "typing",
        "__future__",
    }
    assert imported <= allowed, imported
    forbidden = {"psutil", "numpy", "sklearn", "risk", "ml", "fusion", "pipeline"}
    assert not (imported & forbidden)
