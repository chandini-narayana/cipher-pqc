"""Timing, CPU, memory and platform measurement primitives — standard
library only, no CIPHER domain logic.

Imports nothing from risk/, ml/, fusion/, fingerprint/, entropy/ or
pipeline/ (enforced by a test), and knows nothing about packets, scores or
models: it is handed samples and returns statistics. The orchestration that
drives CIPHER's real modules lives in evaluate_performance.py.

WHAT THE NUMBERS FROM THIS MODULE MEAN, PRECISELY:

- Latency samples are nanoseconds from `time.perf_counter_ns()`, a
  monotonic high-resolution clock. They are reported in milliseconds.
- `cpu_utilization()` divides `time.process_time()` by wall time. A ratio
  of 1.0 means this PROCESS kept approximately one logical core busy for
  the whole interval. It is process CPU utilization, NOT whole-system CPU
  usage, and on a multi-core machine it can exceed 1.0 only if the process
  uses threads across cores.
- `peak_rss_bytes()` is the peak resident set size for the whole PROCESS
  LIFETIME, not for one benchmark. It is not available on Windows without
  a third-party dependency, and reports None there rather than guessing.
- `tracemalloc_peak()` measures the PYTHON-MANAGED HEAP only, and must run
  in a separate pass because tracemalloc materially slows execution.

Nothing here claims network throughput, line-rate performance, production
capacity or physical isolation latency.
"""
from __future__ import annotations

import platform
import statistics
import sys
import time
import tracemalloc
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:  # pragma: no cover - platform-dependent import
    import resource  # POSIX only (Linux, including Raspberry Pi OS, and macOS)
except ImportError:  # pragma: no cover - Windows has no resource module
    resource = None  # type: ignore[assignment]

__all__ = [
    "NANOSECONDS_PER_MILLISECOND",
    "P99_MINIMUM_SAMPLES",
    "RELIABLE_CPU_INTERVAL_TICKS",
    "ABSOLUTE_MIN_CPU_INTERVAL_SECONDS",
    "percentile",
    "timing_statistics",
    "paired_difference_statistics",
    "cpu_utilization",
    "throughput_per_second",
    "ru_maxrss_to_bytes",
    "peak_rss_bytes",
    "tracemalloc_peak",
    "platform_metadata",
    "measure_calls",
]

NANOSECONDS_PER_MILLISECOND = 1_000_000

# Below this sample count a nearest-rank p99 is just the maximum, which
# would dress a single outlier up as a percentile. Reported as None instead.
P99_MINIMUM_SAMPLES = 100

# A CPU-utilization interval must span at least this many process_time clock
# ticks to be treated as reliable — short of that, the ratio is mostly
# quantization noise.
RELIABLE_CPU_INTERVAL_TICKS = 20

# An absolute floor as well, because the resolution `time.get_clock_info()`
# advertises can be far finer than the platform's real CPU-time ACCOUNTING
# granularity: Windows reports a sub-microsecond resolution while
# GetProcessTimes actually updates on a ~15.6 ms scheduler tick. A tick-based
# test alone therefore passes intervals that are in fact badly under-sampled
# (an observed case: a 23 ms interval yielding a ratio of 1.387 for
# single-threaded work, which is impossible).
ABSOLUTE_MIN_CPU_INTERVAL_SECONDS = 0.25


def percentile(values: Sequence[float], pct: float) -> Optional[float]:
    """Nearest-rank percentile of `values`.

    Uses the same convention the project's existing evaluate_demo.py
    percentile helper uses — index = round(pct/100 * (n-1)) into the sorted
    sample, clamped to the last element — so a p95 reported here means the
    same thing as a p95 reported there, rather than introducing a second,
    subtly different definition.

    Returns None for empty input (never 0.0).

    Raises:
        ValueError: if `pct` is outside [0, 100].
    """
    if not 0.0 <= pct <= 100.0:
        raise ValueError(f"pct must be within [0, 100], got {pct}")
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(pct / 100.0 * (len(ordered) - 1))))
    return ordered[index]


def timing_statistics(samples_ns: Sequence[int]) -> Dict[str, Any]:
    """Summarize nanosecond latency samples, reported in milliseconds.

    Every statistic is None for empty input, and `stdev_ms` is None for a
    single sample (standard deviation is undefined there, not 0). `p99_ms`
    is None below P99_MINIMUM_SAMPLES samples — see that constant.

    `total_seconds` is the summed sample time, which is the measured work,
    not the wall-clock duration of the surrounding benchmark loop.
    """
    count = len(samples_ns)
    if count == 0:
        return {
            "n": 0,
            "unit": "milliseconds",
            "mean_ms": None,
            "median_ms": None,
            "p95_ms": None,
            "p99_ms": None,
            "min_ms": None,
            "max_ms": None,
            "stdev_ms": None,
            "total_seconds": 0.0,
        }

    samples_ms = [value / NANOSECONDS_PER_MILLISECOND for value in samples_ns]
    return {
        "n": count,
        "unit": "milliseconds",
        "mean_ms": statistics.fmean(samples_ms),
        "median_ms": statistics.median(samples_ms),
        "p95_ms": percentile(samples_ms, 95),
        "p99_ms": percentile(samples_ms, 99) if count >= P99_MINIMUM_SAMPLES else None,
        "min_ms": min(samples_ms),
        "max_ms": max(samples_ms),
        "stdev_ms": statistics.stdev(samples_ms) if count >= 2 else None,
        "total_seconds": sum(samples_ms) / 1000.0,
    }


def paired_difference_statistics(
    baseline_ns: Sequence[int], treatment_ns: Sequence[int]
) -> Dict[str, Any]:
    """Per-pair difference statistics, `treatment - baseline`.

    PAIRED, not a difference of two independent means: each sample pair is
    the same observation measured both ways, so differencing within the pair
    cancels per-observation variation (payload size, protocol) that would
    otherwise swamp the effect being measured. A negative value means the
    treatment was FASTER for that pair.

    Reports the share of pairs where the treatment was slower, so a mean
    overhead cannot hide a bimodal result.

    Raises:
        ValueError: if the two sequences differ in length — an unpaired
            comparison would be meaningless here.
    """
    if len(baseline_ns) != len(treatment_ns):
        raise ValueError(
            f"paired sequences must have equal length, got "
            f"{len(baseline_ns)} and {len(treatment_ns)}"
        )

    differences = [
        treatment - baseline for baseline, treatment in zip(baseline_ns, treatment_ns)
    ]
    statistics_payload = timing_statistics(differences)
    statistics_payload["pairs"] = len(differences)
    statistics_payload["pairs_slower"] = sum(1 for value in differences if value > 0)
    statistics_payload["fraction_slower"] = (
        None if not differences else sum(1 for value in differences if value > 0) / len(differences)
    )
    statistics_payload["interpretation"] = (
        "treatment minus baseline, per paired observation; positive means the "
        "treatment was slower"
    )
    return statistics_payload


def cpu_utilization(
    process_time_delta_seconds: float, wall_time_delta_seconds: float
) -> Dict[str, Any]:
    """Process CPU utilization over an interval.

        ratio = delta(time.process_time) / delta(wall clock)

    A ratio of ~1.0 means this process kept approximately ONE LOGICAL CORE
    fully busy for the interval. This is process CPU utilization only — it
    is not whole-system CPU usage, and says nothing about what other
    processes were doing.

    Returns None for both figures when the wall interval is not positive,
    rather than dividing by zero or reporting a fabricated 0.0.

    RELIABILITY MATTERS HERE. `time.process_time()` is coarse on some
    platforms — around 15.6 ms on Windows — so over a short interval the
    ratio is dominated by quantization and can even exceed 1.0 for
    single-threaded work. The returned payload therefore carries the clock's
    own resolution and a `reliable` flag (set when the interval spans at
    least RELIABLE_CPU_INTERVAL_TICKS resolution ticks), so an
    under-sampled ratio is visibly marked rather than quietly reported as
    fact.
    """
    ratio = (
        process_time_delta_seconds / wall_time_delta_seconds
        if wall_time_delta_seconds > 0
        else None
    )
    resolution = time.get_clock_info("process_time").resolution
    minimum_interval = max(
        RELIABLE_CPU_INTERVAL_TICKS * resolution, ABSOLUTE_MIN_CPU_INTERVAL_SECONDS
    )
    reliable = (
        wall_time_delta_seconds >= minimum_interval if ratio is not None else False
    )
    return {
        "process_time_seconds": process_time_delta_seconds,
        "wall_time_seconds": wall_time_delta_seconds,
        "cpu_ratio": ratio,
        "process_cpu_utilization_percent": None if ratio is None else ratio * 100.0,
        "process_time_clock_resolution_seconds": resolution,
        "minimum_reliable_interval_seconds": minimum_interval,
        "reliable": reliable,
        "interpretation": (
            "delta(time.process_time) / delta(wall clock). A ratio of 1.0 is "
            "approximately one logical CPU core fully utilized BY THIS PROCESS. "
            "Not whole-system CPU usage."
        ),
        "reliability_note": (
            None
            if reliable
            else (
                "Interval too short relative to the process_time clock resolution "
                "for a trustworthy ratio — quantization dominates, and the value "
                "may even exceed 1.0 for single-threaded work. Treat as indicative "
                "only."
            )
        ),
    }


def throughput_per_second(count: int, wall_time_seconds: float) -> Optional[float]:
    """Operations per wall-clock second, or None if the interval is not
    positive.

    The caller is responsible for labelling what is being counted; this
    function attaches no meaning. In this project it is always single-threaded
    controlled offline processing, never network throughput.
    """
    if wall_time_seconds <= 0:
        return None
    return count / wall_time_seconds


def ru_maxrss_to_bytes(ru_maxrss: int, system: Optional[str] = None) -> Optional[int]:
    """Convert `resource.getrusage().ru_maxrss` to BYTES for `system`.

    The unit is platform-dependent and getting it wrong misreports memory by
    three orders of magnitude:
      - Linux (including Raspberry Pi OS): KIBIBYTES -> multiply by 1024.
      - macOS/Darwin: already bytes.
      - Anything else: None, rather than guessing at a unit.

    `system` defaults to the running platform, and is a parameter so the
    conversion is testable on a machine of any kind.
    """
    resolved = (system or platform.system()).lower()
    if resolved == "linux":
        return int(ru_maxrss) * 1024
    if resolved == "darwin":
        return int(ru_maxrss)
    return None


def peak_rss_bytes() -> Dict[str, Any]:
    """Peak resident set size for this PROCESS'S ENTIRE LIFETIME.

    Available via `resource.getrusage()` on POSIX (Linux, so the Raspberry
    Pi included). On Windows the standard library exposes no reliable RSS
    figure, and this reports `peak_rss_bytes: None` with a reason rather
    than adding a third-party dependency such as psutil for one number.

    This is a high-water mark for the whole process, so it includes
    interpreter startup and every import — it must not be attributed to any
    single benchmark below it.
    """
    system = platform.system()
    if resource is None:
        return {
            "peak_rss_bytes": None,
            "peak_rss_mib": None,
            "source": None,
            "available": False,
            "reason": (
                f"{system} has no `resource` module; the standard library exposes no "
                f"reliable RSS figure, and no third-party dependency is added for it."
            ),
            "scope": "process lifetime high-water mark",
        }

    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    converted = ru_maxrss_to_bytes(raw, system)
    return {
        "peak_rss_bytes": converted,
        "peak_rss_mib": None if converted is None else converted / (1024 * 1024),
        "source": "resource.getrusage(RUSAGE_SELF).ru_maxrss",
        "ru_maxrss_raw": raw,
        "available": converted is not None,
        "reason": None
        if converted is not None
        else f"ru_maxrss unit is unknown for {system}",
        "scope": "process lifetime high-water mark",
    }


def tracemalloc_peak(work: Callable[[], Any]) -> Dict[str, Any]:
    """Run `work()` under tracemalloc and report the PYTHON HEAP peak.

    Measures only Python-managed allocations: it excludes the interpreter's
    own overhead and any memory held inside C extensions such as numpy
    buffers, so it is a lower bound on real memory use, not a substitute for
    RSS.

    tracemalloc materially slows the code it observes, so this must be run as
    a SEPARATE PASS and its timings must never be reported as latency.
    Leaves tracemalloc stopped, and does so even if `work()` raises.
    """
    already_tracing = tracemalloc.is_tracing()
    if not already_tracing:
        tracemalloc.start()
    else:  # pragma: no cover - only when an outer profiler is already running
        tracemalloc.clear_traces()

    try:
        work()
        current, peak = tracemalloc.get_traced_memory()
    finally:
        if not already_tracing:
            tracemalloc.stop()

    return {
        "python_heap_peak_bytes": peak,
        "python_heap_peak_mib": peak / (1024 * 1024),
        "python_heap_current_bytes": current,
        "source": "tracemalloc",
        "scope": "Python-managed heap only; excludes interpreter overhead and C-extension buffers",
        "note": "measured in a separate pass — tracemalloc slows execution, so no latency figure comes from this run",
    }


def platform_metadata() -> Dict[str, Any]:
    """Platform and interpreter identification, recorded with every result
    so a Windows run and a Raspberry Pi run can be told apart later.

    Nothing here is hard-coded to a platform, path, CPU model or interface
    name: every value is read from the running system.
    """
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "architecture": platform.architecture()[0],
        "processor": platform.processor() or None,
        "platform": platform.platform(),
        "node_reported": bool(platform.node()),
    }


def measure_calls(
    work: Callable[[], Any], repetitions: int, warmup: int = 1
) -> List[int]:
    """Time `work()` `repetitions` times, returning nanosecond samples.

    Runs `warmup` untimed calls first, so import-time lazy initialization,
    first-touch allocation and CPU frequency ramp-up land outside the
    measurement. Each sample brackets exactly one call with
    `time.perf_counter_ns()`.

    Raises:
        ValueError: if `repetitions` is not positive or `warmup` is negative.
    """
    if repetitions <= 0:
        raise ValueError(f"repetitions must be positive, got {repetitions}")
    if warmup < 0:
        raise ValueError(f"warmup cannot be negative, got {warmup}")

    for _ in range(warmup):
        work()

    samples: List[int] = []
    for _ in range(repetitions):
        start = time.perf_counter_ns()
        work()
        samples.append(time.perf_counter_ns() - start)
    return samples
