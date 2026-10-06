"""ApplianceCaptureWorker — the repeated bounded-capture loop behind
appliance mode.

This is a **loop around the existing pipeline, not a second pipeline**.
Each cycle is one ordinary `pipeline.runner.run_capture()` call over one
fresh `NetworkLiveCaptureSource`, with the same injected isolation backend
and the same per-packet assessment observer the Pi diagnostic entry point
already uses. Nothing here assesses, scores, fuses or decides anything.

**Why cycles at all.** `run_capture()` is single-pass by design, and two
of its outputs only exist at end of capture: isolation state is stamped
onto each retained representative by `_attach_isolation_state()`, and
reports are generated, both *after* the packet loop finishes. An unbounded
capture would therefore produce no isolation state on any assessment and
no reports at all. A bounded cycle is the natural unit, and
`NetworkLiveCaptureSource` is already bounded by `timeout`/`packet_limit`.

**What is NOT deferred to a cycle boundary.** Physical isolation and the
OLED/LED updates both remain immediate and per-packet, exactly as before:
`run_capture()` calls `should_isolate()` and the backend inside
`_process_packet()`, and hands each assessment to the observer there too.
The cycle boundary governs only when a *snapshot is published to the
dashboard* — never when a device is enforced.

Everything injectable (`source_factory`, `run_capture_fn`, `sleep`) exists
so the loop can be unit-tested with no interface, no capture backend, no
root and no hardware.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, List, Optional, Tuple

from dashboard.state_store import ApplicationStateStore
from models.device_assessment import DeviceAssessment
from utils.exceptions import CipherError

logger = logging.getLogger(__name__)

#: Default appliance cycle length. Short enough that the dashboard feels
#: live, long enough to stay clear of the 1-second resolution of
#: `reports.pdf_generator.generate_report_id` (see MIN_CYCLE_SECONDS).
DEFAULT_CYCLE_SECONDS = 5.0

#: A cycle shorter than this is refused. `generate_report_id` builds a
#: filename from a whole-second UTC timestamp, so two cycles inside one
#: second would produce the same report filename for the same device and
#: the later render would silently overwrite the earlier PDF. One second is
#: the smallest cycle that cannot collide. This is an appliance-level
#: configuration guard: nothing in reports/ or pipeline/ is changed.
MIN_CYCLE_SECONDS = 1.0

#: How long a stopping worker waits between its own checks of the stop
#: event. Only used when a cycle ends early.
_STOP_POLL_SECONDS = 0.1

#: Builds the capture source for one cycle.
SourceFactory = Callable[[], object]

#: Runs one capture pass; signature-compatible with pipeline.runner.run_capture.
RunCaptureFn = Callable[..., Tuple[List[DeviceAssessment], List[Tuple[object, object]]]]


class ApplianceCaptureWorker:
    """Runs bounded capture cycles until asked to stop, publishing each
    cycle's results to an `ApplicationStateStore`.

    Args:
        store: where each completed cycle's snapshot is published.
        source_factory: builds a FRESH capture source per cycle. Fresh on
            purpose: a reused `NetworkLiveCaptureSource` accumulates its
            `counters` across `read_packets()` calls, so per-cycle figures
            would be monotonically growing totals instead.
        run_capture_fn / capture_kwargs: the existing pipeline call and its
            already-composed arguments (detector, keys, isolation backend,
            threshold, observer, report directory).
        stop_event: shared shutdown signal; created if not supplied.
        cycle_seconds: recorded for logging only — the actual cycle length
            is whatever bound the caller gave the capture source.

    A failing cycle never stops the worker and never damages the published
    state: the error is logged and the next cycle runs against the snapshot
    that was already published.
    """

    def __init__(
        self,
        store: ApplicationStateStore,
        source_factory: SourceFactory,
        run_capture_fn: RunCaptureFn,
        capture_kwargs: Optional[dict] = None,
        stop_event: Optional[threading.Event] = None,
        cycle_seconds: float = DEFAULT_CYCLE_SECONDS,
    ) -> None:
        if cycle_seconds < MIN_CYCLE_SECONDS:
            raise CipherError(
                f"appliance cycle must be at least {MIN_CYCLE_SECONDS:g}s, got "
                f"{cycle_seconds:g}s: report filenames carry a whole-second "
                "timestamp, so a shorter cycle would overwrite a device's "
                "previous signed report."
            )

        self._store = store
        self._source_factory = source_factory
        self._run_capture = run_capture_fn
        self._capture_kwargs = dict(capture_kwargs or {})
        self._stop_event = stop_event if stop_event is not None else threading.Event()
        self._cycle_seconds = float(cycle_seconds)

        self.cycles_completed = 0
        self.cycles_failed = 0

    @property
    def stop_event(self) -> threading.Event:
        return self._stop_event

    def stop(self) -> None:
        """Ask the loop to finish after the current cycle."""
        self._stop_event.set()

    def run_cycle(self) -> bool:
        """Run exactly one bounded capture cycle and publish its results.

        Returns True if the cycle completed, False if it failed. Never
        raises for a capture or pipeline failure: an appliance that drops
        one cycle must keep serving and keep trying.
        """
        try:
            capture_source = self._source_factory()
            assessments, reports = self._run_capture(capture_source, **self._capture_kwargs)
        except CipherError:
            self.cycles_failed += 1
            logger.error(
                "Appliance capture cycle failed; previously published state is "
                "unchanged and the next cycle will be attempted.",
                exc_info=True,
            )
            return False
        except Exception:  # noqa: BLE001 - an appliance must not die on one bad cycle
            self.cycles_failed += 1
            logger.error(
                "Appliance capture cycle raised an unexpected error; previously "
                "published state is unchanged and the next cycle will be attempted.",
                exc_info=True,
            )
            return False

        state = self._store.publish_cycle(assessments, reports)
        self.cycles_completed += 1
        logger.info(
            "Appliance cycle %d complete: %d device(s) this cycle, %d known in total, "
            "%d report(s) known.",
            self.cycles_completed,
            len(assessments),
            state.devices_assessed,
            state.reports_generated,
        )
        return True

    def run_forever(self, sleep: Callable[[float], None] = time.sleep) -> None:
        """Run cycles until `stop_event` is set.

        Checked before each cycle as well as after, so a stop requested
        during a cycle takes effect at the boundary rather than starting
        another one. The capture source's own bound provides the pacing —
        there is no artificial delay between cycles, and `sleep` is used
        only to avoid a hot loop if a cycle returns much faster than its
        bound (a failed source, for instance).
        """
        logger.info(
            "Appliance capture worker starting: bounded cycles of about %.1fs.",
            self._cycle_seconds,
        )
        while not self._stop_event.is_set():
            started = time.monotonic()
            self.run_cycle()
            if self._stop_event.is_set():
                break
            if time.monotonic() - started < _STOP_POLL_SECONDS:
                # A cycle that returned almost instantly means the source
                # produced nothing (e.g. it failed to open). Pause briefly
                # rather than spinning the CPU retrying thousands of times.
                sleep(_STOP_POLL_SECONDS)
        logger.info(
            "Appliance capture worker stopped after %d completed and %d failed cycle(s).",
            self.cycles_completed,
            self.cycles_failed,
        )

    def start_thread(self) -> threading.Thread:
        """Run `run_forever()` on a daemon thread and return it.

        Daemon so that a hard termination can never hang the process on a
        capture that is mid-sniff; clean shutdown still goes through
        `stop()` plus `Thread.join()`.
        """
        thread = threading.Thread(
            target=self.run_forever, name="cipher-appliance-capture", daemon=True
        )
        thread.start()
        return thread
