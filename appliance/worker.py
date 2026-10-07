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

from dashboard.state import ApplicationState
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

#: Consecutive cycles in which the capture backend handed over no frame at
#: all before a warning is logged. 6 x 5s = 30s of total silence on an
#: interface that should carry an active client's chatter.
DEFAULT_SILENT_CYCLE_WARNING = 6

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
        cycle_seconds: the length of a cycle; also the pause after a failed
            cycle before the next attempt. The actual capture length is
            whatever bound the caller gave the capture source.
        on_cycle_published: optional, called with each newly published
            `ApplicationState` (appliance mode uses it to hold an enforced
            isolation on the OLED and LEDs). Anything it raises is logged and
            swallowed.
        interface_index_fn: optional, returns the capture interface's current
            ifindex (or None if it is gone). Observability only: a change is
            logged as a warning, and nothing is ever done about it.
        silent_cycle_warning: consecutive cycles with zero captured frames
            before a warning is logged.

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
        on_cycle_published: Optional[Callable[[ApplicationState], None]] = None,
        interface_index_fn: Optional[Callable[[], Optional[int]]] = None,
        silent_cycle_warning: int = DEFAULT_SILENT_CYCLE_WARNING,
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
        self._on_cycle_published = on_cycle_published
        self._interface_index_fn = interface_index_fn
        self._silent_cycle_warning = max(1, int(silent_cycle_warning))

        self.cycles_completed = 0
        self.cycles_failed = 0
        self.consecutive_silent_cycles = 0
        self._last_interface_index: Optional[int] = None
        self._interface_missing_logged = False

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
        self._check_interface_identity()
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
        self._note_capture_volume(capture_source)
        if self._on_cycle_published is not None:
            try:
                self._on_cycle_published(state)
            except Exception:  # noqa: BLE001 - an output hook must never stop the worker
                logger.warning("Post-cycle output hook failed; continuing.", exc_info=True)
        return True

    def _note_capture_volume(self, capture_source: object) -> None:
        """Warn when the capture interface has delivered no frame at all for
        several consecutive cycles. Observability only — nothing is changed.

        Reads the source's public `counters.seen` if it has one; a source
        without counters is never treated as silent.
        """
        counters = getattr(capture_source, "counters", None)
        seen = getattr(counters, "seen", None)
        if not isinstance(seen, int):
            return
        if seen > 0:
            if self.consecutive_silent_cycles >= self._silent_cycle_warning:
                logger.info(
                    "Capture resumed: %d frame(s) seen after %d silent cycle(s).",
                    seen,
                    self.consecutive_silent_cycles,
                )
            self.consecutive_silent_cycles = 0
            return
        self.consecutive_silent_cycles += 1
        if self.consecutive_silent_cycles % self._silent_cycle_warning == 0:
            logger.warning(
                "No frames captured for %d consecutive cycle(s) (~%.0fs). The capture "
                "interface may have no associated client, or may have been reset or "
                "re-created. Check the AP (hostapd) and the interface; CIPHER does "
                "not attempt any repair.",
                self.consecutive_silent_cycles,
                self.consecutive_silent_cycles * self._cycle_seconds,
            )

    def _check_interface_identity(self) -> None:
        """Warn if the capture interface disappeared or was re-created under
        the same name (its ifindex changed). Observability only."""
        if self._interface_index_fn is None:
            return
        try:
            index = self._interface_index_fn()
        except Exception:  # noqa: BLE001 - observability must never break a cycle
            logger.debug("Could not read the capture interface index.", exc_info=True)
            return
        if index is None:
            if not self._interface_missing_logged:
                logger.warning(
                    "The capture interface is not present. CIPHER does not attempt "
                    "any repair; check the adapter and the AP (hostapd)."
                )
                self._interface_missing_logged = True
            return
        self._interface_missing_logged = False
        if self._last_interface_index is not None and index != self._last_interface_index:
            logger.warning(
                "The capture interface was re-created (ifindex %d -> %d). The access "
                "point (hostapd) may no longer be running on it. CIPHER does not "
                "attempt any repair.",
                self._last_interface_index,
                index,
            )
        self._last_interface_index = index

    def _wait(self, seconds: float) -> None:
        """Pause, waking early if a stop is requested."""
        self._stop_event.wait(seconds)

    def run_forever(self, sleep: Optional[Callable[[float], None]] = None) -> None:
        """Run cycles until `stop_event` is set.

        Checked before each cycle as well as after, so a stop requested
        during a cycle takes effect at the boundary rather than starting
        another one. The capture source's own bound provides the pacing —
        there is no artificial delay between successful cycles. A *failed*
        cycle is followed by a pause of one cycle length before the next
        attempt, so a persistent failure (an interface that has gone away)
        retries at the normal cycle rate instead of flooding the log. A
        successful cycle that returned much faster than its bound pauses
        briefly to avoid a hot loop. The default pause wakes early on stop.
        """
        if sleep is None:
            sleep = self._wait
        logger.info(
            "Appliance capture worker starting: bounded cycles of about %.1fs.",
            self._cycle_seconds,
        )
        while not self._stop_event.is_set():
            started = time.monotonic()
            completed = self.run_cycle()
            if self._stop_event.is_set():
                break
            if not completed:
                sleep(self._cycle_seconds)
            elif time.monotonic() - started < _STOP_POLL_SECONDS:
                # A successful cycle that returned almost instantly (a source
                # that ended at once). Pause briefly rather than spinning the
                # CPU retrying thousands of times.
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
