"""HardwareOutputGate — the shutdown barrier between the capture worker's
per-packet hardware writes and releasing that hardware.

The problem it solves. In appliance mode the capture worker thread drives the
OLED and the LEDs through the per-packet assessment observer, while the main
thread owns shutdown. Without a barrier, a worker that has not finished by the
time the join bound expires can still be inside an observer call when the main
thread closes the panel and the pins. Both adapters swallow the resulting
error, so nothing crashes — but the ordering is genuinely wrong in one visible
way: a lamp `on()` landing *after* shutdown's `off()` leaves an LED lit for a
run that is no longer happening, which is exactly the guarantee Phase 3G
makes.

How it works, in two steps that make the common case bounded and race-free:

  1. `close()` first sets a flag that makes every *future* observer call a
     no-op. The worker may still be running and looping; it simply stops
     touching hardware from that moment.
  2. It then waits for at most `timeout` seconds to acquire the same lock the
     observer holds while writing — i.e. it waits out one *in-flight* write,
     not the worker's remaining lifetime. One write is a bounded display
     render plus up to three pin writes.

Because step 1 removes all future writes, step 2 normally completes
immediately even when the worker thread is still alive.

**If the lock cannot be acquired within the bound, the devices are
deliberately NOT closed.** That only happens when a single hardware write has
hung (a wedged I2C bus, for instance), and closing underneath it is precisely
the race this class exists to prevent. The gate reports that outcome so the
caller can log it honestly; the worker is a daemon thread, so process exit
still tears everything down and the OS releases the bus and pins.

No new runtime, service framework or event system: one lock and one flag,
following the same "smallest explicit synchronisation" approach as
`dashboard.state_store`.

**Holding the isolated state.** Per-packet observer calls carry assessments
produced *before* `run_capture` attaches isolation state (that happens at
cycle end), so on their own they can never show ISOLATED, and the next
MEDIUM packet would turn a red lamp amber within milliseconds while the
device stays isolated. `hold_isolated()` is called once per cycle with the
published dashboard assessments. While any of them records an *enforced*
isolation, the most recently isolated one is shown — HIGH, red, "Isolation:
ISOLATED" — and per-packet writes are suppressed so a later lower-priority
observation cannot overwrite it. With no enforced isolation, per-packet
output is exactly as before (LOW green, MEDIUM amber, HIGH red). The hold is
released only when no published assessment records an enforced isolation,
which in the running appliance means at restart. This changes only *what is
shown*: it runs after the cycle, so isolation itself is never delayed.
"""
from __future__ import annotations

import logging
import threading
from typing import Callable, Iterable, Optional

from models.device_assessment import DeviceAssessment

logger = logging.getLogger(__name__)

#: How long `close()` waits for an in-flight hardware write to finish. Short
#: on purpose: with future writes already disabled, there is at most one
#: outstanding call, and a write that takes longer than this is hung rather
#: than slow.
DEFAULT_CLOSE_TIMEOUT_SECONDS = 5.0

#: Called with one assessment to drive the output devices.
ObserverFn = Callable[[DeviceAssessment], None]

#: Called to release one output device.
CloseFn = Callable[[], None]

#: Wraps a call so that nothing it raises escapes (run_pi_live._safe_display).
SafeCallFn = Callable[..., None]


class HardwareOutputGate:
    """Serialises the assessment observer against hardware shutdown.

    Args:
        observer: the existing observer fan-out that writes to the display and
            the LEDs. Called unchanged — the gate adds no behaviour of its own
            to what is shown.
        close_calls: ``(action_label, close_callable)`` pairs to run on
            shutdown, in order.
        safe_call: the existing `_safe_display` wrapper, so a misbehaving
            device cannot turn an observer call or a shutdown into a crash.
        timeout: bound for waiting out an in-flight write.
    """

    def __init__(
        self,
        observer: ObserverFn,
        close_calls,
        safe_call: SafeCallFn,
        timeout: float = DEFAULT_CLOSE_TIMEOUT_SECONDS,
    ) -> None:
        self._observer = observer
        self._close_calls = list(close_calls)
        self._safe_call = safe_call
        self._timeout = float(timeout)
        self._lock = threading.Lock()
        self._closed = threading.Event()
        self._closed_devices = False
        self._held: Optional[DeviceAssessment] = None

    @property
    def closed(self) -> bool:
        """Whether hardware output has been disabled."""
        return self._closed.is_set()

    @property
    def held(self) -> Optional[DeviceAssessment]:
        """The isolated assessment currently held on the outputs, if any."""
        return self._held

    @property
    def devices_released(self) -> bool:
        """Whether the devices were actually closed, as opposed to output
        merely having been disabled after a timed-out wait."""
        return self._closed_devices

    def observe(self, assessment: DeviceAssessment) -> None:
        """The observer handed to `run_capture`. Never raises.

        Checked before and again under the lock, so a `close()` that lands
        between the two cannot let a write through.
        """
        if self._closed.is_set():
            return
        with self._lock:
            if self._closed.is_set():
                return
            if self._held is not None:
                # An enforced isolation is on display; a per-packet frame
                # (which never carries isolation state) must not replace it.
                return
            self._safe_call("assessment output", self._observer, assessment)

    def hold_isolated(self, assessments: Iterable[DeviceAssessment]) -> None:
        """Show, and keep showing, the most recently enforced isolation among
        `assessments` (the published dashboard state). Never raises.

        Renders only when the held assessment changes, so a steady state
        issues no repeated writes. With no enforced isolation present, any
        previous hold is released and per-packet output resumes.
        """
        isolated = [
            assessment
            for assessment in assessments
            if assessment.isolation is not None and assessment.isolation.enforced is True
        ]
        newest = max(isolated, key=lambda a: a.isolation.requested_at, default=None)

        if self._closed.is_set():
            return
        with self._lock:
            if self._closed.is_set():
                return
            if newest is None:
                self._held = None
                return
            if newest is self._held:
                return
            self._held = newest
            self._safe_call("isolation output", self._observer, newest)

    def close(self) -> bool:
        """Disable hardware output, then release the devices.

        Returns True if the devices were released, False if an in-flight write
        did not finish within the bound and they were therefore left open
        rather than closed underneath a live writer. Idempotent, and never
        raises.
        """
        already_closed = self._closed.is_set()
        self._closed.set()
        if already_closed and self._closed_devices:
            return True

        acquired = self._lock.acquire(timeout=self._timeout)
        if not acquired:
            logger.warning(
                "A status-hardware write did not finish within %.1fs, so the "
                "display and LEDs were NOT closed: closing them underneath an "
                "active writer could leave an LED lit. Further output is "
                "disabled, and the capture worker is a daemon thread, so process "
                "exit releases the bus and the pins.",
                self._timeout,
            )
            return False

        try:
            for label, close_call in self._close_calls:
                self._safe_call(label, close_call)
            self._closed_devices = True
        finally:
            self._lock.release()
        return True
