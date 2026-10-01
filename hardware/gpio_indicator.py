"""GPIOStatusIndicator — the optional three-LED GPIO adapter.

Like the SSD1306 adapter, this is a thin, lazily-imported, injectable shim
and nothing more. `gpiozero` is imported inside `start()`, never at module
level, so importing this module on Windows or without the library
installed is safe and cannot break an unrelated runtime — asserted by test.

**Driver choice: gpiozero.** The target is Raspberry Pi OS (Debian 13,
aarch64) on a Pi 4. `RPi.GPIO` is deliberately not used: it pokes
`/dev/mem` and the legacy sysfs interface, and is unmaintained against the
kernel changes in current Raspberry Pi OS releases. `gpiozero` is the
library Raspberry Pi itself ships and documents; on Debian 12/13 it runs
on an `lgpio`/`pigpio` pin factory, which is the supported path on this OS
and kernel. One library only, and no PWM: these are plain on/off lamps.

**Pins are configuration, never a constant.** The three BCM numbers are
constructor arguments with no defaults, because the physical wiring is
still PENDING in docs/hardware_manual and guessing it would be exactly the
kind of invented board detail this project refuses to ship. They are
validated (integers, in BCM range, all distinct) before any pin is
touched.

Failure is never fatal: a missing library, a permission error, a failed
initialization, a failed write and a failed cleanup are each logged once
and swallowed. A failed write disables the indicator for the rest of the
run rather than retrying on every assessment.

Only one risk lamp is ever lit: `show_lamp()` switches the others off in
the same call, and repeating a state issues no writes at all.

NOT VALIDATED ON HARDWARE. No LED has been wired or driven by this code;
the pin map remains PENDING. The tests drive an injected fake lamp factory,
which proves the on/off sequencing and every failure path, not the
electrical behaviour.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, Optional, Sequence

from hardware.indicator import LAMPS, StatusIndicator

logger = logging.getLogger(__name__)

#: Broadcom GPIO numbering bounds on a 40-pin Raspberry Pi header.
MIN_BCM_PIN = 0
MAX_BCM_PIN = 27

#: Builds one controllable lamp from a BCM pin number. Injected in tests.
LampFactory = Callable[[int], Any]


class GPIOUnavailableError(RuntimeError):
    """Raised internally when the optional GPIO library cannot be imported.

    Never escapes `start()`: an absent optional dependency is a
    configuration fact, not a crash.
    """


class InvalidPinConfigurationError(ValueError):
    """Raised by `validate_pins` for a pin set that must not be used.

    Raised from the constructor on purpose — a bad pin map is an operator
    error to fix before anything is driven, not something to paper over at
    runtime. The composition root turns it into a clear message.
    """


def validate_pins(pins: Sequence[Any]) -> Dict[str, int]:
    """Validate three BCM pin numbers and label them green/amber/red.

    Checks exactly what can be checked without knowing the final wiring:
    three values, each a real integer, each inside BCM range, and all
    distinct. It cannot and does not verify that the pins are actually
    wired to LEDs.
    """
    if len(pins) != len(LAMPS):
        raise InvalidPinConfigurationError(
            f"exactly {len(LAMPS)} GPIO pins are required (green, amber, red); "
            f"got {len(pins)}"
        )

    resolved: Dict[str, int] = {}
    for lamp, value in zip(LAMPS, pins):
        if isinstance(value, bool) or not isinstance(value, int):
            raise InvalidPinConfigurationError(
                f"the {lamp} GPIO pin must be an integer BCM number, got {value!r}"
            )
        if not MIN_BCM_PIN <= value <= MAX_BCM_PIN:
            raise InvalidPinConfigurationError(
                f"the {lamp} GPIO pin {value} is outside the BCM range "
                f"{MIN_BCM_PIN}-{MAX_BCM_PIN}"
            )
        resolved[lamp] = value

    if len(set(resolved.values())) != len(resolved):
        raise InvalidPinConfigurationError(
            f"the three GPIO pins must be distinct, got {resolved}"
        )
    return resolved


def _default_lamp_factory(pin: int) -> Any:
    """Build a real gpiozero output for one pin.

    The import lives inside the function on purpose: `gpiozero` is an
    optional, Raspberry-Pi-only extra and must never be required to import
    this module, run the test suite, or start CIPHER on Windows.
    """
    try:
        from gpiozero import LED  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - exercised via injection
        raise GPIOUnavailableError(
            "the optional GPIO library is not installed; install it on the "
            "Raspberry Pi with `pip install gpiozero lgpio` to enable the "
            "status LEDs"
        ) from exc

    return LED(pin)


class GPIOStatusIndicator(StatusIndicator):
    """Optional three-LED GPIO status indicator.

    Args:
        green_pin / amber_pin / red_pin: BCM pin numbers. No defaults — the
            wiring is supplied by configuration, never assumed.
        lamp_factory: builds one lamp per pin; injected by tests so no real
            GPIO, library or privilege is ever needed.

    Raises:
        InvalidPinConfigurationError: from the constructor, for a pin set
            that is not three distinct in-range integers. Nothing is
            acquired or driven when this happens.

    Every other method is exception-safe: a hardware fault marks the
    indicator unavailable and is logged once, never raised at the caller.
    """

    indicator_name = "gpio"

    def __init__(
        self,
        green_pin: int,
        amber_pin: int,
        red_pin: int,
        lamp_factory: LampFactory = _default_lamp_factory,
    ) -> None:
        self._pins = validate_pins([green_pin, amber_pin, red_pin])
        self._lamp_factory = lamp_factory
        self._lamps: Dict[str, Any] = {}
        self._available = False
        self._current: Optional[str] = None

    @property
    def available(self) -> bool:
        return self._available

    @property
    def pins(self) -> Dict[str, int]:
        return dict(self._pins)

    @property
    def current_lamp(self) -> Optional[str]:
        """Which lamp is lit, as far as this object knows. Cached so an
        unchanged risk state issues no GPIO writes at all."""
        return self._current

    def start(self) -> bool:
        """Acquire all three pins and put every lamp out. Never raises."""
        acquired: Dict[str, Any] = {}
        try:
            for lamp in LAMPS:
                acquired[lamp] = self._lamp_factory(self._pins[lamp])
        except GPIOUnavailableError as exc:
            logger.warning("Status LEDs unavailable: %s", exc)
            self._release(acquired)
            return False
        except Exception as exc:  # noqa: BLE001 - no permission, pin busy, no device
            logger.warning(
                "Status LEDs unavailable: could not acquire GPIO pins %s: %s. Check "
                "that the user may access GPIO and that no other process holds these "
                "pins.",
                self._pins,
                exc,
            )
            self._release(acquired)
            return False

        self._lamps = acquired
        self._available = True
        logger.info("Status LEDs ready on BCM pins %s.", self._pins)
        # Start from a known state rather than whatever the pins held.
        self.show_lamp(None)
        return True

    def show_lamp(self, lamp: Optional[str]) -> None:
        """Light exactly one lamp (or none). Never raises.

        Writes nothing when the requested state is already current, so a
        long run at a steady risk level produces no GPIO traffic.
        """
        if not self._available:
            return
        if lamp is not None and lamp not in self._lamps:
            logger.warning("Ignoring unknown status lamp %r.", lamp)
            return
        if lamp == self._current:
            return

        try:
            # Off first, then on: there is no instant at which two risk
            # lamps are both lit.
            for name, device in self._lamps.items():
                if name != lamp:
                    device.off()
            if lamp is not None:
                self._lamps[lamp].on()
        except Exception as exc:  # noqa: BLE001 - a write fault must never reach the pipeline
            self._available = False
            logger.warning(
                "Status LED write failed and the LEDs have been disabled for the "
                "rest of this run: %s",
                exc,
            )
            return

        self._current = lamp

    def close(self) -> None:
        """Put every lamp out and release only these pins. Idempotent and
        never raises. Deliberately does not reset GPIO globally — other
        processes' pins are none of CIPHER's business."""
        for lamp, device in self._lamps.items():
            try:
                device.off()
            except Exception as exc:  # noqa: BLE001 - shutdown must never fail the run
                logger.debug("Status LED %s could not be switched off: %s", lamp, exc)
        self._release(self._lamps)
        self._lamps = {}
        self._available = False
        self._current = None

    @staticmethod
    def _release(lamps: Dict[str, Any]) -> None:
        """Release each lamp if its driver needs it (gpiozero devices own a
        pin until closed). Never raises."""
        for lamp, device in lamps.items():
            close = getattr(device, "close", None)
            if close is None:
                continue
            try:
                close()
            except Exception as exc:  # noqa: BLE001 - cleanup failure is never fatal
                logger.debug("Status LED %s could not be released: %s", lamp, exc)
