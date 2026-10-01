"""SSD1306StatusDisplay — the optional SSD1306 I2C panel adapter.

This is the only module in CIPHER that touches a hardware library, and it
does so **lazily**: nothing is imported from `luma` until `start()` is
called. Importing this module on Windows, or anywhere the driver is not
installed, is therefore safe and cannot break an unrelated runtime — a
property asserted by test.

Scope, deliberately narrow:
  * SSD1306 over **I2C only**. No SPI in this phase.
  * The I2C bus number and device address are constructor arguments. The
    defaults (bus 1, 0x3C) are the standard Raspberry Pi I2C bus and the
    address the overwhelming majority of SSD1306 breakout boards ship
    with; both are overridable because a minority of boards are strapped
    to 0x3D. No other board-specific value is assumed anywhere.
  * Output only. It renders frames that `hardware/display.py` built from
    an existing DeviceAssessment, and contains no risk, ML or isolation
    logic of its own.

Failure is never fatal. A missing driver, a disabled or absent I2C bus, a
permission error, a failed initialization and a failed write are each
logged once and swallowed; the panel is then marked unavailable and
further frames are dropped silently rather than retried on every packet.

I2C writes are throttled (`min_interval_seconds`) and duplicate frames are
skipped, so a fast capture cannot turn into a flood of bus traffic.

NOT VALIDATED ON HARDWARE. No SSD1306 panel has been wired or driven by
this code; the pin map in docs/hardware_manual is still PENDING. Tests
drive an injected fake device, which proves the command/data flow and the
failure handling, not the electrical behavior.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Callable, List, Optional

from hardware.display import MAX_LINES, StatusDisplay

logger = logging.getLogger(__name__)

#: Standard Raspberry Pi I2C bus (`/dev/i2c-1`) on every modern board.
DEFAULT_I2C_BUS = 1

#: The address almost all SSD1306 breakouts use; a minority use 0x3D,
#: which is why this is a parameter and not a constant in the call site.
DEFAULT_I2C_ADDRESS = 0x3C

DEFAULT_MIN_INTERVAL_SECONDS = 1.0

#: Vertical spacing per text line, chosen to fit MAX_LINES on a 128x64
#: panel with the default bitmap font.
_LINE_HEIGHT = 12
_LEFT_MARGIN = 2
_TOP_MARGIN = 1

#: A factory that builds the underlying panel object. Injected in tests.
DeviceFactory = Callable[[int, int], Any]


class DisplayDriverUnavailableError(RuntimeError):
    """Raised internally when the optional driver cannot be imported.

    Never escapes `start()` — it is caught there and reported as an
    unavailable display, because an absent optional dependency is a
    configuration fact, not a crash.
    """


def _default_device_factory(bus: int, address: int) -> Any:
    """Build a real luma.oled SSD1306 device over I2C.

    The import lives inside the function on purpose: `luma.oled` is an
    optional, Raspberry-Pi-only extra and must never be required to import
    this module, run the test suite, or start CIPHER on Windows.
    """
    try:
        from luma.core.interface.serial import i2c  # type: ignore[import-not-found]
        from luma.oled.device import ssd1306  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - exercised via injection
        raise DisplayDriverUnavailableError(
            "the optional SSD1306 driver is not installed; install it on the "
            "Raspberry Pi with `pip install luma.oled` to enable the display"
        ) from exc

    return ssd1306(i2c(port=bus, address=address))


class SSD1306StatusDisplay(StatusDisplay):
    """Optional SSD1306 I2C status panel.

    Args:
        bus: I2C bus number (Raspberry Pi default 1).
        address: I2C device address (0x3C on most boards).
        device_factory: builds the panel object; injected by tests so no
            real bus or driver is ever needed.
        min_interval_seconds: minimum delay between I2C writes.
        canvas_factory: builds the drawing context; injected by tests.

    Every public method is exception-safe: a hardware fault marks the panel
    unavailable and is logged once, never raised at the caller.
    """

    display_name = "oled"

    def __init__(
        self,
        bus: int = DEFAULT_I2C_BUS,
        address: int = DEFAULT_I2C_ADDRESS,
        device_factory: DeviceFactory = _default_device_factory,
        min_interval_seconds: float = DEFAULT_MIN_INTERVAL_SECONDS,
        canvas_factory: Optional[Callable[[Any], Any]] = None,
    ) -> None:
        self._bus = int(bus)
        self._address = int(address)
        self._device_factory = device_factory
        self._min_interval = float(min_interval_seconds)
        self._canvas_factory = canvas_factory
        self._device: Any = None
        self._available = False
        self._last_frame: Optional[List[str]] = None
        self._last_write = 0.0

    @property
    def available(self) -> bool:
        return self._available

    def start(self) -> bool:
        """Open the panel. Returns False (never raises) if unavailable."""
        try:
            self._device = self._device_factory(self._bus, self._address)
        except DisplayDriverUnavailableError as exc:
            logger.warning("Status display unavailable: %s", exc)
            return False
        except Exception as exc:  # noqa: BLE001 - no I2C device, no permission, bad address
            logger.warning(
                "Status display unavailable: could not open SSD1306 on I2C bus %d "
                "address 0x%02X: %s. Check that I2C is enabled and the panel is "
                "wired and detected (i2cdetect).",
                self._bus,
                self._address,
                exc,
            )
            return False

        self._available = True
        logger.info(
            "Status display ready: SSD1306 on I2C bus %d address 0x%02X.",
            self._bus,
            self._address,
        )
        return True

    def show_lines(self, lines: List[str]) -> None:
        """Render a frame, subject to throttling. Never raises.

        Skips the write entirely when the frame is unchanged or when the
        last write was too recent, so a high packet rate cannot flood the
        I2C bus or slow the pipeline that calls this.
        """
        if not self._available or self._device is None:
            return

        frame = list(lines)[:MAX_LINES]
        now = time.monotonic()
        if frame == self._last_frame:
            return
        if self._min_interval > 0 and (now - self._last_write) < self._min_interval:
            return

        try:
            self._render(frame)
        except Exception as exc:  # noqa: BLE001 - a write fault must never reach the pipeline
            self._available = False
            logger.warning(
                "Status display write failed and the display has been disabled "
                "for the rest of this run: %s",
                exc,
            )
            return

        self._last_frame = frame
        self._last_write = now

    def close(self) -> None:
        """Clear and release the panel. Never raises."""
        if self._device is None:
            return
        try:
            self._device.clear()
        except Exception as exc:  # noqa: BLE001 - shutdown must never fail the run
            logger.debug("Status display clear failed during shutdown: %s", exc)
        finally:
            self._available = False
            self._device = None

    # --- internals -------------------------------------------------------

    def _render(self, frame: List[str]) -> None:
        with self._canvas(self._device) as draw:
            for index, line in enumerate(frame):
                draw.text(
                    (_LEFT_MARGIN, _TOP_MARGIN + index * _LINE_HEIGHT),
                    line,
                    fill="white",
                )

    def _canvas(self, device: Any) -> Any:
        """The drawing context. Imported lazily for the same reason the
        device is, and injectable so tests can capture what was drawn."""
        if self._canvas_factory is not None:
            return self._canvas_factory(device)

        from luma.core.render import canvas  # type: ignore[import-not-found]

        return canvas(device)
