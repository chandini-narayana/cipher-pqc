"""hardware — optional physical output devices for the Raspberry Pi runtime.

Status output only. Nothing in this package computes a Quantum Risk Score,
runs or reads the Isolation Forest, applies the fusion rule, or decides
isolation eligibility; it renders state the existing pipeline already
produced and reads it straight off a `DeviceAssessment`. In particular the
isolation line is a pure mapping of fields the enforcement backend already
set, and never says ISOLATED unless `isolation.enforced is True`.

`StatusDisplay` is the boundary and `NoOpStatusDisplay` is the default
everywhere — CIPHER never requires a display, and no entry point enables
one implicitly. `SSD1306StatusDisplay` (ssd1306_display.py) is the optional
SSD1306-over-I2C adapter; it imports its driver lazily inside `start()`, so
importing this package on Windows or without the optional dependency is
safe. A display fault is logged and swallowed, never raised at the caller.

The GPIO status LEDs remain unimplemented — a separate, later phase.
"""

from hardware.display import (
    ISOLATION_FAILED,
    ISOLATION_ISOLATED,
    ISOLATION_NONE,
    ISOLATION_NOOP,
    ISOLATION_UNAVAILABLE,
    MAX_LINE_LENGTH,
    MAX_LINES,
    NoOpStatusDisplay,
    StatusDisplay,
    build_assessment_frame,
    build_ready_frame,
    build_summary_frame,
    describe_isolation,
)
from hardware.ssd1306_display import (
    DEFAULT_I2C_ADDRESS,
    DEFAULT_I2C_BUS,
    SSD1306StatusDisplay,
)

__all__ = [
    "StatusDisplay",
    "NoOpStatusDisplay",
    "SSD1306StatusDisplay",
    "DEFAULT_I2C_BUS",
    "DEFAULT_I2C_ADDRESS",
    "MAX_LINES",
    "MAX_LINE_LENGTH",
    "describe_isolation",
    "build_ready_frame",
    "build_assessment_frame",
    "build_summary_frame",
    "ISOLATION_ISOLATED",
    "ISOLATION_FAILED",
    "ISOLATION_NOOP",
    "ISOLATION_NONE",
    "ISOLATION_UNAVAILABLE",
]
