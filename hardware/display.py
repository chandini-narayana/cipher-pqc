"""StatusDisplay — the optional status-output boundary, and the frame
content CIPHER puts on it.

The display is an OUTPUT DEVICE ONLY. Nothing here computes a Quantum
Risk Score, runs or reads the Isolation Forest, applies the fusion rule,
or decides isolation eligibility: every value rendered was already
produced by the pipeline and is read straight off a `DeviceAssessment`.
The isolation line in particular is a pure mapping of fields the backend
already set — it never infers enforcement from a HIGH category or from an
anomaly, and it never says ISOLATED unless `isolation.enforced is True`.

CIPHER never requires a display. `NoOpStatusDisplay` is the default
everywhere, and a real display is composed only by the Raspberry Pi entry
point when explicitly asked for. This module imports no hardware library
at all — see ssd1306_display.py for the one that does, lazily.

Frames are built as plain lists of short strings by pure functions, so the
exact content shown on a 128x64 SSD1306 is unit-testable with no hardware
and no driver present.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import List, Optional

from models.device_assessment import DeviceAssessment
from models.isolation_status import IsolationStatus

logger = logging.getLogger(__name__)

#: Physical limits of the target panel with the small built-in font: five
#: lines of roughly this width fit legibly on a 128x64 SSD1306.
MAX_LINES = 5
MAX_LINE_LENGTH = 21

#: Short, uppercase isolation labels sized for the panel. These mirror the
#: dashboard's longer labels; both are display mappings of the same
#: backend fields, and neither derives policy.
ISOLATION_ISOLATED = "ISOLATED"
ISOLATION_FAILED = "FAILED"
ISOLATION_NOOP = "NOOP"
ISOLATION_NONE = "NONE"
ISOLATION_UNAVAILABLE = "N/A"


def describe_isolation(isolation: Optional[IsolationStatus]) -> str:
    """Map backend-reported isolation state to a short display label.

    Pure field mapping, in the one order that cannot overclaim:
    no object at all -> N/A; not requested -> NONE; enforced -> ISOLATED;
    otherwise the backend's own `enforcement_capable` flag decides between
    a genuine failure and a deliberately non-enforcing (NoOp) runtime.
    """
    if isolation is None:
        return ISOLATION_UNAVAILABLE
    if isolation.requested is not True:
        return ISOLATION_NONE
    if isolation.enforced is True:
        return ISOLATION_ISOLATED
    return ISOLATION_FAILED if isolation.enforcement_capable is True else ISOLATION_NOOP


def shorten_ip(device_ip: str, width: int = 15) -> str:
    """Fit an address into the panel width, keeping the host-identifying
    end of it rather than the network prefix if it must be cut."""
    text = str(device_ip)
    if len(text) <= width:
        return text
    return "…" + text[-(width - 1) :]


def _clip(lines: List[str]) -> List[str]:
    return [line[:MAX_LINE_LENGTH] for line in lines[:MAX_LINES]]


def build_ready_frame(capture_label: str, enforcement_label: str) -> List[str]:
    """The idle/ready frame shown once the runtime is up but before any
    device has been assessed."""
    return _clip(
        [
            "CIPHER",
            "Status: READY",
            f"Capture: {capture_label}",
            f"Enforce: {enforcement_label}",
        ]
    )


def build_assessment_frame(assessment: DeviceAssessment) -> List[str]:
    """The per-device frame: identity, raw QRS, fused category, isolation.

    Every value is read directly off the assessment. `QRS` is
    `risk_assessment.risk_score` (the raw deterministic score, never
    recomputed) and `Risk` is `final_category` (the already-fused
    category, never re-fused here)."""
    return _clip(
        [
            "CIPHER",
            f"Device: {shorten_ip(assessment.device.ip)}",
            f"QRS: {assessment.risk_assessment.risk_score}/10",
            f"Risk: {assessment.final_category.value}",
            f"Isolation: {describe_isolation(assessment.isolation)}",
        ]
    )


def build_summary_frame(device_count: int, report_count: int, isolated_count: int) -> List[str]:
    """The end-of-run frame. `isolated_count` is supplied by the caller
    from assessments the backend already marked enforced — this module
    counts nothing and judges nothing."""
    return _clip(
        [
            "CIPHER",
            "Status: COMPLETE",
            f"Devices: {device_count}",
            f"Reports: {report_count}",
            f"Isolated: {isolated_count}",
        ]
    )


class StatusDisplay(ABC):
    """Optional status-output boundary.

    Implementations must be forgiving by contract: no method may raise for
    an ordinary hardware problem (absent panel, missing driver, I2C
    permission denied, a failed write). They log and carry on, because a
    display fault must never affect capture, assessment, enforcement or
    reporting.

    `available` reports whether output is actually reaching a panel, so a
    caller can log the truth rather than assume success.
    """

    #: Name used in logs to identify which display is in use.
    display_name: str = "unknown"

    @property
    def available(self) -> bool:
        return False

    @abstractmethod
    def start(self) -> bool:
        """Initialize the display. Returns whether it is usable. Must not
        raise — a failure is a False return plus a logged warning."""
        raise NotImplementedError  # pragma: no cover - interface only

    @abstractmethod
    def show_lines(self, lines: List[str]) -> None:
        """Render up to MAX_LINES short lines. Must not raise."""
        raise NotImplementedError  # pragma: no cover - interface only

    @abstractmethod
    def close(self) -> None:
        """Release the display, clearing it where that makes sense. Must
        not raise."""
        raise NotImplementedError  # pragma: no cover - interface only

    # --- convenience wrappers, shared by every implementation ---------

    def show_ready(self, capture_label: str, enforcement_label: str) -> None:
        self.show_lines(build_ready_frame(capture_label, enforcement_label))

    def show_assessment(self, assessment: DeviceAssessment) -> None:
        self.show_lines(build_assessment_frame(assessment))

    def show_summary(self, device_count: int, report_count: int, isolated_count: int) -> None:
        self.show_lines(build_summary_frame(device_count, report_count, isolated_count))


class NoOpStatusDisplay(StatusDisplay):
    """The default everywhere: accepts every frame and renders nothing.

    Imports no hardware library, touches no bus, and never fails. It keeps
    "CIPHER ran" and "a panel showed something" as two separate facts, the
    same way NoOpIsolationBackend separates decided from enforced.
    """

    display_name = "none"

    def start(self) -> bool:
        logger.debug("Status display disabled (no-op display in use).")
        return True

    @property
    def available(self) -> bool:
        return False

    def show_lines(self, lines: List[str]) -> None:
        logger.debug("Status frame (not displayed): %s", " | ".join(lines))

    def close(self) -> None:
        return None
