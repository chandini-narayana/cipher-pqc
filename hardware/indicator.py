"""StatusIndicator — the optional GPIO status-LED boundary, and the risk
mapping CIPHER drives it with.

A sibling of `StatusDisplay` (display.py), not a subclass of it: the OLED
renders multi-line frames and the LEDs latch one of three mutually
exclusive pin states, so their methods and lifecycles genuinely differ.
What they deliberately share are the conventions — `start() -> bool`,
`available`, `close()`, a never-raise contract, a NoOp default, a lazily
imported driver and Linux-only composition — so neither can surprise the
runtime in a way the other does not.

Output only. The LED state is a direct mapping of
`DeviceAssessment.final_category`, the category the fusion step already
produced. Nothing here recomputes a Quantum Risk Score, re-derives fusion,
or reads an anomaly score or confidence; a structural test asserts the
module references none of those identifiers.

Mapping, exactly as docs/hardware_manual records it as the approved
intent:

    LOW    -> green
    MEDIUM -> amber
    HIGH   -> red

Deliberately nothing more. Isolation state is **not** indicated here: it
would either override the risk colour (losing the one thing the LEDs are
for) or require blink codes that the hardware design does not call for.
The OLED already carries the full isolation state, with far more room to
be honest about the difference between requested and enforced.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Optional

from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory

logger = logging.getLogger(__name__)

#: The three logical lamps. Names, not pins — the physical pin for each is
#: supplied by configuration, never assumed here.
LAMP_GREEN = "green"
LAMP_AMBER = "amber"
LAMP_RED = "red"
LAMPS = (LAMP_GREEN, LAMP_AMBER, LAMP_RED)

#: The one mapping, from the already-fused category to a lamp.
CATEGORY_LAMPS = {
    RiskCategory.LOW: LAMP_GREEN,
    RiskCategory.MEDIUM: LAMP_AMBER,
    RiskCategory.HIGH: LAMP_RED,
}


def lamp_for_category(category: RiskCategory) -> str:
    """The lamp that represents `category`.

    A pure lookup on the fused category. It cannot consult a risk score,
    an anomaly, or anything else: that is the whole point.
    """
    return CATEGORY_LAMPS[category]


def lamp_for_assessment(assessment: DeviceAssessment) -> str:
    """The lamp for an assessment's `final_category` — the category fusion
    already decided, read straight off the object."""
    return lamp_for_category(assessment.final_category)


class StatusIndicator(ABC):
    """Optional GPIO status-LED boundary.

    Implementations must not raise for an ordinary hardware problem (no
    GPIO library, no permission, a failed write, a failed cleanup). They
    log and carry on, because an indicator fault must never affect
    capture, assessment, enforcement, reporting or the OLED.

    `available` reports whether pin writes are actually reaching hardware,
    so a caller logs the truth instead of assuming success.
    """

    #: Name used in logs to identify which indicator is in use.
    indicator_name: str = "unknown"

    @property
    def available(self) -> bool:
        return False

    @abstractmethod
    def start(self) -> bool:
        """Acquire the pins and put every lamp out. Returns whether the
        indicator is usable. Must not raise."""
        raise NotImplementedError  # pragma: no cover - interface only

    @abstractmethod
    def show_lamp(self, lamp: Optional[str]) -> None:
        """Light exactly one lamp, or none when `lamp` is None. Any
        previously lit lamp is switched off. Must not raise."""
        raise NotImplementedError  # pragma: no cover - interface only

    @abstractmethod
    def close(self) -> None:
        """Put every lamp out and release the pins. Idempotent. Must not
        raise."""
        raise NotImplementedError  # pragma: no cover - interface only

    # --- convenience wrappers, shared by every implementation ---------

    def show_ready(self) -> None:
        """Startup/ready state: all lamps off. No boot animation."""
        self.show_lamp(None)

    def show_assessment(self, assessment: DeviceAssessment) -> None:
        """Light the one lamp matching the assessment's fused category."""
        self.show_lamp(lamp_for_assessment(assessment))

    def clear(self) -> None:
        self.show_lamp(None)


class NoOpStatusIndicator(StatusIndicator):
    """The default everywhere: accepts every state and drives nothing.

    Imports no GPIO library, touches no pin, and never fails. Reports
    `available is False` even after a successful `start()`, keeping "CIPHER
    ran" and "a lamp actually lit" separate facts — the same distinction
    NoOpStatusDisplay and NoOpIsolationBackend preserve.
    """

    indicator_name = "none"

    def start(self) -> bool:
        logger.debug("Status LEDs disabled (no-op indicator in use).")
        return True

    @property
    def available(self) -> bool:
        return False

    def show_lamp(self, lamp: Optional[str]) -> None:
        logger.debug("Status lamp (not driven): %s", lamp or "off")

    def close(self) -> None:
        return None
