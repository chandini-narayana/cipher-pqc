"""Unit tests for hardware.indicator — the StatusIndicator boundary, the
NoOp indicator, and the risk-to-lamp mapping (docs/SDD.md Phase 3G
addendum).

No GPIO, no pins, no library and no Raspberry Pi: the mapping is a pure
lookup and the only indicators exercised here are the NoOp one and a test
double.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional

import pytest

from hardware.indicator import (
    CATEGORY_LAMPS,
    LAMP_AMBER,
    LAMP_GREEN,
    LAMP_RED,
    LAMPS,
    NoOpStatusIndicator,
    StatusIndicator,
    lamp_for_assessment,
    lamp_for_category,
)
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
from models.risk_assessment import RiskAssessment

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _assessment(
    category: RiskCategory = RiskCategory.HIGH,
    risk_score: int = 9,
    final_category: Optional[RiskCategory] = None,
    anomaly: Optional[AnomalyAssessment] = None,
    isolation: Optional[IsolationStatus] = None,
) -> DeviceAssessment:
    assessment = DeviceAssessment(
        device=Device.first_contact("192.168.50.21", TS),
        risk_assessment=RiskAssessment(risk_score, category, "Upgrade TLS.", "NIST SP 800-52r2"),
        anomaly_assessment=anomaly,
        final_category=final_category or category,
        assessed_at=TS,
    )
    return assessment if isolation is None else assessment.with_isolation(isolation)


class _RecordingIndicator(StatusIndicator):
    indicator_name = "recording"

    def __init__(self) -> None:
        self.lamps: List[Optional[str]] = []
        self.started = False
        self.closed = False

    def start(self) -> bool:
        self.started = True
        return True

    @property
    def available(self) -> bool:
        return True

    def show_lamp(self, lamp: Optional[str]) -> None:
        self.lamps.append(lamp)

    def close(self) -> None:
        self.closed = True


# --- the mapping ----------------------------------------------------------


def test_low_risk_maps_to_green() -> None:
    assert lamp_for_category(RiskCategory.LOW) == LAMP_GREEN == "green"


def test_medium_risk_maps_to_amber() -> None:
    assert lamp_for_category(RiskCategory.MEDIUM) == LAMP_AMBER == "amber"


def test_high_risk_maps_to_red() -> None:
    assert lamp_for_category(RiskCategory.HIGH) == LAMP_RED == "red"


def test_every_category_has_exactly_one_lamp() -> None:
    assert set(CATEGORY_LAMPS) == set(RiskCategory)
    assert sorted(CATEGORY_LAMPS.values()) == sorted(LAMPS)


def test_the_mapping_matches_the_approved_hardware_table() -> None:
    """docs/hardware_manual records LOW/Green, MEDIUM/Amber, HIGH/Red as
    the approved intent; this is that table and nothing else."""
    assert CATEGORY_LAMPS == {
        RiskCategory.LOW: "green",
        RiskCategory.MEDIUM: "amber",
        RiskCategory.HIGH: "red",
    }


def test_an_assessment_lights_the_lamp_for_its_fused_category() -> None:
    assert lamp_for_assessment(_assessment(RiskCategory.MEDIUM)) == LAMP_AMBER


# --- no policy, no recomputation, inside the LED module -------------------


def test_the_mapping_takes_only_a_category() -> None:
    """There is no parameter through which a QRS value, an anomaly or a
    threshold could reach the mapping."""
    assert lamp_for_category.__code__.co_argcount == 1


def test_the_fused_category_decides_not_the_raw_score() -> None:
    """A device whose raw QRS is 5 but which fusion escalated to HIGH shows
    red, because `final_category` is what the LEDs render. The LED module
    does not re-derive the category from the score."""
    escalated = _assessment(
        category=RiskCategory.MEDIUM,
        risk_score=5,
        final_category=RiskCategory.HIGH,
        anomaly=AnomalyAssessment(anomaly_score=-0.9, is_anomaly=True, confidence=0.99),
    )

    assert lamp_for_assessment(escalated) == LAMP_RED


def test_a_high_raw_score_with_a_low_fused_category_follows_the_fused_one() -> None:
    """The converse: the module never reaches past final_category to the
    score, in either direction."""
    odd = _assessment(category=RiskCategory.HIGH, risk_score=9, final_category=RiskCategory.LOW)
    assert lamp_for_assessment(odd) == LAMP_GREEN


def test_isolation_state_does_not_change_the_lamp() -> None:
    """LEDs stay risk indicators. The OLED carries isolation state."""
    isolation = IsolationStatus(
        requested=True,
        enforced=True,
        backend="linux-iptables",
        reason="isolated",
        requested_at=TS,
        enforcement_capable=True,
    )

    with_isolation = _assessment(RiskCategory.HIGH, isolation=isolation)
    without = _assessment(RiskCategory.HIGH)

    assert lamp_for_assessment(with_isolation) == lamp_for_assessment(without) == LAMP_RED


def test_the_module_references_no_scoring_fusion_or_ml_identifier() -> None:
    """Structural guarantee: no risk, fusion, ML or isolation-policy logic
    lives in the LED module."""
    import ast
    import inspect

    import hardware.indicator as module

    tree = ast.parse(inspect.getsource(module))
    identifiers = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
        elif isinstance(node, ast.alias):
            identifiers.add(node.name.split(".")[-1])

    for forbidden in (
        "risk_score",
        "risk_assessment",
        "should_isolate",
        "fuse_assessments",
        "assess_packet",
        "anomaly_score",
        "is_anomaly",
        "confidence",
        "anomaly_assessment",
        "risk_isolation_threshold",
    ):
        assert forbidden not in identifiers


def test_the_module_imports_no_gpio_library() -> None:
    import ast
    import inspect

    import hardware.indicator as module

    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    for forbidden in ("gpiozero", "RPi", "lgpio", "pigpio", "board", "digitalio"):
        assert forbidden not in imported


# --- the NoOp indicator ---------------------------------------------------


def test_noop_indicator_starts_successfully() -> None:
    assert NoOpStatusIndicator().start() is True


def test_noop_indicator_reports_itself_unavailable() -> None:
    """Started is not the same as driving a pin."""
    indicator = NoOpStatusIndicator()
    indicator.start()
    assert indicator.available is False


def test_noop_indicator_accepts_every_state_without_raising() -> None:
    indicator = NoOpStatusIndicator()
    indicator.start()
    indicator.show_ready()
    indicator.show_assessment(_assessment(RiskCategory.LOW))
    indicator.show_lamp(LAMP_RED)
    indicator.show_lamp(None)
    indicator.clear()
    indicator.close()


def test_noop_indicator_logs_only_at_debug(caplog) -> None:
    with caplog.at_level(logging.DEBUG, logger="hardware.indicator"):
        NoOpStatusIndicator().show_lamp(LAMP_RED)
    assert all(record.levelno <= logging.DEBUG for record in caplog.records)


def test_the_indicator_interface_cannot_be_instantiated() -> None:
    with pytest.raises(TypeError):
        StatusIndicator()


# --- the shared convenience wrappers --------------------------------------


def test_show_ready_puts_every_lamp_out() -> None:
    """Startup/ready is all-off: no boot animation."""
    indicator = _RecordingIndicator()
    indicator.show_ready()
    assert indicator.lamps == [None]


def test_show_assessment_lights_the_mapped_lamp() -> None:
    indicator = _RecordingIndicator()
    indicator.show_assessment(_assessment(RiskCategory.MEDIUM))
    assert indicator.lamps == [LAMP_AMBER]


def test_clear_puts_every_lamp_out() -> None:
    indicator = _RecordingIndicator()
    indicator.clear()
    assert indicator.lamps == [None]


def test_the_indicator_is_not_a_status_display() -> None:
    """Separate abstractions on purpose: the OLED renders frames, the LEDs
    latch one of three pin states."""
    from hardware.display import StatusDisplay

    assert not issubclass(StatusIndicator, StatusDisplay)
    assert not issubclass(StatusDisplay, StatusIndicator)
