"""Unit tests for hardware.display — the StatusDisplay boundary, the NoOp
display, and the exact frame content CIPHER renders (docs/SDD.md Phase 3F
addendum).

No hardware, no I2C bus, no driver and no Raspberry Pi is involved: frames
are built by pure functions and the only displays exercised here are the
NoOp one and test doubles.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import List, Optional

import pytest

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
    shorten_ip,
)
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
from models.risk_assessment import RiskAssessment

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _isolation(**overrides) -> IsolationStatus:
    kwargs = {
        "requested": True,
        "enforced": False,
        "backend": "noop",
        "reason": "Hardware enforcement unavailable in current deployment",
        "requested_at": TS,
        "enforcement_capable": False,
    }
    kwargs.update(overrides)
    return IsolationStatus(**kwargs)


def _assessment(
    ip: str = "192.168.50.21",
    risk_score: int = 9,
    category: RiskCategory = RiskCategory.HIGH,
    final_category: Optional[RiskCategory] = None,
    isolation: Optional[IsolationStatus] = None,
    anomaly: Optional[AnomalyAssessment] = None,
) -> DeviceAssessment:
    assessment = DeviceAssessment(
        device=Device.first_contact(ip, TS),
        risk_assessment=RiskAssessment(risk_score, category, "Upgrade TLS.", "NIST SP 800-52r2"),
        anomaly_assessment=anomaly,
        final_category=final_category or category,
        assessed_at=TS,
    )
    return assessment if isolation is None else assessment.with_isolation(isolation)


class _RecordingDisplay(StatusDisplay):
    """Captures every frame without any hardware."""

    display_name = "recording"

    def __init__(self) -> None:
        self.frames: List[List[str]] = []
        self.started = False
        self.closed = False

    def start(self) -> bool:
        self.started = True
        return True

    @property
    def available(self) -> bool:
        return True

    def show_lines(self, lines: List[str]) -> None:
        self.frames.append(list(lines))

    def close(self) -> None:
        self.closed = True


# --- the NoOp display -----------------------------------------------------


def test_noop_display_starts_successfully() -> None:
    assert NoOpStatusDisplay().start() is True


def test_noop_display_reports_itself_unavailable() -> None:
    """Started is not the same as showing something — CIPHER never claims
    output reached a panel that does not exist."""
    display = NoOpStatusDisplay()
    display.start()
    assert display.available is False


def test_noop_display_accepts_every_frame_without_raising() -> None:
    display = NoOpStatusDisplay()
    display.start()
    display.show_ready("eth0", "noop")
    display.show_assessment(_assessment())
    display.show_summary(2, 1, 1)
    display.show_lines(["anything", "at", "all"])
    display.close()


def test_noop_display_imports_no_hardware_library() -> None:
    """Static check: the default display cannot pull in an I2C stack."""
    import ast
    import inspect

    import hardware.display as module

    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    for forbidden in ("luma", "board", "busio", "smbus", "smbus2", "adafruit_ssd1306", "RPi"):
        assert forbidden not in imported


def test_the_display_interface_cannot_be_instantiated() -> None:
    with pytest.raises(TypeError):
        StatusDisplay()


def test_noop_display_logs_frames_only_at_debug(caplog) -> None:
    with caplog.at_level(logging.DEBUG, logger="hardware.display"):
        NoOpStatusDisplay().show_ready("eth0", "noop")
    assert all(record.levelno <= logging.DEBUG for record in caplog.records)


# --- isolation state mapping ----------------------------------------------


def test_enforced_isolation_maps_to_isolated() -> None:
    label = describe_isolation(_isolation(enforced=True, enforcement_capable=True))
    assert label == ISOLATION_ISOLATED


def test_a_capable_backend_that_did_not_enforce_maps_to_failed() -> None:
    assert describe_isolation(_isolation(enforcement_capable=True)) == ISOLATION_FAILED


def test_a_non_enforcing_backend_maps_to_noop() -> None:
    assert describe_isolation(_isolation(enforcement_capable=False)) == ISOLATION_NOOP


def test_not_requested_maps_to_none() -> None:
    assert describe_isolation(_isolation(requested=False)) == ISOLATION_NONE


def test_a_missing_isolation_object_maps_to_not_available() -> None:
    assert describe_isolation(None) == ISOLATION_UNAVAILABLE


def test_only_an_enforced_outcome_is_ever_shown_as_isolated() -> None:
    """The anti-overclaim rule, on the panel."""
    for isolation in (
        None,
        _isolation(requested=False),
        _isolation(enforcement_capable=False),
        _isolation(enforcement_capable=True),
    ):
        assert describe_isolation(isolation) != ISOLATION_ISOLATED


def test_not_requested_wins_even_if_enforced_were_somehow_set() -> None:
    assert describe_isolation(_isolation(requested=False, enforced=True)) == ISOLATION_NONE


def test_every_state_maps_to_a_distinct_label() -> None:
    labels = {
        describe_isolation(None),
        describe_isolation(_isolation(requested=False)),
        describe_isolation(_isolation(enforcement_capable=False)),
        describe_isolation(_isolation(enforcement_capable=True)),
        describe_isolation(_isolation(enforced=True, enforcement_capable=True)),
    }
    assert len(labels) == 5


# --- no display-side policy inference -------------------------------------


def test_isolation_label_takes_only_the_isolation_object() -> None:
    """There is no parameter through which QRS, category or an anomaly
    could reach this mapping, so the display cannot infer enforcement."""
    assert describe_isolation.__code__.co_argcount == 1


def test_a_high_risk_device_is_not_shown_as_isolated(caplog) -> None:
    frame = build_assessment_frame(
        _assessment(risk_score=10, category=RiskCategory.HIGH, isolation=None)
    )
    assert "Risk: HIGH" in frame
    assert f"Isolation: {ISOLATION_UNAVAILABLE}" in frame
    assert f"Isolation: {ISOLATION_ISOLATED}" not in frame


def test_an_ml_escalated_device_is_not_shown_as_isolated() -> None:
    """Raw QRS 5 fused up to HIGH by the anomaly signal: the panel shows
    the fused category it was given, and no isolation."""
    frame = build_assessment_frame(
        _assessment(
            risk_score=5,
            category=RiskCategory.MEDIUM,
            final_category=RiskCategory.HIGH,
            anomaly=AnomalyAssessment(anomaly_score=-0.9, is_anomaly=True, confidence=0.99),
            isolation=None,
        )
    )

    assert "QRS: 5/10" in frame
    assert f"Isolation: {ISOLATION_UNAVAILABLE}" in frame


def test_the_display_module_references_no_scoring_or_ml_identifier() -> None:
    """Structural guarantee that no risk, ML or fusion logic lives here."""
    import ast
    import inspect

    import hardware.display as module

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
        "should_isolate",
        "fuse_assessments",
        "assess_packet",
        "anomaly_score",
        "is_anomaly",
        "AnomalyDetector",
        "risk_isolation_threshold",
    ):
        assert forbidden not in identifiers


# --- frame content --------------------------------------------------------


def test_the_ready_frame_names_the_product_and_state() -> None:
    frame = build_ready_frame("eth0", "noop")
    assert frame[0] == "CIPHER"
    assert "Status: READY" in frame
    assert "Capture: eth0" in frame


def test_the_assessment_frame_shows_raw_qrs_and_fused_category() -> None:
    frame = build_assessment_frame(
        _assessment(ip="192.168.50.21", risk_score=7, category=RiskCategory.HIGH)
    )

    assert "Device: 192.168.50.21" in frame
    assert "QRS: 7/10" in frame
    assert "Risk: HIGH" in frame


@pytest.mark.parametrize(
    ("category", "score"),
    [(RiskCategory.LOW, 1), (RiskCategory.MEDIUM, 5), (RiskCategory.HIGH, 9)],
)
def test_every_risk_category_renders(category, score) -> None:
    frame = build_assessment_frame(_assessment(risk_score=score, category=category))
    assert f"Risk: {category.value}" in frame
    assert f"QRS: {score}/10" in frame


def test_the_assessment_frame_shows_the_isolation_state() -> None:
    frame = build_assessment_frame(
        _assessment(isolation=_isolation(enforced=True, enforcement_capable=True))
    )
    assert f"Isolation: {ISOLATION_ISOLATED}" in frame


def test_the_summary_frame_reports_the_run_totals() -> None:
    frame = build_summary_frame(4, 2, 1)
    assert "Status: COMPLETE" in frame
    assert "Devices: 4" in frame
    assert "Reports: 2" in frame
    assert "Isolated: 1" in frame


def test_every_frame_fits_the_physical_panel() -> None:
    frames = [
        build_ready_frame("a-very-long-interface-name-indeed", "iptables"),
        build_assessment_frame(
            _assessment(isolation=_isolation(enforcement_capable=True))
        ),
        build_summary_frame(1000, 1000, 1000),
    ]

    for frame in frames:
        assert len(frame) <= MAX_LINES
        for line in frame:
            assert len(line) <= MAX_LINE_LENGTH


def test_a_long_address_is_shortened_keeping_the_host_end() -> None:
    assert shorten_ip("192.168.100.200", width=15) == "192.168.100.200"
    shortened = shorten_ip("192.168.100.200", width=10)
    assert len(shortened) == 10
    assert shortened.endswith("100.200")


def test_a_normal_ipv4_address_is_never_altered() -> None:
    for ip in ("10.0.0.5", "192.168.50.21", "255.255.255.255"):
        assert shorten_ip(ip) == ip


# --- the convenience wrappers use the frame builders ----------------------


def test_show_ready_renders_the_ready_frame() -> None:
    display = _RecordingDisplay()
    display.show_ready("eth0", "noop")
    assert display.frames == [build_ready_frame("eth0", "noop")]


def test_show_assessment_renders_the_assessment_frame() -> None:
    display = _RecordingDisplay()
    assessment = _assessment()
    display.show_assessment(assessment)
    assert display.frames == [build_assessment_frame(assessment)]


def test_show_summary_renders_the_summary_frame() -> None:
    display = _RecordingDisplay()
    display.show_summary(3, 2, 1)
    assert display.frames == [build_summary_frame(3, 2, 1)]
