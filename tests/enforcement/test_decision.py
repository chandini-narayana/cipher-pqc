"""Unit tests for enforcement.decision.should_isolate — the pure,
deterministic Phase 14 isolation-eligibility decision (docs/SDD.md
Phase 14 addendum).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import pytest

from enforcement.decision import should_isolate
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.risk_assessment import RiskAssessment

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
_DEFAULT_THRESHOLD = 7


def _assessment(
    risk_score: int,
    category: RiskCategory,
    final_category: RiskCategory,
    anomaly: Optional[AnomalyAssessment] = None,
) -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact("192.168.1.10", TS),
        risk_assessment=RiskAssessment(risk_score, category, "text", "NIST SP 800-52r2"),
        anomaly_assessment=anomaly,
        final_category=final_category,
        assessed_at=TS,
    )


@pytest.mark.parametrize("risk_score", [0, 1, 2, 3, 4, 5, 6])
def test_qrs_below_seven_is_not_eligible(risk_score: int) -> None:
    category = RiskCategory.LOW if risk_score <= 2 else RiskCategory.MEDIUM
    assessment = _assessment(risk_score, category, category)
    assert should_isolate(assessment, _DEFAULT_THRESHOLD) is False


def test_qrs_exactly_seven_is_eligible() -> None:
    assessment = _assessment(7, RiskCategory.HIGH, RiskCategory.HIGH)
    assert should_isolate(assessment, _DEFAULT_THRESHOLD) is True


@pytest.mark.parametrize("risk_score", [8, 9, 10])
def test_qrs_above_seven_is_eligible(risk_score: int) -> None:
    assessment = _assessment(risk_score, RiskCategory.HIGH, RiskCategory.HIGH)
    assert should_isolate(assessment, _DEFAULT_THRESHOLD) is True


def test_ml_escalated_final_category_does_not_make_a_low_raw_qrs_eligible() -> None:
    """The frozen Phase 14 policy: ML-only escalation to HIGH must not
    trigger isolation when the raw, deterministic QRS itself is below
    the threshold."""
    assessment = _assessment(
        risk_score=5,
        category=RiskCategory.MEDIUM,
        final_category=RiskCategory.HIGH,  # escalated by fusion due to an ML anomaly
        anomaly=AnomalyAssessment(anomaly_score=0.9, is_anomaly=True, confidence=0.9),
    )
    assert assessment.final_category == RiskCategory.HIGH
    assert assessment.risk_assessment.risk_score == 5

    assert should_isolate(assessment, _DEFAULT_THRESHOLD) is False


def test_should_isolate_never_reads_final_category() -> None:
    """Static confirmation, not just behavioral: the decision function's
    code (not its docstring, which explains the omission by name) never
    accesses a `final_category` attribute."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(should_isolate))
    function_body = tree.body[0].body[1:]  # skip the docstring (body[0])
    accessed_attrs = {
        node.attr
        for statement in function_body
        for node in ast.walk(statement)
        if isinstance(node, ast.Attribute)
    }
    assert "final_category" not in accessed_attrs


@pytest.mark.parametrize(
    "risk_score,threshold,expected",
    [
        (4, 5, False),
        (5, 5, True),
        (6, 5, True),
        (9, 10, False),
        (10, 10, True),
    ],
)
def test_custom_threshold_is_respected(risk_score: int, threshold: int, expected: bool) -> None:
    """The threshold is a parameter, not a hardcoded constant — this
    does not change the production default of 7 anywhere else."""
    assessment = _assessment(risk_score, RiskCategory.HIGH, RiskCategory.HIGH)
    assert should_isolate(assessment, threshold) is expected


def test_should_isolate_performs_no_logging(caplog) -> None:
    import logging

    assessment = _assessment(9, RiskCategory.HIGH, RiskCategory.HIGH)
    with caplog.at_level(logging.DEBUG):
        should_isolate(assessment, _DEFAULT_THRESHOLD)
    assert caplog.records == []
