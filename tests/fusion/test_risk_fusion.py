"""Unit tests for fusion.risk_fusion.fuse_assessments — the frozen
category-floor, one-level-escalation Risk Fusion rule (docs/SDD.md
Step 10 addendum)."""
from datetime import datetime, timezone

import pytest

from fusion.risk_fusion import fuse_assessments
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.enums import RiskCategory
from models.risk_assessment import RiskAssessment

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _risk(category: RiskCategory) -> RiskAssessment:
    score = {RiskCategory.LOW: 1, RiskCategory.MEDIUM: 5, RiskCategory.HIGH: 9}[category]
    return RiskAssessment(score, category, "Upgrade TLS", "SP 800-52r2")


def _anomaly(is_anomaly: bool, confidence: float = 0.5) -> AnomalyAssessment:
    return AnomalyAssessment(anomaly_score=0.7, is_anomaly=is_anomaly, confidence=confidence)


def _device() -> Device:
    return Device.first_contact("192.168.1.10", TS)


@pytest.mark.parametrize(
    "category,is_anomaly,expected",
    [
        (RiskCategory.LOW, False, RiskCategory.LOW),
        (RiskCategory.LOW, True, RiskCategory.MEDIUM),
        (RiskCategory.MEDIUM, False, RiskCategory.MEDIUM),
        (RiskCategory.MEDIUM, True, RiskCategory.HIGH),
        (RiskCategory.HIGH, False, RiskCategory.HIGH),
        (RiskCategory.HIGH, True, RiskCategory.HIGH),
    ],
)
def test_escalation_table(category: RiskCategory, is_anomaly: bool, expected: RiskCategory) -> None:
    result = fuse_assessments(_risk(category), _anomaly(is_anomaly), _device(), assessed_at=TS)
    assert result.final_category == expected


def test_none_anomaly_assessment_passes_through_category() -> None:
    result = fuse_assessments(_risk(RiskCategory.MEDIUM), None, _device(), assessed_at=TS)
    assert result.final_category == RiskCategory.MEDIUM
    assert result.anomaly_assessment is None


def test_confidence_does_not_influence_fusion_when_anomalous() -> None:
    low_conf = fuse_assessments(
        _risk(RiskCategory.LOW), _anomaly(True, confidence=0.0), _device(), assessed_at=TS
    )
    high_conf = fuse_assessments(
        _risk(RiskCategory.LOW), _anomaly(True, confidence=1.0), _device(), assessed_at=TS
    )
    assert low_conf.final_category == high_conf.final_category == RiskCategory.MEDIUM


def test_confidence_does_not_influence_fusion_when_not_anomalous() -> None:
    low_conf = fuse_assessments(
        _risk(RiskCategory.HIGH), _anomaly(False, confidence=0.0), _device(), assessed_at=TS
    )
    high_conf = fuse_assessments(
        _risk(RiskCategory.HIGH), _anomaly(False, confidence=1.0), _device(), assessed_at=TS
    )
    assert low_conf.final_category == high_conf.final_category == RiskCategory.HIGH


def test_low_never_jumps_directly_to_high() -> None:
    result = fuse_assessments(_risk(RiskCategory.LOW), _anomaly(True), _device(), assessed_at=TS)
    assert result.final_category != RiskCategory.HIGH
    assert result.final_category == RiskCategory.MEDIUM


def test_inputs_are_not_mutated() -> None:
    risk = _risk(RiskCategory.LOW)
    anomaly = _anomaly(True)
    risk_copy = RiskAssessment(
        risk.risk_score, risk.category, risk.remediation, risk.nist_reference
    )
    anomaly_copy = AnomalyAssessment(
        anomaly.anomaly_score, anomaly.is_anomaly, anomaly.confidence
    )

    fuse_assessments(risk, anomaly, _device(), assessed_at=TS)

    assert risk == risk_copy
    assert anomaly == anomaly_copy


def test_device_is_preserved() -> None:
    device = _device()
    result = fuse_assessments(_risk(RiskCategory.LOW), None, device, assessed_at=TS)
    assert result.device == device


def test_explicit_assessed_at_is_preserved() -> None:
    result = fuse_assessments(_risk(RiskCategory.LOW), None, _device(), assessed_at=TS)
    assert result.assessed_at == TS


def test_default_assessed_at_is_timezone_aware_utc() -> None:
    before = datetime.now(timezone.utc)
    result = fuse_assessments(_risk(RiskCategory.LOW), None, _device())
    after = datetime.now(timezone.utc)

    assert result.assessed_at.tzinfo is not None
    assert result.assessed_at.utcoffset() == timezone.utc.utcoffset(None)
    assert before <= result.assessed_at <= after


def test_risk_assessment_produces_the_final_device_assessment_fields() -> None:
    device = _device()
    risk = _risk(RiskCategory.HIGH)
    anomaly = _anomaly(False)
    result = fuse_assessments(risk, anomaly, device, assessed_at=TS)

    assert result.device == device
    assert result.risk_assessment == risk
    assert result.anomaly_assessment == anomaly


@pytest.mark.parametrize(
    "kwargs",
    [
        {"risk_assessment": "not-a-risk-assessment", "anomaly_assessment": None, "device": _device()},
        {"risk_assessment": _risk(RiskCategory.LOW), "anomaly_assessment": "not-an-anomaly", "device": _device()},
        {"risk_assessment": _risk(RiskCategory.LOW), "anomaly_assessment": None, "device": "not-a-device"},
    ],
)
def test_invalid_argument_types_fail_clearly(kwargs: dict) -> None:
    with pytest.raises(TypeError):
        fuse_assessments(**kwargs)


def test_fusion_does_not_directly_import_risk_or_ml_engines() -> None:
    """Static check: fusion/risk_fusion.py must never import risk/ or
    ml/ — fusion combines their already-produced outputs (RiskAssessment,
    AnomalyAssessment), it must not invoke either engine itself."""
    import ast
    import inspect

    import fusion.risk_fusion as fusion_module

    tree = ast.parse(inspect.getsource(fusion_module))
    imported_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module.split(".")[0])

    assert "risk" not in imported_modules
    assert "ml" not in imported_modules
    assert imported_modules <= {"__future__", "datetime", "typing", "models"}
