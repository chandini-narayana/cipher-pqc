"""Unit tests for models.device_assessment.DeviceAssessment."""
from datetime import datetime

from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.risk_assessment import RiskAssessment

TS = datetime(2026, 1, 1, 12, 0, 0)


def _build() -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact("192.168.1.10", TS),
        risk_assessment=RiskAssessment(9, RiskCategory.HIGH, "Upgrade TLS", "SP 800-52r2"),
        anomaly_assessment=AnomalyAssessment(anomaly_score=-0.4, is_anomaly=True, confidence=0.9),
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    )


def test_constructs_from_valid_parts() -> None:
    assessment = _build()
    assert assessment.final_category == RiskCategory.HIGH
    assert assessment.risk_assessment.risk_score == 9
    assert assessment.anomaly_assessment.is_anomaly is True


def test_final_category_is_independent_of_sub_assessments() -> None:
    """final_category is fusion output, not required to equal either
    sub-assessment's own category/label — that fusion logic lives
    outside this model (see module docstring)."""
    assessment = DeviceAssessment(
        device=Device.first_contact("10.0.0.1", TS),
        risk_assessment=RiskAssessment(2, RiskCategory.LOW, "n/a", "n/a"),
        anomaly_assessment=AnomalyAssessment(anomaly_score=0.9, is_anomaly=True, confidence=0.99),
        final_category=RiskCategory.HIGH,  # fusion escalated it despite low rule-based score
        assessed_at=TS,
    )
    assert assessment.final_category == RiskCategory.HIGH
    assert assessment.risk_assessment.category == RiskCategory.LOW


def test_round_trip_serialization() -> None:
    a1 = _build()
    a2 = DeviceAssessment.from_dict(a1.to_dict())
    assert a1 == a2