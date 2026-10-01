"""Unit tests for models.device_assessment.DeviceAssessment."""
from datetime import datetime

from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
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


def _build_without_anomaly() -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact("192.168.1.10", TS),
        risk_assessment=RiskAssessment(9, RiskCategory.HIGH, "Upgrade TLS", "SP 800-52r2"),
        anomaly_assessment=None,
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    )


def test_to_dict_serializes_none_anomaly_assessment_as_none() -> None:
    assessment = _build_without_anomaly()
    as_dict = assessment.to_dict()
    assert as_dict["anomaly_assessment"] is None


def test_round_trip_serialization_with_none_anomaly_assessment() -> None:
    a1 = _build_without_anomaly()
    a2 = DeviceAssessment.from_dict(a1.to_dict())
    assert a1 == a2
    assert a2.anomaly_assessment is None

# --- Phase 3B: optional isolation state ---


def _isolation() -> IsolationStatus:
    return IsolationStatus(
        requested=True,
        enforced=False,
        backend="noop",
        reason="Hardware enforcement unavailable in current deployment",
        requested_at=TS,
        enforcement_capable=False,
    )


def test_isolation_defaults_to_none() -> None:
    """Optional and absent by default: most observations are not
    isolation-eligible, and every pre-Phase-3B construction site must
    keep working untouched."""
    assert _build().isolation is None


def test_to_dict_serializes_absent_isolation_as_none() -> None:
    assert _build().to_dict()["isolation"] is None


def test_with_isolation_returns_a_copy_carrying_the_status() -> None:
    original = _build()
    updated = original.with_isolation(_isolation())
    assert updated.isolation == _isolation()
    assert original.isolation is None


def test_with_isolation_changes_nothing_else() -> None:
    """Enforcement state must never alter a risk, ML or fusion value."""
    original = _build()
    updated = original.with_isolation(_isolation())
    assert updated.device == original.device
    assert updated.risk_assessment == original.risk_assessment
    assert updated.anomaly_assessment == original.anomaly_assessment
    assert updated.final_category == original.final_category
    assert updated.assessed_at == original.assessed_at


def test_round_trip_serialization_with_isolation() -> None:
    a1 = _build().with_isolation(_isolation())
    a2 = DeviceAssessment.from_dict(a1.to_dict())
    assert a1 == a2
    assert a2.isolation == _isolation()


def test_from_dict_tolerates_a_payload_without_an_isolation_key() -> None:
    """Backward compatibility: a payload serialized before isolation
    state existed must still load, as None."""
    payload = _build().to_dict()
    del payload["isolation"]
    assert DeviceAssessment.from_dict(payload).isolation is None
