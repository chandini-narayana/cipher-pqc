"""Unit tests for models.signed_event.SignedEvent."""
from datetime import datetime

import pytest

from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.risk_assessment import RiskAssessment
from models.signed_event import SignedEvent

TS = datetime(2026, 1, 1, 12, 0, 0)


def _assessment() -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact("192.168.1.10", TS),
        risk_assessment=RiskAssessment(9, RiskCategory.HIGH, "Upgrade TLS", "SP 800-52r2"),
        anomaly_assessment=AnomalyAssessment(anomaly_score=-0.4, is_anomaly=True, confidence=0.9),
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    )


def test_valid_signed_event() -> None:
    se = SignedEvent(
        assessment=_assessment(),
        signature_hex="deadbeef",
        algorithm="FIPS-204-Dilithium2",
        signed_at=TS,
    )
    assert se.algorithm == "FIPS-204-Dilithium2"


def test_rejects_invalid_hex_signature() -> None:
    with pytest.raises(ValueError, match="hexadecimal"):
        SignedEvent(
            assessment=_assessment(),
            signature_hex="not-hex!!",
            algorithm="FIPS-204-Dilithium2",
            signed_at=TS,
        )


def test_rejects_empty_algorithm() -> None:
    with pytest.raises(ValueError, match="algorithm"):
        SignedEvent(
            assessment=_assessment(),
            signature_hex="deadbeef",
            algorithm="",
            signed_at=TS,
        )


def test_tamper_detection_via_changed_signature_breaks_equality() -> None:
    """This model doesn't verify signatures itself (signing/ does),
    but it should at least make a tampered copy trivially distinguishable."""
    se1 = SignedEvent(_assessment(), "deadbeef", "FIPS-204-Dilithium2", TS)
    se2 = SignedEvent(_assessment(), "deadbeee", "FIPS-204-Dilithium2", TS)
    assert se1 != se2


def test_round_trip_serialization() -> None:
    se1 = SignedEvent(_assessment(), "deadbeef", "FIPS-204-Dilithium2", TS)
    se2 = SignedEvent.from_dict(se1.to_dict())
    assert se1 == se2