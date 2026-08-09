"""Unit tests for models.enums."""
import pytest

from models.enums import ProtocolType, RiskCategory, TLSVersion


def test_protocol_type_members() -> None:
    assert ProtocolType.HTTPS == "HTTPS"
    assert ProtocolType.MQTT.value == "MQTT"
    assert ProtocolType.OTHER in ProtocolType


def test_risk_category_members() -> None:
    assert set(RiskCategory) == {RiskCategory.LOW, RiskCategory.MEDIUM, RiskCategory.HIGH}


def test_tls_version_values() -> None:
    assert TLSVersion.TLS_1_3.value == 1.3
    assert TLSVersion.TLS_1_0.value == 1.0


def test_tls_version_rejects_invalid_value() -> None:
    with pytest.raises(ValueError):
        TLSVersion(2.7)