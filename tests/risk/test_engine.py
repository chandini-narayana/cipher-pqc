"""Unit tests for risk.engine.evaluate_risk — the DeviceFeatures ->
RiskAssessment entry point."""
from datetime import datetime, timezone

import pytest

from models.device import Device
from models.device_features import DeviceFeatures
from models.entropy_metrics import EntropyMetrics
from models.enums import ProtocolType, RiskCategory, TLSVersion
from models.packet_metadata import PacketMetadata
from models.protocol_fingerprint import ProtocolFingerprint
from models.risk_assessment import RiskAssessment
from risk.engine import evaluate_risk

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _features(
    tls_version=TLSVersion.TLS_1_3,
    key_size=3072,
    forward_secrecy=True,
    entropy=7.9,
    protocol=ProtocolType.HTTPS,
) -> DeviceFeatures:
    return DeviceFeatures(
        device=Device.first_contact("192.168.1.10", TS),
        packet=PacketMetadata(
            src_ip="192.168.1.10", dst_ip="192.168.1.1",
            src_port=51000, dst_port=443, packet_size=100, timestamp=TS,
        ),
        fingerprint=ProtocolFingerprint(
            protocol=protocol, tls_version=tls_version, key_size=key_size,
            forward_secrecy=forward_secrecy,
        ),
        entropy=EntropyMetrics(shannon_entropy=entropy, sample_size=100),
    )


def test_evaluate_risk_returns_a_risk_assessment() -> None:
    result = evaluate_risk(_features(), port_risk=0)
    assert isinstance(result, RiskAssessment)


def test_evaluate_risk_lowest_risk_case() -> None:
    result = evaluate_risk(_features(), port_risk=0)
    assert result.risk_score == 0
    assert result.category == RiskCategory.LOW


def test_evaluate_risk_highest_risk_case() -> None:
    result = evaluate_risk(
        _features(tls_version=TLSVersion.TLS_1_0, key_size=512, forward_secrecy=False, entropy=3.0),
        port_risk=2,
    )
    assert result.risk_score == 10
    assert result.category == RiskCategory.HIGH


def test_evaluate_risk_pulls_fields_from_the_correct_nested_models() -> None:
    """Confirms tls_version/key_size/pfs come from features.fingerprint
    and entropy comes from features.entropy — not swapped or ignored."""
    result = evaluate_risk(
        _features(tls_version=TLSVersion.TLS_1_1, key_size=1536, forward_secrecy=False, entropy=5.5),
        port_risk=0,
    )
    # TLS1.1(3) + key1536(3) + noPFS(1) + entropy5.5(2) + port_risk(0) = 9
    assert result.risk_score == 9


def test_evaluate_risk_with_unknown_tls_version_and_key_size() -> None:
    """Realistic case: an HTTPS ApplicationData packet where neither
    version nor key size is visible in this specific payload."""
    result = evaluate_risk(
        _features(tls_version=None, key_size=None, forward_secrecy=True, entropy=7.9),
        port_risk=0,
    )
    # TLS None(2) + key None(0) + PFS(0) + entropy7.9(0) + port_risk(0) = 2
    assert result.risk_score == 2
    assert result.category == RiskCategory.LOW


def test_evaluate_risk_is_deterministic() -> None:
    features = _features(tls_version=TLSVersion.TLS_1_1, key_size=1536, forward_secrecy=False, entropy=5.5)
    first = evaluate_risk(features, port_risk=1)
    second = evaluate_risk(features, port_risk=1)
    assert first == second


def test_evaluate_risk_propagates_invalid_port_risk() -> None:
    with pytest.raises(ValueError, match="port_risk"):
        evaluate_risk(_features(), port_risk=-1)


def test_evaluate_risk_remediation_is_present_and_specific() -> None:
    result = evaluate_risk(
        _features(tls_version=TLSVersion.TLS_1_0, key_size=1024, forward_secrecy=False, entropy=4.0),
        port_risk=0,
    )
    assert "TLS 1.0" in result.remediation
    assert "1024" in result.remediation
    assert "forward secrecy" in result.remediation.lower()


def test_evaluate_risk_has_no_ml_or_network_imports() -> None:
    """Same static-analysis check as test_scoring.py, applied to the
    engine module specifically."""
    import ast
    import inspect

    import risk.engine as engine_module

    source = inspect.getsource(engine_module)
    tree = ast.parse(source)

    forbidden = {"sklearn", "socket", "requests", "urllib", "http", "scapy", "flask"}
    found_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found_modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found_modules.add(node.module.split(".")[0])

    assert not (found_modules & forbidden)