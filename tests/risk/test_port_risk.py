"""Unit tests for risk.port_risk.port_risk_for_protocol — the frozen
engineering-policy mapping that resolves the previously-open port_risk
gap (docs/SDD.md Step 12B addendum). Not a re-derivation of QRS itself
— risk/scoring.py and risk/engine.py are unchanged by this module.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from entropy.engine import compute_entropy_metrics
from fingerprint.protocol import fingerprint_packet
from models.device import Device
from models.device_features import DeviceFeatures
from models.enums import ProtocolType
from models.packet_metadata import PacketMetadata
from risk.engine import evaluate_risk
from risk.port_risk import port_risk_for_protocol
from risk.scoring import entropy_risk, key_size_risk, tls_version_risk

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


# --- 1-5. exact frozen values ---


@pytest.mark.parametrize(
    "protocol,expected",
    [
        (ProtocolType.HTTPS, 0),
        (ProtocolType.OTHER, 0),
        (ProtocolType.HTTP, 1),
        (ProtocolType.MQTT, 1),
        (ProtocolType.TELNET, 2),
    ],
)
def test_frozen_mapping(protocol: ProtocolType, expected: int) -> None:
    assert port_risk_for_protocol(protocol) == expected


# --- 6. exact full ProtocolType coverage ---


def test_covers_every_protocol_type_member() -> None:
    for protocol in ProtocolType:
        # Must not raise for any actual member — full coverage, no gaps.
        port_risk_for_protocol(protocol)

    assert {p for p in ProtocolType} == {
        ProtocolType.HTTPS,
        ProtocolType.HTTP,
        ProtocolType.MQTT,
        ProtocolType.TELNET,
        ProtocolType.OTHER,
    }


# --- 7. invalid input fails clearly ---


@pytest.mark.parametrize("bad_input", ["HTTPS", "OTHER", 1, None, object()])
def test_invalid_input_raises_type_error(bad_input) -> None:
    with pytest.raises(TypeError):
        port_risk_for_protocol(bad_input)


# --- 8 & 9. output is always an int within 0..2 ---


def test_output_is_always_an_int_within_bounds() -> None:
    for protocol in ProtocolType:
        result = port_risk_for_protocol(protocol)
        assert isinstance(result, int)
        assert 0 <= result <= 2


# --- 10. static dependency check ---


def test_port_risk_module_has_no_forbidden_dependencies() -> None:
    import ast
    import inspect

    import risk.port_risk as port_risk_module

    tree = ast.parse(inspect.getsource(port_risk_module))
    imported_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module.split(".")[0])

    forbidden = {"pipeline", "ml", "fusion", "capture", "reports", "signing"}
    assert not (imported_modules & forbidden)


# --- integration: fingerprint.protocol -> port_risk_for_protocol -> evaluate_risk ---


def test_fingerprint_protocol_flows_into_evaluate_risk_via_port_risk_for_protocol() -> None:
    """Demonstrates the intended future runtime wiring (fingerprint ->
    port_risk_for_protocol -> evaluate_risk) without changing
    evaluate_risk itself — evaluate_risk still just takes port_risk as
    a plain externally-supplied int, exactly as before Step 12B."""
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"

    fingerprint = fingerprint_packet(payload)
    assert fingerprint.protocol == ProtocolType.HTTP

    port_risk = port_risk_for_protocol(fingerprint.protocol)
    assert port_risk == 1

    entropy = compute_entropy_metrics(payload)
    features = DeviceFeatures(
        device=Device.first_contact("192.168.1.10", TS),
        packet=PacketMetadata(
            src_ip="192.168.1.10", dst_ip="93.184.216.34",
            src_port=51000, dst_port=80, packet_size=len(payload), timestamp=TS,
        ),
        fingerprint=fingerprint,
        entropy=entropy,
    )

    result = evaluate_risk(features, port_risk)

    expected_score = min(
        tls_version_risk(fingerprint.tls_version)
        + key_size_risk(fingerprint.key_size)
        + (0 if fingerprint.forward_secrecy else 1)
        + entropy_risk(entropy.shannon_entropy)
        + port_risk,
        10,
    )
    assert result.risk_score == expected_score
