"""Unit tests for fingerprint.protocol — HTTP/HTTPS/MQTT/Telnet
classification and the fingerprint_packet entry point.

Every payload is deterministic, hand-crafted bytes. A dedicated test
at the bottom of this file proves port numbers have zero influence on
classification, using real capture.RawPacket instances.
"""
from datetime import datetime, timezone

import pytest

from fingerprint.protocol import detect_protocol_type, fingerprint_packet
from models.enums import ProtocolType
from models.protocol_fingerprint import ProtocolFingerprint
from tests.fingerprint._helpers import build_client_hello, build_mqtt_connect


# --- HTTP ---


def test_detects_http_get_request() -> None:
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    assert detect_protocol_type(payload) == ProtocolType.HTTP


def test_detects_http_post_request() -> None:
    payload = b"POST /submit HTTP/1.1\r\nHost: example.com\r\n\r\nname=value"
    assert detect_protocol_type(payload) == ProtocolType.HTTP


def test_detects_http_response() -> None:
    payload = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    assert detect_protocol_type(payload) == ProtocolType.HTTP


def test_method_looking_text_without_version_marker_is_not_http() -> None:
    """Starting with "GET " alone isn't enough — real HTTP evidence
    requires the version marker too, or this would false-positive on
    arbitrary text."""
    assert detect_protocol_type(b"GET SOME RANDOM TEXT NOT REALLY HTTP AT ALL") == ProtocolType.OTHER


# --- HTTPS / TLS distinction ---


def test_detects_https_from_tls_handshake_record() -> None:
    payload = build_client_hello()
    assert detect_protocol_type(payload) == ProtocolType.HTTPS


def test_detects_https_from_tls_application_data_record() -> None:
    """Even post-handshake encrypted application data is still
    confirmed TLS-protected traffic at the record layer."""
    app_data = bytes([0x17, 0x03, 0x03, 0x00, 0x05]) + b"xxxxx"
    assert detect_protocol_type(app_data) == ProtocolType.HTTPS


def test_detects_https_from_tls_alert_record() -> None:
    alert = bytes([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28])
    assert detect_protocol_type(alert) == ProtocolType.HTTPS


# --- MQTT ---


def test_detects_mqtt_connect_with_mqtt_protocol_name() -> None:
    payload = build_mqtt_connect(protocol_name=b"MQTT", version_byte=0x04)
    assert detect_protocol_type(payload) == ProtocolType.MQTT


def test_detects_mqtt_connect_with_legacy_mqisdp_name() -> None:
    """MQTT 3.1 used "MQIsdp" as its protocol name before 3.1.1
    standardized on "MQTT"."""
    payload = build_mqtt_connect(protocol_name=b"MQIsdp", version_byte=0x03)
    assert detect_protocol_type(payload) == ProtocolType.MQTT


def test_data_that_merely_starts_with_mqtt_connect_byte_is_not_enough() -> None:
    """The first byte alone (0x10) matching CONNECT's message type is
    not sufficient evidence — the protocol name must genuinely be
    present at the correct offset, or this would false-positive on
    arbitrary binary data."""
    fake = bytes([0x10, 0x05, 1, 2, 3, 4, 5])
    assert detect_protocol_type(fake) == ProtocolType.OTHER


def test_wrong_protocol_name_is_not_mqtt() -> None:
    payload = build_mqtt_connect(protocol_name=b"XXXX", version_byte=0x04)
    assert detect_protocol_type(payload) == ProtocolType.OTHER


# --- Telnet ---


def test_detects_telnet_will_negotiation() -> None:
    payload = bytes([0xFF, 0xFB, 0x01])  # IAC WILL ECHO
    assert detect_protocol_type(payload) == ProtocolType.TELNET


def test_detects_telnet_do_negotiation() -> None:
    payload = bytes([0xFF, 0xFD, 0x18, 0x00, 0x00])  # IAC DO <opt>
    assert detect_protocol_type(payload) == ProtocolType.TELNET


def test_iac_byte_with_invalid_command_is_not_telnet() -> None:
    """0xFF followed by a byte that isn't WILL/WONT/DO/DONT (0xFB-0xFE)
    isn't genuine Telnet option-negotiation evidence."""
    payload = bytes([0xFF, 0x05, 0x10])
    assert detect_protocol_type(payload) == ProtocolType.OTHER


# --- Unknown / malformed / empty ---


def test_unrecognized_binary_payload_is_other() -> None:
    assert detect_protocol_type(bytes([5, 10, 15, 20, 25, 30])) == ProtocolType.OTHER


def test_empty_payload_is_other_not_a_crash() -> None:
    assert detect_protocol_type(b"") == ProtocolType.OTHER


# --- fingerprint_packet: the full entry point ---


def test_fingerprint_packet_on_https_populates_tls_fields() -> None:
    payload = build_client_hello(supported_versions=bytes([0x03, 0x04]))
    result = fingerprint_packet(payload)
    assert isinstance(result, ProtocolFingerprint)
    assert result.protocol == ProtocolType.HTTPS
    assert result.tls_version is not None


def test_fingerprint_packet_on_http_leaves_tls_fields_none() -> None:
    payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    result = fingerprint_packet(payload)
    assert result.protocol == ProtocolType.HTTP
    assert result.tls_version is None
    assert result.key_size is None


def test_fingerprint_packet_on_empty_payload_is_graceful() -> None:
    """Empty payloads are permitted by this API (unlike RawPacket,
    which forbids them) — the honest answer is OTHER, not a crash."""
    result = fingerprint_packet(b"")
    assert result.protocol == ProtocolType.OTHER
    assert result.tls_version is None
    assert result.key_size is None


def test_fingerprint_packet_never_fabricates_forward_secrecy_or_cipher_suite() -> None:
    """Deliberately deferred fields (see module docstring) — always
    the conservative defaults in Step 7, regardless of protocol."""
    result = fingerprint_packet(build_client_hello(supported_versions=bytes([0x03, 0x04])))
    assert result.forward_secrecy is False
    assert result.cipher_suite is None


# --- Port-independence: the explicit requirement ---


def test_classification_ignores_port_numbers_entirely() -> None:
    """Build real RawPacket instances with deliberately misleading
    ports and confirm classification is driven only by payload bytes.
    fingerprint_packet doesn't even accept a port argument, so this is
    guaranteed by construction — this test proves it end to end."""
    from capture.raw_packet import RawPacket

    http_payload_on_tls_port = RawPacket(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=5000, dst_port=443,
        payload=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        timestamp=datetime.now(timezone.utc),
    )
    tls_payload_on_http_port = RawPacket(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=5000, dst_port=80,
        payload=build_client_hello(), timestamp=datetime.now(timezone.utc),
    )
    mqtt_payload_on_https_port = RawPacket(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=5000, dst_port=443,
        payload=build_mqtt_connect(), timestamp=datetime.now(timezone.utc),
    )

    assert fingerprint_packet(http_payload_on_tls_port.payload).protocol == ProtocolType.HTTP
    assert fingerprint_packet(tls_payload_on_http_port.payload).protocol == ProtocolType.HTTPS
    assert fingerprint_packet(mqtt_payload_on_https_port.payload).protocol == ProtocolType.MQTT