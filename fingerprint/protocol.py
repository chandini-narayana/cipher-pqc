"""Protocol classification: HTTP vs HTTPS vs MQTT vs Telnet vs unknown.

Classifies strictly from payload-level evidence — no port numbers are
read or considered anywhere in this module (the functions below don't
even accept a port as an argument, which structurally guarantees port
numbers can't influence the result, not just by convention).
"""
from __future__ import annotations

from typing import Optional, Tuple

from fingerprint.tls import detect_tls_version, extract_rsa_key_size
from models.enums import ProtocolType, TLSVersion
from models.protocol_fingerprint import ProtocolFingerprint

# ChangeCipherSpec, Alert, Handshake, ApplicationData
_TLS_CONTENT_TYPES = {0x14, 0x15, 0x16, 0x17}

_HTTP_METHODS = (
    b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
    b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ",
)

_MQTT_CONNECT_FIRST_BYTE = 0x10  # message type 1 (CONNECT), flags 0000 (reserved)
_MQTT_PROTOCOL_NAMES = (b"MQTT", b"MQIsdp")

_TELNET_IAC = 0xFF
_TELNET_NEGOTIATION_COMMANDS = {0xFB, 0xFC, 0xFD, 0xFE}  # WILL, WONT, DO, DONT


def detect_protocol_type(payload: bytes) -> ProtocolType:
    """Classify `payload` using only evidence present in the bytes
    themselves.

    Returns ProtocolType.OTHER whenever the payload doesn't match any
    of the specific, deterministic signatures below — including for
    empty input. OTHER means "no confident evidence," not "definitely
    none of these."
    """
    if _looks_like_tls_record(payload):
        return ProtocolType.HTTPS
    if _looks_like_http(payload):
        return ProtocolType.HTTP
    if _looks_like_mqtt_connect(payload):
        return ProtocolType.MQTT
    if _looks_like_telnet_negotiation(payload):
        return ProtocolType.TELNET
    return ProtocolType.OTHER


def fingerprint_packet(payload: bytes) -> ProtocolFingerprint:
    """Build a ProtocolFingerprint from a single captured packet's
    payload — the intended entry point for the capture -> fingerprint
    -> ProtocolFingerprint flow (analogous to entropy's
    compute_entropy_metrics in Step 6).

    tls_version and key_size are only populated when THIS payload is
    itself a parseable TLS handshake message carrying that evidence
    (see fingerprint/tls.py) — a real handshake spans several packets,
    and this function does not correlate across them (see docs/SDD.md
    Section 19).

    cipher_suite and forward_secrecy are deliberately left at their
    conservative defaults (None and False): confirming forward secrecy
    requires classifying the ServerHello's negotiated cipher suite
    against known PFS-providing suites, which edges into risk-relevant
    judgment reserved for the later risk-analysis milestone and wasn't
    in Step 7's required scope. False reflects "not confirmed," not a
    claim that PFS is absent.
    """
    protocol = detect_protocol_type(payload)

    tls_version: Optional[TLSVersion] = None
    key_size: Optional[int] = None
    if protocol == ProtocolType.HTTPS:
        tls_version = detect_tls_version(payload)
        key_size = extract_rsa_key_size(payload)

    return ProtocolFingerprint(
        protocol=protocol,
        tls_version=tls_version,
        key_size=key_size,
        forward_secrecy=False,
        cipher_suite=None,
    )


# --- internal detection helpers ---


def _looks_like_tls_record(payload: bytes) -> bool:
    if len(payload) < 5:
        return False
    content_type, major, minor = payload[0], payload[1], payload[2]
    return (
        content_type in _TLS_CONTENT_TYPES
        and major == 0x03
        and minor in (0x00, 0x01, 0x02, 0x03, 0x04)
    )


def _looks_like_http(payload: bytes) -> bool:
    line_end = payload.find(b"\r\n")
    first_line = payload[:line_end] if line_end != -1 else payload[:200]

    if first_line.startswith(b"HTTP/1."):
        return True  # a response

    for method in _HTTP_METHODS:
        if first_line.startswith(method):
            return b"HTTP/1." in first_line  # a request, with a version marker present

    return False


def _looks_like_mqtt_connect(payload: bytes) -> bool:
    if len(payload) < 2 or payload[0] != _MQTT_CONNECT_FIRST_BYTE:
        return False

    remaining_length, header_len = _decode_mqtt_remaining_length(payload[1:])
    if remaining_length is None:
        return False

    variable_header = payload[1 + header_len :]
    if len(variable_header) < 2:
        return False

    name_len = int.from_bytes(variable_header[0:2], "big")
    name = variable_header[2 : 2 + name_len]
    return name in _MQTT_PROTOCOL_NAMES


def _decode_mqtt_remaining_length(data: bytes) -> Tuple[Optional[int], int]:
    """Decode MQTT's variable-length "remaining length" field.

    Returns (value, bytes_consumed), or (None, 0) if the encoding is
    malformed — more than 4 continuation bytes, or ran out of data.
    """
    value = 0
    multiplier = 1
    for i in range(4):  # MQTT caps this field at 4 bytes
        if i >= len(data):
            return None, 0
        byte = data[i]
        value += (byte & 0x7F) * multiplier
        if not (byte & 0x80):
            return value, i + 1
        multiplier *= 128
    return None, 0


def _looks_like_telnet_negotiation(payload: bytes) -> bool:
    return (
        len(payload) >= 3
        and payload[0] == _TELNET_IAC
        and payload[1] in _TELNET_NEGOTIATION_COMMANDS
    )