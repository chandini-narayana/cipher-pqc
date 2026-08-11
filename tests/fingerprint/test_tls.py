"""Unit tests for fingerprint.tls — TLS version detection and RSA
key-size extraction.

Every payload is hand-assembled from the actual TLS wire format (see
_helpers.py) — nothing here depends on real network traffic or a live
interface.
"""
import pytest

from fingerprint.tls import detect_tls_version, extract_rsa_key_size
from models.enums import TLSVersion
from tests.fingerprint._helpers import (
    build_certificate_message,
    build_client_hello,
    build_ec_certificate_der,
    build_rsa_certificate_der,
    build_server_hello,
)


# --- TLS version: ClientHello ---


def test_client_hello_tls_1_2_via_legacy_version() -> None:
    """No supported_versions extension: the legacy client_version
    field IS the true version for TLS 1.2 and below."""
    payload = build_client_hello(legacy_version=(0x03, 0x03))
    assert detect_tls_version(payload) == TLSVersion.TLS_1_2


def test_client_hello_tls_1_0_and_1_1() -> None:
    assert detect_tls_version(build_client_hello(legacy_version=(0x03, 0x01))) == TLSVersion.TLS_1_0
    assert detect_tls_version(build_client_hello(legacy_version=(0x03, 0x02))) == TLSVersion.TLS_1_1


def test_client_hello_tls_1_3_via_supported_versions_extension() -> None:
    """The critical case: legacy field stays pinned to {0x03,0x03} for
    TLS 1.3, so detection MUST come from the extension, not the legacy
    field, or every TLS 1.3 handshake would be misreported as 1.2."""
    payload = build_client_hello(supported_versions=bytes([0x03, 0x04]))
    assert detect_tls_version(payload) == TLSVersion.TLS_1_3


def test_client_hello_picks_highest_offered_version() -> None:
    """Client offers both 1.2 and 1.3 (preference order client's own
    choice) — the highest offered is the most informative honest
    answer about what this client supports."""
    payload = build_client_hello(supported_versions=bytes([0x03, 0x03, 0x03, 0x04]))
    assert detect_tls_version(payload) == TLSVersion.TLS_1_3


# --- TLS version: ServerHello ---


def test_server_hello_tls_1_2_via_legacy_version() -> None:
    payload = build_server_hello(legacy_version=(0x03, 0x03))
    assert detect_tls_version(payload) == TLSVersion.TLS_1_2


def test_server_hello_tls_1_3_via_supported_versions_extension() -> None:
    """ServerHello's supported_versions extension is authoritative —
    it states the ONE version actually negotiated, not an offer list."""
    payload = build_server_hello(selected_version=(0x03, 0x04))
    assert detect_tls_version(payload) == TLSVersion.TLS_1_3


# --- Unknown / malformed / non-TLS input ---


def test_non_tls_payload_returns_none() -> None:
    assert detect_tls_version(b"this is not a TLS record at all") is None


def test_empty_payload_returns_none() -> None:
    assert detect_tls_version(b"") is None


def test_truncated_handshake_returns_none_or_legacy_fallback_not_a_crash() -> None:
    """A record header + handshake header with no body at all: not
    enough to reach the legacy version field, so None — must not raise."""
    truncated = bytes([0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00])
    assert detect_tls_version(truncated) is None


def test_tls_record_with_wrong_content_type_returns_none() -> None:
    """content type 0x17 (ApplicationData) carries no handshake at
    all — version genuinely isn't determinable from it."""
    app_data = bytes([0x17, 0x03, 0x03, 0x00, 0x05]) + b"hello"
    assert detect_tls_version(app_data) is None


def test_malformed_extension_length_does_not_crash() -> None:
    """An extensions length field claiming more bytes than actually
    present must fail gracefully (fallback to legacy version), not
    raise an exception."""
    body = bytes([0x03, 0x03]) + b"\x00" * 32 + bytes([0]) + (2).to_bytes(2, "big") + b"\x00\x2f"
    body += bytes([1]) + b"\x00"
    body += (9999).to_bytes(2, "big")  # claims way more extension bytes than exist
    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    payload = bytes([0x16, 0x03, 0x03]) + len(handshake).to_bytes(2, "big") + handshake
    assert detect_tls_version(payload) == TLSVersion.TLS_1_2  # falls back to legacy field


# --- RSA key size extraction ---


@pytest.mark.parametrize("key_size", [1024, 2048, 3072])
def test_extracts_correct_rsa_key_size(key_size: int) -> None:
    der = build_rsa_certificate_der(key_size)
    payload = build_certificate_message([der])
    assert extract_rsa_key_size(payload) == key_size


def test_ec_certificate_returns_none_not_a_fabricated_size() -> None:
    """A non-RSA (EC) certificate must yield None — 'RSA key size'
    genuinely doesn't apply, and nothing should be invented."""
    der = build_ec_certificate_der()
    payload = build_certificate_message([der])
    assert extract_rsa_key_size(payload) is None


def test_missing_certificate_data_returns_none() -> None:
    """A ClientHello (no certificate at all) must not yield a key size."""
    payload = build_client_hello()
    assert extract_rsa_key_size(payload) is None


def test_malformed_certificate_der_returns_none_not_a_crash() -> None:
    garbage_der = b"\x00\x01\x02not-real-der-data\xff\xfe"
    payload = build_certificate_message([garbage_der])
    assert extract_rsa_key_size(payload) is None


def test_non_certificate_handshake_type_returns_none() -> None:
    """A ServerHello (handshake type 0x02, not 0x0b Certificate)."""
    payload = build_server_hello()
    assert extract_rsa_key_size(payload) is None


def test_empty_payload_returns_none_for_key_size() -> None:
    assert extract_rsa_key_size(b"") is None