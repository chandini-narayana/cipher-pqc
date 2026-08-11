"""TLS handshake parsing: version detection and RSA key-size extraction.

Operates on the raw bytes of a single captured packet's payload — the
same payload capture/ and entropy/ already see (capture.RawPacket.payload).
No Scapy dependency, no port-number reasoning anywhere: everything here
is derived strictly from TLS wire-format evidence actually present in
`payload`.

Deliberately per-packet: a real TLS handshake spans several packets
(ClientHello, ServerHello, Certificate, ...). This module makes no
attempt to correlate packets from the same connection — that's out of
scope for Step 7 (see docs/SDD.md Section 19). Each function looks
only at the one payload it's given and returns None whenever the
evidence it needs isn't in THAT payload, rather than guessing.
"""
from __future__ import annotations

from typing import Iterator, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import load_der_x509_certificate

from models.enums import TLSVersion

_HANDSHAKE_CONTENT_TYPE = 0x16
_CLIENT_HELLO = 0x01
_SERVER_HELLO = 0x02
_CERTIFICATE = 0x0B
_SUPPORTED_VERSIONS_EXTENSION = 0x002B

_VERSION_BYTES_TO_ENUM = {
    (0x03, 0x01): TLSVersion.TLS_1_0,
    (0x03, 0x02): TLSVersion.TLS_1_1,
    (0x03, 0x03): TLSVersion.TLS_1_2,
    (0x03, 0x04): TLSVersion.TLS_1_3,
}


def detect_tls_version(payload: bytes) -> Optional[TLSVersion]:
    """Detect the TLS version evidenced by a single captured payload.

    Only looks inside Handshake (ClientHello/ServerHello) messages —
    the only place TLS version is actually negotiated on the wire.

    For TLS 1.3, the record-layer/legacy version field is pinned to
    {0x03, 0x03} for backward compatibility with pre-1.3 middleboxes;
    the real version is only visible in the supported_versions
    extension. Trusting the legacy field alone would misreport every
    TLS 1.3 handshake as TLS 1.2, so this function parses that far
    before falling back to the legacy field.

    Returns None if `payload` isn't a recognizable TLS Handshake
    message, or if parsing runs out of bytes at any point — it never
    guesses from partial or malformed structure.
    """
    if len(payload) < 9 or payload[0] != _HANDSHAKE_CONTENT_TYPE:
        return None

    handshake_type = payload[5]
    body = payload[9:]  # handshake message body, past the 4-byte handshake header

    if handshake_type == _CLIENT_HELLO:
        return _version_from_client_hello(body)
    if handshake_type == _SERVER_HELLO:
        return _version_from_server_hello(body)
    return None


def extract_rsa_key_size(payload: bytes) -> Optional[int]:
    """Extract the RSA modulus size (in bits) from a captured
    Certificate handshake message, if one is present and its leaf
    certificate carries an RSA public key.

    Returns None whenever the evidence isn't there to answer
    honestly: not a Certificate message, no parseable certificate, or
    a certificate using a non-RSA public key (e.g., ECDSA). Never
    fabricates a key size and never infers one from a port number or
    the TLS version.

    Note: in TLS 1.3 the Certificate message is encrypted as part of
    the handshake and is not visible in a passive, undecrypted
    capture — this function can only see certificates exchanged in a
    TLS 1.2-or-earlier handshake (or supplied directly for testing).
    """
    if len(payload) < 9 or payload[0] != _HANDSHAKE_CONTENT_TYPE:
        return None
    if payload[5] != _CERTIFICATE:
        return None

    cert_der = _first_certificate_der(payload[9:])
    if cert_der is None:
        return None
    return _rsa_key_size_from_der(cert_der)


# --- internal parsing helpers ---


def _legacy_version(body: bytes) -> Optional[TLSVersion]:
    if len(body) < 2:
        return None
    return _VERSION_BYTES_TO_ENUM.get((body[0], body[1]))


def _version_from_client_hello(body: bytes) -> Optional[TLSVersion]:
    fallback = _legacy_version(body)

    offset = 2 + 32  # past client_version (2) and random (32)
    if len(body) < offset + 1:
        return fallback
    session_id_len = body[offset]
    offset += 1 + session_id_len

    if len(body) < offset + 2:
        return fallback
    cipher_suites_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2 + cipher_suites_len

    if len(body) < offset + 1:
        return fallback
    compression_len = body[offset]
    offset += 1 + compression_len

    if len(body) < offset + 2:
        return fallback
    extensions_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    extensions = body[offset : offset + extensions_len]

    return _highest_client_supported_version(extensions) or fallback


def _version_from_server_hello(body: bytes) -> Optional[TLSVersion]:
    fallback = _legacy_version(body)

    offset = 2 + 32  # past server_version (2) and random (32)
    if len(body) < offset + 1:
        return fallback
    session_id_len = body[offset]
    offset += 1 + session_id_len

    if len(body) < offset + 2:
        return fallback
    offset += 2  # past the single selected cipher_suite

    if len(body) < offset + 1:
        return fallback
    offset += 1  # past compression_method

    if len(body) < offset + 2:
        return fallback
    extensions_len = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    extensions = body[offset : offset + extensions_len]

    return _selected_server_supported_version(extensions) or fallback


def _iter_extensions(extensions: bytes) -> Iterator[Tuple[int, bytes]]:
    offset = 0
    while offset + 4 <= len(extensions):
        ext_type = int.from_bytes(extensions[offset : offset + 2], "big")
        ext_len = int.from_bytes(extensions[offset + 2 : offset + 4], "big")
        data_start = offset + 4
        data_end = data_start + ext_len
        if data_end > len(extensions):
            return  # truncated extension — stop rather than misread
        yield ext_type, extensions[data_start:data_end]
        offset = data_end


def _highest_client_supported_version(extensions: bytes) -> Optional[TLSVersion]:
    """ClientHello's supported_versions extension is a length-prefixed
    LIST of versions the client offers (its preference order) — the
    caller doesn't yet know which one will actually be negotiated, so
    the highest offered is the most informative honest answer."""
    for ext_type, data in _iter_extensions(extensions):
        if ext_type != _SUPPORTED_VERSIONS_EXTENSION or not data:
            continue
        list_len = data[0]
        versions_bytes = data[1 : 1 + list_len]
        best: Optional[TLSVersion] = None
        for i in range(0, len(versions_bytes) - 1, 2):
            candidate = _VERSION_BYTES_TO_ENUM.get((versions_bytes[i], versions_bytes[i + 1]))
            if candidate is not None and (best is None or candidate.value > best.value):
                best = candidate
        return best
    return None


def _selected_server_supported_version(extensions: bytes) -> Optional[TLSVersion]:
    """ServerHello's supported_versions extension is exactly 2 bytes:
    the single version actually selected — this is authoritative, not
    a list to choose from."""
    for ext_type, data in _iter_extensions(extensions):
        if ext_type != _SUPPORTED_VERSIONS_EXTENSION or len(data) != 2:
            continue
        return _VERSION_BYTES_TO_ENUM.get((data[0], data[1]))
    return None


def _first_certificate_der(body: bytes) -> Optional[bytes]:
    if len(body) < 3:
        return None
    cert_list_len = int.from_bytes(body[0:3], "big")
    cert_list = body[3 : 3 + cert_list_len]

    if len(cert_list) < 3:
        return None
    first_cert_len = int.from_bytes(cert_list[0:3], "big")
    cert_der = cert_list[3 : 3 + first_cert_len]

    if len(cert_der) != first_cert_len or not cert_der:
        return None
    return cert_der


def _rsa_key_size_from_der(cert_der: bytes) -> Optional[int]:
    try:
        certificate = load_der_x509_certificate(cert_der)
    except ValueError:
        # Not valid DER / not a well-formed X.509 certificate.
        return None

    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        return None
    return public_key.key_size