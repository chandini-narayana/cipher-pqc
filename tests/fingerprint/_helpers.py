"""Test-only helpers for crafting deterministic TLS/MQTT/Telnet byte
payloads, and generating real (ephemeral, throwaway) certificates for
RSA key-size extraction tests.

Not part of any public package — imported directly by test files in
this directory. Nothing here depends on real network traffic; every
payload is hand-assembled from the relevant wire format.
"""
from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

_HANDSHAKE = 0x16
_CLIENT_HELLO = 0x01
_SERVER_HELLO = 0x02
_CERTIFICATE = 0x0B
_SUPPORTED_VERSIONS = 0x002B


def build_client_hello(legacy_version=(0x03, 0x03), supported_versions=None) -> bytes:
    """supported_versions: optional bytes of 2-byte version values to
    list in the ClientHello's supported_versions extension (client's
    offered list, in whatever order given)."""
    body = bytes(legacy_version) + b"\x00" * 32  # client_version + random
    body += bytes([0])  # session_id_len = 0
    body += (2).to_bytes(2, "big") + b"\x00\x2f"  # 1 cipher suite offered
    body += bytes([1]) + b"\x00"  # 1 compression method

    extensions = b""
    if supported_versions is not None:
        ext_data = bytes([len(supported_versions)]) + supported_versions
        extensions += _SUPPORTED_VERSIONS.to_bytes(2, "big") + len(ext_data).to_bytes(2, "big") + ext_data
    body += len(extensions).to_bytes(2, "big") + extensions

    handshake = bytes([_CLIENT_HELLO]) + len(body).to_bytes(3, "big") + body
    return bytes([_HANDSHAKE, 0x03, 0x03]) + len(handshake).to_bytes(2, "big") + handshake


def build_server_hello(legacy_version=(0x03, 0x03), selected_version=None) -> bytes:
    """selected_version: optional 2-byte tuple, the single version the
    server actually selected (ServerHello's supported_versions
    extension form, distinct from ClientHello's list form)."""
    body = bytes(legacy_version) + b"\x00" * 32
    body += bytes([0])  # session_id_len = 0
    body += b"\x00\x2f"  # the single selected cipher suite
    body += bytes([0])  # compression method

    extensions = b""
    if selected_version is not None:
        ext_data = bytes(selected_version)
        extensions += _SUPPORTED_VERSIONS.to_bytes(2, "big") + len(ext_data).to_bytes(2, "big") + ext_data
    body += len(extensions).to_bytes(2, "big") + extensions

    handshake = bytes([_SERVER_HELLO]) + len(body).to_bytes(3, "big") + body
    return bytes([_HANDSHAKE, 0x03, 0x03]) + len(handshake).to_bytes(2, "big") + handshake


def _self_signed_der(public_key, sign_key) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cipher-test.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(sign_key, hashes.SHA256())
    )
    return cert.public_bytes(encoding=serialization.Encoding.DER)


def build_rsa_certificate_der(key_size: int) -> bytes:
    """A real, throwaway, self-signed RSA certificate of `key_size`
    bits, DER-encoded — for RSA key-size extraction tests."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return _self_signed_der(key.public_key(), key)


def build_ec_certificate_der() -> bytes:
    """A real, throwaway, self-signed EC (non-RSA) certificate,
    DER-encoded — for confirming non-RSA certs correctly yield None."""
    key = ec.generate_private_key(ec.SECP256R1())
    return _self_signed_der(key.public_key(), key)


def build_certificate_message(cert_der_list) -> bytes:
    """Wrap one or more DER certificates in a TLS Certificate handshake
    message (record header + handshake header + certificate_list)."""
    cert_list = b""
    for der in cert_der_list:
        cert_list += len(der).to_bytes(3, "big") + der
    body = len(cert_list).to_bytes(3, "big") + cert_list
    handshake = bytes([_CERTIFICATE]) + len(body).to_bytes(3, "big") + body
    return bytes([_HANDSHAKE, 0x03, 0x03]) + len(handshake).to_bytes(2, "big") + handshake


def build_mqtt_connect(protocol_name: bytes = b"MQTT", version_byte: int = 0x04) -> bytes:
    """A well-formed MQTT CONNECT packet with `protocol_name` as its
    declared protocol name (e.g., b"MQTT" for 3.1.1/5.0, b"MQIsdp" for 3.1)."""
    var_header = (
        len(protocol_name).to_bytes(2, "big")
        + protocol_name
        + bytes([version_byte, 0x02])  # protocol level, connect flags
        + (60).to_bytes(2, "big")  # keep-alive
    )
    client_id = b"cli1"
    payload = len(client_id).to_bytes(2, "big") + client_id
    remaining = var_header + payload
    assert len(remaining) < 128, "test helper only supports single-byte remaining-length encoding"
    return bytes([0x10, len(remaining)]) + remaining