"""Unit tests for models.protocol_fingerprint.ProtocolFingerprint."""
import pytest

from models.enums import ProtocolType, TLSVersion
from models.protocol_fingerprint import ProtocolFingerprint


def test_valid_fingerprint_with_tls() -> None:
    fp = ProtocolFingerprint(
        protocol=ProtocolType.HTTPS,
        tls_version=TLSVersion.TLS_1_3,
        key_size=3072,
        forward_secrecy=True,
        cipher_suite="TLS_AES_256_GCM_SHA384",
    )
    assert fp.tls_version is TLSVersion.TLS_1_3


def test_valid_fingerprint_without_tls_for_plaintext_protocol() -> None:
    fp = ProtocolFingerprint(
        protocol=ProtocolType.HTTP,
        tls_version=None,
        key_size=None,
        forward_secrecy=False,
    )
    assert fp.tls_version is None
    assert fp.cipher_suite is None  # default


def test_rejects_non_positive_key_size() -> None:
    with pytest.raises(ValueError, match="key_size"):
        ProtocolFingerprint(
            protocol=ProtocolType.HTTPS,
            tls_version=TLSVersion.TLS_1_0,
            key_size=0,
            forward_secrecy=False,
        )


def test_rejects_empty_cipher_suite() -> None:
    with pytest.raises(ValueError, match="cipher_suite"):
        ProtocolFingerprint(
            protocol=ProtocolType.HTTPS,
            tls_version=TLSVersion.TLS_1_2,
            key_size=2048,
            forward_secrecy=True,
            cipher_suite="",
        )


def test_round_trip_serialization_with_tls() -> None:
    fp1 = ProtocolFingerprint(
        protocol=ProtocolType.MQTT,
        tls_version=TLSVersion.TLS_1_1,
        key_size=1024,
        forward_secrecy=False,
        cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
    )
    fp2 = ProtocolFingerprint.from_dict(fp1.to_dict())
    assert fp1 == fp2


def test_round_trip_serialization_without_tls() -> None:
    fp1 = ProtocolFingerprint(
        protocol=ProtocolType.TELNET,
        tls_version=None,
        key_size=None,
        forward_secrecy=False,
    )
    fp2 = ProtocolFingerprint.from_dict(fp1.to_dict())
    assert fp1 == fp2