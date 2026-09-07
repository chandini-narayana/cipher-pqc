"""Unit tests for signing.dilithium_signer — ML-DSA-44 (FIPS 204)
sign/verify, canonicalization, and SignedEvent production/verification
(docs/SDD.md Phase 9 addendum)."""
from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone

import pytest

from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.risk_assessment import RiskAssessment
from models.signed_event import SignedEvent
from signing.dilithium_signer import (
    ALGORITHM_NAME,
    canonicalize_assessment,
    generate_keypair,
    sign,
    sign_assessment,
    verify,
    verify_signed_event,
)

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _assessment() -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact("192.168.1.10", TS),
        risk_assessment=RiskAssessment(9, RiskCategory.HIGH, "Upgrade TLS", "SP 800-52r2"),
        anomaly_assessment=AnomalyAssessment(anomaly_score=-0.4, is_anomaly=True, confidence=0.9),
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    )


# --- 1-3. keypair generation ---


def test_generate_keypair_returns_bytes() -> None:
    public_key, secret_key = generate_keypair()
    assert isinstance(public_key, bytes)
    assert isinstance(secret_key, bytes)
    assert len(public_key) > 0
    assert len(secret_key) > 0


def test_generated_keys_are_usable_for_sign_and_verify() -> None:
    public_key, secret_key = generate_keypair()
    signature = sign(b"payload", secret_key)
    assert verify(b"payload", signature, public_key) is True


def test_independent_keygen_calls_produce_different_keypairs() -> None:
    public_key_a, secret_key_a = generate_keypair()
    public_key_b, secret_key_b = generate_keypair()
    assert public_key_a != public_key_b
    assert secret_key_a != secret_key_b


# --- 4-7. sign/verify primitive ---


def test_sign_then_verify_succeeds() -> None:
    public_key, secret_key = generate_keypair()
    signature = sign(b"hello cipher", secret_key)
    assert verify(b"hello cipher", signature, public_key) is True


def test_modified_payload_fails_verification() -> None:
    public_key, secret_key = generate_keypair()
    signature = sign(b"hello cipher", secret_key)
    assert verify(b"hello CIPHER", signature, public_key) is False


def test_modified_signature_fails_verification() -> None:
    public_key, secret_key = generate_keypair()
    signature = bytearray(sign(b"hello cipher", secret_key))
    signature[0] ^= 0xFF
    assert verify(b"hello cipher", bytes(signature), public_key) is False


def test_wrong_public_key_fails_verification() -> None:
    public_key_a, secret_key_a = generate_keypair()
    public_key_b, _ = generate_keypair()
    signature = sign(b"hello cipher", secret_key_a)
    assert verify(b"hello cipher", signature, public_key_b) is False


# --- 8-11. canonicalization ---


def test_canonicalization_is_deterministic() -> None:
    assessment = _assessment()
    assert canonicalize_assessment(assessment) == canonicalize_assessment(assessment)


def test_canonical_output_is_sorted_compact_json() -> None:
    payload = canonicalize_assessment(_assessment())
    decoded = json.loads(payload.decode("utf-8"))

    reencoded = json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert payload == reencoded
    # Compact separators: no space after "," or ":" (string content, e.g.
    # "Upgrade TLS", may still legitimately contain spaces).
    assert b", " not in payload
    assert b": " not in payload


def test_semantically_identical_assessments_produce_identical_bytes() -> None:
    """Two separately-constructed but semantically-equal DeviceAssessment
    objects must canonicalize to identical bytes — the encoding depends
    on the data, not on object identity."""
    assert canonicalize_assessment(_assessment()) == canonicalize_assessment(_assessment())


def test_canonicalization_does_not_rely_on_repr_or_pickle() -> None:
    payload = canonicalize_assessment(_assessment())
    # A repr()/pickle-based encoding would not be valid JSON at all.
    json.loads(payload.decode("utf-8"))
    assert b"DeviceAssessment" not in payload


# --- 12-16. sign_assessment ---


def test_sign_assessment_returns_signed_event() -> None:
    _, secret_key = generate_keypair()
    event = sign_assessment(_assessment(), secret_key, signed_at=TS)
    assert isinstance(event, SignedEvent)


def test_sign_assessment_algorithm_matches_constant() -> None:
    _, secret_key = generate_keypair()
    event = sign_assessment(_assessment(), secret_key, signed_at=TS)
    assert event.algorithm == ALGORITHM_NAME


def test_sign_assessment_signature_hex_is_valid_hex() -> None:
    _, secret_key = generate_keypair()
    event = sign_assessment(_assessment(), secret_key, signed_at=TS)
    bytes.fromhex(event.signature_hex)  # raises ValueError if not valid hex


def test_sign_assessment_preserves_explicit_signed_at() -> None:
    _, secret_key = generate_keypair()
    explicit_ts = datetime(2027, 6, 15, 8, 30, 0, tzinfo=timezone.utc)
    event = sign_assessment(_assessment(), secret_key, signed_at=explicit_ts)
    assert event.signed_at == explicit_ts


def test_sign_assessment_default_signed_at_is_timezone_aware_utc() -> None:
    _, secret_key = generate_keypair()
    before = datetime.now(timezone.utc)
    event = sign_assessment(_assessment(), secret_key)
    after = datetime.now(timezone.utc)

    assert event.signed_at.tzinfo is not None
    assert event.signed_at.utcoffset() == timezone.utc.utcoffset(None)
    assert before <= event.signed_at <= after


# --- 17-22. verify_signed_event ---


def test_verify_signed_event_succeeds_for_a_genuine_event() -> None:
    public_key, secret_key = generate_keypair()
    event = sign_assessment(_assessment(), secret_key, signed_at=TS)
    assert verify_signed_event(event, public_key) is True


def test_assessment_tampering_breaks_verification() -> None:
    public_key, secret_key = generate_keypair()
    event = sign_assessment(_assessment(), secret_key, signed_at=TS)

    tampered_assessment = dataclasses.replace(event.assessment, final_category=RiskCategory.LOW)
    tampered_event = dataclasses.replace(event, assessment=tampered_assessment)

    assert verify_signed_event(tampered_event, public_key) is False


def test_signature_tampering_breaks_verification() -> None:
    public_key, secret_key = generate_keypair()
    event = sign_assessment(_assessment(), secret_key, signed_at=TS)

    corrupted_signature = bytearray.fromhex(event.signature_hex)
    corrupted_signature[0] ^= 0xFF  # flip every bit of the first byte
    tampered_event = dataclasses.replace(event, signature_hex=bytes(corrupted_signature).hex())

    assert verify_signed_event(tampered_event, public_key) is False


def test_wrong_public_key_breaks_signed_event_verification() -> None:
    public_key_a, secret_key_a = generate_keypair()
    public_key_b, _ = generate_keypair()
    event = sign_assessment(_assessment(), secret_key_a, signed_at=TS)

    assert verify_signed_event(event, public_key_b) is False


def test_algorithm_label_mismatch_fails_verification() -> None:
    public_key, secret_key = generate_keypair()
    event = sign_assessment(_assessment(), secret_key, signed_at=TS)

    relabeled_event = dataclasses.replace(event, algorithm="some-other-algorithm")

    assert verify_signed_event(relabeled_event, public_key) is False


def test_signed_event_round_trip_remains_verifiable() -> None:
    public_key, secret_key = generate_keypair()
    event = sign_assessment(_assessment(), secret_key, signed_at=TS)

    round_tripped = SignedEvent.from_dict(event.to_dict())

    assert round_tripped == event
    assert verify_signed_event(round_tripped, public_key) is True


# --- error handling for malformed programming inputs ---


def test_sign_rejects_non_bytes_payload() -> None:
    _, secret_key = generate_keypair()
    with pytest.raises(TypeError):
        sign("not bytes", secret_key)


def test_verify_rejects_non_bytes_public_key() -> None:
    public_key, secret_key = generate_keypair()
    signature = sign(b"payload", secret_key)
    with pytest.raises(TypeError):
        verify(b"payload", signature, "not bytes")


def test_canonicalize_assessment_rejects_non_device_assessment() -> None:
    with pytest.raises(TypeError):
        canonicalize_assessment("not a DeviceAssessment")


def test_verify_signed_event_rejects_non_signed_event() -> None:
    public_key, _ = generate_keypair()
    with pytest.raises(TypeError):
        verify_signed_event("not a SignedEvent", public_key)


# --- 30-32. dependency boundaries ---


def test_signer_module_has_no_forbidden_dependencies() -> None:
    import ast
    import inspect

    import signing.dilithium_signer as signer_module

    tree = ast.parse(inspect.getsource(signer_module))
    imported_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module.split(".")[0])

    forbidden = {"reports", "dashboard", "pipeline", "flask", "frontend", "risk", "ml"}
    assert not (imported_modules & forbidden)


def test_no_pdf_or_report_implementation_was_introduced() -> None:
    """Sentinel check: Phase 9 must not have touched reports/ — PDF/
    report generation and report signing remain a later phase."""
    import inspect

    import reports.pdf_generator as pdf_generator_module

    source = inspect.getsource(pdf_generator_module)
    assert "TODO: implement ReportGenerator" in source
