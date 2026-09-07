"""ML-DSA-44 (FIPS 204) signing and verification for CIPHER's
tamper-evident DeviceAssessment records.

ML-DSA is NIST's finalized post-quantum digital-signature standard
(FIPS 204), standardizing the CRYSTALS-Dilithium algorithm family.
ML-DSA-44 is the NIST security level 2 parameter set — the finalized
descendant of the original pre-standardization "Dilithium2" parameter
set (identical core parameters: k=4, l=4, eta=2, tau=39). This module
deliberately uses the finalized standard's implementation
(`dilithium_py.ml_dsa.ML_DSA_44`), not the library's legacy
pre-standardization `dilithium_py.dilithium.Dilithium2` object — see
docs/SDD.md's Phase 9 addendum for the full rationale.

Plain functions only, consistent with this repository's other
stateless modules (entropy/, fingerprint/, risk/) — there is no fitted
state to hold between calls; every call is independent given explicit
key bytes.

Signing target (frozen — see docs/SDD.md Phase 9 addendum): the
canonical JSON bytes of `DeviceAssessment.to_dict()`, not the Python
object itself, its repr(), or any pickle/joblib serialization, and not
a pre-hash of it. Report-level signing (hashing rendered PDF bytes for
`models.ReportMetadata`) is explicitly out of scope here — it belongs
to a later, unimplemented report-generation step, which will reuse the
generic `sign()`/`verify()` primitives below on a report hash.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from dilithium_py.ml_dsa import ML_DSA_44

from models.device_assessment import DeviceAssessment
from models.signed_event import SignedEvent

ALGORITHM_NAME = "ML-DSA-44 (FIPS 204; derived from CRYSTALS-Dilithium)"


def _require_bytes(name: str, value: object) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError(f"{name} must be bytes or bytearray, got {type(value).__name__}")
    return bytes(value)


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh, independent ML-DSA-44 keypair.

    Returns:
        (public_key, secret_key), matching ML_DSA_44.keygen()'s own
        return order.
    """
    return ML_DSA_44.keygen()


def sign(payload: bytes, secret_key: bytes) -> bytes:
    """Sign `payload` with `secret_key`, returning the raw signature bytes.

    Raises:
        TypeError: if `payload` or `secret_key` is not bytes/bytearray.
    """
    payload = _require_bytes("payload", payload)
    secret_key = _require_bytes("secret_key", secret_key)
    return ML_DSA_44.sign(secret_key, payload)


def verify(payload: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify `signature` over `payload` under `public_key`.

    A cryptographically invalid signature — tampered payload, tampered
    signature, or the wrong public key — returns False; it never
    raises for that reason. Only malformed argument *types* raise.

    Raises:
        TypeError: if `payload`, `signature`, or `public_key` is not
            bytes/bytearray.
    """
    payload = _require_bytes("payload", payload)
    signature = _require_bytes("signature", signature)
    public_key = _require_bytes("public_key", public_key)
    return bool(ML_DSA_44.verify(public_key, payload, signature))


def canonicalize_assessment(assessment: DeviceAssessment) -> bytes:
    """Produce the canonical, deterministic byte representation of
    `assessment` that is signed and later re-derived for verification.

    Frozen rule: sorted-key, compact-separator JSON over
    `assessment.to_dict()`, UTF-8 encoded — deterministic regardless of
    dict insertion order, with no incidental whitespace variance.

    Raises:
        TypeError: if `assessment` is not a DeviceAssessment.
    """
    if not isinstance(assessment, DeviceAssessment):
        raise TypeError(
            f"assessment must be a DeviceAssessment, got {type(assessment).__name__}"
        )
    return json.dumps(
        assessment.to_dict(), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sign_assessment(
    assessment: DeviceAssessment,
    secret_key: bytes,
    signed_at: Optional[datetime] = None,
) -> SignedEvent:
    """Canonicalize `assessment`, sign it, and wrap the result in a
    SignedEvent. Neither `assessment` nor `secret_key` is mutated.

    `signed_at` is preserved if explicitly supplied, otherwise set to
    the current UTC time.
    """
    payload = canonicalize_assessment(assessment)
    signature = sign(payload, secret_key)
    return SignedEvent(
        assessment=assessment,
        signature_hex=signature.hex(),
        algorithm=ALGORITHM_NAME,
        signed_at=signed_at if signed_at is not None else datetime.now(timezone.utc),
    )


def verify_signed_event(event: SignedEvent, public_key: bytes) -> bool:
    """Verify that `event.signature_hex` is a valid ML-DSA-44 signature,
    under `public_key`, over `event.assessment`'s canonical bytes.

    Returns False (rather than raising) for any genuine verification
    failure: an algorithm label that doesn't match ALGORITHM_NAME, a
    tampered assessment, a tampered signature, or the wrong public key.

    Raises:
        TypeError: if `event` is not a SignedEvent, or `public_key` is
            not bytes/bytearray (propagated from verify()).
    """
    if not isinstance(event, SignedEvent):
        raise TypeError(f"event must be a SignedEvent, got {type(event).__name__}")
    if event.algorithm != ALGORITHM_NAME:
        return False

    payload = canonicalize_assessment(event.assessment)
    signature = bytes.fromhex(event.signature_hex)
    return verify(payload, signature, public_key)
