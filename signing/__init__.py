"""signing — ML-DSA-44 (FIPS 204) sign/verify for tamper-evidence.

ML-DSA is NIST's finalized post-quantum digital-signature standard
(FIPS 204), standardizing the CRYSTALS-Dilithium algorithm family;
ML-DSA-44 is the NIST security level 2 parameter set — the finalized
descendant of the original pre-standardization "Dilithium2" parameter
set. See docs/SDD.md's Phase 9 addendum for the full rationale, the
frozen canonicalization rule, and the key-lifecycle contract.
"""

from signing.dilithium_signer import (
    ALGORITHM_NAME,
    canonicalize_assessment,
    generate_keypair,
    sign,
    sign_assessment,
    verify,
    verify_signed_event,
)
from signing.key_store import load_or_create_keypair

__all__ = [
    "ALGORITHM_NAME",
    "generate_keypair",
    "sign",
    "verify",
    "canonicalize_assessment",
    "sign_assessment",
    "verify_signed_event",
    "load_or_create_keypair",
]
