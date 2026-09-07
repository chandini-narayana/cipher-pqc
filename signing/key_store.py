"""load_or_create_keypair — minimal Phase-1 ML-DSA-44 key persistence.

Frozen filenames and lifecycle (see docs/SDD.md's Phase 9 addendum):
both key files present -> load them; neither present -> generate one
keypair and persist both; exactly one present -> fail clearly rather
than regenerating or overwriting the surviving key. Existing key files
are never overwritten.

Deliberately minimal: raw key bytes are written to plain files with no
passphrase encryption, no OS keyring integration, and no permissions
hardening. Production-grade secret-key protection is explicitly future
hardening, not attempted in Phase 1.
"""
from __future__ import annotations

from pathlib import Path
from typing import Union

from signing.dilithium_signer import generate_keypair

PUBLIC_KEY_FILENAME = "ml_dsa_44_public.key"
SECRET_KEY_FILENAME = "ml_dsa_44_secret.key"


def load_or_create_keypair(key_dir: Union[str, Path]) -> tuple[bytes, bytes]:
    """Load an existing ML-DSA-44 keypair from `key_dir`, or generate
    and persist a new one if neither key file exists yet.

    Returns:
        (public_key, secret_key), matching ML_DSA_44.keygen()'s own
        return order.

    Raises:
        RuntimeError: if exactly one of the two key files exists — an
            incomplete keypair state that must be resolved manually,
            never silently regenerated or overwritten.
    """
    key_dir = Path(key_dir)
    public_path = key_dir / PUBLIC_KEY_FILENAME
    secret_path = key_dir / SECRET_KEY_FILENAME

    public_exists = public_path.exists()
    secret_exists = secret_path.exists()

    if public_exists and secret_exists:
        return public_path.read_bytes(), secret_path.read_bytes()

    if public_exists != secret_exists:
        existing_name = PUBLIC_KEY_FILENAME if public_exists else SECRET_KEY_FILENAME
        missing_name = SECRET_KEY_FILENAME if public_exists else PUBLIC_KEY_FILENAME
        raise RuntimeError(
            f"Incomplete ML-DSA-44 keypair in {key_dir}: found {existing_name} "
            f"but not {missing_name}. Refusing to regenerate or overwrite the "
            f"surviving key — resolve this manually before continuing."
        )

    key_dir.mkdir(parents=True, exist_ok=True)
    public_key, secret_key = generate_keypair()
    public_path.write_bytes(public_key)
    secret_path.write_bytes(secret_key)
    return public_key, secret_key
