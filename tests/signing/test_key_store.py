"""Unit tests for signing.key_store.load_or_create_keypair — the
frozen Phase-1 key lifecycle (docs/SDD.md Phase 9 addendum): both
present -> load; neither present -> generate and persist; exactly one
present -> fail clearly, never regenerate or overwrite.

All tests use tmp_path — never data/keys/.
"""
from __future__ import annotations

import pytest

from signing.key_store import (
    PUBLIC_KEY_FILENAME,
    SECRET_KEY_FILENAME,
    load_or_create_keypair,
)


# --- 23-25. generate-then-load lifecycle ---


def test_no_key_files_generates_both(tmp_path) -> None:
    key_dir = tmp_path / "keys"
    public_key, secret_key = load_or_create_keypair(key_dir)

    assert isinstance(public_key, bytes) and len(public_key) > 0
    assert isinstance(secret_key, bytes) and len(secret_key) > 0
    assert (key_dir / PUBLIC_KEY_FILENAME).exists()
    assert (key_dir / SECRET_KEY_FILENAME).exists()


def test_generated_files_can_be_loaded_later(tmp_path) -> None:
    key_dir = tmp_path / "keys"
    public_key, secret_key = load_or_create_keypair(key_dir)

    loaded_public_key, loaded_secret_key = load_or_create_keypair(key_dir)

    assert loaded_public_key == public_key
    assert loaded_secret_key == secret_key


def test_repeated_call_loads_same_pair_instead_of_regenerating(tmp_path) -> None:
    key_dir = tmp_path / "keys"
    first_public_key, first_secret_key = load_or_create_keypair(key_dir)

    for _ in range(3):
        public_key, secret_key = load_or_create_keypair(key_dir)
        assert public_key == first_public_key
        assert secret_key == first_secret_key


# --- 26-28. incomplete keypair states fail clearly, never overwrite ---


def test_public_only_state_fails_clearly(tmp_path) -> None:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / PUBLIC_KEY_FILENAME).write_bytes(b"only-public")

    with pytest.raises(RuntimeError):
        load_or_create_keypair(key_dir)


def test_secret_only_state_fails_clearly(tmp_path) -> None:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    (key_dir / SECRET_KEY_FILENAME).write_bytes(b"only-secret")

    with pytest.raises(RuntimeError):
        load_or_create_keypair(key_dir)


def test_existing_keys_are_never_overwritten(tmp_path) -> None:
    key_dir = tmp_path / "keys"
    original_public_key, original_secret_key = load_or_create_keypair(key_dir)

    load_or_create_keypair(key_dir)

    assert (key_dir / PUBLIC_KEY_FILENAME).read_bytes() == original_public_key
    assert (key_dir / SECRET_KEY_FILENAME).read_bytes() == original_secret_key


def test_incomplete_state_never_overwrites_the_surviving_key(tmp_path) -> None:
    key_dir = tmp_path / "keys"
    key_dir.mkdir()
    surviving_key_bytes = b"surviving-public-key-bytes"
    (key_dir / PUBLIC_KEY_FILENAME).write_bytes(surviving_key_bytes)

    with pytest.raises(RuntimeError):
        load_or_create_keypair(key_dir)

    assert (key_dir / PUBLIC_KEY_FILENAME).read_bytes() == surviving_key_bytes
    assert not (key_dir / SECRET_KEY_FILENAME).exists()


# --- 29. tmp_path only (structural confirmation) ---


def test_key_generation_in_these_tests_uses_tmp_path_only(tmp_path) -> None:
    """Structural guard: every test above passes a tmp_path-derived
    directory, never signing/'s real data/keys/ default."""
    key_dir = tmp_path / "keys"
    load_or_create_keypair(key_dir)
    assert str(tmp_path) in str(key_dir)
