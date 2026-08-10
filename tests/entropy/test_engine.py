"""Unit tests for entropy.engine — shannon_entropy() and compute_entropy_metrics().

Every test verifies an actual mathematical result (with hand-derived
expected values documented inline), not just "a float came back."
Payloads are all deterministic byte literals or seeded pseudo-random
sequences — nothing depends on real network traffic.
"""
import math
import random

import pytest

from entropy.engine import compute_entropy_metrics, shannon_entropy
from models.entropy_metrics import EntropyMetrics


# --- 1. Empty bytes ---


def test_empty_payload_returns_zero() -> None:
    assert shannon_entropy(b"") == 0.0


# --- 2. Single repeated byte ---


def test_single_repeated_byte_returns_exactly_zero() -> None:
    """A payload of one distinct byte value has zero information
    content: p(x) = 1.0, log2(1.0) = 0, so H = 0.0 exactly."""
    assert shannon_entropy(b"A" * 500) == 0.0
    assert shannon_entropy(b"\x00" * 10) == 0.0


# --- 3. Highly repetitive payload (mostly one value, low but nonzero) ---


def test_highly_repetitive_payload_has_low_nonzero_entropy() -> None:
    """999 A's + 1 B. p(A) = 0.999, p(B) = 0.001.
    H = -(0.999*log2(0.999) + 0.001*log2(0.001)) ~= 0.0114 bits/byte —
    low, but not exactly zero, since there IS a small amount of variation."""
    payload = b"A" * 999 + b"B"
    entropy = shannon_entropy(payload)
    assert 0.0 < entropy < 0.1


# --- 4 & 5. Multiple byte values / known entropy calculations ---


def test_known_entropy_two_symbols_equal_frequency() -> None:
    """b"AABB": p(A)=p(B)=0.5. H = -(0.5*log2(0.5)*2) = 1.0 exactly."""
    assert shannon_entropy(b"AABB") == pytest.approx(1.0)


def test_known_entropy_two_symbols_unequal_frequency() -> None:
    """b"AAAB": p(A)=0.75, p(B)=0.25.
    H = -(0.75*log2(0.75) + 0.25*log2(0.25)) = 0.8112781244591328."""
    expected = -(0.75 * math.log2(0.75) + 0.25 * math.log2(0.25))
    assert shannon_entropy(b"AAAB") == pytest.approx(expected)
    assert shannon_entropy(b"AAAB") == pytest.approx(0.8112781244591328)


def test_known_entropy_four_equally_likely_symbols() -> None:
    """4 distinct byte values, each appearing 25 times (100 total).
    p(x)=0.25 for each. H = -4*(0.25*log2(0.25)) = 2.0 exactly."""
    payload = bytes([0, 1, 2, 3]) * 25
    assert shannon_entropy(payload) == pytest.approx(2.0)


def test_known_entropy_maximum_all_256_values_equally_likely() -> None:
    """Every possible byte value exactly once: p(x)=1/256 for all 256
    values. H = -256*(1/256 * log2(1/256)) = 8.0 exactly — the
    theoretical maximum for a byte stream."""
    payload = bytes(range(256))
    assert shannon_entropy(payload) == pytest.approx(8.0)


# --- 6. Boundary/range behavior ---

# Computed once here, with a single reused Random instance, rather than
# inline inside the parametrize list — see the note in
# test_random_like_payload_has_high_entropy about why
# `random.Random(seed).randint(...) for _ in range(n)` silently
# re-seeds on every iteration if the Random(...) call is placed inside
# the generator expression itself.
_seeded_payload_for_bounds_test = bytes(random.Random(1).randbytes(500))


@pytest.mark.parametrize(
    "payload",
    [
        b"A",
        b"AABB",
        b"AAAB",
        bytes(range(256)),
        b"\x00" * 50 + b"\xff" * 50,
        _seeded_payload_for_bounds_test,
    ],
)
def test_entropy_always_within_theoretical_bounds(payload: bytes) -> None:
    entropy = shannon_entropy(payload)
    assert 0.0 <= entropy <= 8.0


# --- 7. Deterministic input ---


def test_same_input_always_produces_same_output() -> None:
    payload = b"the quick brown fox jumps over the lazy dog" * 3
    first = shannon_entropy(payload)
    second = shannon_entropy(payload)
    assert first == second


# --- 8. Binary payloads ---


def test_binary_payload_with_null_and_high_bytes() -> None:
    """b"\\x00\\x00\\xff\\xff": same shape as the AABB case (two
    symbols, 50/50 split) but using non-printable binary byte values
    rather than ASCII letters. H = 1.0 exactly."""
    payload = b"\x00\x00\xff\xff"
    assert shannon_entropy(payload) == pytest.approx(1.0)


def test_binary_payload_full_byte_range_is_also_the_max_entropy_case() -> None:
    """bytes(range(256)) doubles as both the "binary payload" case
    (includes every non-printable byte value 0-255) and the maximum-
    entropy case tested above."""
    payload = bytes(range(256))
    assert shannon_entropy(payload) == pytest.approx(8.0)


# --- 9. Random-like payload (seeded, deterministic, but statistically random) ---


def test_random_like_payload_has_high_entropy() -> None:
    """A seeded pseudo-random byte sequence (deterministic across runs
    via the fixed seed, so this is not a flaky test) large enough that
    its distribution across 256 byte values is very close to uniform —
    entropy should be close to the theoretical maximum of 8.0.

    Note: the single random.Random instance is created ONCE, outside
    the generator expression, and reused across all 100,000 draws. A
    version that instead did
    ``random.Random(42).randint(0, 255) for _ in range(100_000)``
    would silently re-seed a fresh generator on every iteration,
    producing 100,000 copies of the same first draw — an easy mistake
    with an identical symptom to a broken entropy calculation
    (entropy 0.0), so it's worth the explicit note here.
    """
    rng = random.Random(42)
    payload = bytes(rng.randint(0, 255) for _ in range(100_000))
    entropy = shannon_entropy(payload)
    assert entropy > 7.9


# --- 10. Invalid input handling ---


@pytest.mark.parametrize("bad_input", ["a string", 12345, None, [65, 66, 67]])
def test_rejects_non_bytes_input(bad_input) -> None:
    with pytest.raises(TypeError, match="bytes or bytearray"):
        shannon_entropy(bad_input)


def test_accepts_bytearray_as_well_as_bytes() -> None:
    assert shannon_entropy(bytearray(b"AABB")) == pytest.approx(1.0)


# --- compute_entropy_metrics: the bridge to models.EntropyMetrics ---


def test_compute_entropy_metrics_wraps_value_and_length_correctly() -> None:
    metrics = compute_entropy_metrics(b"AABB")
    assert isinstance(metrics, EntropyMetrics)
    assert metrics.shannon_entropy == pytest.approx(1.0)
    assert metrics.sample_size == 4


def test_compute_entropy_metrics_rejects_empty_payload() -> None:
    """Propagated from EntropyMetrics' own Step 4 validation — no
    duplicate validation was added here (see module docstring)."""
    with pytest.raises(ValueError, match="sample_size"):
        compute_entropy_metrics(b"")


def test_compute_entropy_metrics_matches_shannon_entropy_directly() -> None:
    payload = bytes(range(256))
    metrics = compute_entropy_metrics(payload)
    assert metrics.shannon_entropy == shannon_entropy(payload)
    assert metrics.sample_size == 256


# --- Integration: the intended capture.RawPacket -> entropy -> EntropyMetrics flow ---


def test_integration_with_a_real_raw_packet_payload() -> None:
    from datetime import datetime

    from capture.raw_packet import RawPacket

    packet = RawPacket(
        src_ip="192.168.1.10",
        dst_ip="192.168.1.1",
        src_port=51000,
        dst_port=443,
        payload=b"AABB",
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
    )
    metrics = compute_entropy_metrics(packet.payload)
    assert metrics.shannon_entropy == pytest.approx(1.0)
    assert metrics.sample_size == len(packet.payload) == 4