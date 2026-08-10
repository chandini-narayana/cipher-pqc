"""Shannon entropy calculation for packet payloads.

Operates purely on bytes: no Scapy dependency, no awareness of
capture.RawPacket or models.PacketMetadata. shannon_entropy() is the
pure calculation; compute_entropy_metrics() is the bridge from a raw
payload to the Step 4 models.EntropyMetrics domain object — these are
kept separate deliberately (see compute_entropy_metrics' docstring).

Implemented as plain functions rather than a class: the calculation is
pure and stateless (no configuration, nothing to hold between calls),
so a class wrapper would be an abstraction with nothing to abstract.
This is a deliberate, small deviation from the SDD's original class
diagram sketch (EntropyEngine.shannon()) — see docs/SDD.md Section 18
for the corresponding documentation update.
"""
from __future__ import annotations

import math
from collections import Counter

from models.entropy_metrics import EntropyMetrics


def shannon_entropy(data: bytes) -> float:
    """Compute the Shannon entropy of `data`, in bits per byte.

    H = -sum(p(x) * log2(p(x))) over each distinct byte value x
    present in `data`, where p(x) is that value's frequency within
    `data`.

    Returns 0.0 for empty input — there is no information content in
    zero bytes, and this is also the sensible limit of the formula as
    the sample shrinks to nothing. This is a property of the
    calculation itself, independent of models.EntropyMetrics (which
    correctly refuses to represent a zero-length sample as a metric —
    see compute_entropy_metrics below).

    The result is always within [0.0, 8.0]: 0.0 for a payload
    consisting of a single repeated byte value, up to 8.0 for a
    payload where all 256 byte values occur equally often.

    Args:
        data: the byte sequence to measure.

    Returns:
        Shannon entropy of `data` in bits per byte, as a float in
        [0.0, 8.0].

    Raises:
        TypeError: if `data` is not bytes or bytearray.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"data must be bytes or bytearray, got {type(data).__name__}")

    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def compute_entropy_metrics(payload: bytes) -> EntropyMetrics:
    """Compute Shannon entropy for `payload` and wrap it, with the
    payload's length, into an EntropyMetrics.

    This is the intended entry point for the capture -> entropy ->
    EntropyMetrics flow: call this on capture.RawPacket.payload, not
    on a RawPacket or Scapy object directly (this module has no
    knowledge of either).

    Raises:
        TypeError: if `payload` is not bytes or bytearray (propagated
            from shannon_entropy).
        ValueError: if `payload` is empty. models.EntropyMetrics
            requires sample_size > 0 (Step 4) — correctly so, since
            every capture.RawPacket already guarantees a non-empty
            payload (see capture/raw_packet.py's own validation). An
            empty payload reaching this function indicates a caller
            bug, not a legitimate packet to represent as a metric. If
            you need the raw mathematical value for empty input
            without constructing a metrics object, call
            shannon_entropy(b"") directly — it returns 0.0.
    """
    entropy_value = shannon_entropy(payload)
    return EntropyMetrics(shannon_entropy=entropy_value, sample_size=len(payload))