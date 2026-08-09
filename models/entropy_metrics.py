"""EntropyMetrics — Shannon entropy facts about a packet's payload.

Populated by entropy/ (not implemented in this step). Holds only the
computed value and the sample size it was computed over — no
computation logic and no "is this suspicious" judgment, which belongs
to risk/.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from models._validation import validate_range


@dataclass(frozen=True, slots=True)
class EntropyMetrics:
    """Shannon entropy measurement for a payload sample.

    Raises:
        ValueError: if `shannon_entropy` is outside [0.0, 8.0] bits/byte
            (the theoretical bound for a byte stream, log2(256) = 8),
            or if `sample_size` is not positive.
    """

    shannon_entropy: float
    sample_size: int

    def __post_init__(self) -> None:
        validate_range("shannon_entropy", self.shannon_entropy, 0.0, 8.0)
        if self.sample_size <= 0:
            raise ValueError(f"sample_size must be positive, got {self.sample_size}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "shannon_entropy": self.shannon_entropy,
            "sample_size": self.sample_size,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EntropyMetrics":
        return cls(
            shannon_entropy=data["shannon_entropy"],
            sample_size=data["sample_size"],
        )