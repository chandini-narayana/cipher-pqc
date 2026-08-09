"""SignedEvent — a DeviceAssessment plus its Dilithium2 signature.

Produced by signing/ (not implemented in this step). This model only
describes the shape of a signed record; it contains no cryptographic
logic — signing and verification are signing/'s responsibility.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict

from models._validation import validate_hex, validate_non_empty
from models.device_assessment import DeviceAssessment


@dataclass(frozen=True, slots=True)
class SignedEvent:
    """A DeviceAssessment together with its signature and signing metadata.

    Raises:
        ValueError: if `signature_hex` is not valid hexadecimal, or
            `algorithm` is empty.
    """

    assessment: DeviceAssessment
    signature_hex: str
    algorithm: str
    signed_at: datetime

    def __post_init__(self) -> None:
        validate_hex("signature_hex", self.signature_hex)
        validate_non_empty("algorithm", self.algorithm)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "assessment": self.assessment.to_dict(),
            "signature_hex": self.signature_hex,
            "algorithm": self.algorithm,
            "signed_at": self.signed_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignedEvent":
        return cls(
            assessment=DeviceAssessment.from_dict(data["assessment"]),
            signature_hex=data["signature_hex"],
            algorithm=data["algorithm"],
            signed_at=datetime.fromisoformat(data["signed_at"]),
        )