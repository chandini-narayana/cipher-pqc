"""RiskAssessment — the rule-based Quantum Risk Score result.

Populated by risk/ (not implemented in this step). This is the
"primary explainable security engine" output referenced in the frozen
ML architecture (docs/SDD.md addendum) — it stands on its own and is
never replaced by the Isolation Forest; the two are fused later into
a DeviceAssessment.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from models._validation import validate_non_empty, validate_range
from models.enums import RiskCategory


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    """The rule-based Quantum Risk Score outcome for one device observation.

    Raises:
        ValueError: if `risk_score` is outside [0, 10], or if
            `remediation`/`nist_reference` are empty.
    """

    risk_score: int
    category: RiskCategory
    remediation: str
    nist_reference: str

    def __post_init__(self) -> None:
        validate_range("risk_score", self.risk_score, 0, 10)
        validate_non_empty("remediation", self.remediation)
        validate_non_empty("nist_reference", self.nist_reference)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "category": self.category.value,
            "remediation": self.remediation,
            "nist_reference": self.nist_reference,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RiskAssessment":
        return cls(
            risk_score=data["risk_score"],
            category=RiskCategory(data["category"]),
            remediation=data["remediation"],
            nist_reference=data["nist_reference"],
        )