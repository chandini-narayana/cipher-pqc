"""AnomalyAssessment — the Isolation Forest anomaly-detection result.

Populated by ml/ (not implemented in this step). Per the frozen ML
architecture, Isolation Forest performs anomaly detection only and
never replaces rule-based reasoning — this model is intentionally
independent of RiskAssessment; the two are fused later into a
DeviceAssessment, not merged here.

No ML-library-specific assumptions are encoded here (e.g., no
assumption about the sign or scale of `anomaly_score`, since that is
an implementation detail of whichever anomaly-detection algorithm
produces it) — only generic validation that the values are sane.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

from models._validation import validate_finite, validate_range


@dataclass(frozen=True, slots=True)
class AnomalyAssessment:
    """The anomaly-detection outcome for one device observation.

    Raises:
        ValueError: if `anomaly_score` is NaN/infinite, or if
            `confidence` is outside [0.0, 1.0].
    """

    anomaly_score: float
    is_anomaly: bool
    confidence: float

    def __post_init__(self) -> None:
        validate_finite("anomaly_score", self.anomaly_score)
        validate_range("confidence", self.confidence, 0.0, 1.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_score": self.anomaly_score,
            "is_anomaly": self.is_anomaly,
            "confidence": self.confidence,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnomalyAssessment":
        return cls(
            anomaly_score=data["anomaly_score"],
            is_anomaly=data["is_anomaly"],
            confidence=data["confidence"],
        )