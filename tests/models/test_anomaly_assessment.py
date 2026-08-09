"""Unit tests for models.anomaly_assessment.AnomalyAssessment."""
import math

import pytest

from models.anomaly_assessment import AnomalyAssessment


def test_valid_anomaly_assessment() -> None:
    aa = AnomalyAssessment(anomaly_score=-0.31, is_anomaly=True, confidence=0.87)
    assert aa.is_anomaly is True


def test_negative_anomaly_score_is_allowed() -> None:
    """No sign convention is enforced — that's an ML-library detail,
    not something the model should assume (see module docstring)."""
    aa = AnomalyAssessment(anomaly_score=-5.0, is_anomaly=False, confidence=0.1)
    assert aa.anomaly_score == -5.0


@pytest.mark.parametrize("bad_score", [math.nan, math.inf, -math.inf])
def test_rejects_non_finite_score(bad_score: float) -> None:
    with pytest.raises(ValueError, match="anomaly_score"):
        AnomalyAssessment(anomaly_score=bad_score, is_anomaly=False, confidence=0.5)


@pytest.mark.parametrize("confidence", [-0.1, 1.1, 2.0])
def test_rejects_out_of_range_confidence(confidence: float) -> None:
    with pytest.raises(ValueError, match="confidence"):
        AnomalyAssessment(anomaly_score=0.1, is_anomaly=False, confidence=confidence)


def test_accepts_boundary_confidence() -> None:
    assert AnomalyAssessment(0.0, False, 0.0).confidence == 0.0
    assert AnomalyAssessment(0.0, True, 1.0).confidence == 1.0


def test_round_trip_serialization() -> None:
    aa1 = AnomalyAssessment(anomaly_score=0.42, is_anomaly=False, confidence=0.6)
    aa2 = AnomalyAssessment.from_dict(aa1.to_dict())
    assert aa1 == aa2