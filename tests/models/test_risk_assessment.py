"""Unit tests for models.risk_assessment.RiskAssessment."""
import pytest

from models.enums import RiskCategory
from models.risk_assessment import RiskAssessment


def test_valid_risk_assessment() -> None:
    ra = RiskAssessment(
        risk_score=9,
        category=RiskCategory.HIGH,
        remediation="Upgrade to TLS 1.3 with a >=3072-bit key.",
        nist_reference="SP 800-52r2",
    )
    assert ra.category == RiskCategory.HIGH


@pytest.mark.parametrize("score", [-1, 11, 100])
def test_rejects_out_of_range_score(score: int) -> None:
    with pytest.raises(ValueError, match="risk_score"):
        RiskAssessment(
            risk_score=score,
            category=RiskCategory.LOW,
            remediation="n/a",
            nist_reference="n/a",
        )


def test_accepts_boundary_scores() -> None:
    assert RiskAssessment(0, RiskCategory.LOW, "ok", "ref").risk_score == 0
    assert RiskAssessment(10, RiskCategory.HIGH, "fix", "ref").risk_score == 10


def test_rejects_empty_remediation() -> None:
    with pytest.raises(ValueError, match="remediation"):
        RiskAssessment(5, RiskCategory.MEDIUM, "", "SP 800-131A")


def test_rejects_empty_nist_reference() -> None:
    with pytest.raises(ValueError, match="nist_reference"):
        RiskAssessment(5, RiskCategory.MEDIUM, "Patch it", "")


def test_round_trip_serialization() -> None:
    ra1 = RiskAssessment(7, RiskCategory.HIGH, "Rotate keys", "SP 800-131A")
    ra2 = RiskAssessment.from_dict(ra1.to_dict())
    assert ra1 == ra2