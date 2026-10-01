"""DeviceAssessment — the final, fused, API-facing per-device result.

This is the only assessment object dashboard/, reports/, and the REST
API are meant to consume (see the frozen frontend contract in
docs/SDD.md: the API exposes only stable, fused results — never raw
RiskAssessment/AnomalyAssessment internals or ML objects directly).
The fusion logic that produces final_category from risk_assessment and
anomaly_assessment lives in fusion/risk_fusion.py (Step 10), not here —
this model only composes already-fused results.

`anomaly_assessment` is Optional: per the frozen fusion rule, ML not
having run (or being unavailable) is not itself an anomaly signal, so
a DeviceAssessment may legitimately carry final_category derived from
risk_assessment alone.

`isolation` is Optional for the same kind of reason, and is set by
pipeline/runner.py after enforcement, never by fusion: most observations
are not isolation-eligible (raw QRS < threshold), an offline analysis
run may use a non-enforcing backend, and `None` is the honest
representation of "no isolation attempt was made for this device".
Attaching it here rather than in a parallel isolation registry means it
is serialized over REST, rendered into the PDF, and covered by the
Dilithium signature through the existing to_dict() payload — with no new
persistence of any kind.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Dict, Optional

from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
from models.risk_assessment import RiskAssessment


@dataclass(frozen=True, slots=True)
class DeviceAssessment:
    """The fused final assessment for one device.

    No additional validation beyond composing already-validated parts.
    """

    device: Device
    risk_assessment: RiskAssessment
    anomaly_assessment: Optional[AnomalyAssessment]
    final_category: RiskCategory
    assessed_at: datetime
    isolation: Optional[IsolationStatus] = None

    def with_isolation(self, isolation: IsolationStatus) -> "DeviceAssessment":
        """Return a copy carrying `isolation`, leaving this instance (and
        every risk/ML/fusion value on it) untouched.

        A copy, not a mutation, because DeviceAssessment is frozen — and
        because enforcement happens *after* an assessment is produced,
        so the isolation result can only ever be added afterwards.
        """
        return replace(self, isolation=isolation)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device": self.device.to_dict(),
            "risk_assessment": self.risk_assessment.to_dict(),
            "anomaly_assessment": (
                self.anomaly_assessment.to_dict()
                if self.anomaly_assessment is not None
                else None
            ),
            "final_category": self.final_category.value,
            "assessed_at": self.assessed_at.isoformat(),
            "isolation": self.isolation.to_dict() if self.isolation is not None else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceAssessment":
        anomaly_data = data["anomaly_assessment"]
        return cls(
            device=Device.from_dict(data["device"]),
            risk_assessment=RiskAssessment.from_dict(data["risk_assessment"]),
            anomaly_assessment=(
                AnomalyAssessment.from_dict(anomaly_data) if anomaly_data is not None else None
            ),
            final_category=RiskCategory(data["final_category"]),
            assessed_at=datetime.fromisoformat(data["assessed_at"]),
            # .get(), not [...]: a payload serialized before isolation
            # state existed must still load, as None.
            isolation=(
                IsolationStatus.from_dict(data["isolation"])
                if data.get("isolation") is not None
                else None
            ),
        )