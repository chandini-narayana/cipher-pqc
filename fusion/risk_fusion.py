"""fuse_assessments — the frozen Risk Fusion rule (docs/SDD.md Step 10 addendum).

final_category = risk_assessment.category

if anomaly_assessment is not None and anomaly_assessment.is_anomaly:
    escalate exactly one level: LOW -> MEDIUM, MEDIUM -> HIGH, HIGH -> HIGH

The rule-based Quantum Risk Score category is the floor; Isolation
Forest may only raise it by one level, never more, and never directly
LOW -> HIGH. This is a category-floor rule, not a weighted or numeric
fusion: there is no combined score, and `anomaly_assessment.confidence`
never influences the outcome — only the boolean `is_anomaly` flag does.
`anomaly_assessment=None` (ML not run/unavailable) passes the
rule-based category through unchanged; it is not itself an anomaly
signal.

This is an approved architecture decision — not open for redesign here.

Depends only on models.* (already-computed assessment objects). Never
imports risk/ or ml/ directly: fusion combines their outputs, it does
not invoke either engine.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.risk_assessment import RiskAssessment

_ESCALATE_ONE_LEVEL = {
    RiskCategory.LOW: RiskCategory.MEDIUM,
    RiskCategory.MEDIUM: RiskCategory.HIGH,
    RiskCategory.HIGH: RiskCategory.HIGH,
}


def fuse_assessments(
    risk_assessment: RiskAssessment,
    anomaly_assessment: Optional[AnomalyAssessment],
    device: Device,
    assessed_at: Optional[datetime] = None,
) -> DeviceAssessment:
    """Fuse a rule-based RiskAssessment with an optional AnomalyAssessment
    into the final DeviceAssessment.

    `assessed_at` is preserved if explicitly supplied, otherwise set to
    the current UTC time.

    Raises:
        TypeError: if `risk_assessment` is not a RiskAssessment, `device`
            is not a Device, or `anomaly_assessment` is neither an
            AnomalyAssessment nor None.
    """
    if not isinstance(risk_assessment, RiskAssessment):
        raise TypeError(
            f"risk_assessment must be a RiskAssessment, got {type(risk_assessment).__name__}"
        )
    if not isinstance(device, Device):
        raise TypeError(f"device must be a Device, got {type(device).__name__}")
    if anomaly_assessment is not None and not isinstance(anomaly_assessment, AnomalyAssessment):
        raise TypeError(
            "anomaly_assessment must be an AnomalyAssessment or None, "
            f"got {type(anomaly_assessment).__name__}"
        )

    final_category = risk_assessment.category
    if anomaly_assessment is not None and anomaly_assessment.is_anomaly:
        final_category = _ESCALATE_ONE_LEVEL[final_category]

    return DeviceAssessment(
        device=device,
        risk_assessment=risk_assessment,
        anomaly_assessment=anomaly_assessment,
        final_category=final_category,
        assessed_at=assessed_at if assessed_at is not None else datetime.now(timezone.utc),
    )
