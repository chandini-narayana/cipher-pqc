"""should_isolate — the pure, deterministic Phase 14 isolation-eligibility
decision.

Frozen policy (docs/SDD.md's Phase 14 addendum): the Execution Report
specifies isolation eligibility as a literal numeric condition —
`QRS >= 7/10` — not a category. This function therefore compares
`assessment.risk_assessment.risk_score` (the raw, deterministic Quantum
Risk Score) against `threshold`, and deliberately never reads
`assessment.final_category`.

This distinction is intentional, not an oversight: Risk Fusion
(fusion/risk_fusion.py) may escalate a device's *reported* category
from MEDIUM to HIGH when Isolation Forest flags an anomaly, but an ML
anomaly signal alone must never trigger a high-consequence physical
isolation action that the deterministic, explainable QRS score does
not itself support. A device with risk_score=5 and an ML-escalated
final_category of HIGH is NOT eligible for isolation under this
function — only the raw score matters here.

Pure by design: no logging, no I/O, no subprocess calls, no knowledge
of any hardware backend. Independently testable and hardware-independent.
"""
from __future__ import annotations

from models.device_assessment import DeviceAssessment


def should_isolate(assessment: DeviceAssessment, threshold: int) -> bool:
    """Return True iff `assessment`'s raw QRS score meets or exceeds
    `threshold`.

    Deliberately keyed on `assessment.risk_assessment.risk_score`, never
    `assessment.final_category` — see module docstring.
    """
    return assessment.risk_assessment.risk_score >= threshold
