"""fusion — combines already-produced RiskAssessment and AnomalyAssessment
outputs into a single fused DeviceAssessment.

See docs/SDD.md Step 10 addendum for the frozen category-floor,
one-level-escalation architecture. This package depends only on
domain model types (models.*) — never on risk/ or ml/ directly, since
it fuses their already-produced outputs, not their computation.
"""

from fusion.risk_fusion import fuse_assessments

__all__ = ["fuse_assessments"]
