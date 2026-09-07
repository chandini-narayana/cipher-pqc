"""pipeline — the runtime sequence CIPHER actually runs (SDD D3).

`assessment_pipeline.assess_packet` (Step 11) is the small, stateless,
single-observation composition function: entropy -> fingerprint ->
DeviceFeatures -> QRS -> optional anomaly detection -> fusion ->
DeviceAssessment, for one already-identified Device and one already-
captured RawPacket. It has no loop, no thread, and no registry.

`runner.run_capture` (Phase 11) is the synchronous, single-pass offline
orchestrator: it drives a CaptureSource through assess_packet once per
packet, retains one representative DeviceAssessment per device, and
generates a Phase 10 PDF report for every flagged device after EOF. No
background thread, no live-capture handling — see docs/SDD.md's Phase
11 addendum.

main.py constructs components (CaptureSource, the optional
AnomalyDetector, the signing keypair) and hands them to run_capture; it
contains no orchestration logic itself.
"""

from pipeline.assessment_pipeline import assess_packet
from pipeline.runner import run_capture

__all__ = ["assess_packet", "run_capture"]
