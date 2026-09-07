"""pipeline — the runtime sequence CIPHER actually runs (SDD D3).

`assessment_pipeline.assess_packet` (Step 11) is the small, stateless,
single-observation composition function: entropy -> fingerprint ->
DeviceFeatures -> QRS -> optional anomaly detection -> fusion ->
DeviceAssessment, for one already-identified Device and one already-
captured RawPacket. It has no loop, no thread, and no registry.

main.py constructs components and hands them to Pipeline; it contains no
orchestration logic itself. Pipeline (runner.py, not implemented yet)
owns the background-thread capture loop and the per-packet fault
isolation described in SDD Section 12 — it will call assess_packet once
per packet once it exists.
"""

from pipeline.assessment_pipeline import assess_packet

__all__ = ["assess_packet"]
