"""reports — per-device PDF security report generation and verification.

One concise, 3-page PDF per flagged device (models.DeviceAssessment
with final_category != LOW), reusing risk_assessment.remediation/
.nist_reference verbatim and signing/'s existing ML-DSA-44 primitives
unchanged. See docs/SDD.md's Phase 10 addendum for the frozen layout,
the flagged-device rule, and the non-self-referential report-signing
design (a canonical report-data payload is hashed and signed, never
the rendered PDF's own bytes).
"""

from reports.pdf_generator import (
    DEFAULT_REPORT_OUTPUT_DIR,
    generate_report,
    generate_report_id,
    is_flagged_device,
    verify_report,
)

__all__ = [
    "generate_report",
    "verify_report",
    "is_flagged_device",
    "generate_report_id",
    "DEFAULT_REPORT_OUTPUT_DIR",
]
