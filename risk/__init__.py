"""risk — the deterministic, rule-based Quantum Risk Score.

Pure computation only: no packet capture, no Scapy, no TLS parsing, no
entropy calculation, no ML, no network I/O, no database access, no
REST, no PDF generation, no signing. See docs/SDD.md Section 20 for
the two inputs (key_size=None handling, port_risk derivation) that the
approved execution report doesn't specify precisely enough to resolve
without a documented judgment call.
"""

from risk.engine import evaluate_risk
from risk.nist_mapping import build_remediation_and_reference, contributing_findings
from risk.scoring import (
    category_for_score,
    entropy_risk,
    key_size_risk,
    quantum_risk_score,
    tls_version_risk,
)

__all__ = [
    "evaluate_risk",
    "quantum_risk_score",
    "category_for_score",
    "tls_version_risk",
    "key_size_risk",
    "entropy_risk",
    "contributing_findings",
    "build_remediation_and_reference",
]