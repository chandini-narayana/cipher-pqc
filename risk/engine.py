"""evaluate_risk — the top-level entry point combining scoring.py and
nist_mapping.py into a single models.RiskAssessment.

Plain function, not a class: no state or configuration to hold between
calls (same precedent as entropy/ and fingerprint/ — see docs/SDD.md
Sections 18-19). Consumes models.DeviceFeatures, per the approved
conceptual boundary (ProtocolFingerprint / EntropyMetrics /
DeviceFeatures -> Risk Engine -> RiskAssessment).

Does not capture packets, parse Scapy objects, perform TLS parsing,
calculate entropy, run ML, touch a database, call REST endpoints,
generate PDFs, or sign anything — all of that already happened
upstream (capture/, entropy/, fingerprint/) or happens in later
milestones (ml/, reports/, signing/, pipeline/).
"""
from __future__ import annotations

from models.device_features import DeviceFeatures
from models.risk_assessment import RiskAssessment
from risk.nist_mapping import build_remediation_and_reference
from risk.scoring import category_for_score, quantum_risk_score


def evaluate_risk(features: DeviceFeatures, port_risk: int) -> RiskAssessment:
    """Compute the Quantum Risk Score for one device observation and
    build the resulting RiskAssessment.

    `port_risk` is a required, externally-supplied argument — deriving
    it from features.fingerprint.protocol is an open decision the
    approved execution report doesn't specify precisely enough to
    implement without guessing (see risk/scoring.py's
    quantum_risk_score docstring and docs/SDD.md Section 20).

    Raises:
        ValueError: propagated from quantum_risk_score/category_for_score
            if any input is out of its valid range.
    """
    tls_version = features.fingerprint.tls_version
    key_size = features.fingerprint.key_size
    pfs = features.fingerprint.forward_secrecy
    entropy = features.entropy.shannon_entropy

    score = quantum_risk_score(tls_version, key_size, pfs, entropy, port_risk)
    category = category_for_score(score)
    remediation, nist_reference = build_remediation_and_reference(
        tls_version, key_size, pfs, entropy, port_risk
    )

    return RiskAssessment(
        risk_score=score,
        category=category,
        remediation=remediation,
        nist_reference=nist_reference,
    )