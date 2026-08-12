"""Remediation text and NIST reference generation for each Quantum
Risk Score component that contributes non-zero risk.

Pure text generation — no scoring logic lives here (that belongs to
risk/scoring.py); this module only explains findings scoring.py's
functions have already identified as non-zero. NIST references used
below are exactly the ones given per-component in the approved
project document's Section 8.2 table:

    TLS version risk    -> NIST SP 800-52r2
    RSA key size risk   -> NIST SP 800-131A
    Forward secrecy     -> NIST SP 800-52r2
    Entropy risk        -> Shannon (1948) [not a NIST reference —
                            the approved table itself cites Shannon's
                            original paper here, not a NIST SP number]
    Protocol exposure   -> NIST SP 800-41

No reference beyond these five is used or fabricated.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from models.enums import TLSVersion
from risk.scoring import entropy_risk, key_size_risk, tls_version_risk

_NO_FINDINGS_REMEDIATION = (
    "No remediation needed. All assessed factors (TLS version, key size, "
    "forward secrecy, entropy, protocol exposure) are within the safe "
    "thresholds defined by the approved risk model."
)
_NO_FINDINGS_NIST_REFERENCE = "N/A — no findings triggered a NIST reference."


def contributing_findings(
    tls_version: Optional[TLSVersion],
    key_size: Optional[int],
    pfs: bool,
    entropy: float,
    port_risk: int,
) -> List[Tuple[str, str]]:
    """Return (remediation_text, nist_reference) for each factor that
    contributed non-zero risk to the QRS total, in the formula's fixed
    component order (TLS, key size, PFS, entropy, protocol exposure).
    """
    findings: List[Tuple[str, str]] = []

    if tls_version_risk(tls_version) > 0:
        label = tls_version.name.replace("_", ".").replace("TLS.", "TLS ") if tls_version else "an undetected/unknown TLS version"
        findings.append((f"Upgrade from {label} to TLS 1.3.", "NIST SP 800-52r2"))

    if key_size_risk(key_size) > 0:
        findings.append(
            (
                f"Increase RSA key size to at least 3072 bits (observed: {key_size} bits).",
                "NIST SP 800-131A",
            )
        )

    if not pfs:
        findings.append(
            (
                "Enable forward secrecy (e.g., ECDHE cipher suites) instead of "
                "static RSA key exchange.",
                "NIST SP 800-52r2",
            )
        )

    if entropy_risk(entropy) > 0:
        findings.append(
            (
                f"Traffic entropy is low ({entropy:.2f} bits/byte), indicating "
                "weak or absent encryption.",
                "Shannon (1948), A Mathematical Theory of Communication",
            )
        )

    if port_risk > 0:
        findings.append(
            (
                "Unencrypted or legacy protocol exposure detected; migrate to "
                "an encrypted, modern protocol.",
                "NIST SP 800-41",
            )
        )

    return findings


def build_remediation_and_reference(
    tls_version: Optional[TLSVersion],
    key_size: Optional[int],
    pfs: bool,
    entropy: float,
    port_risk: int,
) -> Tuple[str, str]:
    """Combine all contributing findings into the single remediation
    string and single nist_reference string models.RiskAssessment
    requires (both fields are non-optional single strings, not lists
    — see Step 4)."""
    findings = contributing_findings(tls_version, key_size, pfs, entropy, port_risk)

    if not findings:
        return _NO_FINDINGS_REMEDIATION, _NO_FINDINGS_NIST_REFERENCE

    remediation = " ".join(text for text, _ in findings)

    references: List[str] = []
    for _, ref in findings:
        if ref not in references:
            references.append(ref)
    nist_reference = ", ".join(references)

    return remediation, nist_reference