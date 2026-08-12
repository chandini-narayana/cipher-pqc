"""Deterministic, rule-based Quantum Risk Score.

Implements the QRS formula exactly as specified in the approved CIPHER
project document (Section 8.2) and execution report (Phase 3):

    QRS = TLS_risk + KeySize_risk + (1 if no_PFS else 0)
          + Entropy_risk + Port_risk

capped at 10. Pure and deterministic — no I/O, no ML, no randomness,
no network access. Plain functions, not a class: there is no state or
configuration to hold between calls (same precedent as entropy/ and
fingerprint/ — see docs/SDD.md Sections 18-19).

Two inputs are NOT fully resolvable from the approved source material
as given — see the docstrings on key_size_risk() and
quantum_risk_score() for exactly what's preserved verbatim versus what
required a judgment call, and docs/SDD.md Section 20 for the full
reasoning on both.
"""
from __future__ import annotations

from typing import Optional

from models.enums import RiskCategory, TLSVersion

# Category thresholds, from the approved execution report's dashboard
# risk-badge design: green <3, amber 3-6, red 7+. The red/7+ boundary
# also matches RISK_ISOLATION_THRESHOLD (config/constants.py, Step 3)
# exactly — both sources agree, so this is preserved, not invented.
_LOW_MAX = 2  # score <= 2 -> LOW  (i.e. score < 3)
_MEDIUM_MAX = 6  # score <= 6 -> MEDIUM (3-6); score >= 7 -> HIGH

_TLS_VERSION_TABLE = {
    TLSVersion.TLS_1_0: 4,
    TLSVersion.TLS_1_1: 3,
    TLSVersion.TLS_1_2: 1,
    TLSVersion.TLS_1_3: 0,
}


def tls_version_risk(tls_version: Optional[TLSVersion]) -> int:
    """TLS version component — exact table from the approved formula.

    TLS 1.0=4, TLS 1.1=3, TLS 1.2=1, TLS 1.3=0. Any other value,
    including unknown/undetected (tls_version=None, e.g. a packet that
    isn't a ClientHello/ServerHello) = 2 — this is the approved
    formula's own documented fallback (its Python reference
    implementation reads `{1.0:4, 1.1:3, 1.2:1, 1.3:0}.get(tls_ver, 2)`),
    preserved exactly, not invented here.
    """
    return _TLS_VERSION_TABLE.get(tls_version, 2)


def key_size_risk(key_size: Optional[int]) -> int:
    """RSA key size component — exact table from the approved formula
    for a known key size: <1024=4, <2048=3, <3072=2, >=3072=0.

    key_size=None contributes 0. This specific case has NO fallback
    defined anywhere in the approved formula (unlike TLS version's
    explicit `.get(tls_ver, 2)`) — it is a genuine gap, not a
    preserved rule. 0 was chosen, rather than a fabricated non-zero
    penalty, because key_size is structurally always None for TLS 1.3
    (its Certificate message is encrypted and never visible to a
    passive capture — see fingerprint/tls.py, Step 7): scoring unknown
    key size as risky would incorrectly penalize TLS 1.3 traffic — the
    safest version — purely for a visibility limitation rather than a
    real observed weakness. See docs/SDD.md Section 20 for the full
    reasoning — flagged there for your review, since the approved
    material doesn't settle this case explicitly.

    Raises:
        ValueError: if `key_size` is not None and not positive.
    """
    if key_size is None:
        return 0
    if key_size <= 0:
        raise ValueError(f"key_size must be positive or None, got {key_size}")
    if key_size < 1024:
        return 4
    if key_size < 2048:
        return 3
    if key_size < 3072:
        return 2
    return 0


def entropy_risk(entropy: float) -> int:
    """Entropy component — exact table from the approved formula:
    <6.0=+2, <7.0=+1, >=7.0=0.

    Raises:
        ValueError: if `entropy` is outside [0.0, 8.0].
    """
    if not 0.0 <= entropy <= 8.0:
        raise ValueError(f"entropy must be within [0.0, 8.0], got {entropy}")
    if entropy < 6.0:
        return 2
    if entropy < 7.0:
        return 1
    return 0


def quantum_risk_score(
    tls_version: Optional[TLSVersion],
    key_size: Optional[int],
    pfs: bool,
    entropy: float,
    port_risk: int,
) -> int:
    """The approved Quantum Risk Score formula, exactly as specified,
    capped at 10.

    `port_risk` is a REQUIRED, externally-supplied argument, not
    computed internally by this function. The approved execution
    report specifies protocol-exposure risk only as a range
    ("HTTP/Telnet/MQTT = +1 to +2"), without stating which protocol
    maps to which exact value within that range — implementing a
    specific per-protocol mapping would mean inventing numbers the
    approved material doesn't actually give. The approved formula's
    own reference implementation already treats port_risk as an
    external parameter (not an internal calculation), so this
    preserves that structure rather than guessing at the missing
    mapping. See docs/SDD.md Section 20 — this is flagged as an open
    decision, not resolved here.

    Raises:
        ValueError: if `entropy` is outside [0.0, 8.0] (propagated
            from entropy_risk), if `key_size` is invalid (propagated
            from key_size_risk), or if `port_risk` is negative.
    """
    if port_risk < 0:
        raise ValueError(f"port_risk cannot be negative, got {port_risk}")

    total = (
        tls_version_risk(tls_version)
        + key_size_risk(key_size)
        + (0 if pfs else 1)
        + entropy_risk(entropy)
        + port_risk
    )
    return min(total, 10)


def category_for_score(score: int) -> RiskCategory:
    """Maps a QRS value to a RiskCategory using the approved dashboard
    badge thresholds (green <3, amber 3-6, red 7+), which also match
    RISK_ISOLATION_THRESHOLD=7 (config/constants.py) exactly — both
    sources agree, so this mapping is preserved, not invented.

    Raises:
        ValueError: if `score` is outside [0, 10].
    """
    if not 0 <= score <= 10:
        raise ValueError(f"score must be within [0, 10], got {score}")
    if score <= _LOW_MAX:
        return RiskCategory.LOW
    if score <= _MEDIUM_MAX:
        return RiskCategory.MEDIUM
    return RiskCategory.HIGH