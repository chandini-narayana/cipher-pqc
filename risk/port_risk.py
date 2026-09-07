"""port_risk_for_protocol — the frozen ProtocolType -> port_risk mapping.

Resolves the previously-open port_risk gap (see risk/scoring.py's
quantum_risk_score docstring and docs/SDD.md's Step 12B addendum): the
approved execution report specifies only that plaintext/insecure
protocols such as HTTP, Telnet, and MQTT contribute "+1 to +2" risk,
without stating an exact per-protocol value. The mapping below is an
explicit ENGINEERING POLICY decision that operationalizes that range —
it is not itself quoted from the execution report, and should not be
represented as such.

Pure, deterministic, and keyed strictly on the already-classified
models.ProtocolType enum (fingerprint/protocol.py's own output) — never
on transport port numbers, and never by string-matching a protocol
name. Plain function, not a class: no state or configuration to hold
between calls (same precedent as entropy/, fingerprint/, risk/scoring.py
— see docs/SDD.md Sections 18-20).
"""
from __future__ import annotations

from models.enums import ProtocolType

_PORT_RISK_TABLE = {
    ProtocolType.HTTPS: 0,
    ProtocolType.OTHER: 0,
    ProtocolType.HTTP: 1,
    ProtocolType.MQTT: 1,
    ProtocolType.TELNET: 2,
}


def port_risk_for_protocol(protocol: ProtocolType) -> int:
    """Map a classified ProtocolType to its frozen port_risk contribution.

    HTTPS and OTHER contribute 0. HTTP and MQTT (plaintext/lightweight,
    commonly unauthenticated) contribute 1. TELNET (plaintext remote
    shell access) contributes 2 — the top of the execution report's
    approved "+1 to +2" range, reflecting its materially higher exposure.

    Raises:
        TypeError: if `protocol` is not a ProtocolType member — an
            unrecognized or wrong-typed input fails clearly rather
            than being silently treated as ProtocolType.OTHER.
    """
    if not isinstance(protocol, ProtocolType):
        raise TypeError(
            f"protocol must be a ProtocolType, got {type(protocol).__name__}"
        )
    return _PORT_RISK_TABLE[protocol]
