"""Expected-result manifest for the Phase 15 controlled evaluation
scenarios (docs/SDD.md's Phase 15 evaluation addendum).

This module stores EXPECTED OUTCOMES only — it contains no scoring,
fingerprinting, fusion, or enforcement logic of its own, and imports
none of risk/, fingerprint/, fusion/, or enforcement/. Every expected
value here was derived by actually running the corresponding fixture
through the real CIPHER pipeline once (see
tests/fixtures/generate_evaluation_fixtures.py's module docstring and
tests/fixtures/test_evaluation_fixtures.py, which re-verifies every
value below against the real pipeline on every test run) — nothing
here is a guess, and nothing here should ever be treated as the source
of truth for what CIPHER computes. If real scoring logic ever changes,
these expectations must be re-derived from the real pipeline, never
hand-edited to match a new interpretation.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from models.enums import ProtocolType, RiskCategory
from tests.fixtures.generate_evaluation_fixtures import (
    DEMO_PRESENTATION_PCAP,
    ENCRYPTED_ENTROPY_PCAP,
    HIGH_RISK_PCAP,
    KNOWN_SAFE_SET_PCAP,
    KNOWN_SAFE_SET_SIZE,
    LEGACY_TLS10_PCAP,
    MQTT_PCAP,
    PLAIN_HTTP_PCAP,
    SECURE_TLS13_PCAP,
    WEAK_RSA_PCAP,
)


@dataclass(frozen=True)
class EvaluationScenario:
    """One controlled evaluation scenario's expected outcome.

    `expected_qrs_min`/`expected_qrs_max` are inclusive. `notes`
    records anything a reader needs to correctly interpret the
    expected range (e.g. a structural floor/ceiling that isn't this
    fixture's doing).
    """

    scenario_id: str
    description: str
    pcap_path: Path
    expected_protocol: ProtocolType
    expected_qrs_min: int
    expected_qrs_max: int
    expected_category: RiskCategory
    expected_isolation_request: bool
    notes: str


# The CORE FIVE-SCENARIO EVALUATION, exactly matching the Execution
# Report's stated 5-scenario target — nothing else is counted toward
# this number. MQTT_SCENARIO (below, outside this list) is a separate,
# ADDITIONAL protocol-validation check: keep the two counts distinct,
# never report "5-scenario target -> 6/6" or similar.
CORE_EVALUATION_SCENARIOS = [
    EvaluationScenario(
        scenario_id="secure_modern_tls",
        description=(
            "A real TLS 1.3 ServerHello (supported_versions + key_share + "
            "RFC 7685 padding) representing a modern, secure configuration."
        ),
        pcap_path=SECURE_TLS13_PCAP,
        expected_protocol=ProtocolType.HTTPS,
        expected_qrs_min=0,
        expected_qrs_max=2,
        expected_category=RiskCategory.LOW,
        expected_isolation_request=False,
        notes=(
            "fingerprint.protocol.fingerprint_packet() always sets "
            "forward_secrecy=False (Step 7 scope: confirming PFS requires "
            "classifying the negotiated cipher suite, out of scope) -- the "
            "resulting QRS floor is 1, not 0. This is a structural "
            "limitation of the fingerprinter, not this fixture."
        ),
    ),
    EvaluationScenario(
        scenario_id="legacy_tls",
        description="A real TLS 1.0 ClientHello, no supported_versions extension.",
        pcap_path=LEGACY_TLS10_PCAP,
        expected_protocol=ProtocolType.HTTPS,
        expected_qrs_min=7,
        expected_qrs_max=9,
        expected_category=RiskCategory.HIGH,
        expected_isolation_request=True,
        notes=(
            "Lands at the low end (7) of the Execution Report's stated "
            "7-9 range: TLS_1_0's own risk (4) + no-PFS (1) + this "
            "fixture's deliberately low entropy (2) + HTTPS port_risk (0) "
            "= 7 exactly, which is also the raw-QRS isolation threshold -- "
            "a real TLS 1.0 ClientHello is independently isolation-eligible "
            "under the frozen Phase 14 policy, not only the dedicated "
            "high_risk_enforcement scenario below."
        ),
    ),
    EvaluationScenario(
        scenario_id="weak_key_size",
        description=(
            "A real, self-signed X.509 certificate (513-bit RSA) inside a "
            "genuine TLS Certificate handshake message."
        ),
        pcap_path=WEAK_RSA_PCAP,
        expected_protocol=ProtocolType.HTTPS,
        expected_qrs_min=7,
        expected_qrs_max=9,
        expected_category=RiskCategory.HIGH,
        expected_isolation_request=True,
        notes=(
            "tls_version is None for this packet (a Certificate message "
            "carries no version field -- see fingerprint/tls.py), so the "
            "non-TLS-detected fallback risk (2) applies alongside the "
            "weak-key risk (4, the <1024-bit bucket), no-PFS (1), and this "
            "certificate's own entropy (2) = 9. A real, independent path "
            "to HIGH via key-size scoring alone, distinct from the TLS- "
            "version and protocol-exposure mechanisms exercised elsewhere."
        ),
    ),
    EvaluationScenario(
        scenario_id="plaintext_protocol",
        description="A real, plaintext HTTP/1.1 GET request (no TLS at all).",
        pcap_path=PLAIN_HTTP_PCAP,
        expected_protocol=ProtocolType.HTTP,
        expected_qrs_min=5,
        expected_qrs_max=7,
        expected_category=RiskCategory.MEDIUM,
        expected_isolation_request=False,
        notes="Confirms port_risk_for_protocol(HTTP)=1 is genuinely applied via the real fingerprinter, not asserted in isolation.",
    ),
    EvaluationScenario(
        scenario_id="high_risk_enforcement",
        description=(
            "A real Telnet option-negotiation burst -- the dedicated "
            "scenario for the Phase 14 enforcement demonstration."
        ),
        pcap_path=HIGH_RISK_PCAP,
        expected_protocol=ProtocolType.TELNET,
        expected_qrs_min=7,
        expected_qrs_max=10,
        expected_category=RiskCategory.HIGH,
        expected_isolation_request=True,
        notes=(
            "Reaches the raw-QRS>=7 isolation threshold via protocol "
            "exposure alone (Telnet's maximum port_risk=2) plus this "
            "payload's genuinely low entropy -- no TLS, no certificate. "
            "This is the scenario evaluate_demo.py uses for the "
            "should_isolate()/NoOpIsolationBackend walkthrough."
        ),
    ),
]

# ADDITIONAL PROTOCOL VALIDATION — not one of the five core scenarios,
# never counted in the "x/5" figure. Closes a real coverage gap the
# Phase 15 inspection found: the original sample.pcap MQTT-shaped
# packet (b"MQTT-CONNECT-PAYLOAD" on UDP/1883) is not valid MQTT wire
# format and is classified ProtocolType.OTHER — not a detector bug.
# MQTT_SCENARIO exercises a genuinely-valid MQTT CONNECT packet
# instead (see generate_evaluation_fixtures.build_mqtt_connect);
# fingerprint/protocol.py itself is unmodified.
MQTT_SCENARIO = EvaluationScenario(
    scenario_id="mqtt_protocol_detection",
    description=(
        "ADDITIONAL VALIDATION (not one of the five core scenarios): a "
        "real MQTT 3.1.1 CONNECT packet, closing the MQTT detection gap "
        "the Phase 15 inspection found in the original sample.pcap fixture."
    ),
    pcap_path=MQTT_PCAP,
    expected_protocol=ProtocolType.MQTT,
    expected_qrs_min=5,
    expected_qrs_max=7,
    expected_category=RiskCategory.MEDIUM,
    expected_isolation_request=False,
    notes="Confirms fingerprint.protocol._looks_like_mqtt_connect() genuinely recognizes valid MQTT wire format -- no detector change was needed or made.",
)

KNOWN_SAFE_SET_PCAP_PATH = KNOWN_SAFE_SET_PCAP
KNOWN_SAFE_SET_EXPECTED_COUNT = KNOWN_SAFE_SET_SIZE

DEMO_PRESENTATION_PCAP_PATH = DEMO_PRESENTATION_PCAP

# Execution Report entropy targets (evaluated directly by
# evaluate_demo.py against the REAL entropy/ implementation — this
# manifest stores only the fixture paths and thresholds, never
# recomputes entropy itself).
ENCRYPTED_ENTROPY_PCAP_PATH = ENCRYPTED_ENTROPY_PCAP
ENCRYPTED_ENTROPY_TARGET_MIN = 7.5  # "encrypted entropy > 7.5"
HTTP_ENTROPY_PCAP_PATH = PLAIN_HTTP_PCAP  # reuses the plaintext_protocol core scenario's own fixture
HTTP_ENTROPY_TARGET_MAX = 5.0  # "HTTP entropy < 5"
