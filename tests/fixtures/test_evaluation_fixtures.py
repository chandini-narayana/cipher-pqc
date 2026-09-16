"""Verifies the Phase 15 controlled evaluation fixtures against
tests/fixtures/evaluation_manifest.py's frozen expectations, using the
real CIPHER pipeline end to end (capture -> fingerprint -> QRS ->
fusion -> should_isolate) — never a hand-constructed RiskAssessment or
DeviceAssessment standing in for a fixture.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from capture.offline_source import OfflinePcapSource
from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD
from entropy.engine import compute_entropy_metrics
from enforcement.decision import should_isolate
from fingerprint.protocol import detect_protocol_type, fingerprint_packet
from models.device import Device
from models.enums import ProtocolType, RiskCategory
from pipeline.assessment_pipeline import assess_packet
from risk.port_risk import port_risk_for_protocol
from tests.fixtures.evaluation_manifest import (
    CORE_EVALUATION_SCENARIOS,
    DEMO_PRESENTATION_PCAP_PATH,
    ENCRYPTED_ENTROPY_PCAP_PATH,
    ENCRYPTED_ENTROPY_TARGET_MIN,
    HTTP_ENTROPY_PCAP_PATH,
    HTTP_ENTROPY_TARGET_MAX,
    KNOWN_SAFE_SET_EXPECTED_COUNT,
    KNOWN_SAFE_SET_PCAP_PATH,
    MQTT_SCENARIO,
    EvaluationScenario,
)
from tests.fixtures.generate_evaluation_fixtures import build_mqtt_connect

FIXED_ASSESSED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _assess_single_packet_pcap(pcap_path):
    packets = list(OfflinePcapSource(pcap_path).read_packets())
    assert len(packets) == 1, f"{pcap_path} must contain exactly one packet"
    raw_packet = packets[0]
    device = Device.first_contact(raw_packet.src_ip, raw_packet.timestamp)
    fingerprint = fingerprint_packet(raw_packet.payload)
    port_risk = port_risk_for_protocol(fingerprint.protocol)
    assessment = assess_packet(raw_packet, device, port_risk, None, assessed_at=FIXED_ASSESSED_AT)
    return fingerprint, assessment


@pytest.mark.parametrize("scenario", CORE_EVALUATION_SCENARIOS, ids=lambda s: s.scenario_id)
def test_core_scenario_matches_manifest_expectations(scenario: EvaluationScenario) -> None:
    """One of the five CORE scenarios (the Execution Report's stated
    5-scenario target — MQTT is deliberately not parametrized here,
    see the auxiliary-validation tests below)."""
    fingerprint, assessment = _assess_single_packet_pcap(scenario.pcap_path)
    ra = assessment.risk_assessment

    assert fingerprint.protocol == scenario.expected_protocol
    assert scenario.expected_qrs_min <= ra.risk_score <= scenario.expected_qrs_max, (
        f"{scenario.scenario_id}: QRS {ra.risk_score} outside "
        f"[{scenario.expected_qrs_min}, {scenario.expected_qrs_max}]"
    )
    assert ra.category == scenario.expected_category
    assert assessment.final_category == scenario.expected_category  # no ML ran (anomaly_detector=None)
    assert (
        should_isolate(assessment, DEFAULT_RISK_ISOLATION_THRESHOLD)
        == scenario.expected_isolation_request
    )


def test_core_evaluation_is_exactly_five_scenarios() -> None:
    """Freezes the count itself: the Execution Report's target is 5
    scenarios, not 6 — MQTT is additional validation, tracked
    separately (see test_mqtt_scenario_matches_manifest_expectations
    below), and must never be folded into this count."""
    assert len(CORE_EVALUATION_SCENARIOS) == 5


def test_core_scenario_ids_are_unique_and_exactly_the_five_named_cases() -> None:
    scenario_ids = {scenario.scenario_id for scenario in CORE_EVALUATION_SCENARIOS}
    assert len(scenario_ids) == len(CORE_EVALUATION_SCENARIOS), "duplicate scenario_id in manifest"
    assert scenario_ids == {
        "secure_modern_tls",
        "legacy_tls",
        "weak_key_size",
        "plaintext_protocol",
        "high_risk_enforcement",
    }


def test_mqtt_scenario_is_not_among_the_core_five() -> None:
    core_ids = {scenario.scenario_id for scenario in CORE_EVALUATION_SCENARIOS}
    assert MQTT_SCENARIO.scenario_id not in core_ids


def test_every_manifest_pcap_path_exists_on_disk() -> None:
    for scenario in [*CORE_EVALUATION_SCENARIOS, MQTT_SCENARIO]:
        assert scenario.pcap_path.is_file(), f"missing fixture: {scenario.pcap_path}"


def test_high_risk_enforcement_scenario_raw_qrs_at_least_seven() -> None:
    """The specific, literal Phase 14 condition — spelled out on its
    own so it isn't only implied by the parametrized range check."""
    scenario = next(s for s in CORE_EVALUATION_SCENARIOS if s.scenario_id == "high_risk_enforcement")
    _fingerprint, assessment = _assess_single_packet_pcap(scenario.pcap_path)
    assert assessment.risk_assessment.risk_score >= 7
    assert should_isolate(assessment, DEFAULT_RISK_ISOLATION_THRESHOLD) is True


def test_high_risk_enforcement_scenario_flows_through_noop_backend() -> None:
    """The full Phase 14 decision path, genuinely exercised end to
    end: assess_packet -> should_isolate -> NoOpIsolationBackend."""
    from enforcement.backends import NoOpIsolationBackend

    scenario = next(s for s in CORE_EVALUATION_SCENARIOS if s.scenario_id == "high_risk_enforcement")
    _fingerprint, assessment = _assess_single_packet_pcap(scenario.pcap_path)
    assert should_isolate(assessment, DEFAULT_RISK_ISOLATION_THRESHOLD) is True

    outcome = NoOpIsolationBackend().isolate(
        assessment.device.ip, assessment.risk_assessment.risk_score
    )
    assert outcome.requested is True
    assert outcome.enforced is False


# --- MQTT: additional protocol validation, not one of the core five -----


def test_mqtt_fixture_payload_is_genuinely_detected_as_mqtt() -> None:
    """Focused proof the CURRENT detector (unchanged) recognizes a
    genuinely valid MQTT CONNECT packet — the previous inspection's
    finding was that the OLD sample.pcap payload (`b"MQTT-CONNECT-
    PAYLOAD"` on UDP/1883) is not valid MQTT wire format and was never
    a detector bug."""
    payload = build_mqtt_connect()
    assert detect_protocol_type(payload) == ProtocolType.MQTT


def test_mqtt_scenario_matches_manifest_expectations() -> None:
    fingerprint, assessment = _assess_single_packet_pcap(MQTT_SCENARIO.pcap_path)
    ra = assessment.risk_assessment

    assert fingerprint.protocol == ProtocolType.MQTT == MQTT_SCENARIO.expected_protocol
    assert MQTT_SCENARIO.expected_qrs_min <= ra.risk_score <= MQTT_SCENARIO.expected_qrs_max
    assert assessment.final_category == MQTT_SCENARIO.expected_category
    assert (
        should_isolate(assessment, DEFAULT_RISK_ISOLATION_THRESHOLD)
        == MQTT_SCENARIO.expected_isolation_request
    )


# --- entropy targets ("encrypted entropy > 7.5", "HTTP entropy < 5") ----


def test_encrypted_fixture_entropy_exceeds_target() -> None:
    """Measures the REAL entropy/ implementation's output on a genuine
    TLS Application Data record (real ciphertext stand-in) — never the
    secure_modern_tls ServerHello, which is handshake negotiation, sent
    in cleartext even under TLS 1.3, and so is not a faithful
    representation of "encrypted" traffic for this specific target."""
    packets = list(OfflinePcapSource(ENCRYPTED_ENTROPY_PCAP_PATH).read_packets())
    assert len(packets) == 1
    entropy = compute_entropy_metrics(packets[0].payload).shannon_entropy
    assert entropy > ENCRYPTED_ENTROPY_TARGET_MIN, (
        f"encrypted entropy {entropy:.4f} does not exceed the "
        f"{ENCRYPTED_ENTROPY_TARGET_MIN} target"
    )


def test_http_fixture_entropy_is_below_target() -> None:
    """Reuses the plaintext_protocol core scenario's own real HTTP
    GET request fixture -- no separate fixture needed, since it's
    already a faithful representation of plaintext traffic."""
    packets = list(OfflinePcapSource(HTTP_ENTROPY_PCAP_PATH).read_packets())
    assert len(packets) == 1
    entropy = compute_entropy_metrics(packets[0].payload).shannon_entropy
    assert entropy < HTTP_ENTROPY_TARGET_MAX, (
        f"HTTP entropy {entropy:.4f} does not stay below the "
        f"{HTTP_ENTROPY_TARGET_MAX} target"
    )


# --- known-safe set / false-positive evaluation -------------------------


def test_known_safe_set_has_expected_count() -> None:
    packets = list(OfflinePcapSource(KNOWN_SAFE_SET_PCAP_PATH).read_packets())
    assert len(packets) == KNOWN_SAFE_SET_EXPECTED_COUNT


def test_known_safe_set_all_remain_within_the_safe_threshold() -> None:
    """The controlled false-positive criterion (see evaluate_demo.py
    and docs/SDD.md's Phase 15 evaluation addendum): a known-safe
    observation is "flagged" iff its final_category != LOW (the exact
    same rule reports/pdf_generator.is_flagged_device already uses for
    report-generation eligibility). This is a loose safety-ceiling
    check, not the primary source of the measured false-positive rate
    -- evaluate_demo.py is."""
    packets = list(OfflinePcapSource(KNOWN_SAFE_SET_PCAP_PATH).read_packets())
    flagged = 0
    for raw_packet in packets:
        device = Device.first_contact(raw_packet.src_ip, raw_packet.timestamp)
        fingerprint = fingerprint_packet(raw_packet.payload)
        port_risk = port_risk_for_protocol(fingerprint.protocol)
        assessment = assess_packet(raw_packet, device, port_risk, None, assessed_at=FIXED_ASSESSED_AT)
        if assessment.final_category != RiskCategory.LOW:
            flagged += 1
    assert flagged == 0, f"{flagged}/{len(packets)} known-safe observations were flagged"


# --- demo_presentation.pcap ----------------------------------------------


def test_demo_presentation_fixture_has_a_low_medium_and_high_device() -> None:
    packets = list(OfflinePcapSource(DEMO_PRESENTATION_PCAP_PATH).read_packets())
    categories = set()
    for raw_packet in packets:
        device = Device.first_contact(raw_packet.src_ip, raw_packet.timestamp)
        fingerprint = fingerprint_packet(raw_packet.payload)
        port_risk = port_risk_for_protocol(fingerprint.protocol)
        assessment = assess_packet(raw_packet, device, port_risk, None, assessed_at=FIXED_ASSESSED_AT)
        categories.add(assessment.final_category)

    assert RiskCategory.LOW in categories
    assert RiskCategory.MEDIUM in categories
    assert RiskCategory.HIGH in categories


def test_sample_pcap_is_unmodified_by_this_work() -> None:
    """Sentinel: tests/fixtures/sample.pcap must still contain exactly
    the 3 original yielded packets (2 filtered out) — Phase 15
    evaluation work must never touch it."""
    from tests.fixtures.generate_fixtures import SAMPLE_PCAP_PATH

    packets = list(OfflinePcapSource(SAMPLE_PCAP_PATH).read_packets())
    assert len(packets) == 3
