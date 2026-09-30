"""Verifies the Phase 2A controlled labelled evaluation dataset against
tests/fixtures/labelled_evaluation_manifest.py's declared ground truth,
through the REAL CIPHER pipeline (capture -> fingerprint -> entropy -> QRS
-> fusion -> should_isolate) — never a hand-constructed RiskAssessment or
DeviceAssessment standing in for a packet.

This is the Quantum Risk Score specification-conformance test suite. It
proves the manifest's declared expectations are what the frozen
implementation actually produces, so evaluate_research.py's reported
conformance figures cannot drift unnoticed, and so any future change to
scoring, fingerprinting or entropy fails here with the specific
observation named.

It deliberately does NOT assert that the specification is correct or that
the external security labels are right — only that implementation and
declaration agree.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from capture.offline_source import OfflinePcapSource
from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD
from enforcement.decision import should_isolate
from entropy.engine import compute_entropy_metrics
from fingerprint.protocol import fingerprint_packet
from models.device import Device
from models.enums import RiskCategory
from pipeline.assessment_pipeline import assess_packet
from risk.port_risk import port_risk_for_protocol
from risk.scoring import category_for_score, entropy_risk, key_size_risk, tls_version_risk
from tests.fixtures.generate_labelled_evaluation_fixtures import (
    LABELLED_PACKET_SPECS,
    LABELLED_SET_PCAP,
    LABELLED_SET_SIZE,
    RSA_CERTIFICATE_ENTROPY_FLOOR,
    build_labelled_packets,
    build_rsa_certificate_handshake,
    build_telnet_negotiation_variant,
    build_tls13_client_hello,
    build_tls13_server_hello,
)
from tests.fixtures.labelled_evaluation_manifest import (
    BINARY_OBSERVATIONS,
    EXPECTED_OBSERVATION_COUNT,
    EXTERNAL_LABELS,
    GROUPS,
    LABEL_EXCLUDED,
    LABEL_RISKY,
    LABEL_SAFE,
    LABELLED_OBSERVATION_COUNT,
    LABELLED_OBSERVATIONS,
    LabelledObservation,
    group_counts,
    label_counts,
    observation_by_scenario_id,
)

FIXED_ASSESSED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _packets_by_source_ip() -> dict:
    packets = {}
    for raw_packet in OfflinePcapSource(LABELLED_SET_PCAP).read_packets():
        packets[raw_packet.src_ip] = raw_packet
    return packets


@pytest.fixture(scope="module")
def packets() -> dict:
    return _packets_by_source_ip()


def _assess(raw_packet):
    device = Device.first_contact(raw_packet.src_ip, raw_packet.timestamp)
    fingerprint = fingerprint_packet(raw_packet.payload)
    port_risk = port_risk_for_protocol(fingerprint.protocol)
    assessment = assess_packet(
        raw_packet, device, port_risk, None, assessed_at=FIXED_ASSESSED_AT
    )
    return fingerprint, port_risk, assessment


# --- manifest integrity ---------------------------------------------------


def test_manifest_has_the_expected_number_of_observations() -> None:
    assert LABELLED_OBSERVATION_COUNT == EXPECTED_OBSERVATION_COUNT


def test_dataset_size_is_within_the_approved_range() -> None:
    """The approved Phase 2A design targets roughly 25-40 deterministic
    observations — small enough to stay reproducible and reviewable, large
    enough for the strata to be meaningful, and deliberately not inflated
    with near-duplicates."""
    assert 25 <= LABELLED_OBSERVATION_COUNT <= 40


def test_scenario_ids_are_unique() -> None:
    ids = [observation.scenario_id for observation in LABELLED_OBSERVATIONS]
    assert len(set(ids)) == len(ids)


def test_source_ips_are_unique() -> None:
    """src_ip is the join key between the generator, the manifest and the
    runner — a duplicate would silently collapse two observations."""
    ips = [observation.src_ip for observation in LABELLED_OBSERVATIONS]
    assert len(set(ips)) == len(ips)


def test_manifest_and_generator_describe_exactly_the_same_observations() -> None:
    """Ground truth and packet construction live in separate modules by
    design; this is what keeps them from drifting apart."""
    manifest_ids = {observation.scenario_id for observation in LABELLED_OBSERVATIONS}
    generator_ids = {spec.scenario_id for spec in LABELLED_PACKET_SPECS}
    assert manifest_ids == generator_ids

    manifest_ips = {
        observation.scenario_id: observation.src_ip
        for observation in LABELLED_OBSERVATIONS
    }
    generator_ips = {spec.scenario_id: spec.src_ip for spec in LABELLED_PACKET_SPECS}
    assert manifest_ips == generator_ips


def test_manifest_count_matches_generator_count() -> None:
    assert LABELLED_OBSERVATION_COUNT == LABELLED_SET_SIZE


@pytest.mark.parametrize(
    "observation", LABELLED_OBSERVATIONS, ids=lambda o: o.scenario_id
)
def test_every_observation_is_completely_specified(
    observation: LabelledObservation,
) -> None:
    assert observation.scenario_id
    assert observation.src_ip
    assert observation.description.strip()
    assert observation.group in GROUPS
    assert observation.external_security_label in EXTERNAL_LABELS
    assert observation.security_rationale.strip()
    assert 0 <= observation.qrs_expected_total <= 10
    assert isinstance(observation.qrs_expected_category, RiskCategory)
    assert isinstance(observation.qrs_expected_isolation_eligible, bool)


def test_manifest_isolation_threshold_matches_the_frozen_constant() -> None:
    """The manifest declares the threshold its eligibility expectations
    were written against rather than importing config/; this is the check
    that keeps the two in step."""
    for observation in LABELLED_OBSERVATIONS:
        assert observation.ISOLATION_THRESHOLD == DEFAULT_RISK_ISOLATION_THRESHOLD


@pytest.mark.parametrize(
    "observation", LABELLED_OBSERVATIONS, ids=lambda o: o.scenario_id
)
def test_declared_category_is_consistent_with_the_declared_score(
    observation: LabelledObservation,
) -> None:
    """Cross-checks the manifest's own two declarations against the real
    threshold function, so a hand-typed category cannot contradict its
    score."""
    assert category_for_score(observation.qrs_expected_total) == (
        observation.qrs_expected_category
    )


def test_all_three_risk_categories_and_all_four_groups_are_represented() -> None:
    categories = {
        observation.qrs_expected_category for observation in LABELLED_OBSERVATIONS
    }
    assert categories == {RiskCategory.LOW, RiskCategory.MEDIUM, RiskCategory.HIGH}

    counts = group_counts()
    assert all(counts[group] > 0 for group in GROUPS), counts


def test_both_binary_classes_and_the_excluded_class_are_populated() -> None:
    counts = label_counts()
    assert counts[LABEL_SAFE] > 0
    assert counts[LABEL_RISKY] > 0
    assert counts[LABEL_EXCLUDED] > 0
    assert sum(counts.values()) == LABELLED_OBSERVATION_COUNT


def test_binary_observations_exclude_only_the_excluded_label() -> None:
    assert len(BINARY_OBSERVATIONS) == (
        LABELLED_OBSERVATION_COUNT - label_counts()[LABEL_EXCLUDED]
    )
    for observation in BINARY_OBSERVATIONS:
        assert observation.external_security_label in (LABEL_SAFE, LABEL_RISKY)
        assert observation.participates_in_binary_metrics is True


def test_excluded_observations_refuse_to_supply_a_binary_label() -> None:
    """Returning False for an EXCLUDED observation would silently count it
    as safe, which is exactly the fabrication the rubric forbids."""
    excluded = [
        observation
        for observation in LABELLED_OBSERVATIONS
        if observation.external_security_label == LABEL_EXCLUDED
    ]
    assert excluded
    for observation in excluded:
        assert observation.participates_in_binary_metrics is False
        with pytest.raises(ValueError, match="no binary security label"):
            _ = observation.is_externally_risky


def test_risky_and_safe_observations_report_their_binary_truth_value() -> None:
    for observation in BINARY_OBSERVATIONS:
        expected = observation.external_security_label == LABEL_RISKY
        assert observation.is_externally_risky is expected


def test_observation_lookup_by_scenario_id() -> None:
    found = observation_by_scenario_id("telnet_negotiation_a")
    assert found.external_security_label == LABEL_RISKY
    with pytest.raises(KeyError, match="no labelled observation"):
        observation_by_scenario_id("does-not-exist")


# --- manifest self-consistency validation --------------------------------


def _valid_kwargs(**overrides) -> dict:
    kwargs = {
        "scenario_id": "probe",
        "src_ip": "192.168.99.1",
        "group": GROUPS[0],
        "description": "probe",
        "expected_protocol": LABELLED_OBSERVATIONS[0].expected_protocol,
        "qrs_expected_tls_risk": 2,
        "qrs_expected_key_size_risk": 0,
        "qrs_expected_pfs_risk": 1,
        "qrs_expected_entropy_risk": 2,
        "qrs_expected_port_risk": 1,
        "qrs_expected_total": 6,
        "qrs_expected_category": RiskCategory.MEDIUM,
        "qrs_expected_isolation_eligible": False,
        "external_security_label": LABEL_RISKY,
        "security_rationale": "probe rationale",
    }
    kwargs.update(overrides)
    return kwargs


def test_valid_probe_observation_constructs() -> None:
    assert LabelledObservation(**_valid_kwargs()).qrs_expected_total == 6


def test_manifest_rejects_components_that_do_not_sum_to_the_total() -> None:
    with pytest.raises(ValueError, match="components sum to"):
        LabelledObservation(**_valid_kwargs(qrs_expected_total=7))


def test_manifest_rejects_an_unknown_group() -> None:
    with pytest.raises(ValueError, match="unknown group"):
        LabelledObservation(**_valid_kwargs(group="not-a-group"))


def test_manifest_rejects_an_unknown_external_label() -> None:
    with pytest.raises(ValueError, match="unknown external_security_label"):
        LabelledObservation(**_valid_kwargs(external_security_label="PROBABLY_FINE"))


def test_manifest_rejects_an_empty_rationale() -> None:
    with pytest.raises(ValueError, match="security_rationale must not be empty"):
        LabelledObservation(**_valid_kwargs(security_rationale="   "))


def test_manifest_rejects_an_isolation_expectation_contradicting_the_score() -> None:
    with pytest.raises(ValueError, match="qrs_expected_isolation_eligible"):
        LabelledObservation(**_valid_kwargs(qrs_expected_isolation_eligible=True))


def test_manifest_rejects_a_total_outside_the_formula_range() -> None:
    with pytest.raises(ValueError, match=r"outside the formula's \[0, 10\] range"):
        LabelledObservation(
            **_valid_kwargs(qrs_expected_tls_risk=20, qrs_expected_total=24)
        )


# --- the real pipeline vs. declared ground truth --------------------------


def test_pcap_contains_exactly_the_manifest_observations(packets: dict) -> None:
    assert len(packets) == LABELLED_OBSERVATION_COUNT
    assert set(packets) == {
        observation.src_ip for observation in LABELLED_OBSERVATIONS
    }


@pytest.mark.parametrize(
    "observation", LABELLED_OBSERVATIONS, ids=lambda o: o.scenario_id
)
def test_actual_protocol_matches_declared_expectation(
    observation: LabelledObservation, packets: dict
) -> None:
    fingerprint, _port_risk, _assessment = _assess(packets[observation.src_ip])
    assert fingerprint.protocol == observation.expected_protocol


@pytest.mark.parametrize(
    "observation", LABELLED_OBSERVATIONS, ids=lambda o: o.scenario_id
)
def test_actual_qrs_matches_declared_expectation(
    observation: LabelledObservation, packets: dict
) -> None:
    _fingerprint, _port_risk, assessment = _assess(packets[observation.src_ip])
    assert assessment.risk_assessment.risk_score == observation.qrs_expected_total


@pytest.mark.parametrize(
    "observation", LABELLED_OBSERVATIONS, ids=lambda o: o.scenario_id
)
def test_actual_category_matches_declared_expectation(
    observation: LabelledObservation, packets: dict
) -> None:
    _fingerprint, _port_risk, assessment = _assess(packets[observation.src_ip])
    assert assessment.risk_assessment.category == observation.qrs_expected_category


@pytest.mark.parametrize(
    "observation", LABELLED_OBSERVATIONS, ids=lambda o: o.scenario_id
)
def test_actual_isolation_eligibility_matches_declared_expectation(
    observation: LabelledObservation, packets: dict
) -> None:
    _fingerprint, _port_risk, assessment = _assess(packets[observation.src_ip])
    eligible = should_isolate(assessment, DEFAULT_RISK_ISOLATION_THRESHOLD)
    assert eligible == observation.qrs_expected_isolation_eligible


@pytest.mark.parametrize(
    "observation", LABELLED_OBSERVATIONS, ids=lambda o: o.scenario_id
)
def test_actual_component_contributions_match_declared_expectations(
    observation: LabelledObservation, packets: dict
) -> None:
    """Per-component conformance: an aggregate score can match by accident
    while two components are individually wrong in opposite directions."""
    raw_packet = packets[observation.src_ip]
    fingerprint, port_risk, _assessment = _assess(raw_packet)
    metrics = compute_entropy_metrics(raw_packet.payload)

    assert tls_version_risk(fingerprint.tls_version) == observation.qrs_expected_tls_risk
    assert key_size_risk(fingerprint.key_size) == observation.qrs_expected_key_size_risk
    assert (0 if fingerprint.forward_secrecy else 1) == observation.qrs_expected_pfs_risk
    assert entropy_risk(metrics.shannon_entropy) == observation.qrs_expected_entropy_risk
    assert port_risk == observation.qrs_expected_port_risk


@pytest.mark.parametrize(
    "observation", LABELLED_OBSERVATIONS, ids=lambda o: o.scenario_id
)
def test_declared_components_sum_to_the_score_the_engine_produced(
    observation: LabelledObservation, packets: dict
) -> None:
    _fingerprint, _port_risk, assessment = _assess(packets[observation.src_ip])
    component_sum = (
        observation.qrs_expected_tls_risk
        + observation.qrs_expected_key_size_risk
        + observation.qrs_expected_pfs_risk
        + observation.qrs_expected_entropy_risk
        + observation.qrs_expected_port_risk
    )
    assert component_sum == assessment.risk_assessment.risk_score


@pytest.mark.parametrize(
    "observation", LABELLED_OBSERVATIONS, ids=lambda o: o.scenario_id
)
def test_qrs_only_mode_leaves_the_final_category_equal_to_the_qrs_category(
    observation: LabelledObservation, packets: dict
) -> None:
    """With anomaly_detector=None the frozen fusion rule passes the
    rule-based category through unchanged. Asserted per observation so the
    Phase 2A figures are demonstrably free of any ML influence."""
    _fingerprint, _port_risk, assessment = _assess(packets[observation.src_ip])
    assert assessment.anomaly_assessment is None
    assert assessment.final_category == assessment.risk_assessment.category
    assert assessment.final_category == observation.qrs_expected_category


# --- fixture construction properties ------------------------------------


def test_deterministic_payloads_are_byte_for_byte_reproducible() -> None:
    """Every payload except the two randomly-keyed RSA certificates must
    rebuild identically, so a regenerated pcap yields identical scores."""
    randomly_keyed = {"rsa2048_certificate", "rsa3072_certificate"}
    for spec in LABELLED_PACKET_SPECS:
        if spec.scenario_id in randomly_keyed:
            continue
        assert spec.build_payload() == spec.build_payload(), spec.scenario_id


def test_randomly_keyed_rsa_certificates_keep_a_wide_entropy_margin() -> None:
    """The two documented non-reproducible observations. Their bytes differ
    per regeneration, so what must hold is that measured entropy stays far
    from the 7.0 scoring boundary — which is why their declared
    entropy_risk of 0 is stable despite the random key."""
    for bits in (2048, 3072):
        for _ in range(3):
            payload = build_rsa_certificate_handshake(bits)
            entropy = compute_entropy_metrics(payload).shannon_entropy
            assert entropy > RSA_CERTIFICATE_ENTROPY_FLOOR, (bits, entropy)
            assert entropy_risk(entropy) == 0


def test_rsa1024_boundary_case_is_deliberately_absent() -> None:
    """Per the approved Phase 2A decisions: its measured entropy sits within
    0.01 of the 7.0 boundary with a random key, so its score would be
    unstable. It is omitted rather than reported as a flaky result."""
    assert not any(
        "rsa1024" in spec.scenario_id.lower() for spec in LABELLED_PACKET_SPECS
    )


def test_every_observation_entropy_stays_clear_of_a_scoring_boundary(
    packets: dict,
) -> None:
    """The declared entropy_risk values are only trustworthy if no
    observation sits on a knife edge. Boundaries are 6.0 and 7.0; the
    narrowest real margin in this dataset is ~0.14 bits/byte."""
    for observation in LABELLED_OBSERVATIONS:
        entropy = compute_entropy_metrics(
            packets[observation.src_ip].payload
        ).shannon_entropy
        for boundary in (6.0, 7.0):
            assert abs(entropy - boundary) > 0.1, (observation.scenario_id, entropy)


def test_secure_tls13_observations_use_no_high_entropy_server_side_padding() -> None:
    """The specific flaw in the legacy known-safe fixture that this dataset
    exists to avoid: a ServerHello must not carry an RFC 7685 padding
    extension at all, and ClientHello padding must be zero-filled."""
    padding_extension = bytes([0x00, 0x15])

    for seed in ("probe-a", "probe-b"):
        server_hello = build_tls13_server_hello(seed)
        assert padding_extension not in server_hello
        hybrid = build_tls13_server_hello(seed, hybrid_key_share=True)
        assert padding_extension not in hybrid

    padded = build_tls13_client_hello("probe-pad", pad_to=512)
    assert padding_extension in padded
    # The pad is a genuine run of zero bytes, never entropy-rich filler.
    assert bytes(64) in padded


def test_legacy_known_safe_fixture_is_not_reused_as_the_secure_baseline() -> None:
    """The Phase 15 known-safe set stays untouched for continuity, but must
    not leak into this scientific dataset."""
    import tests.fixtures.generate_labelled_evaluation_fixtures as generator

    source_names = set(dir(generator))
    assert "build_known_safe_variant" not in source_names
    assert "KNOWN_SAFE_SET_PCAP" not in source_names


def test_hybrid_post_quantum_observations_advertise_the_pq_named_group() -> None:
    """X25519MLKEM768 (0x11EC) must actually be on the wire — the hybrid
    observations are the dataset's strongest secure configuration and would
    be mislabelled if the group were absent."""
    pq_group = bytes([0x11, 0xEC])
    assert pq_group in build_tls13_client_hello("probe-pq", hybrid_key_share=True)
    assert pq_group in build_tls13_server_hello("probe-pq", hybrid_key_share=True)
    assert pq_group not in build_tls13_client_hello("probe-classical")


def test_telnet_variant_builder_rejects_an_unknown_variant() -> None:
    with pytest.raises(ValueError, match="unknown telnet variant"):
        build_telnet_negotiation_variant(99)


def test_build_labelled_packets_produces_one_packet_per_specification() -> None:
    built = build_labelled_packets()
    assert len(built) == LABELLED_SET_SIZE


def test_generating_the_dataset_leaves_existing_fixtures_untouched() -> None:
    """A guard on the promise that this phase adds a fixture rather than
    modifying any existing one."""
    from tests.fixtures.generate_evaluation_fixtures import (
        DEMO_PRESENTATION_PCAP,
        KNOWN_SAFE_SET_PCAP,
        SECURE_TLS13_PCAP,
    )
    from tests.fixtures.generate_fixtures import SAMPLE_PCAP_PATH

    protected = (
        SAMPLE_PCAP_PATH,
        DEMO_PRESENTATION_PCAP,
        KNOWN_SAFE_SET_PCAP,
        SECURE_TLS13_PCAP,
    )
    before = {path: path.read_bytes() for path in protected if path.exists()}

    from tests.fixtures.generate_labelled_evaluation_fixtures import main

    main()

    for path, contents in before.items():
        assert path.read_bytes() == contents, path
    assert LABELLED_SET_PCAP.exists()
