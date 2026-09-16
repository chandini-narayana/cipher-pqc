"""evaluate_demo.py — Phase 15 controlled evaluation harness (docs/SDD.md's
Phase 15 evaluation addendum).

Runs the CORE FIVE evaluation scenarios (tests/fixtures/
generate_evaluation_fixtures.py, expectations in tests/fixtures/
evaluation_manifest.py's CORE_EVALUATION_SCENARIOS) — exactly matching
the Execution Report's stated 5-scenario target, never 6 — through the
REAL, unmodified CIPHER pipeline: fingerprint_packet ->
port_risk_for_protocol -> assess_packet -> should_isolate ->
NoOpIsolationBackend, and generate_report/verify_report for
tamper-detection. MQTT protocol detection is run and reported
separately, as ADDITIONAL VALIDATION — a real coverage gap this phase
closed, but never counted toward the "x/5" core figure.

Everything measured here comes from actually calling CIPHER's own
production functions; nothing is hardcoded or fabricated. This is a
CONTROLLED, SYNTHETIC evaluation on fixtures this project built for
itself, run on controlled local synthetic/offline observations on this
machine — not a real-world network validation, not Raspberry
Pi/live-network latency, and not a research-grade Isolation Forest
accuracy claim (see the printed notice below and docs/SDD.md).

Never starts a Flask server and never binds a port — see
measure_startup.py (run separately) for the startup-time measurement.
"""
from __future__ import annotations

import json
import logging
import statistics
import sys
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import List, Tuple

from capture.offline_source import OfflinePcapSource
from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD
from config.settings import load_settings
from entropy.engine import compute_entropy_metrics
from enforcement.backends import NoOpIsolationBackend
from enforcement.decision import should_isolate
from fingerprint.protocol import fingerprint_packet
from ml.classifier import AnomalyDetector
from ml.loading import load_anomaly_detector
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from pipeline.assessment_pipeline import assess_packet
from reports.pdf_generator import generate_report, verify_report
from risk.port_risk import port_risk_for_protocol
from signing import generate_keypair, sign_assessment, verify_signed_event
from tests.fixtures.evaluation_manifest import (
    CORE_EVALUATION_SCENARIOS,
    ENCRYPTED_ENTROPY_PCAP_PATH,
    ENCRYPTED_ENTROPY_TARGET_MIN,
    HTTP_ENTROPY_PCAP_PATH,
    HTTP_ENTROPY_TARGET_MAX,
    KNOWN_SAFE_SET_PCAP_PATH,
    MQTT_SCENARIO,
)

REPO_ROOT = Path(__file__).resolve().parent
RESULTS_DIR = REPO_ROOT / "data" / "evaluation"
RESULTS_PATH = RESULTS_DIR / "latest_results.json"

LATENCY_TRIAL_COUNT = 50  # repeated per scenario, for a stable mean/p95/max
ASSESSMENT_LATENCY_TARGET_MS = 500.0
FALSE_POSITIVE_TARGET_MAX = 0.10  # Execution Report: "false positives < 10%"
STARTUP_TARGET_SECONDS = 30.0  # measured separately by measure_startup.py

FALSE_POSITIVE_CRITERION = (
    "A known-safe observation counts as 'flagged' iff its final_category "
    "!= LOW -- the same rule reports/pdf_generator.py's is_flagged_device() "
    "already uses to decide report-generation eligibility. This is a "
    "CONTROLLED, SYNTHETIC evaluation set (tests/fixtures/"
    "evaluation_known_safe_set.pcap), not a measurement of real-world "
    "network false-positive performance."
)


def _load_single_packet(pcap_path: Path):
    packets = list(OfflinePcapSource(pcap_path).read_packets())
    assert len(packets) == 1, f"{pcap_path} must contain exactly one packet"
    return packets[0]


def _assess(raw_packet, anomaly_detector) -> Tuple[float, DeviceAssessment]:
    """Returns (latency_seconds, assessment): latency covers exactly
    "packet ready -> DeviceAssessment returned" (assess_packet() alone),
    not fingerprinting/port_risk lookup, which are cheap, already-timed-
    elsewhere pre-steps rather than part of the assessment itself."""
    device = Device.first_contact(raw_packet.src_ip, raw_packet.timestamp)
    fingerprint = fingerprint_packet(raw_packet.payload)
    port_risk = port_risk_for_protocol(fingerprint.protocol)
    start = perf_counter()
    assessment = assess_packet(raw_packet, device, port_risk, anomaly_detector)
    elapsed = perf_counter() - start
    return elapsed, assessment


def _percentile(values: List[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(pct / 100.0 * (len(ordered) - 1))))
    return ordered[index]


def _latency_stats(samples_seconds: List[float]) -> dict:
    samples_ms = [s * 1000.0 for s in samples_seconds]
    return {
        "unit": "milliseconds",
        "sample_count": len(samples_ms),
        "mean_ms": round(statistics.mean(samples_ms), 4) if samples_ms else 0.0,
        "p95_ms": round(_percentile(samples_ms, 95), 4),
        "max_ms": round(max(samples_ms), 4) if samples_ms else 0.0,
    }


def _scenario_row(scenario, anomaly_detector) -> dict:
    raw_packet = _load_single_packet(scenario.pcap_path)
    _elapsed, assessment = _assess(raw_packet, anomaly_detector)
    ra = assessment.risk_assessment
    fingerprint = fingerprint_packet(raw_packet.payload)
    isolation_required = should_isolate(assessment, DEFAULT_RISK_ISOLATION_THRESHOLD)

    passed = (
        fingerprint.protocol == scenario.expected_protocol
        and scenario.expected_qrs_min <= ra.risk_score <= scenario.expected_qrs_max
        and assessment.final_category == scenario.expected_category
        and isolation_required == scenario.expected_isolation_request
    )
    return {
        "scenario_id": scenario.scenario_id,
        "description": scenario.description,
        "detected_protocol": fingerprint.protocol.value,
        "qrs": ra.risk_score,
        "qrs_category": ra.category.value,
        "final_category": assessment.final_category.value,
        "anomaly_available": assessment.anomaly_assessment is not None,
        "anomaly_detected": (
            assessment.anomaly_assessment.is_anomaly
            if assessment.anomaly_assessment is not None
            else None
        ),
        "isolation_required": isolation_required,
        "isolation_physically_enforced": False,  # NoOp only -- never claimed otherwise
        "expected_qrs_range": [scenario.expected_qrs_min, scenario.expected_qrs_max],
        "expected_category": scenario.expected_category.value,
        "pass": passed,
        "notes": scenario.notes,
    }


def run_core_scenario_table(anomaly_detector) -> List[dict]:
    """The CORE FIVE-SCENARIO EVALUATION only — exactly matching the
    Execution Report's stated target. MQTT is never included here;
    see run_mqtt_auxiliary_check()."""
    return [_scenario_row(scenario, anomaly_detector) for scenario in CORE_EVALUATION_SCENARIOS]


def run_mqtt_auxiliary_check(anomaly_detector) -> dict:
    """ADDITIONAL PROTOCOL VALIDATION — not one of the core five, never
    counted toward the "x/5" figure. Closes a real MQTT-detection
    coverage gap (see tests/fixtures/evaluation_manifest.py)."""
    return _scenario_row(MQTT_SCENARIO, anomaly_detector)


def measure_entropy_targets() -> dict:
    """The Execution Report's entropy targets ("encrypted entropy >
    7.5", "HTTP entropy < 5"), measured directly against the REAL
    entropy/ implementation -- never re-derived or asserted without
    measurement. The encrypted-entropy fixture is genuine TLS
    Application Data (real ciphertext characteristics), deliberately
    NOT the secure_modern_tls core scenario's ServerHello, which is
    handshake negotiation sent in cleartext even under TLS 1.3 and so
    is not a faithful stand-in for "encrypted" traffic for this
    specific target (see tests/fixtures/generate_evaluation_fixtures.py's
    build_encrypted_application_data() docstring for the full reasoning
    and the measured convergence behavior verified against real
    os.urandom output)."""
    encrypted_packet = _load_single_packet(ENCRYPTED_ENTROPY_PCAP_PATH)
    encrypted_entropy = compute_entropy_metrics(encrypted_packet.payload).shannon_entropy

    http_packet = _load_single_packet(HTTP_ENTROPY_PCAP_PATH)
    http_entropy = compute_entropy_metrics(http_packet.payload).shannon_entropy

    return {
        "encrypted_entropy": {
            "actual": round(encrypted_entropy, 4),
            "target": f"> {ENCRYPTED_ENTROPY_TARGET_MIN}",
            "pass": encrypted_entropy > ENCRYPTED_ENTROPY_TARGET_MIN,
        },
        "http_entropy": {
            "actual": round(http_entropy, 4),
            "target": f"< {HTTP_ENTROPY_TARGET_MAX}",
            "pass": http_entropy < HTTP_ENTROPY_TARGET_MAX,
        },
    }


def measure_assessment_latency(anomaly_detector) -> dict:
    """Measured on controlled local synthetic/offline observations on
    this machine -- never Raspberry Pi hardware or live-network
    conditions, which remain unmeasured until Pi integration."""
    packets = [_load_single_packet(s.pcap_path) for s in CORE_EVALUATION_SCENARIOS]
    samples = []
    for _ in range(LATENCY_TRIAL_COUNT):
        for raw_packet in packets:
            elapsed, _assessment = _assess(raw_packet, anomaly_detector)
            samples.append(elapsed)
    return _latency_stats(samples)


def measure_enforcement_decision_latency(anomaly_detector) -> dict:
    """Software enforcement-decision/backend latency: should_isolate()
    + NoOpIsolationBackend.isolate(), timed on this machine. This is
    NEVER physical isolation latency -- Phase 1 has no hardware backend
    (see docs/SDD.md's Phase 14 addendum) -- and must never be reported
    as such. Real physical network isolation latency remains
    unmeasured until Raspberry Pi hardware integration."""
    scenario = next(s for s in CORE_EVALUATION_SCENARIOS if s.scenario_id == "high_risk_enforcement")
    raw_packet = _load_single_packet(scenario.pcap_path)
    _elapsed, assessment = _assess(raw_packet, anomaly_detector)
    backend = NoOpIsolationBackend()

    # NoOpIsolationBackend deliberately logs a WARNING on every call
    # (auditability, see docs/SDD.md's Phase 14 addendum) -- exactly
    # right for a single real decision, but LATENCY_TRIAL_COUNT repeated
    # calls here are a pure timing benchmark, not new decisions worth
    # logging individually. Suppressed only for this loop; the one-shot
    # isolation demonstration below still logs normally.
    backend_logger = logging.getLogger("enforcement.backends")
    previous_level = backend_logger.level
    backend_logger.setLevel(logging.ERROR)
    try:
        samples = []
        for _ in range(LATENCY_TRIAL_COUNT):
            start = perf_counter()
            eligible = should_isolate(assessment, DEFAULT_RISK_ISOLATION_THRESHOLD)
            if eligible:
                backend.isolate(assessment.device.ip, assessment.risk_assessment.risk_score)
            samples.append(perf_counter() - start)
    finally:
        backend_logger.setLevel(previous_level)
    return _latency_stats(samples)


def measure_false_positive_rate(anomaly_detector) -> dict:
    packets = list(OfflinePcapSource(KNOWN_SAFE_SET_PCAP_PATH).read_packets())
    flagged = 0
    for raw_packet in packets:
        _elapsed, assessment = _assess(raw_packet, anomaly_detector)
        if assessment.final_category != RiskCategory.LOW:
            flagged += 1
    total = len(packets)
    rate = flagged / total if total else 0.0
    return {
        "criterion": FALSE_POSITIVE_CRITERION,
        "total_known_safe_observations": total,
        "flagged_count": flagged,
        "false_positive_rate": round(rate, 4),
    }


def _flip_hex_char(value: str) -> str:
    """Flips the first hex character to a different, still-valid hex
    digit, so a tampered hex-validated field (report_hash,
    signature_hex) remains structurally valid but cryptographically
    wrong -- exactly the "corrupted in transit/storage" case, not a
    malformed-input case."""
    flipped = "1" if value[0] != "1" else "2"
    return flipped + value[1:]


def run_tamper_detection_demo() -> dict:
    """Every tamper case here operates on an ephemeral, freshly
    generated keypair and a temporary report directory -- never the
    user's real data/keys/ or data/reports/."""
    public_key, secret_key = generate_keypair()
    other_public_key, _other_secret_key = generate_keypair()

    scenario = next(s for s in CORE_EVALUATION_SCENARIOS if s.scenario_id == "high_risk_enforcement")
    raw_packet = _load_single_packet(scenario.pcap_path)
    _elapsed, assessment = _assess(raw_packet, None)

    tampered_risk_assessment = replace(
        assessment.risk_assessment, risk_score=max(0, assessment.risk_assessment.risk_score - 1)
    )
    tampered_assessment = replace(assessment, risk_assessment=tampered_risk_assessment)

    attempted = 0
    detected = 0
    cases: List[Tuple[str, bool]] = []

    # --- assessment-level: signing.sign_assessment / verify_signed_event ---
    event = sign_assessment(assessment, secret_key)
    cases.append(("assessment: original verifies", verify_signed_event(event, public_key) is True))

    tampered_event_score = replace(event, assessment=tampered_assessment)
    attempted += 1
    ok = verify_signed_event(tampered_event_score, public_key) is False
    detected += int(ok)
    cases.append(("assessment: tampered risk_score is rejected", ok))

    tampered_event_sig = replace(event, signature_hex=_flip_hex_char(event.signature_hex))
    attempted += 1
    ok = verify_signed_event(tampered_event_sig, public_key) is False
    detected += int(ok)
    cases.append(("assessment: tampered signature is rejected", ok))

    attempted += 1
    ok = verify_signed_event(event, other_public_key) is False
    detected += int(ok)
    cases.append(("assessment: wrong public key is rejected", ok))

    # --- report-level: reports.pdf_generator.generate_report / verify_report ---
    with tempfile.TemporaryDirectory(prefix="cipher-tamper-demo-") as tmp_dir:
        _path, metadata = generate_report(assessment, secret_key, public_key, output_dir=tmp_dir)

        cases.append(("report: original verifies", verify_report(metadata, assessment, public_key) is True))

        tampered_hash_metadata = replace(metadata, report_hash=_flip_hex_char(metadata.report_hash))
        attempted += 1
        ok = verify_report(tampered_hash_metadata, assessment, public_key) is False
        detected += int(ok)
        cases.append(("report: tampered report_hash is rejected", ok))

        tampered_sig_metadata = replace(metadata, signature_hex=_flip_hex_char(metadata.signature_hex))
        attempted += 1
        ok = verify_report(tampered_sig_metadata, assessment, public_key) is False
        detected += int(ok)
        cases.append(("report: tampered signature_hex is rejected", ok))

        attempted += 1
        ok = verify_report(metadata, tampered_assessment, public_key) is False
        detected += int(ok)
        cases.append(("report: tampered assessment content is rejected", ok))

        attempted += 1
        ok = verify_report(metadata, assessment, other_public_key) is False
        detected += int(ok)
        cases.append(("report: wrong public key is rejected", ok))

    rate = detected / attempted if attempted else 0.0
    return {
        "tamper_checks_attempted": attempted,
        "tamper_checks_detected": detected,
        "tamper_detection_rate": round(rate, 4),
        "cases": [{"name": name, "passed": passed} for name, passed in cases],
    }


def run_isolation_demonstration(anomaly_detector) -> dict:
    scenario = next(s for s in CORE_EVALUATION_SCENARIOS if s.scenario_id == "high_risk_enforcement")
    raw_packet = _load_single_packet(scenario.pcap_path)
    _elapsed, assessment = _assess(raw_packet, anomaly_detector)

    raw_qrs = assessment.risk_assessment.risk_score
    decision = should_isolate(assessment, DEFAULT_RISK_ISOLATION_THRESHOLD)
    outcome = NoOpIsolationBackend().isolate(assessment.device.ip, raw_qrs)

    print(f"  Raw QRS: {raw_qrs} (isolation threshold: {DEFAULT_RISK_ISOLATION_THRESHOLD})")
    print(f"  Isolation Decision: {'REQUIRED' if decision else 'NOT REQUIRED'}")
    print(f"  Physical Enforcement: {'PERFORMED' if outcome.enforced else 'NOT PERFORMED'}")
    print(f"  Reason: {outcome.reason}")

    return {
        "raw_qrs": raw_qrs,
        "threshold": DEFAULT_RISK_ISOLATION_THRESHOLD,
        "isolation_decision_required": decision,
        "backend_requested": outcome.requested,
        "physically_enforced": outcome.enforced,
        "reason": outcome.reason,
    }


def _print_scenario_table(rows: List[dict]) -> None:
    header = (
        f"{'scenario':<24} {'protocol':<8} {'qrs':>4} {'category':<9} "
        f"{'final':<9} {'isolate?':<9} {'result':<6}"
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        print(
            f"{row['scenario_id']:<24} {row['detected_protocol']:<8} "
            f"{row['qrs']:>4} {row['qrs_category']:<9} {row['final_category']:<9} "
            f"{str(row['isolation_required']):<9} {'PASS' if row['pass'] else 'FAIL':<6}"
        )


def _print_final_target_table(core: dict, additional: dict) -> None:
    core_scenarios = core["scenarios"]
    core_pass_count = sum(1 for row in core_scenarios if row["pass"])

    def _tls_qrs(scenario_id: str) -> int:
        return next(row["qrs"] for row in core_scenarios if row["scenario_id"] == scenario_id)

    startup = core["startup_seconds"]
    startup_display = (
        f"{startup:.2f}s" if startup is not None else "not measured this run (see measure_startup.py)"
    )
    startup_result = (
        ("PASS" if startup < STARTUP_TARGET_SECONDS else "FAIL") if startup is not None else "N/A"
    )

    rows = [
        ("Five controlled scenarios", f"{core_pass_count}/{len(core_scenarios)}", "PASS" if core_pass_count == len(core_scenarios) else "FAIL"),
        (
            "Controlled false-positive rate (<10%)",
            f"{core['false_positive']['false_positive_rate']:.2%}",
            "PASS" if core["false_positive"]["false_positive_rate"] < FALSE_POSITIVE_TARGET_MAX else "FAIL",
        ),
        (
            "Assessment latency (<500ms)",
            f"{core['assessment_latency']['mean_ms']:.3f}ms mean",
            "PASS" if core["assessment_latency"]["mean_ms"] < ASSESSMENT_LATENCY_TARGET_MS else "FAIL",
        ),
        ("TLS 1.0 QRS (7-9)", str(_tls_qrs("legacy_tls")), "PASS" if 7 <= _tls_qrs("legacy_tls") <= 9 else "FAIL"),
        ("TLS 1.3 QRS (0-2)", str(_tls_qrs("secure_modern_tls")), "PASS" if 0 <= _tls_qrs("secure_modern_tls") <= 2 else "FAIL"),
        (
            f"Encrypted entropy (>{ENCRYPTED_ENTROPY_TARGET_MIN})",
            str(core["entropy"]["encrypted_entropy"]["actual"]),
            "PASS" if core["entropy"]["encrypted_entropy"]["pass"] else "FAIL",
        ),
        (
            f"HTTP entropy (<{HTTP_ENTROPY_TARGET_MAX})",
            str(core["entropy"]["http_entropy"]["actual"]),
            "PASS" if core["entropy"]["http_entropy"]["pass"] else "FAIL",
        ),
        (
            "Tamper detection (100%)",
            f"{core['tamper_detection']['tamper_detection_rate']:.0%}",
            "PASS" if core["tamper_detection"]["tamper_detection_rate"] == 1.0 else "FAIL",
        ),
        ("Startup time (<30s)", startup_display, startup_result),
    ]

    print("CORE EXECUTION REPORT TARGETS")
    width = max(len(r[0]) for r in rows) + 2
    for name, measured, result in rows:
        print(f"  {name:<{width}} {measured:<28} {result}")

    print()
    print("ADDITIONAL VALIDATION (not part of the Execution Report's 5-scenario/target count)")
    mqtt_row = additional["mqtt"]
    print(f"  {'MQTT protocol detection':<{width}} {mqtt_row['detected_protocol']:<28} {'PASS' if mqtt_row['pass'] else 'FAIL'}")
    enf = additional["enforcement_decision_latency"]
    print(
        f"  {'Software enforcement-decision/backend latency':<{width}} "
        f"{enf['mean_ms']:.3f}ms mean{'':<10} (informational -- NoOp software timing only, not physical isolation latency)"
    )


def main(results_path: Path = RESULTS_PATH) -> int:
    """`results_path` defaults to this repo's own data/evaluation/
    directory (a stable, gitignored, project-relative location — see
    module docstring); overridable so tests can redirect it to a
    tmp_path instead of writing into the real checkout."""
    print("=" * 78)
    print("CIPHER Phase 15 -- Controlled Evaluation Harness")
    print("=" * 78)
    print(
        "\nThe CORE evaluation below is exactly the Execution Report's "
        "5-scenario target -- MQTT protocol detection is reported "
        "separately, as ADDITIONAL VALIDATION, and is never counted "
        "toward that figure. Every fixture (tests/fixtures/"
        "generate_evaluation_fixtures.py) is run through the REAL "
        "production pipeline on controlled local synthetic/offline "
        "observations on THIS machine -- not a real-world network "
        "validation, not Raspberry Pi/live-network conditions. Isolation "
        "Forest results (if any) reflect this project's own "
        "synthetically-trained model only, never a research-grade or "
        "real-world anomaly-detection accuracy claim.\n"
    )

    settings = load_settings()
    anomaly_detector: AnomalyDetector = load_anomaly_detector(settings.model_path)
    if anomaly_detector is None:
        print("(No trained anomaly-detection model found -- ML is unavailable for this run; QRS assessment is unaffected.)\n")

    print("=== CORE: five-scenario evaluation table ===")
    core_rows = run_core_scenario_table(anomaly_detector)
    _print_scenario_table(core_rows)
    print()

    print("--- CORE: entropy targets ---")
    entropy = measure_entropy_targets()
    print(
        f"  encrypted entropy = {entropy['encrypted_entropy']['actual']} "
        f"(target {entropy['encrypted_entropy']['target']}) -> "
        f"{'PASS' if entropy['encrypted_entropy']['pass'] else 'FAIL'}"
    )
    print(
        f"  http entropy      = {entropy['http_entropy']['actual']} "
        f"(target {entropy['http_entropy']['target']}) -> "
        f"{'PASS' if entropy['http_entropy']['pass'] else 'FAIL'}"
    )
    print()

    print("--- CORE: assessment latency (controlled local synthetic/offline observations, this machine) ---")
    assessment_latency = measure_assessment_latency(anomaly_detector)
    print(
        f"  mean={assessment_latency['mean_ms']:.3f}ms  "
        f"p95={assessment_latency['p95_ms']:.3f}ms  "
        f"max={assessment_latency['max_ms']:.3f}ms  "
        f"(n={assessment_latency['sample_count']}, target: < {ASSESSMENT_LATENCY_TARGET_MS:.0f}ms -> "
        f"{'PASS' if assessment_latency['mean_ms'] < ASSESSMENT_LATENCY_TARGET_MS else 'FAIL'})"
    )
    print()

    print("--- CORE: isolation demonstration (high_risk_enforcement scenario) ---")
    isolation_demo = run_isolation_demonstration(anomaly_detector)
    print()

    print("--- CORE: controlled false-positive evaluation (synthetic known-safe set) ---")
    fp = measure_false_positive_rate(anomaly_detector)
    print(
        f"  {fp['flagged_count']}/{fp['total_known_safe_observations']} flagged -> "
        f"false_positive_rate={fp['false_positive_rate']:.2%} "
        f"(target: < {FALSE_POSITIVE_TARGET_MAX:.0%})"
    )
    print(f"  Criterion: {fp['criterion']}")
    print()

    print("--- CORE: tamper-detection demo (ephemeral keypair, temporary report copy) ---")
    tamper = run_tamper_detection_demo()
    print(
        f"  {tamper['tamper_checks_detected']}/{tamper['tamper_checks_attempted']} "
        f"tamper cases detected ({tamper['tamper_detection_rate']:.2%})"
    )
    for case in tamper["cases"]:
        print(f"    [{'OK' if case['passed'] else 'FAIL'}] {case['name']}")
    print()

    print("=== ADDITIONAL VALIDATION (not part of the core 5-scenario target) ===")
    mqtt_row = run_mqtt_auxiliary_check(anomaly_detector)
    print(f"  MQTT protocol detection: {mqtt_row['detected_protocol']} -> {'PASS' if mqtt_row['pass'] else 'FAIL'}")
    print(
        "  (Software enforcement-decision/backend latency is reported "
        "below, alongside this — it is NoOp software timing only, never "
        "physical isolation latency, which remains unmeasured until "
        "Raspberry Pi hardware integration.)"
    )
    enforcement_latency = measure_enforcement_decision_latency(anomaly_detector)
    print(
        f"  Software enforcement-decision/backend latency: "
        f"mean={enforcement_latency['mean_ms']:.3f}ms  "
        f"p95={enforcement_latency['p95_ms']:.3f}ms  "
        f"max={enforcement_latency['max_ms']:.3f}ms  (n={enforcement_latency['sample_count']})"
    )
    print()

    core = {
        "scenarios": core_rows,
        "scenarios_passed": f"{sum(1 for r in core_rows if r['pass'])}/{len(core_rows)}",
        "entropy": entropy,
        "assessment_latency": assessment_latency,
        "assessment_latency_target_ms": ASSESSMENT_LATENCY_TARGET_MS,
        "assessment_latency_note": "measured on controlled local synthetic/offline observations on this machine -- not Raspberry Pi or live-network conditions",
        "isolation_demonstration": isolation_demo,
        "false_positive": fp,
        "false_positive_target_max": FALSE_POSITIVE_TARGET_MAX,
        "tamper_detection": tamper,
        "startup_seconds": None,
        "startup_target_seconds": STARTUP_TARGET_SECONDS,
    }
    additional = {
        "mqtt": mqtt_row,
        "enforcement_decision_latency": enforcement_latency,
        "enforcement_decision_latency_note": "software-only NoOp should_isolate()+isolate() timing, NEVER physical isolation latency; real physical network isolation latency remains unmeasured until Raspberry Pi integration",
    }

    print("=" * 78)
    _print_final_target_table(core, additional)
    print("=" * 78)

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "core": core,
        "additional": additional,
        "notes": (
            "CORE matches the Execution Report's 5-scenario target "
            "exactly; ADDITIONAL VALIDATION (MQTT detection, software "
            "enforcement-decision/backend latency) is never counted "
            "toward that target. Controlled/synthetic evaluation on "
            "fixtures this project built for itself, measured on this "
            "machine -- not a real-world network validation, not "
            "Raspberry Pi/live-network latency. Isolation Forest outputs, "
            "if present, reflect this project's own synthetically-trained "
            "model only. Startup timing is measured separately by "
            "measure_startup.py (never here, since this script never "
            "starts a server) -- run it and merge its printed "
            "startup_seconds into this file's 'core.startup_seconds' "
            "field if a single combined artifact is wanted."
        ),
    }

    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps(result, indent=2))
    print(f"Full machine-readable results written to {results_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
