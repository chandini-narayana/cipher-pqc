"""Unit tests for evaluate_demo.py — the Phase 15 controlled evaluation
harness (docs/SDD.md's Phase 15 evaluation addendum).

Exercises the harness's individual functions directly (never
evaluate_demo.main() with its real, project-relative default
results_path) so nothing here writes into this checkout's real
data/evaluation/ — see test_main_writes_a_valid_structured_json_result
below for the one exception, which redirects results_path to tmp_path.
"""
from __future__ import annotations

import json

import pytest

import evaluate_demo


def test_core_scenario_table_has_five_rows_and_all_pass() -> None:
    """Exactly 5 -- the Execution Report's target -- never 6; MQTT is
    reported separately (see test_mqtt_auxiliary_check_passes)."""
    rows = evaluate_demo.run_core_scenario_table(None)
    assert len(rows) == 5
    assert all(row["pass"] for row in rows), [r for r in rows if not r["pass"]]


def test_core_scenario_table_includes_exactly_the_five_named_scenarios() -> None:
    rows = evaluate_demo.run_core_scenario_table(None)
    ids = {row["scenario_id"] for row in rows}
    assert ids == {
        "secure_modern_tls",
        "legacy_tls",
        "weak_key_size",
        "plaintext_protocol",
        "high_risk_enforcement",
    }
    assert "mqtt_protocol_detection" not in ids


def test_core_scenario_table_never_claims_physical_enforcement() -> None:
    rows = evaluate_demo.run_core_scenario_table(None)
    assert all(row["isolation_physically_enforced"] is False for row in rows)


def test_mqtt_auxiliary_check_passes_and_is_labeled_additional() -> None:
    row = evaluate_demo.run_mqtt_auxiliary_check(None)
    assert row["scenario_id"] == "mqtt_protocol_detection"
    assert row["detected_protocol"] == "MQTT"
    assert row["pass"] is True
    assert row["isolation_physically_enforced"] is False


def test_entropy_targets_measured_against_real_fixtures() -> None:
    result = evaluate_demo.measure_entropy_targets()

    assert result["encrypted_entropy"]["actual"] > evaluate_demo.ENCRYPTED_ENTROPY_TARGET_MIN
    assert result["encrypted_entropy"]["pass"] is True

    assert result["http_entropy"]["actual"] < evaluate_demo.HTTP_ENTROPY_TARGET_MAX
    assert result["http_entropy"]["pass"] is True


def test_false_positive_rate_is_zero_on_the_known_safe_set() -> None:
    result = evaluate_demo.measure_false_positive_rate(None)
    assert result["total_known_safe_observations"] == 10
    assert result["flagged_count"] == 0
    assert result["false_positive_rate"] == 0.0
    assert result["false_positive_rate"] < evaluate_demo.FALSE_POSITIVE_TARGET_MAX
    assert "CONTROLLED" in result["criterion"] or "controlled" in result["criterion"].lower()


def test_isolation_demonstration_matches_frozen_phase_14_wording() -> None:
    result = evaluate_demo.run_isolation_demonstration(None)
    assert result["raw_qrs"] >= 7
    assert result["isolation_decision_required"] is True
    assert result["backend_requested"] is True
    assert result["physically_enforced"] is False
    assert result["reason"] == "Hardware enforcement unavailable in current deployment"


def test_tamper_detection_demo_detects_every_controlled_case() -> None:
    result = evaluate_demo.run_tamper_detection_demo()
    assert result["tamper_checks_attempted"] > 0
    assert result["tamper_checks_detected"] == result["tamper_checks_attempted"]
    assert result["tamper_detection_rate"] == 1.0
    assert all(case["passed"] for case in result["cases"])


def test_tamper_detection_demo_operates_on_ephemeral_keys_and_temp_files(tmp_path, monkeypatch) -> None:
    """Sentinel: this must never touch the real data/keys/ or
    data/reports/ — run it with cwd redirected to a fresh tmp_path and
    confirm nothing appears there."""
    monkeypatch.chdir(tmp_path)
    evaluate_demo.run_tamper_detection_demo()
    assert not (tmp_path / "data").exists()


def test_latency_stats_shape() -> None:
    stats = evaluate_demo._latency_stats([0.001, 0.002, 0.003, 0.004])
    assert stats["unit"] == "milliseconds"
    assert stats["sample_count"] == 4
    assert stats["mean_ms"] == pytest.approx(2.5)
    assert stats["max_ms"] == pytest.approx(4.0)
    assert stats["p95_ms"] <= stats["max_ms"]


def test_latency_stats_empty_input_does_not_raise() -> None:
    stats = evaluate_demo._latency_stats([])
    assert stats["sample_count"] == 0
    assert stats["mean_ms"] == 0.0
    assert stats["max_ms"] == 0.0


def test_assessment_latency_measurement_produces_positive_samples() -> None:
    """Measured on the 5 CORE scenarios only (n = trials * 5), on
    controlled local synthetic/offline observations on this machine."""
    stats = evaluate_demo.measure_assessment_latency(None)
    assert stats["sample_count"] == evaluate_demo.LATENCY_TRIAL_COUNT * 5
    assert stats["mean_ms"] >= 0.0
    assert stats["max_ms"] >= stats["mean_ms"]


def test_enforcement_decision_latency_measurement_produces_positive_samples() -> None:
    stats = evaluate_demo.measure_enforcement_decision_latency(None)
    assert stats["sample_count"] == evaluate_demo.LATENCY_TRIAL_COUNT
    assert stats["mean_ms"] >= 0.0


def test_main_writes_a_valid_structured_json_result_distinguishing_core_and_additional(
    tmp_path, monkeypatch
) -> None:
    """The only test here that calls main() — results_path is
    explicitly redirected to tmp_path, never the real project
    data/evaluation/ directory."""
    monkeypatch.chdir(tmp_path)
    results_path = tmp_path / "results" / "latest_results.json"

    exit_code = evaluate_demo.main(results_path=results_path)

    assert exit_code == 0
    assert results_path.is_file()

    data = json.loads(results_path.read_text())
    assert "timestamp" in data
    assert "core" in data
    assert "additional" in data

    core = data["core"]
    assert len(core["scenarios"]) == 5
    assert core["scenarios_passed"] == "5/5"
    assert {row["scenario_id"] for row in core["scenarios"]} == {
        "secure_modern_tls",
        "legacy_tls",
        "weak_key_size",
        "plaintext_protocol",
        "high_risk_enforcement",
    }
    assert core["entropy"]["encrypted_entropy"]["pass"] is True
    assert core["entropy"]["http_entropy"]["pass"] is True
    assert core["assessment_latency"]["sample_count"] > 0
    assert core["false_positive"]["total_known_safe_observations"] == 10
    assert core["tamper_detection"]["tamper_checks_detected"] == core["tamper_detection"]["tamper_checks_attempted"]
    assert core["isolation_demonstration"]["physically_enforced"] is False
    assert core["startup_seconds"] is None  # measured separately by measure_startup.py

    additional = data["additional"]
    assert additional["mqtt"]["scenario_id"] == "mqtt_protocol_detection"
    assert additional["mqtt"]["pass"] is True
    assert additional["enforcement_decision_latency"]["sample_count"] > 0
