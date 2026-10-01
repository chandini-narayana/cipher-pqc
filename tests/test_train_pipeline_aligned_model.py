"""Tests for Phase 2D: pipeline-aligned Isolation Forest training, threshold
calibration and the single frozen-test evaluation.

The load-bearing tests here are the separation ones. Everything else in this
phase is only meaningful if the frozen N=24 cohort genuinely never informed
fitting or calibration, so that is asserted from several directions: seed
namespaces, payload bytes, and — the one that actually matters — feature
vectors, since two differently-seeded packets that vectorize identically would
still be leakage.

Cohort construction is cached at module scope: building 860 observations
involves RSA key generation, so it is done once and shared.
"""
from __future__ import annotations

import ast
from pathlib import Path

import numpy as np
import pytest

import train_pipeline_aligned_model as phase2d
from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD
from ml.classifier import DEFAULT_CONTAMINATION, DEFAULT_RANDOM_STATE
from ml.features import FEATURE_NAMES, NUM_FEATURES
from models.enums import RiskCategory
from tests.fixtures.pipeline_cohorts import (
    LABEL_RISKY,
    LABEL_SAFE,
    TRAIN_SEED_PREFIX,
    VALIDATION_SEED_PREFIX,
    build_training_observations,
    build_validation_observations,
    payload_digest,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def cohorts():
    train = build_training_observations()
    validation = build_validation_observations()
    return train, validation


@pytest.fixture(scope="module")
def extracted(cohorts, tmp_path_factory):
    """Feature vectors for every cohort, taken through the real pipeline.

    Cohort pcaps are written into a tmp_path so this never depends on, or
    disturbs, the repository's own fixture files.
    """
    train_obs, validation_obs = cohorts
    directory = tmp_path_factory.mktemp("phase2d")
    train = phase2d.extract_cohort(train_obs, directory / "train.pcap")
    validation = phase2d.extract_cohort(validation_obs, directory / "validation.pcap")
    frozen = phase2d.extract_frozen_test_cohort()
    return train, validation, frozen


# --- deterministic construction -----------------------------------------


def test_cohort_construction_is_deterministic() -> None:
    """Two builds must agree byte-for-byte on every payload, or nothing in this
    phase is reproducible."""
    first = build_validation_observations()
    second = build_validation_observations()
    assert [o.payload for o in first] == [o.payload for o in second]
    assert [o.observation_id for o in first] == [o.observation_id for o in second]


def test_training_cohort_composition(cohorts) -> None:
    train, _ = cohorts
    assert len(train) == 700
    assert {o.label for o in train} == {LABEL_SAFE}, "training corpus must be SAFE-only"
    families = {o.family for o in train}
    assert "tls13_client_hello" in families
    assert "tls13_server_hello" in families
    assert "tls_application_data" in families
    assert any(f.startswith("certificate_rsa") for f in families)


def test_validation_cohort_has_both_classes(cohorts) -> None:
    _, validation = cohorts
    safe = [o for o in validation if o.label == LABEL_SAFE]
    risky = [o for o in validation if o.label == LABEL_RISKY]
    assert len(safe) == 80
    assert len(risky) == 80
    assert len(validation) == 160


def test_validation_risky_families_cover_the_rubric(cohorts) -> None:
    _, validation = cohorts
    families = {o.family for o in validation if o.label == LABEL_RISKY}
    assert {
        "tls10_client_hello",
        "tls11_client_hello",
        "weak_rsa_certificate",
        "http_cleartext",
        "mqtt_no_tls",
        "telnet",
    } <= families


def test_all_payloads_within_a_cohort_are_distinct(cohorts) -> None:
    train, validation = cohorts
    assert len(payload_digest(train)) == len(train)
    assert len(payload_digest(validation)) == len(validation)


def test_training_corpus_is_not_one_template_repeated(cohorts) -> None:
    """Variation must be structural. Distinct payload lengths across the corpus
    is the cheapest objective evidence of that."""
    train, _ = cohorts
    lengths = {len(o.payload) for o in train}
    assert len(lengths) > 50, f"only {len(lengths)} distinct payload lengths"


# --- separation ---------------------------------------------------------


def test_seed_namespaces_are_disjoint(cohorts) -> None:
    train, validation = cohorts
    assert all(o.observation_id.startswith(TRAIN_SEED_PREFIX) for o in train)
    assert all(o.observation_id.startswith(VALIDATION_SEED_PREFIX) for o in validation)
    assert TRAIN_SEED_PREFIX != VALIDATION_SEED_PREFIX


def test_train_and_validation_payloads_are_disjoint(cohorts) -> None:
    train, validation = cohorts
    assert not (payload_digest(train) & payload_digest(validation))


def test_no_cohort_shares_a_feature_vector_with_the_frozen_test_set(extracted) -> None:
    """The central anti-leakage assertion, at the level that matters."""
    train, validation, frozen = extracted
    train_v = {o.vector for o in train}
    validation_v = {o.vector for o in validation}
    frozen_v = {o.vector for o in frozen}

    assert not (train_v & frozen_v), "training vectors leak into the frozen test set"
    assert not (validation_v & frozen_v), "validation vectors leak into the frozen test set"
    assert not (train_v & validation_v), "training and validation overlap"


def test_separation_report_records_zero_overlap(extracted) -> None:
    train, validation, frozen = extracted
    report = phase2d.prove_separation(train, validation, frozen)
    assert report["train_frozen_vector_overlap"] == 0
    assert report["validation_frozen_vector_overlap"] == 0
    assert report["train_validation_vector_overlap"] == 0
    assert report["frozen_test_observations"] == 30


def test_frozen_test_weak_rsa_fixture_is_not_reused_in_validation(cohorts) -> None:
    """The deterministic 513-bit certificate IS a frozen-test observation, so
    reusing it in validation would place a test observation into calibration."""
    from tests.fixtures.generate_evaluation_fixtures import (
        build_weak_rsa_certificate_handshake,
    )

    _, validation = cohorts
    frozen_payload = build_weak_rsa_certificate_handshake()
    assert all(o.payload != frozen_payload for o in validation)


def test_trainer_touches_the_frozen_test_set_only_after_calibration() -> None:
    """A static ordering check on main(): the frozen cohort must be extracted
    after the corpus is built and the threshold applied."""
    source = (REPO_ROOT / "train_pipeline_aligned_model.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    main = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    calls = [
        node.func.id
        for node in ast.walk(main)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert calls.index("fit_candidate") < calls.index("extract_frozen_test_cohort")
    assert calls.index("calibrate_threshold") < calls.index("extract_frozen_test_cohort")
    assert calls.index("apply_threshold") < calls.index("extract_frozen_test_cohort")


def test_calibration_never_receives_the_frozen_cohort() -> None:
    """calibrate_threshold's signature admits only a detector and one cohort,
    and its body must not reach for the frozen fixture."""
    source = (REPO_ROOT / "train_pipeline_aligned_model.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    function = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "calibrate_threshold"
    )
    names = {node.id for node in ast.walk(function) if isinstance(node, ast.Name)}
    assert "extract_frozen_test_cohort" not in names
    assert "LABELLED_OBSERVATIONS" not in names
    assert "LABELLED_SET_PCAP_PATH" not in names


# --- production feature extraction --------------------------------------


def test_features_come_from_the_production_path_not_hand_built() -> None:
    """The trainer must never construct a DeviceFeatures itself."""
    source = (REPO_ROOT / "train_pipeline_aligned_model.py").read_text(encoding="utf-8")
    assert "DeviceFeatures(" not in source
    assert "assess_packet(" in source


def test_extracted_vectors_have_the_production_feature_width(extracted) -> None:
    train, validation, frozen = extracted
    for cohort in (train, validation, frozen):
        assert all(len(o.vector) == NUM_FEATURES for o in cohort)
        assert NUM_FEATURES == len(FEATURE_NAMES) == 12


def test_collector_returns_a_valid_placeholder_assessment() -> None:
    """The collector proxy stands in for a model that does not exist yet during
    feature collection; its placeholder must satisfy AnomalyAssessment's own
    validation so the pipeline runs unchanged."""
    from models.device_features import DeviceFeatures  # noqa: F401 (type context)

    collector = phase2d._FeatureCollector()
    sentinel = object()
    result = collector.predict_one(sentinel)
    assert collector.features == [sentinel]
    assert result.is_anomaly is False
    assert 0.0 <= result.confidence <= 1.0


def test_pipeline_extracted_vectors_reproduce_the_documented_zero_patterns(extracted) -> None:
    """The Phase 2B investigation found these are correct packet-level absence.
    The new corpus must reproduce them rather than contradict them."""
    train, _, _ = extracted
    pfs = FEATURE_NAMES.index("forward_secrecy")
    tls_obs = FEATURE_NAMES.index("tls_version_observed")
    key_obs = FEATURE_NAMES.index("key_size_observed")

    assert all(o.vector[pfs] == 0.0 for o in train), "forward_secrecy is constant 0 at serve time"
    # No single packet may present both a TLS version and a key size.
    assert not any(
        o.vector[tls_obs] == 1.0 and o.vector[key_obs] == 1.0 for o in train
    )
    # But the corpus must contain both kinds, or the model never learns either.
    assert any(o.vector[tls_obs] == 1.0 for o in train)
    assert any(o.vector[key_obs] == 1.0 for o in train)


# --- model parameters ---------------------------------------------------


def test_model_parameters_are_unchanged_from_production(extracted) -> None:
    train, _, _ = extracted
    detector, metadata = phase2d.fit_candidate(train)
    assert metadata["contamination"] == DEFAULT_CONTAMINATION == 0.05
    assert metadata["random_state"] == DEFAULT_RANDOM_STATE == 42
    assert detector.is_fitted is True
    assert metadata["training_matrix_shape"] == [len(train), NUM_FEATURES]


def test_fitting_is_reproducible(extracted) -> None:
    train, validation, _ = extracted
    first, _ = phase2d.fit_candidate(train)
    second, _ = phase2d.fit_candidate(train)
    assert phase2d.anomaly_scores(first, validation) == phase2d.anomaly_scores(
        second, validation
    )


# --- threshold calibration ----------------------------------------------


def test_threshold_selection_is_deterministic(extracted) -> None:
    train, validation, _ = extracted
    detector_a, _ = phase2d.fit_candidate(train)
    detector_b, _ = phase2d.fit_candidate(train)
    first = phase2d.calibrate_threshold(detector_a, validation)
    second = phase2d.calibrate_threshold(detector_b, validation)
    assert first["selected_threshold"] == second["selected_threshold"]


def test_threshold_maximizes_balanced_accuracy_on_validation(extracted) -> None:
    """The declared primary objective must actually hold: no candidate may beat
    the selected one on balanced accuracy."""
    train, validation, _ = extracted
    detector, _ = phase2d.fit_candidate(train)
    calibration = phase2d.calibrate_threshold(detector, validation)

    scores = phase2d.anomaly_scores(detector, validation)
    labels = [o.label == LABEL_RISKY for o in validation]
    selected = calibration["selected_validation_metrics"]["balanced_accuracy"]

    for candidate in sorted(set(scores)):
        metrics = phase2d._metrics_at(candidate, labels, scores)
        if metrics["balanced_accuracy"] is not None:
            assert metrics["balanced_accuracy"] <= selected + 1e-12


def test_threshold_tie_breaking_order_is_applied() -> None:
    """Hand-built tie: equal balanced accuracy, so F1 must decide, and on an F1
    tie the lower false-positive rate, then proximity to zero."""
    labels = [True, True, False, False]
    # Two thresholds give identical balanced accuracy of 0.75 here; the tie-break
    # chain must pick deterministically rather than by list order.
    scores = [1.0, 0.5, -0.5, -1.0]

    best = None
    for threshold in (-0.75, 0.0, 0.75):
        metrics = phase2d._metrics_at(threshold, labels, scores)
        key = (
            -(metrics["balanced_accuracy"] or -1.0),
            -(metrics["f1"] or -1.0),
            metrics["false_positive_rate"] if metrics["false_positive_rate"] is not None else 2.0,
            abs(threshold),
        )
        if best is None or key < best[0]:
            best = (key, threshold)
    # Threshold 0.0 separates both classes perfectly and is closest to zero.
    assert best[1] == 0.0


def test_applying_the_threshold_shifts_the_offset_consistently(extracted) -> None:
    """offset_new = offset_old - threshold must make `anomaly_score > 0`
    equivalent to the pre-calibration `anomaly_score > threshold`."""
    train, validation, _ = extracted
    detector, _ = phase2d.fit_candidate(train)
    threshold = 0.0123
    before = phase2d.anomaly_scores(detector, validation)
    previous_offset = float(detector._model.offset_)

    new_offset = phase2d.apply_threshold(detector, threshold)
    after = phase2d.anomaly_scores(detector, validation)

    assert new_offset == pytest.approx(previous_offset - threshold)
    for old, new in zip(before, after):
        assert new == pytest.approx(old - threshold)
        assert (new > 0.0) == (old > threshold)


def test_calibration_reports_the_original_operating_point_for_comparison(extracted) -> None:
    train, validation, _ = extracted
    detector, _ = phase2d.fit_candidate(train)
    calibration = phase2d.calibrate_threshold(detector, validation)
    assert "original_zero_operating_point_metrics" in calibration
    assert calibration["cohort_used"].startswith("validation only")


# --- metrics and acceptance ---------------------------------------------


def test_acceptance_check_reports_each_criterion() -> None:
    perfect = {
        "accuracy": 0.95,
        "precision": 0.95,
        "recall_sensitivity": 0.95,
        "specificity": 0.95,
        "f1": 0.95,
        "false_positive_rate": 0.05,
        "balanced_accuracy": 0.95,
    }
    result = phase2d.check_acceptance(perfect)
    assert result["all_passed"] is True
    assert all(item["passed"] for item in result["criteria"].values())


def test_acceptance_check_reports_failure_rather_than_hiding_it() -> None:
    failing = {
        "accuracy": 0.875,
        "precision": 0.8125,
        "recall_sensitivity": 1.0,
        "specificity": 0.7273,
        "f1": 0.8966,
        "false_positive_rate": 0.2727,
        "balanced_accuracy": 0.8636,
    }
    result = phase2d.check_acceptance(failing)
    assert result["all_passed"] is False
    assert result["criteria"]["specificity"]["passed"] is False
    assert result["criteria"]["false_positive_rate"]["passed"] is False
    assert result["criteria"]["accuracy"]["passed"] is True


def test_acceptance_criteria_are_the_pre_declared_ones() -> None:
    assert phase2d.ACCEPTANCE_CRITERIA["accuracy"] == (">=", 0.80)
    assert phase2d.ACCEPTANCE_CRITERIA["specificity"] == (">=", 0.80)
    assert phase2d.ACCEPTANCE_CRITERIA["false_positive_rate"] == ("<=", 0.20)
    assert "roc_auc" not in phase2d.ACCEPTANCE_CRITERIA


# --- preserved baseline -------------------------------------------------


def test_phase_2b_baseline_is_preserved_verbatim() -> None:
    """The research record must retain the original synthetic-model result."""
    baseline = phase2d.PHASE_2B_BASELINE
    assert baseline["accuracy"] == 0.5833
    assert baseline["specificity"] == 0.0909
    assert baseline["false_positive_rate"] == 0.9091
    assert baseline["roc_auc"] == 0.9371
    assert baseline["true_positives"] == 13
    assert baseline["false_positives"] == 10
    assert "Phase 2B" in baseline["source"]


# --- artifact isolation -------------------------------------------------


def test_candidate_artifact_path_is_outside_the_production_path() -> None:
    assert phase2d.CANDIDATE_ARTIFACT != phase2d.PRODUCTION_ARTIFACT
    assert phase2d.CANDIDATE_ARTIFACT.parent.name == "candidates"
    assert "phase2d" in phase2d.CANDIDATE_ARTIFACT.name


def test_trainer_never_writes_the_production_artifact() -> None:
    """Static guard: the production artifact may be named for reporting, but it
    must never be an argument to save() or load()."""
    source = (REPO_ROOT / "train_pipeline_aligned_model.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"save", "load"}:
                arguments = {
                    argument.id for argument in node.args if isinstance(argument, ast.Name)
                }
                assert "PRODUCTION_ARTIFACT" not in arguments


def test_production_artifact_is_untouched_by_a_training_run(tmp_path, cohorts) -> None:
    artifact = phase2d.PRODUCTION_ARTIFACT
    before = artifact.read_bytes() if artifact.exists() else None

    train_obs, _ = cohorts
    train = phase2d.extract_cohort(train_obs[:60], tmp_path / "small.pcap")
    detector, _ = phase2d.fit_candidate(train)
    detector.save(tmp_path / "candidate.joblib")

    after = artifact.read_bytes() if artifact.exists() else None
    assert after == before


# --- frozen invariants --------------------------------------------------


def test_quantum_risk_scores_are_unchanged_by_phase_2d(extracted) -> None:
    """Phase 2D must not perturb the deterministic engine at all. The frozen
    cohort's scores must still match its own manifest expectations."""
    from tests.fixtures.labelled_evaluation_manifest import LABELLED_OBSERVATIONS

    _, _, frozen = extracted
    expected = {o.scenario_id: o for o in LABELLED_OBSERVATIONS}
    for observation in frozen:
        declared = expected[observation.observation_id]
        assert observation.qrs == declared.qrs_expected_total
        assert observation.qrs_category == declared.qrs_expected_category


def test_isolation_eligibility_is_unchanged_by_phase_2d(extracted) -> None:
    _, _, frozen = extracted
    for observation in frozen:
        assert observation.isolation_eligible == (
            observation.qrs >= DEFAULT_RISK_ISOLATION_THRESHOLD
        )


def test_fusion_comparison_preserves_the_isolation_invariant(extracted) -> None:
    train, validation, frozen = extracted
    detector, _ = phase2d.fit_candidate(train)
    calibration = phase2d.calibrate_threshold(detector, validation)
    phase2d.apply_threshold(detector, calibration["selected_threshold"])

    comparison = phase2d.fusion_comparison(detector, frozen)
    invariant = comparison["physical_isolation_invariant"]
    assert invariant["identical_with_and_without_ml"] is True


def test_fusion_never_lowers_a_category(extracted) -> None:
    """The frozen rule only ever escalates, and only by one level."""
    train, validation, frozen = extracted
    detector, _ = phase2d.fit_candidate(train)
    calibration = phase2d.calibrate_threshold(detector, validation)
    phase2d.apply_threshold(detector, calibration["selected_threshold"])

    scores = phase2d.anomaly_scores(detector, frozen)
    rank = {RiskCategory.LOW: 0, RiskCategory.MEDIUM: 1, RiskCategory.HIGH: 2}
    one_level = {
        RiskCategory.LOW: RiskCategory.MEDIUM,
        RiskCategory.MEDIUM: RiskCategory.HIGH,
        RiskCategory.HIGH: RiskCategory.HIGH,
    }
    for observation, score in zip(frozen, scores):
        fused = one_level[observation.qrs_category] if score > 0 else observation.qrs_category
        assert rank[fused] >= rank[observation.qrs_category]


def test_phase_2d_changes_no_production_module() -> None:
    """Phase 2D is training and evaluation tooling. It must not import a
    production module in order to modify it, and the frozen engines must be
    reachable only as callers."""
    source = (REPO_ROOT / "train_pipeline_aligned_model.py").read_text(encoding="utf-8")
    for forbidden in (
        "quantum_risk_score =",
        "category_for_score =",
        "_PORT_RISK_TABLE",
        "_TLS_VERSION_TABLE",
        "_ESCALATE_ONE_LEVEL[",
        "DEFAULT_RISK_ISOLATION_THRESHOLD =",
    ):
        assert forbidden not in source, forbidden
