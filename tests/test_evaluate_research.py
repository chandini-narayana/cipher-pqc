"""Unit tests for evaluate_research.py — the Phase 2A deterministic
QRS-only controlled evaluation runner (docs/SDD.md's Phase 2A addendum).

main() is only ever called with results_dir redirected to a tmp_path, so
nothing here writes into this checkout's real data/evaluation/research/.
"""
from __future__ import annotations

import ast
import csv
import json
from pathlib import Path

import pytest

import evaluate_research
from models.enums import RiskCategory
from tests.fixtures.labelled_evaluation_manifest import (
    EXPECTED_OBSERVATION_COUNT,
    LABEL_EXCLUDED,
    LABELLED_OBSERVATIONS,
    label_counts,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def results() -> list:
    return evaluate_research.load_observation_results()


@pytest.fixture(scope="module")
def report(results) -> dict:
    return evaluate_research.build_report(results)


# --- loading --------------------------------------------------------------


def test_loads_one_result_per_manifest_observation(results) -> None:
    assert len(results) == EXPECTED_OBSERVATION_COUNT
    assert [r.observation.scenario_id for r in results] == [
        observation.scenario_id for observation in LABELLED_OBSERVATIONS
    ]


def test_missing_fixture_raises_with_an_actionable_message(tmp_path) -> None:
    with pytest.raises(FileNotFoundError) as error:
        evaluate_research.load_observation_results(tmp_path / "absent.pcap")
    message = str(error.value)
    assert "python -m tests.fixtures.generate_labelled_evaluation_fixtures" in message


def test_pcap_not_matching_the_manifest_raises(tmp_path) -> None:
    """Silently evaluating a different set than the manifest declares would
    misreport N."""
    from scapy.all import IP, TCP, Ether, wrpcap

    stray = tmp_path / "stray.pcap"
    wrpcap(
        str(stray),
        [Ether() / IP(src="10.9.9.9", dst="10.9.9.1") / TCP() / b"GET / HTTP/1.1\r\n\r\n"],
    )

    with pytest.raises(ValueError, match="does not match the labelled manifest"):
        evaluate_research.load_observation_results(stray)


def test_duplicate_source_ip_in_pcap_raises(tmp_path) -> None:
    from scapy.all import IP, TCP, Ether, wrpcap

    duplicated = tmp_path / "duplicated.pcap"
    packet = (
        Ether()
        / IP(src="192.168.40.11", dst="192.168.40.254")
        / TCP()
        / b"GET / HTTP/1.1\r\n\r\n"
    )
    wrpcap(str(duplicated), [packet, packet])

    with pytest.raises(ValueError, match="more than one packet from"):
        evaluate_research.load_observation_results(duplicated)


# --- QRS-only guarantee ---------------------------------------------------


def test_no_observation_ever_receives_an_anomaly_assessment(results) -> None:
    """The central Phase 2A claim: Isolation Forest never runs, so no
    reported figure can reflect ML behavior."""
    for result in results:
        assert result.assessment.anomaly_assessment is None


def test_final_category_equals_the_qrs_category_for_every_observation(results) -> None:
    for result in results:
        assert result.actual_final_category == result.actual_category


def test_report_records_the_qrs_only_invariant_and_mode(report) -> None:
    assert report["evaluation_mode"] == "Deterministic QRS-only controlled evaluation"
    assert report["dataset"]["qrs_only"] is True
    assert report["dataset"]["anomaly_detection_used"] is False
    invariant = report["qrs_only_invariant"]
    assert invariant["final_category_equals_qrs_category_for_every_observation"] is True


def test_runner_never_reads_or_writes_the_on_disk_model_artifact() -> None:
    """A static guard on the reproducibility requirement: the runner must
    never touch ml/artifacts/anomaly_detector.joblib, so no reported figure
    can depend on whether that untracked file exists on the machine running
    it, or on which scikit-learn version pickled it.

    Phase 2B does legitimately import AnomalyDetector — it fits one IN
    MEMORY from ml/dataset.py (see build_in_memory_detector). What must stay
    absent is every path that would load or persist an artifact."""
    tree = ast.parse((REPO_ROOT / "evaluate_research.py").read_text(encoding="utf-8"))

    # Inspect parsed identifiers, not raw text: the module docstring names the
    # artifact and joblib precisely in order to state that it never touches
    # them, and a substring scan would flag that explanation.
    identifiers = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    identifiers |= {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            identifiers.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                identifiers.add(node.module.split(".")[0])
            identifiers.update(alias.name for alias in node.names)

    for forbidden in (
        "load_anomaly_detector",
        "joblib",
        "model_path",
        "DEFAULT_MODEL_PATH",
        "load_settings",
        "save",
        "load",
    ):
        assert forbidden not in identifiers, forbidden

    # No string literal may name an artifact file either.
    literals = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    assert not any(value.endswith(".joblib") for value in literals)


def test_phase_2a_results_are_still_produced_without_any_model(results) -> None:
    """Phase 2B must not have leaked a detector into the Phase 2A path: its
    conformance and classification figures remain strictly QRS-only."""
    for result in results:
        assert result.assessment.anomaly_assessment is None


# --- component decomposition ---------------------------------------------


def test_every_component_decomposition_matches_the_engine_score(results) -> None:
    for result in results:
        assert result.component_sum_matches_engine_qrs, result.observation.scenario_id


def test_report_lists_no_decomposition_failures(report) -> None:
    assert report["qrs_conformance"]["component_decomposition_failures"] == []


# --- conformance results -------------------------------------------------


def test_qrs_conformance_is_currently_exact(report) -> None:
    """The dataset's expectations were derived from the frozen formula, so
    a conformance failure means the implementation and its specification
    have diverged — a real regression signal, not a target to tune."""
    score = report["qrs_conformance"]["score"]
    assert score["observation_count"] == EXPECTED_OBSERVATION_COUNT
    assert score["exact_matches"] == EXPECTED_OBSERVATION_COUNT
    assert score["exact_match_rate"] == 1.0
    assert score["mean_absolute_error"] == 0.0
    assert score["max_absolute_error"] == 0
    assert score["mismatches"] == []


def test_all_component_and_category_conformance_is_exact(report) -> None:
    conformance = report["qrs_conformance"]
    for name, component in conformance["components"].items():
        assert component["agreement_rate"] == 1.0, name
        assert component["mismatches"] == []
    assert conformance["category_confusion"]["accuracy"] == 1.0
    assert conformance["isolation_eligibility"]["agreement_rate"] == 1.0
    assert conformance["protocol_detection"]["agreement_rate"] == 1.0


def test_category_confusion_is_diagonal_over_all_three_categories(report) -> None:
    matrix = report["qrs_conformance"]["category_confusion"]["matrix"]
    labels = [RiskCategory.LOW.value, RiskCategory.MEDIUM.value, RiskCategory.HIGH.value]
    for expected_label in labels:
        for actual_label in labels:
            count = matrix[expected_label][actual_label]
            if expected_label != actual_label:
                assert count == 0, (expected_label, actual_label)
    assert sum(matrix[label][label] for label in labels) == EXPECTED_OBSERVATION_COUNT


# --- classification results ----------------------------------------------


def test_excluded_observations_are_omitted_from_binary_metrics(report) -> None:
    classification = report["controlled_security_classification"]
    excluded_count = label_counts()[LABEL_EXCLUDED]

    assert classification["observations_excluded"] == excluded_count
    assert classification["observations_in_binary_metrics"] == (
        EXPECTED_OBSERVATION_COUNT - excluded_count
    )
    for point in classification["operating_points"].values():
        assert point["counts"]["total"] == (EXPECTED_OBSERVATION_COUNT - excluded_count)


def test_both_operating_points_are_reported_with_definitions(report) -> None:
    points = report["controlled_security_classification"]["operating_points"]
    assert set(points) == {"flagged_for_remediation", "high_risk_isolation_eligible"}
    for name, point in points.items():
        assert point["operating_point"] == name
        assert point["definition"].strip()


def test_operating_point_counts_are_internally_consistent(report) -> None:
    for point in report["controlled_security_classification"][
        "operating_points"
    ].values():
        counts = point["counts"]
        assert counts["total"] == (
            counts["true_positives"]
            + counts["true_negatives"]
            + counts["false_positives"]
            + counts["false_negatives"]
        )
        assert len(point["false_positive_scenarios"]) == counts["false_positives"]
        assert len(point["false_negative_scenarios"]) == counts["false_negatives"]


def test_isolation_operating_point_is_conservative_by_design(report) -> None:
    """The frozen raw-QRS>=7 rule flags no externally-safe observation on
    this set, at the cost of missing externally-risky ones that score
    below 7. Both halves of that trade-off are recorded rather than only
    the favourable one."""
    point = report["controlled_security_classification"]["operating_points"][
        "high_risk_isolation_eligible"
    ]
    assert point["counts"]["false_positives"] == 0
    assert point["false_positive_rate"] == 0.0
    assert point["counts"]["false_negatives"] > 0
    assert point["recall_sensitivity"] < 1.0


def test_flagged_operating_point_reports_its_controlled_false_positives(report) -> None:
    """Realistic secure TLS 1.3 observations whose short or zero-padded
    payloads take an entropy penalty are genuine controlled false
    positives, and are reported as such."""
    point = report["controlled_security_classification"]["operating_points"][
        "flagged_for_remediation"
    ]
    assert point["counts"]["false_positives"] > 0
    assert point["false_positive_rate"] > 0.0
    assert point["counts"]["false_negatives"] == 0
    assert set(point["false_positive_scenarios"]) <= {
        observation.scenario_id for observation in LABELLED_OBSERVATIONS
    }


def test_reported_metrics_are_reproducible_across_runs() -> None:
    """Determinism: two independent runs must agree on every figure."""
    first = evaluate_research.build_report(evaluate_research.load_observation_results())
    second = evaluate_research.build_report(evaluate_research.load_observation_results())
    del first["timestamp"], second["timestamp"]
    assert first == second


# --- outputs -------------------------------------------------------------


def test_main_writes_json_and_csv_to_the_given_directory(tmp_path, capsys) -> None:
    exit_code = evaluate_research.main(results_dir=tmp_path)
    assert exit_code == 0

    json_path = tmp_path / evaluate_research.JSON_FILENAME
    csv_path = tmp_path / evaluate_research.CSV_FILENAME
    assert json_path.exists()
    assert csv_path.exists()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["phase"] == "Phase 2A"
    assert len(payload["observations"]) == EXPECTED_OBSERVATION_COUNT

    output = capsys.readouterr().out
    assert "Deterministic QRS-only controlled evaluation" in output
    assert "Quantum Risk Score specification conformance" in output
    assert "controlled security classification" in output


def test_main_does_not_write_into_the_real_results_directory(tmp_path) -> None:
    real_json = evaluate_research.DEFAULT_RESULTS_DIR / evaluate_research.JSON_FILENAME
    before = real_json.read_bytes() if real_json.exists() else None

    evaluate_research.main(results_dir=tmp_path)

    after = real_json.read_bytes() if real_json.exists() else None
    assert after == before


def test_csv_has_the_documented_research_columns(tmp_path) -> None:
    evaluate_research.main(results_dir=tmp_path)
    with (tmp_path / evaluate_research.CSV_FILENAME).open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == EXPECTED_OBSERVATION_COUNT
    required = {
        "scenario_id",
        "group",
        "external_label",
        "expected_qrs",
        "actual_qrs",
        "expected_category",
        "actual_category",
        "expected_isolation",
        "actual_isolation",
        "qrs_match",
        "category_match",
        "security_rationale",
    }
    assert required <= set(rows[0])
    for row in rows:
        assert row["security_rationale"].strip()
        assert row["external_label"] in {"SAFE", "RISKY", "EXCLUDED"}


def test_undefined_metrics_print_as_undefined_never_as_zero() -> None:
    assert evaluate_research._format_metric(None) == "undefined"
    assert evaluate_research._format_metric(0.0) == "0.00%"
    assert evaluate_research._format_metric(0.8125) == "81.25%"


def test_main_returns_one_when_the_fixture_is_missing(tmp_path, monkeypatch, capsys) -> None:
    def _missing(*_args, **_kwargs):
        raise FileNotFoundError(evaluate_research.MISSING_FIXTURE_MESSAGE)

    monkeypatch.setattr(evaluate_research, "load_observation_results", _missing)
    assert evaluate_research.main(results_dir=tmp_path) == 1
    assert "is missing" in capsys.readouterr().err


# --- scientific wording --------------------------------------------------


def test_no_overclaiming_wording_anywhere_in_the_phase_2a_sources() -> None:
    """Guards the approved wording constraints: conformance and controlled
    classification figures must never be described as real-world,
    production, general-IoT, clinical or network-wide accuracy."""
    forbidden = (
        "real-world detection accuracy",
        "real-world accuracy",
        "production accuracy",
        "general iot accuracy",
        "clinically validated",
        "network-wide accuracy",
    )
    sources = (
        REPO_ROOT / "evaluate_research.py",
        REPO_ROOT / "evaluation" / "metrics.py",
        REPO_ROOT / "evaluation" / "__init__.py",
        REPO_ROOT / "tests" / "fixtures" / "labelled_evaluation_manifest.py",
        REPO_ROOT / "tests" / "fixtures" / "generate_labelled_evaluation_fixtures.py",
    )
    for path in sources:
        text = path.read_text(encoding="utf-8").lower()
        for phrase in forbidden:
            # "NOT real-world detection accuracy" style disclaimers are the
            # only legitimate use, so require a negation nearby.
            index = text.find(phrase)
            while index != -1:
                # Wide enough to cover a disclaimer that negates several
                # phrases in one sentence ("Neither is real-world detection
                # accuracy, production accuracy, general IoT accuracy, ...").
                window = text[max(0, index - 220) : index]
                negated = any(
                    marker in window for marker in ("not", "never", "neither", "nor")
                )
                assert negated, (path.name, phrase, window)
                index = text.find(phrase, index + 1)


def test_report_notes_state_the_controlled_synthetic_scope(report) -> None:
    notes = report["notes"].lower()
    assert "controlled" in notes
    assert "synthetic" in notes
    assert "neither is real-world detection accuracy" in notes
    assert "isolation forest evaluation is a separate" in notes


def test_conformance_and_classification_sections_carry_interpretation_text(
    report,
) -> None:
    assert "NOT detection accuracy" in report["qrs_conformance"]["interpretation"]
    classification = report["controlled_security_classification"]
    assert "NOT real-world detection accuracy" in classification["interpretation"]
    assert "never from any CIPHER output" in classification["positive_class"]


# --- runtime isolation ---------------------------------------------------


_RUNTIME_ENTRY_POINTS = (
    "main.py",
    "run_demo.py",
    "run_api.py",
    "run_live_demo.py",
    "launch_cipher.py",
    "preflight.py",
    "measure_startup.py",
)

_RUNTIME_PACKAGES = (
    "capture",
    "config",
    "dashboard",
    "enforcement",
    "entropy",
    "fingerprint",
    "fusion",
    "ml",
    "models",
    "pipeline",
    "reports",
    "risk",
    "signing",
    "utils",
)


def _imported_top_level_modules(path: Path) -> set:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    return imported


def _runtime_source_files() -> list:
    files = [REPO_ROOT / name for name in _RUNTIME_ENTRY_POINTS]
    for package in _RUNTIME_PACKAGES:
        files.extend(sorted((REPO_ROOT / package).rglob("*.py")))
    return [path for path in files if path.exists()]


def test_no_runtime_module_imports_the_evaluation_package() -> None:
    """The load-bearing guarantee that this phase adds zero overhead to a
    normal CIPHER run: nothing on the runtime import graph may reach
    evaluation/ or the test fixtures."""
    offenders = {}
    for path in _runtime_source_files():
        imported = _imported_top_level_modules(path)
        forbidden = imported & {"evaluation", "tests", "evaluate_research"}
        if forbidden:
            offenders[str(path.relative_to(REPO_ROOT))] = sorted(forbidden)
    assert offenders == {}, offenders


def test_runtime_files_were_checked_at_all() -> None:
    """Protects the test above from silently passing on an empty file list."""
    files = _runtime_source_files()
    assert len(files) > 30
    names = {path.name for path in files}
    assert {"main.py", "runner.py", "scoring.py", "risk_fusion.py"} <= names


# =========================================================================
# PHASE 2B — Isolation Forest measurement
# =========================================================================


@pytest.fixture(scope="module")
def detector_and_metadata():
    return evaluate_research.build_in_memory_detector()


@pytest.fixture(scope="module")
def ml_results(detector_and_metadata) -> list:
    detector, _metadata = detector_and_metadata
    return evaluate_research.load_ml_observation_results(detector)


@pytest.fixture(scope="module")
def ml_report(results) -> dict:
    report, _ml_results = evaluate_research.run_ml_evaluation(results)
    return report


# --- model provenance ----------------------------------------------------


def test_detector_is_fitted_with_the_frozen_configuration(detector_and_metadata) -> None:
    from ml.classifier import DEFAULT_CONTAMINATION, DEFAULT_RANDOM_STATE

    detector, metadata = detector_and_metadata
    assert detector.is_fitted is True
    assert metadata["contamination"] == DEFAULT_CONTAMINATION
    assert metadata["random_state"] == DEFAULT_RANDOM_STATE
    assert metadata["training_matrix_shape"] == [190, 12]
    assert metadata["feature_count"] == 12


def test_metadata_records_everything_needed_to_reproduce_the_fit(
    detector_and_metadata,
) -> None:
    import numpy
    import sklearn

    from ml.features import FEATURE_NAMES

    _detector, metadata = detector_and_metadata
    assert metadata["sklearn_version"] == sklearn.__version__
    assert metadata["numpy_version"] == numpy.__version__
    assert metadata["feature_names"] == list(FEATURE_NAMES)
    assert "never read or written" in metadata["fitted"]


def test_fitting_is_reproducible_across_calls() -> None:
    """Two independent in-memory fits must score identically, or none of the
    Phase 2B figures would be reproducible."""
    from tests.fixtures.ml_heldout_set import build_heldout_feature_matrix

    first, _ = evaluate_research.build_in_memory_detector()
    second, _ = evaluate_research.build_in_memory_detector()
    matrix = build_heldout_feature_matrix()

    assert evaluate_research.score_feature_matrix(first, matrix) == (
        evaluate_research.score_feature_matrix(second, matrix)
    )


def test_model_artifact_on_disk_is_never_modified(detector_and_metadata) -> None:
    """The untracked artifact must survive an evaluation run untouched."""
    artifact = REPO_ROOT / "ml" / "artifacts" / "anomaly_detector.joblib"
    before = artifact.read_bytes() if artifact.exists() else None

    detector, _metadata = detector_and_metadata
    evaluate_research.load_ml_observation_results(detector)

    after = artifact.read_bytes() if artifact.exists() else None
    assert after == before


# --- sign convention and score semantics ---------------------------------


def test_feature_matrix_scoring_matches_predict_one_exactly(
    detector_and_metadata, ml_results
) -> None:
    """score_feature_matrix() reaches the fitted estimator directly, so its
    equivalence with the public predict_one() is verified rather than
    assumed."""
    import numpy as np

    detector, _metadata = detector_and_metadata
    for result in ml_results[:6]:
        vector = np.array([result.vector], dtype=float)
        raw_decisions, anomaly_scores, is_anomaly = (
            evaluate_research.score_feature_matrix(detector, vector)
        )
        reference = detector.predict_one(result.features)

        assert anomaly_scores[0] == pytest.approx(reference.anomaly_score)
        assert is_anomaly[0] is reference.is_anomaly
        assert raw_decisions[0] == pytest.approx(-reference.anomaly_score)


def test_anomaly_score_sign_convention_holds_for_every_observation(ml_results) -> None:
    """High anomaly_score means more anomalous, and is_anomaly is exactly
    raw_decision < 0 — the frozen convention in ml/classifier.py."""
    for result in ml_results:
        assert result.raw_decision == pytest.approx(-result.anomaly_score)
        assert result.is_anomaly == (result.raw_decision < 0)
        assert result.is_anomaly == (result.anomaly_score > 0)


def test_confidence_is_recorded_but_never_treated_as_a_probability(
    ml_report, ml_results
) -> None:
    """It is reported under a name that says what it is not, and no
    calibration metric appears anywhere in the report."""
    for result in ml_results:
        assert 0.0 <= result.confidence <= 1.0
        assert "confidence_not_a_probability" in result.to_row()

    # Check the report's KEYS, not its prose: the model section deliberately
    # names these metrics to record that none of them is computed.
    def _all_keys(node) -> set:
        keys = set()
        if isinstance(node, dict):
            for key, value in node.items():
                keys.add(key.lower())
                keys |= _all_keys(value)
        elif isinstance(node, list):
            for item in node:
                keys |= _all_keys(item)
        return keys

    reported_keys = _all_keys(ml_report)
    for forbidden in ("brier", "brier_score", "log_loss", "calibration", "probability"):
        assert forbidden not in reported_keys, forbidden

    semantics = ml_report["model"]["confidence_semantics"].lower()
    assert "not a calibrated probability" in semantics
    assert "no calibration metric" in semantics


def test_confidence_is_monotone_in_anomaly_score(ml_results) -> None:
    """Confirms confidence adds no ranking information beyond the score, which
    is why ROC-AUC is taken over the score alone."""
    ordered = sorted(ml_results, key=lambda r: r.anomaly_score)
    confidences = [r.confidence for r in ordered]
    assert confidences == sorted(confidences)


# --- Section A: synthetic held-out ---------------------------------------


def test_section_a_uses_construction_labels_not_model_output(ml_report) -> None:
    from tests.fixtures.ml_heldout_set import (
        HELDOUT_NORMAL_COUNT,
        HELDOUT_OUTLIER_COUNT,
        HELDOUT_RANDOM_STATE,
    )

    section = ml_report["section_a_synthetic_feature_distribution"]
    assert section["heldout_random_state"] == HELDOUT_RANDOM_STATE
    assert section["training_random_state"] == 42
    assert section["n_normal_by_construction"] == HELDOUT_NORMAL_COUNT
    assert section["n_outlier_by_construction"] == HELDOUT_OUTLIER_COUNT
    assert "Never derived from any model output" in section["label_provenance"]
    assert section["counts"]["total"] == HELDOUT_NORMAL_COUNT + HELDOUT_OUTLIER_COUNT


def test_section_a_is_labelled_as_a_synthetic_feature_result(ml_report) -> None:
    section = ml_report["section_a_synthetic_feature_distribution"]
    assert section["section"] == "Synthetic feature-distribution evaluation"
    caveat = section["caveat"]
    assert "not real packet accuracy" in caveat
    assert "not real network accuracy" in caveat


def test_section_a_reports_distinct_vectors_and_per_class_score_ranges(
    ml_report,
) -> None:
    section = ml_report["section_a_synthetic_feature_distribution"]
    assert section["distinct_feature_vectors"] == section["total_rows"]
    by_class = section["anomaly_score_by_class"]
    assert by_class["outlier_by_construction"]["count"] == 10
    assert by_class["normal_by_construction"]["count"] == 180
    for summary in by_class.values():
        assert summary["min"] is not None
        assert summary["median"] is not None
        assert summary["max"] is not None


def test_section_a_roc_auc_is_computed_over_the_continuous_score(ml_report) -> None:
    section = ml_report["section_a_synthetic_feature_distribution"]
    auc = section["roc_auc"]
    assert auc["auc"] is not None
    assert auc["n_positive"] == 10
    assert auc["n_negative"] == 180
    assert "anomaly_score" in section["roc_auc_input"]
    assert "never is_anomaly" in section["roc_auc_input"]


# --- Section B: pipeline-extracted ---------------------------------------


def test_section_b_features_come_from_the_real_pipeline_not_hand_built(
    ml_results,
) -> None:
    """The recorded DeviceFeatures must be the objects assess_packet() itself
    built and handed to the model."""
    from models.device_features import DeviceFeatures

    for result in ml_results:
        assert isinstance(result.features, DeviceFeatures)
        assert len(result.vector) == 12


def test_recorded_features_reproduce_the_reported_vector(ml_results) -> None:
    from ml.features import vectorize_features

    for result in ml_results:
        rebuilt = [float(value) for value in vectorize_features(result.features)]
        assert rebuilt == result.vector


def test_runner_builds_no_device_features_by_hand() -> None:
    """Static guard: the Phase 2B path must obtain features by interception,
    never by constructing DeviceFeatures itself."""
    source = (REPO_ROOT / "evaluate_research.py").read_text(encoding="utf-8")
    assert "DeviceFeatures(" not in source


def test_all_twelve_features_are_recorded_per_observation(ml_report) -> None:
    from ml.features import FEATURE_NAMES

    for row in ml_report["observations"]:
        for name in FEATURE_NAMES:
            assert f"feature_{name}" in row
            assert isinstance(row[f"feature_{name}"], float)


def test_section_b_records_every_required_per_observation_field(ml_report) -> None:
    required = {
        "scenario_id",
        "external_label",
        "qrs",
        "qrs_category",
        "raw_decision",
        "anomaly_score",
        "is_anomaly",
        "confidence_not_a_probability",
        "fused_final_category",
    }
    for row in ml_report["observations"]:
        assert required <= set(row)


def test_section_b_binary_metrics_exclude_the_excluded_label(ml_report) -> None:
    from tests.fixtures.labelled_evaluation_manifest import LABEL_EXCLUDED, label_counts

    section = ml_report["section_b_pipeline_extracted"]
    excluded_count = label_counts()[LABEL_EXCLUDED]
    assert section["observations_in_binary_metrics"] == (
        EXPECTED_OBSERVATION_COUNT - excluded_count
    )
    assert section["counts"]["total"] == EXPECTED_OBSERVATION_COUNT - excluded_count
    assert section["excluded_observations"]["count"] == excluded_count


def test_excluded_observations_keep_their_scores_without_entering_metrics(
    ml_report,
) -> None:
    excluded = ml_report["section_b_pipeline_extracted"]["excluded_observations"]
    assert len(excluded["scenarios"]) == excluded["count"]
    for entry in excluded["scenarios"]:
        assert "anomaly_score" in entry
        assert "is_anomaly" in entry


def test_section_b_reports_score_distributions_per_external_label(ml_report) -> None:
    from tests.fixtures.labelled_evaluation_manifest import (
        LABEL_EXCLUDED,
        LABEL_RISKY,
        LABEL_SAFE,
    )

    by_label = ml_report["section_b_pipeline_extracted"][
        "anomaly_score_by_external_label"
    ]
    assert set(by_label) == {LABEL_SAFE, LABEL_RISKY, LABEL_EXCLUDED}
    assert by_label[LABEL_SAFE]["count"] == 11
    assert by_label[LABEL_RISKY]["count"] == 13
    assert by_label[LABEL_EXCLUDED]["count"] == 6


def test_section_b_records_a_high_controlled_false_positive_rate(ml_report) -> None:
    """The headline Phase 2B finding, asserted so it cannot quietly vanish:
    on real pipeline vectors the model flags most externally SAFE
    observations as anomalous."""
    section = ml_report["section_b_pipeline_extracted"]
    assert section["counts"]["false_positives"] > 0
    assert section["false_positive_rate"] > 0.5
    assert section["specificity"] < 0.5


def test_section_b_roc_auc_is_reported_with_its_class_sizes(ml_report) -> None:
    auc = ml_report["section_b_pipeline_extracted"]["roc_auc"]
    assert auc["auc"] is not None
    assert auc["n_positive"] == 13
    assert auc["n_negative"] == 11
    assert auc["n_pairs"] == 143
    assert "Mann-Whitney" in auc["tie_handling"]


def test_section_b_roc_auc_matches_an_independent_recomputation(ml_results) -> None:
    from sklearn.metrics import roc_auc_score

    binary = [r for r in ml_results if r.observation.participates_in_binary_metrics]
    y_true = [r.observation.is_externally_risky for r in binary]
    scores = [r.anomaly_score for r in binary]

    from evaluation.metrics import roc_auc

    assert roc_auc(y_true, scores).auc == pytest.approx(roc_auc_score(y_true, scores))


# --- train/serve comparison ----------------------------------------------


def test_train_serve_comparison_covers_all_twelve_features_and_four_cohorts(
    ml_report,
) -> None:
    from ml.features import FEATURE_NAMES

    comparison = ml_report["train_serve_feature_comparison"]
    assert set(comparison["features"]) == set(FEATURE_NAMES)
    required_cohorts = {
        "training_normal",
        "training_outlier",
        "pipeline_safe",
        "pipeline_risky",
    }
    for summaries in comparison["features"].values():
        assert required_cohorts <= set(summaries)


def test_train_serve_comparison_quantifies_the_key_divergences(ml_report) -> None:
    """key_size_observed and forward_secrecy are the structural mismatches:
    always present/mostly-set in training, never set on real pipeline
    vectors."""
    features = ml_report["train_serve_feature_comparison"]["features"]

    key_observed = features["key_size_observed"]
    assert key_observed["training_normal"]["zero_fraction"] == 0.0
    assert key_observed["pipeline_safe"]["zero_fraction"] == 1.0

    forward_secrecy = features["forward_secrecy"]
    assert forward_secrecy["pipeline_safe"]["zero_fraction"] == 1.0
    assert forward_secrecy["pipeline_risky"]["zero_fraction"] == 1.0
    assert forward_secrecy["training_normal"]["zero_fraction"] < 1.0


def test_train_serve_cohort_sizes_match_the_dataset(ml_report) -> None:
    sizes = ml_report["train_serve_feature_comparison"]["cohort_sizes"]
    assert sizes["training_normal"] == 180
    assert sizes["training_outlier"] == 10
    assert sizes["pipeline_safe"] == 11
    assert sizes["pipeline_risky"] == 13
    assert sizes["pipeline_excluded"] == 6


def test_train_serve_comparison_lists_structural_findings(ml_report) -> None:
    findings = ml_report["train_serve_feature_comparison"]["structural_findings"]
    named = {finding["feature"] for finding in findings}
    assert {"key_size_observed", "forward_secrecy", "shannon_entropy"} <= named


# --- Section C: paired fusion comparison ---------------------------------


def test_section_c_pairs_the_same_observations(ml_report) -> None:
    fusion = ml_report["section_c_fusion_comparison"]
    assert fusion["observations_total"] == EXPECTED_OBSERVATION_COUNT
    assert (
        fusion["observations_escalated"] + fusion["observations_unchanged"]
        == EXPECTED_OBSERVATION_COUNT
    )
    assert len(fusion["per_scenario"]) == EXPECTED_OBSERVATION_COUNT


def test_section_c_refuses_an_unpaired_comparison(results, ml_results) -> None:
    with pytest.raises(ValueError, match="same observations in the same order"):
        evaluate_research.build_fusion_comparison(results[:-1], ml_results)


def test_section_c_qrs_only_metrics_reproduce_phase_2a(report, ml_report) -> None:
    """The paired comparison's QRS-only side must be identical to Phase 2A's
    own flagged-for-remediation result, or the two phases would disagree."""
    phase_2a = report["controlled_security_classification"]["operating_points"][
        "flagged_for_remediation"
    ]
    paired = ml_report["section_c_fusion_comparison"]["qrs_only_metrics"]

    assert paired["counts"] == phase_2a["counts"]
    assert paired["accuracy"] == phase_2a["accuracy"]
    assert paired["precision"] == phase_2a["precision"]
    assert paired["false_positive_rate"] == phase_2a["false_positive_rate"]


def test_section_c_reports_escalations_by_external_label(ml_report) -> None:
    fusion = ml_report["section_c_fusion_comparison"]
    safe = fusion["safe_observations_incorrectly_escalated"]
    risky = fusion["risky_observations_usefully_escalated"]

    assert safe["count"] == len(safe["scenarios"])
    assert risky["count"] == len(risky["scenarios"])
    assert safe["count"] + risky["count"] <= fusion["observations_escalated"]


def test_section_c_escalation_flags_agree_with_the_frozen_fusion_rule(
    results, ml_results
) -> None:
    """Escalation must be exactly one level, never LOW -> HIGH, and must
    occur precisely when the model flagged an anomaly."""
    from models.enums import RiskCategory

    one_level = {
        RiskCategory.LOW: RiskCategory.MEDIUM,
        RiskCategory.MEDIUM: RiskCategory.HIGH,
        RiskCategory.HIGH: RiskCategory.HIGH,
    }
    for qrs_result, ml_result in zip(results, ml_results):
        base = qrs_result.actual_final_category
        expected = one_level[base] if ml_result.is_anomaly else base
        assert ml_result.fused_final_category == expected, (
            ml_result.observation.scenario_id
        )


def test_section_c_verdict_is_driven_by_the_measurements(ml_report) -> None:
    """The verdict must not claim an improvement the paired numbers do not
    show."""
    fusion = ml_report["section_c_fusion_comparison"]
    verdict = fusion["verdict"]
    before = fusion["qrs_only_metrics"]
    after = fusion["fused_metrics"]

    if verdict["metrics_worsened"]:
        assert verdict["paired_measurements_support_an_improvement_claim"] is False
        assert "DO NOT support" in verdict["statement"]

    # On this controlled set, fusion demonstrably degrades flagging.
    assert after["false_positive_rate"] > before["false_positive_rate"]
    assert after["precision"] < before["precision"]
    assert "specificity" in verdict["metrics_worsened"]


def test_section_c_reports_metric_deltas(ml_report) -> None:
    fusion = ml_report["section_c_fusion_comparison"]
    deltas = fusion["metric_deltas_fused_minus_qrs_only"]
    before = fusion["qrs_only_metrics"]
    after = fusion["fused_metrics"]

    assert deltas["precision"] == pytest.approx(
        after["precision"] - before["precision"], abs=1e-6
    )
    assert deltas["false_positive_rate"] > 0


def test_fusion_never_lowers_a_category(results, ml_results) -> None:
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    for qrs_result, ml_result in zip(results, ml_results):
        assert (
            rank[ml_result.fused_final_category.value]
            >= rank[qrs_result.actual_final_category.value]
        )


# --- the physical-isolation invariant ------------------------------------


def test_physical_isolation_eligibility_is_identical_with_and_without_ml(
    ml_report,
) -> None:
    invariant = ml_report["section_c_fusion_comparison"][
        "physical_isolation_invariant"
    ]
    assert invariant["identical"] is True
    assert invariant["mismatched_scenarios"] == []
    assert invariant["eligible_with_ml"] == invariant["eligible_without_ml"]


def test_isolation_invariant_holds_observation_by_observation(
    results, ml_results
) -> None:
    """Checked directly against the real should_isolate() as well as through
    the report, since this is the guarantee that an ML-only escalation can
    never trigger a physical action."""
    for qrs_result, ml_result in zip(results, ml_results):
        assert ml_result.isolation_eligible == qrs_result.actual_isolation_eligible


def test_ml_escalated_observations_below_the_threshold_stay_ineligible(
    ml_results,
) -> None:
    """The specific case the frozen rule exists for: an observation the model
    escalated to HIGH whose raw score is under 7 must not be eligible."""
    from models.enums import RiskCategory

    escalated_to_high = [
        r
        for r in ml_results
        if r.fused_final_category == RiskCategory.HIGH and r.qrs < 7
    ]
    assert escalated_to_high, "expected at least one ML-only escalation to HIGH"
    for result in escalated_to_high:
        assert result.isolation_eligible is False


def test_qrs_scores_are_unaffected_by_attaching_the_model(results, ml_results) -> None:
    for qrs_result, ml_result in zip(results, ml_results):
        assert ml_result.qrs == qrs_result.actual_qrs
        assert ml_result.qrs_category == qrs_result.actual_category


# --- Phase 2B outputs ----------------------------------------------------


def test_main_writes_the_phase_2b_outputs(tmp_path, capsys) -> None:
    assert evaluate_research.main(results_dir=tmp_path) == 0

    ml_json = tmp_path / evaluate_research.ML_JSON_FILENAME
    ml_csv = tmp_path / evaluate_research.ML_CSV_FILENAME
    feature_csv = tmp_path / evaluate_research.ML_FEATURE_CSV_FILENAME
    assert ml_json.exists()
    assert ml_csv.exists()
    assert feature_csv.exists()

    payload = json.loads(ml_json.read_text(encoding="utf-8"))
    assert payload["phase"] == "Phase 2B"
    assert len(payload["observations"]) == EXPECTED_OBSERVATION_COUNT

    output = capsys.readouterr().out
    assert "SECTION A" in output
    assert "SECTION B" in output
    assert "SECTION C" in output


def test_phase_2a_outputs_are_still_written_alongside_phase_2b(tmp_path) -> None:
    """Phase 2A results must remain intact."""
    evaluate_research.main(results_dir=tmp_path)
    phase_2a = json.loads(
        (tmp_path / evaluate_research.JSON_FILENAME).read_text(encoding="utf-8")
    )
    assert phase_2a["phase"] == "Phase 2A"
    assert phase_2a["qrs_conformance"]["score"]["exact_match_rate"] == 1.0
    assert (tmp_path / evaluate_research.CSV_FILENAME).exists()


def test_ml_csv_has_the_documented_columns(tmp_path) -> None:
    from ml.features import FEATURE_NAMES

    evaluate_research.main(results_dir=tmp_path)
    with (tmp_path / evaluate_research.ML_CSV_FILENAME).open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == EXPECTED_OBSERVATION_COUNT
    required = {
        "scenario_id",
        "external_label",
        "qrs",
        "qrs_category",
        "qrs_only_final_category",
        "fused_final_category",
        "escalated_by_ml",
        "raw_decision",
        "anomaly_score",
        "is_anomaly",
        "confidence_not_a_probability",
    }
    assert required <= set(rows[0])
    for name in FEATURE_NAMES:
        assert f"feature_{name}" in rows[0]


def test_ml_feature_distribution_csv_covers_every_feature_and_cohort(tmp_path) -> None:
    from ml.features import FEATURE_NAMES

    evaluate_research.main(results_dir=tmp_path)
    with (tmp_path / evaluate_research.ML_FEATURE_CSV_FILENAME).open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))

    assert {row["feature"] for row in rows} == set(FEATURE_NAMES)
    cohorts = {row["cohort"] for row in rows}
    assert {"training_normal", "training_outlier", "pipeline_safe", "pipeline_risky"} <= (
        cohorts
    )
    assert len(rows) == len(FEATURE_NAMES) * len(cohorts)


def test_ml_report_notes_avoid_overclaiming(ml_report) -> None:
    notes = ml_report["notes"].lower()
    assert "measurement" in notes
    assert "nothing was tuned" in notes
    assert "neither real packet nor real network accuracy" in notes
    assert "not a calibrated probability" in notes


def test_ml_report_is_reproducible_across_runs(results) -> None:
    first, _ = evaluate_research.run_ml_evaluation(results)
    second, _ = evaluate_research.run_ml_evaluation(results)
    del first["timestamp"], second["timestamp"]
    assert first == second


def test_evaluation_package_imports_no_scoring_or_ml_module() -> None:
    """Measurement must not contain, or depend on, the logic it measures."""
    for path in sorted((REPO_ROOT / "evaluation").rglob("*.py")):
        imported = _imported_top_level_modules(path)
        assert not (
            imported & {"risk", "ml", "fusion", "fingerprint", "entropy", "pipeline"}
        ), path.name
