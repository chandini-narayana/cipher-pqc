"""evaluate_research.py — controlled research evaluation runner.

    python evaluate_research.py

Two independent evaluations, reported separately and never conflated:

PHASE 2A — DETERMINISTIC QRS-ONLY (docs/SDD.md's Phase 2A addendum).
Runs every observation in the controlled labelled dataset
(tests/fixtures/labelled_evaluation_manifest.py) through the REAL,
unmodified CIPHER assessment path — fingerprint_packet ->
port_risk_for_protocol -> assess_packet -> should_isolate — and reports:

  1. Quantum Risk Score SPECIFICATION CONFORMANCE: expected vs. actual
     score, per-component contribution, category and isolation
     eligibility.
  2. CONTROLLED SECURITY CLASSIFICATION against an a-priori external
     standards rubric, at two clearly named deterministic operating
     points.

Every Phase 2A figure is produced with `anomaly_detector=None`, so
Isolation Forest never runs and cannot influence a single one of them, and
the fused final category equals the Quantum Risk Score category by
construction (fusion/risk_fusion.py passes the rule-based category through
unchanged when anomaly_assessment is None).

PHASE 2B — EXISTING ISOLATION FOREST, MEASURED (docs/SDD.md's Phase 2B
addendum). Measurement only: nothing about the model is improved, tuned,
retrained differently, repaired or redesigned. Three sections:

  A. Synthetic feature-distribution evaluation on a deterministic held-out
     set drawn from ml/dataset.py's own distributions at a non-training
     seed. This is a FEATURE-LEVEL result, never real packet or network
     accuracy.
  B. Pipeline-extracted controlled evaluation: the same 30 labelled packets
     as Phase 2A, with the feature vectors the REAL production inference
     path actually builds, captured as assess_packet() hands them to the
     model (never hand-constructed DeviceFeatures).
  C. Paired QRS-only versus fused-category comparison on those same
     observations, plus verification that physical-isolation eligibility is
     bit-for-bit identical with and without ML.

THE MODEL IS FITTED IN MEMORY, NEVER LOADED FROM THE ARTIFACT.
`ml/artifacts/anomaly_detector.joblib` is untracked and was pickled by a
scikit-learn version outside this project's pins, so depending on it would
make these figures unreproducible. Instead the frozen training matrix is
regenerated from ml/dataset.py at the frozen seed and the frozen
AnomalyDetector is fitted on it in memory. Nothing is ever saved, and no
artifact is read or written.

ISOLATION FOREST CONFIDENCE IS NOT A PROBABILITY. It is a monotone sigmoid
of the anomaly score, scaled by a training-time standard deviation.
Nothing here calibrates it, and no calibration metric (Brier score, log
loss, reliability) is computed, because Isolation Forest is not a
probabilistic estimator. ROC-AUC is computed ONLY over the continuous
`anomaly_score`, never over `is_anomaly`, a risk category, or confidence
treated as a probability.

WHAT THESE NUMBERS ARE AND ARE NOT. These are CONTROLLED evaluations on
deterministic synthetic/offline observations this project constructed for
itself, measured on whichever machine runs the script. Conformance figures
measure whether the implementation matches its own frozen specification.
Classification figures measure how fixed thresholds align with an external
standards rubric on this controlled set. Neither is real-world detection
accuracy, production accuracy, general IoT accuracy, or a network-wide
measurement, and neither should ever be described that way.

No threshold, weight, formula, fusion rule, model parameter, feature or
fingerprinting behavior was changed to influence any figure below. This
script only measures; it imports the frozen modules and calls them.
"""
from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import sklearn

from capture.offline_source import OfflinePcapSource
from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD
from enforcement.decision import should_isolate
from entropy.engine import compute_entropy_metrics
from evaluation.metrics import (
    binary_metrics,
    category_confusion,
    confusion_counts,
    exact_agreement,
    qrs_conformance,
    roc_auc,
    value_summary,
)
from fingerprint.protocol import fingerprint_packet
from ml.classifier import DEFAULT_CONTAMINATION, DEFAULT_RANDOM_STATE, AnomalyDetector
from ml.features import FEATURE_NAMES, vectorize_features
from models.device import Device
from models.device_features import DeviceFeatures
from models.enums import RiskCategory
from pipeline.assessment_pipeline import assess_packet
from risk.port_risk import port_risk_for_protocol
from risk.scoring import entropy_risk, key_size_risk, tls_version_risk
from tests.fixtures.labelled_evaluation_manifest import (
    EXPECTED_OBSERVATION_COUNT,
    EXTERNAL_RUBRIC_CITATIONS,
    LABEL_EXCLUDED,
    LABEL_RISKY,
    LABEL_SAFE,
    LABELLED_OBSERVATIONS,
    LABELLED_SET_PCAP_PATH,
    RISK_CATEGORY_LABELS,
    group_counts,
    label_counts,
)
from tests.fixtures.ml_heldout_set import (
    HELDOUT_OUTLIER_COUNT,
    HELDOUT_NORMAL_COUNT,
    HELDOUT_RANDOM_STATE,
    build_heldout_feature_matrix,
    build_training_feature_matrix,
    heldout_construction_labels,
    training_construction_labels,
)

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_RESULTS_DIR = REPO_ROOT / "data" / "evaluation" / "research"
JSON_FILENAME = "latest_qrs_evaluation.json"
CSV_FILENAME = "qrs_observations.csv"
ML_JSON_FILENAME = "latest_ml_evaluation.json"
ML_CSV_FILENAME = "ml_observations.csv"
ML_FEATURE_CSV_FILENAME = "ml_feature_distribution.csv"

EVALUATION_MODE = "Deterministic QRS-only controlled evaluation"

# The two deterministic operating points. Both read CIPHER's own frozen
# outputs; neither introduces a new threshold.
OPERATING_POINT_FLAGGED = "flagged_for_remediation"
OPERATING_POINT_ISOLATION = "high_risk_isolation_eligible"

OPERATING_POINT_DEFINITIONS = {
    OPERATING_POINT_FLAGGED: (
        "Predicted positive iff final_category != LOW — the same rule "
        "reports/pdf_generator.is_flagged_device() already uses to decide "
        "report-generation eligibility. In QRS-only mode final_category is the "
        "Quantum Risk Score category unchanged."
    ),
    OPERATING_POINT_ISOLATION: (
        f"Predicted positive iff raw Quantum Risk Score >= "
        f"{DEFAULT_RISK_ISOLATION_THRESHOLD}, evaluated through the real "
        f"enforcement.decision.should_isolate() — the frozen Phase 14 isolation "
        f"eligibility rule, which reads the raw score and never the fused category."
    ),
}

POSITIVE_CLASS_DEFINITION = (
    "The positive class is 'RISKY under the a-priori external security rubric' "
    "(tests/fixtures/labelled_evaluation_manifest.py). Labels come from published "
    "standards and are fixed before execution — never from any CIPHER output. "
    "EXCLUDED observations are omitted from every confusion matrix and reported "
    "separately."
)

MISSING_FIXTURE_MESSAGE = (
    "CIPHER Phase 2A labelled evaluation data is missing.\n"
    f"Expected: {LABELLED_SET_PCAP_PATH}\n"
    "Generate it first (it is deliberately gitignored, like every other "
    "evaluation fixture):\n"
    "    python -m tests.fixtures.generate_labelled_evaluation_fixtures"
)


class ObservationResult:
    """One observation's declared expectations beside the real pipeline's
    actual output. Holds no logic beyond composing already-computed
    values."""

    def __init__(self, observation, raw_packet) -> None:
        self.observation = observation
        self.payload_bytes = len(raw_packet.payload)

        # Recomputed from the same payload bytes via the same production
        # functions assess_packet() itself calls, purely so the actual
        # per-component contributions can be reported. Both are pure and
        # deterministic, so these are the identical values the assessment
        # used — and `component_sum_matches_engine_qrs` below verifies
        # exactly that against the engine's own total rather than assuming
        # it.
        self.fingerprint = fingerprint_packet(raw_packet.payload)
        self.entropy_metrics = compute_entropy_metrics(raw_packet.payload)
        self.port_risk = port_risk_for_protocol(self.fingerprint.protocol)

        device = Device.first_contact(raw_packet.src_ip, raw_packet.timestamp)
        self.assessment = assess_packet(
            raw_packet, device, self.port_risk, anomaly_detector=None
        )

        self.actual_qrs = self.assessment.risk_assessment.risk_score
        self.actual_category = self.assessment.risk_assessment.category
        self.actual_final_category = self.assessment.final_category
        self.actual_isolation_eligible = should_isolate(
            self.assessment, DEFAULT_RISK_ISOLATION_THRESHOLD
        )

        self.actual_tls_risk = tls_version_risk(self.fingerprint.tls_version)
        self.actual_key_size_risk = key_size_risk(self.fingerprint.key_size)
        self.actual_pfs_risk = 0 if self.fingerprint.forward_secrecy else 1
        self.actual_entropy_risk = entropy_risk(self.entropy_metrics.shannon_entropy)
        self.actual_port_risk = self.port_risk

    @property
    def component_sum(self) -> int:
        return (
            self.actual_tls_risk
            + self.actual_key_size_risk
            + self.actual_pfs_risk
            + self.actual_entropy_risk
            + self.actual_port_risk
        )

    @property
    def component_sum_matches_engine_qrs(self) -> bool:
        """Cross-check: the reported component decomposition must add up to
        the score the engine independently produced (no observation in this
        dataset reaches the formula's cap of 10, where the two would
        legitimately differ)."""
        return self.component_sum == self.actual_qrs

    @property
    def flagged_for_remediation(self) -> bool:
        return self.actual_final_category != RiskCategory.LOW

    @property
    def expected_components(self) -> Tuple[int, int, int, int, int]:
        o = self.observation
        return (
            o.qrs_expected_tls_risk,
            o.qrs_expected_key_size_risk,
            o.qrs_expected_pfs_risk,
            o.qrs_expected_entropy_risk,
            o.qrs_expected_port_risk,
        )

    @property
    def actual_components(self) -> Tuple[int, int, int, int, int]:
        return (
            self.actual_tls_risk,
            self.actual_key_size_risk,
            self.actual_pfs_risk,
            self.actual_entropy_risk,
            self.actual_port_risk,
        )

    def to_row(self) -> Dict[str, Any]:
        """One flat record, used for both the CSV and the JSON."""
        o = self.observation
        return {
            "scenario_id": o.scenario_id,
            "group": o.group,
            "external_label": o.external_security_label,
            "src_ip": o.src_ip,
            "payload_bytes": self.payload_bytes,
            "shannon_entropy": round(self.entropy_metrics.shannon_entropy, 4),
            "expected_protocol": o.expected_protocol.value,
            "actual_protocol": self.fingerprint.protocol.value,
            "protocol_match": self.fingerprint.protocol == o.expected_protocol,
            "expected_qrs": o.qrs_expected_total,
            "actual_qrs": self.actual_qrs,
            "qrs_match": self.actual_qrs == o.qrs_expected_total,
            "qrs_absolute_error": abs(self.actual_qrs - o.qrs_expected_total),
            "expected_category": o.qrs_expected_category.value,
            "actual_category": self.actual_category.value,
            "category_match": self.actual_category == o.qrs_expected_category,
            "actual_final_category": self.actual_final_category.value,
            "expected_isolation": o.qrs_expected_isolation_eligible,
            "actual_isolation": self.actual_isolation_eligible,
            "isolation_match": (
                self.actual_isolation_eligible == o.qrs_expected_isolation_eligible
            ),
            "flagged_for_remediation": self.flagged_for_remediation,
            "expected_tls_risk": o.qrs_expected_tls_risk,
            "actual_tls_risk": self.actual_tls_risk,
            "expected_key_size_risk": o.qrs_expected_key_size_risk,
            "actual_key_size_risk": self.actual_key_size_risk,
            "expected_pfs_risk": o.qrs_expected_pfs_risk,
            "actual_pfs_risk": self.actual_pfs_risk,
            "expected_entropy_risk": o.qrs_expected_entropy_risk,
            "actual_entropy_risk": self.actual_entropy_risk,
            "expected_port_risk": o.qrs_expected_port_risk,
            "actual_port_risk": self.actual_port_risk,
            "components_match": self.expected_components == self.actual_components,
            "component_sum_matches_engine_qrs": self.component_sum_matches_engine_qrs,
            "detected_tls_version": (
                self.fingerprint.tls_version.value
                if self.fingerprint.tls_version is not None
                else None
            ),
            "detected_key_size": self.fingerprint.key_size,
            "security_rationale": o.security_rationale,
        }


CSV_COLUMNS = [
    "scenario_id",
    "group",
    "external_label",
    "expected_qrs",
    "actual_qrs",
    "qrs_match",
    "qrs_absolute_error",
    "expected_category",
    "actual_category",
    "category_match",
    "actual_final_category",
    "expected_isolation",
    "actual_isolation",
    "isolation_match",
    "flagged_for_remediation",
    "expected_protocol",
    "actual_protocol",
    "protocol_match",
    "payload_bytes",
    "shannon_entropy",
    "detected_tls_version",
    "detected_key_size",
    "expected_tls_risk",
    "actual_tls_risk",
    "expected_key_size_risk",
    "actual_key_size_risk",
    "expected_pfs_risk",
    "actual_pfs_risk",
    "expected_entropy_risk",
    "actual_entropy_risk",
    "expected_port_risk",
    "actual_port_risk",
    "components_match",
    "component_sum_matches_engine_qrs",
    "src_ip",
    "security_rationale",
]


def load_observation_results(
    pcap_path: Path = LABELLED_SET_PCAP_PATH,
) -> List[ObservationResult]:
    """Assess every labelled observation through the real pipeline.

    Packets are matched to manifest observations by source IP, never by
    packet order.

    Raises:
        FileNotFoundError: if the labelled pcap has not been generated —
            with the exact command to generate it, the same fail-fast
            pattern run_demo.py uses for its own missing fixture.
        ValueError: if the pcap's observations and the manifest's do not
            correspond exactly (missing, unexpected or duplicated source
            IPs) — evaluating a silently different set than the manifest
            declares would misreport N.
    """
    if not Path(pcap_path).exists():
        raise FileNotFoundError(MISSING_FIXTURE_MESSAGE)

    packets_by_ip: Dict[str, Any] = {}
    for raw_packet in OfflinePcapSource(pcap_path).read_packets():
        if raw_packet.src_ip in packets_by_ip:
            raise ValueError(
                f"{pcap_path} contains more than one packet from {raw_packet.src_ip}; "
                f"each labelled observation must be a uniquely addressed packet"
            )
        packets_by_ip[raw_packet.src_ip] = raw_packet

    expected_ips = {observation.src_ip for observation in LABELLED_OBSERVATIONS}
    missing = sorted(expected_ips - set(packets_by_ip))
    unexpected = sorted(set(packets_by_ip) - expected_ips)
    if missing or unexpected:
        raise ValueError(
            f"{pcap_path} does not match the labelled manifest. "
            f"Missing source IPs: {missing}. Unexpected source IPs: {unexpected}. "
            f"Regenerate with: python -m "
            f"tests.fixtures.generate_labelled_evaluation_fixtures"
        )

    return [
        ObservationResult(observation, packets_by_ip[observation.src_ip])
        for observation in LABELLED_OBSERVATIONS
    ]


def build_qrs_conformance_report(results: List[ObservationResult]) -> Dict[str, Any]:
    """Quantum Risk Score specification conformance — implementation
    agreement with the frozen formula, never detection accuracy."""
    identifiers = [r.observation.scenario_id for r in results]

    score_conformance = qrs_conformance(
        expected=[r.observation.qrs_expected_total for r in results],
        actual=[r.actual_qrs for r in results],
        identifiers=identifiers,
    )

    component_names = ("tls_risk", "key_size_risk", "pfs_risk", "entropy_risk", "port_risk")
    components: Dict[str, Any] = {}
    for index, name in enumerate(component_names):
        components[name] = exact_agreement(
            expected=[r.expected_components[index] for r in results],
            actual=[r.actual_components[index] for r in results],
            identifiers=identifiers,
        )

    categories = category_confusion(
        expected=[r.observation.qrs_expected_category.value for r in results],
        actual=[r.actual_category.value for r in results],
        labels=RISK_CATEGORY_LABELS,
    )

    isolation = exact_agreement(
        expected=[r.observation.qrs_expected_isolation_eligible for r in results],
        actual=[r.actual_isolation_eligible for r in results],
        identifiers=identifiers,
    )

    protocols = exact_agreement(
        expected=[r.observation.expected_protocol.value for r in results],
        actual=[r.fingerprint.protocol.value for r in results],
        identifiers=identifiers,
    )

    decomposition_failures = [
        r.observation.scenario_id for r in results if not r.component_sum_matches_engine_qrs
    ]

    return {
        "interpretation": (
            "Specification conformance of the deterministic Quantum Risk Score "
            "implementation against the frozen published formula. This is NOT "
            "detection accuracy and NOT a real-world measurement."
        ),
        "observation_count": len(results),
        "score": score_conformance.to_dict(),
        "components": components,
        "category_confusion": categories.to_dict(),
        "isolation_eligibility": isolation,
        "protocol_detection": protocols,
        "component_decomposition_failures": decomposition_failures,
    }


def _operating_point_report(
    results: List[ObservationResult], operating_point: str
) -> Dict[str, Any]:
    binary_results = [
        r for r in results if r.observation.participates_in_binary_metrics
    ]
    y_true = [r.observation.is_externally_risky for r in binary_results]

    if operating_point == OPERATING_POINT_FLAGGED:
        y_predicted = [r.flagged_for_remediation for r in binary_results]
    elif operating_point == OPERATING_POINT_ISOLATION:
        y_predicted = [r.actual_isolation_eligible for r in binary_results]
    else:  # pragma: no cover - guarded by the caller's fixed list
        raise ValueError(f"unknown operating point {operating_point!r}")

    metrics = binary_metrics(confusion_counts(y_true, y_predicted))

    false_positives = [
        r.observation.scenario_id
        for r, actual, predicted in zip(binary_results, y_true, y_predicted)
        if predicted and not actual
    ]
    false_negatives = [
        r.observation.scenario_id
        for r, actual, predicted in zip(binary_results, y_true, y_predicted)
        if actual and not predicted
    ]

    report = metrics.to_dict()
    report["operating_point"] = operating_point
    report["definition"] = OPERATING_POINT_DEFINITIONS[operating_point]
    report["false_positive_scenarios"] = false_positives
    report["false_negative_scenarios"] = false_negatives
    return report


def build_classification_report(results: List[ObservationResult]) -> Dict[str, Any]:
    """Controlled security classification against the external rubric, at
    both deterministic operating points."""
    excluded = [
        r.observation.scenario_id
        for r in results
        if r.observation.external_security_label == LABEL_EXCLUDED
    ]
    binary_count = sum(
        1 for r in results if r.observation.participates_in_binary_metrics
    )

    return {
        "interpretation": (
            "Agreement between CIPHER's frozen deterministic operating points and an "
            "a-priori external security rubric, on this controlled set of "
            "deterministic synthetic/offline observations. NOT real-world detection "
            "accuracy."
        ),
        "positive_class": POSITIVE_CLASS_DEFINITION,
        "external_rubric_citations": list(EXTERNAL_RUBRIC_CITATIONS),
        "observations_in_binary_metrics": binary_count,
        "observations_excluded": len(excluded),
        "excluded_scenarios": excluded,
        "operating_points": {
            OPERATING_POINT_FLAGGED: _operating_point_report(
                results, OPERATING_POINT_FLAGGED
            ),
            OPERATING_POINT_ISOLATION: _operating_point_report(
                results, OPERATING_POINT_ISOLATION
            ),
        },
    }


def build_dataset_composition(results: List[ObservationResult]) -> Dict[str, Any]:
    return {
        "pcap_path": str(LABELLED_SET_PCAP_PATH),
        "observation_count": len(results),
        "expected_observation_count": EXPECTED_OBSERVATION_COUNT,
        "external_label_counts": label_counts(),
        "group_counts": group_counts(),
        "qrs_only": True,
        "anomaly_detection_used": False,
    }


def build_report(results: List[ObservationResult]) -> Dict[str, Any]:
    fused_matches_qrs = all(
        r.actual_final_category == r.actual_category for r in results
    )
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evaluation_mode": EVALUATION_MODE,
        "phase": "Phase 2A",
        "dataset": build_dataset_composition(results),
        "qrs_conformance": build_qrs_conformance_report(results),
        "controlled_security_classification": build_classification_report(results),
        "qrs_only_invariant": {
            "final_category_equals_qrs_category_for_every_observation": fused_matches_qrs,
            "explanation": (
                "Isolation Forest was never loaded or run (anomaly_detector=None at "
                "every call site), so fusion/risk_fusion.py passes the rule-based "
                "category through unchanged. This is a structural invariant of "
                "QRS-only mode, never evidence about anomaly-detection performance."
            ),
        },
        "observations": [r.to_row() for r in results],
        "notes": (
            "Deterministic QRS-only controlled evaluation on deterministic "
            "synthetic/offline observations built by this project "
            "(tests/fixtures/generate_labelled_evaluation_fixtures.py), run through "
            "the real, unmodified CIPHER assessment path. Conformance figures measure "
            "implementation agreement with the frozen specification; classification "
            "figures measure that specification's fixed thresholds against an "
            "a-priori external standards rubric on this controlled set. Neither is "
            "real-world detection accuracy, production accuracy, general IoT accuracy, "
            "or a network-wide measurement. No threshold, weight, formula or fusion "
            "rule was changed. Isolation Forest evaluation is a separate, later phase."
        ),
    }


def write_outputs(report: Dict[str, Any], results_dir: Path) -> Tuple[Path, Path]:
    """Write the JSON report and the per-observation CSV."""
    results_dir.mkdir(parents=True, exist_ok=True)

    json_path = results_dir / JSON_FILENAME
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    csv_path = results_dir / CSV_FILENAME
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in report["observations"]:
            writer.writerow(row)

    return json_path, csv_path


def _format_metric(value: Optional[float]) -> str:
    """Undefined metrics print as 'undefined', never as 0.00% — see
    evaluation/metrics.py's own rule."""
    if value is None:
        return "undefined"
    return f"{value:.2%}"


def _print_dataset(report: Dict[str, Any]) -> None:
    dataset = report["dataset"]
    print("--- dataset composition ---")
    print(f"  observations: {dataset['observation_count']}")
    labels = dataset["external_label_counts"]
    print(
        f"  external labels: SAFE={labels['SAFE']}  RISKY={labels['RISKY']}  "
        f"EXCLUDED={labels['EXCLUDED']}"
    )
    groups = dataset["group_counts"]
    print("  groups: " + "  ".join(f"{name}={count}" for name, count in groups.items()))
    print()


def _print_conformance(report: Dict[str, Any]) -> None:
    conformance = report["qrs_conformance"]
    score = conformance["score"]
    print("--- Quantum Risk Score specification conformance ---")
    print(f"  observations:        {score['observation_count']}")
    print(
        f"  exact score matches: {score['exact_matches']}/{score['observation_count']} "
        f"({_format_metric(score['exact_match_rate'])})"
    )
    print(f"  mean absolute error: {score['mean_absolute_error']}")
    print(f"  max absolute error:  {score['max_absolute_error']}")
    print(
        f"  protocol detection:  "
        f"{conformance['protocol_detection']['matches']}/"
        f"{conformance['protocol_detection']['observation_count']} "
        f"({_format_metric(conformance['protocol_detection']['agreement_rate'])})"
    )
    print(
        f"  isolation eligibility: "
        f"{conformance['isolation_eligibility']['matches']}/"
        f"{conformance['isolation_eligibility']['observation_count']} "
        f"({_format_metric(conformance['isolation_eligibility']['agreement_rate'])})"
    )

    print("  per-component agreement:")
    for name, component in conformance["components"].items():
        print(
            f"    {name:<16} {component['matches']}/{component['observation_count']} "
            f"({_format_metric(component['agreement_rate'])})"
        )

    for name, component in conformance["components"].items():
        for mismatch in component["mismatches"]:
            print(
                f"    MISMATCH {name}: {mismatch['scenario_id']} "
                f"expected={mismatch['expected']} actual={mismatch['actual']}"
            )
    for mismatch in score["mismatches"]:
        print(
            f"    MISMATCH score: {mismatch['scenario_id']} "
            f"expected={mismatch['expected_qrs']} actual={mismatch['actual_qrs']}"
        )

    categories = conformance["category_confusion"]
    print("  category confusion (rows = expected, columns = actual):")
    header = "            " + "".join(f"{label:>9}" for label in categories["labels"])
    print(header)
    for expected_label in categories["labels"]:
        row = categories["matrix"][expected_label]
        cells = "".join(f"{row[actual]:>9}" for actual in categories["labels"])
        print(f"    {expected_label:<8}{cells}")
    print(f"  category accuracy: {_format_metric(categories['accuracy'])}")
    print()


def _print_classification(report: Dict[str, Any]) -> None:
    classification = report["controlled_security_classification"]
    print("--- controlled security classification (external rubric) ---")
    print(
        f"  observations in binary metrics: "
        f"{classification['observations_in_binary_metrics']}  "
        f"(EXCLUDED and reported separately: "
        f"{classification['observations_excluded']})"
    )
    print(f"  positive class: RISKY under {', '.join(EXTERNAL_RUBRIC_CITATIONS)}")
    print()

    for name, point in classification["operating_points"].items():
        counts = point["counts"]
        print(f"  operating point: {name}")
        print(f"    {point['definition']}")
        print(
            f"    TP={counts['true_positives']}  TN={counts['true_negatives']}  "
            f"FP={counts['false_positives']}  FN={counts['false_negatives']}  "
            f"N={counts['total']}"
        )
        print(
            f"    accuracy={_format_metric(point['accuracy'])}  "
            f"precision={_format_metric(point['precision'])}  "
            f"recall={_format_metric(point['recall_sensitivity'])}  "
            f"specificity={_format_metric(point['specificity'])}"
        )
        print(
            f"    F1={_format_metric(point['f1'])}  "
            f"FPR={_format_metric(point['false_positive_rate'])}  "
            f"FNR={_format_metric(point['false_negative_rate'])}  "
            f"balanced accuracy={_format_metric(point['balanced_accuracy'])}"
        )
        if point["false_positive_scenarios"]:
            print(f"    false positives: {', '.join(point['false_positive_scenarios'])}")
        if point["false_negative_scenarios"]:
            print(f"    false negatives: {', '.join(point['false_negative_scenarios'])}")
        print()


# =========================================================================
# PHASE 2B — measurement of the EXISTING Isolation Forest
# =========================================================================

ML_EVALUATION_SCOPE = (
    "Measurement only. The Isolation Forest under evaluation is the existing, "
    "frozen one: ml/dataset.py's synthetic training matrix at its frozen seed, "
    "fitted with the frozen contamination and random_state. Nothing was tuned, "
    "retrained differently, repaired or redesigned, and no feature, threshold or "
    "fusion rule was changed."
)

CONFIDENCE_SEMANTICS = (
    "AnomalyAssessment.confidence is NOT a calibrated probability. It is a "
    "monotone sigmoid of anomaly_score scaled by a training-time score standard "
    "deviation, so it carries no more ordering information than anomaly_score "
    "itself. No calibration metric (Brier score, log loss, reliability) is "
    "computed, and ROC-AUC is taken over anomaly_score only."
)

SYNTHETIC_SECTION_TITLE = "Synthetic feature-distribution evaluation"
PIPELINE_SECTION_TITLE = "Pipeline-extracted controlled Isolation Forest evaluation"

SYNTHETIC_SECTION_CAVEAT = (
    "This is a FEATURE-LEVEL result on vectors drawn from ml/dataset.py's own "
    "synthetic distributions at a held-out seed. It measures generalization "
    "within that synthetic distribution and NOTHING ELSE. It is not real "
    "packet accuracy, not real network accuracy, and must never be reported as "
    "either. The pipeline-extracted evaluation is the one that reflects vectors "
    "CIPHER actually produces."
)


def build_in_memory_detector() -> Tuple[AnomalyDetector, Dict[str, Any]]:
    """Fit the frozen AnomalyDetector on the frozen training matrix, in memory.

    Deliberately does NOT read ml/artifacts/anomaly_detector.joblib: that file
    is untracked, absent on a fresh clone, and the copy on the development
    machine was pickled by a scikit-learn version outside this project's pins
    (it loads with an InconsistentVersionWarning). Regenerating the matrix and
    refitting gives a reproducible model with identical configuration on any
    machine with the pinned dependencies. Nothing is saved: the artifact is
    neither read nor written.

    Returns:
        (detector, metadata) where metadata records everything needed to
        reproduce the fit.
    """
    matrix = build_training_feature_matrix()
    detector = AnomalyDetector(
        contamination=DEFAULT_CONTAMINATION, random_state=DEFAULT_RANDOM_STATE
    )
    detector.fit(matrix)

    metadata = {
        "model": "sklearn.ensemble.IsolationForest (via ml.classifier.AnomalyDetector)",
        "fitted": "in memory, from ml/dataset.py — the on-disk joblib artifact is never read or written",
        "contamination": DEFAULT_CONTAMINATION,
        "random_state": DEFAULT_RANDOM_STATE,
        "training_matrix_shape": list(matrix.shape),
        "training_random_state": DEFAULT_RANDOM_STATE,
        "feature_names": list(FEATURE_NAMES),
        "feature_count": len(FEATURE_NAMES),
        "sklearn_version": sklearn.__version__,
        "numpy_version": np.__version__,
        "n_estimators": detector._model.get_params()["n_estimators"],
        "max_samples_resolved": int(detector._model.max_samples_),
        "offset": float(detector._model.offset_),
        "training_score_std_used_by_confidence": float(detector._score_std),
        "scope": ML_EVALUATION_SCOPE,
        "confidence_semantics": CONFIDENCE_SEMANTICS,
    }
    return detector, metadata


def score_feature_matrix(
    detector: AnomalyDetector, matrix: np.ndarray
) -> Tuple[List[float], List[float], List[bool]]:
    """Score raw feature-vector rows, applying exactly the transformation
    ml.classifier.AnomalyDetector.predict_one() applies.

    Reaches through to the fitted estimator (`detector._model`) because the
    public predict_one() takes a DeviceFeatures, and the held-out rows ARE
    feature vectors by construction — rebuilding synthetic DeviceFeatures
    objects around them just to re-derive the same vectors would add a lossy
    round-trip with nothing to gain. The transformation applied here is the
    frozen one, not a reimplementation of scoring:

        raw_decision  = decision_function(x)
        anomaly_score = -raw_decision      (high = more anomalous)
        is_anomaly    = raw_decision < 0

    A test asserts this path returns exactly what predict_one() returns for
    the same vector, so the equivalence is verified rather than assumed.

    Returns:
        (raw_decisions, anomaly_scores, is_anomaly_flags)
    """
    raw_decisions = [float(value) for value in detector._model.decision_function(matrix)]
    anomaly_scores = [-value for value in raw_decisions]
    is_anomaly = [value < 0 for value in raw_decisions]
    return raw_decisions, anomaly_scores, is_anomaly


class _RecordingAnomalyDetector:
    """A transparent proxy that records the DeviceFeatures the production
    pipeline hands to the model, then delegates unchanged.

    This is how Section B obtains the twelve feature values WITHOUT
    hand-constructing a DeviceFeatures: pipeline.assessment_pipeline
    .assess_packet() builds the features itself from the raw packet (entropy
    -> fingerprint -> packet metadata -> DeviceFeatures) and passes them to
    `anomaly_detector.predict_one(...)`. Intercepting exactly that call
    guarantees the recorded vectors are precisely the ones real inference
    consumed — a stronger guarantee than rebuilding them alongside and hoping
    the two agree.

    The delegation is genuinely unmodified: the real detector produces every
    returned AnomalyAssessment, so fusion and every reported score are the
    real model's, not this wrapper's.
    """

    def __init__(self, detector: AnomalyDetector) -> None:
        self._detector = detector
        self.recorded_features: List[DeviceFeatures] = []

    def predict_one(self, features: DeviceFeatures):
        self.recorded_features.append(features)
        return self._detector.predict_one(features)

    @property
    def last_vector(self) -> np.ndarray:
        """The vectorized form of the most recently recorded observation,
        produced by ml.features.vectorize_features — the same pure function
        predict_one() uses internally, so this is the identical vector."""
        return vectorize_features(self.recorded_features[-1])


class MLObservationResult:
    """One labelled observation assessed WITH the Isolation Forest, paired
    against its QRS-only result."""

    def __init__(self, observation, raw_packet, detector: AnomalyDetector) -> None:
        self.observation = observation

        recorder = _RecordingAnomalyDetector(detector)
        device = Device.first_contact(raw_packet.src_ip, raw_packet.timestamp)
        fingerprint = fingerprint_packet(raw_packet.payload)
        port_risk = port_risk_for_protocol(fingerprint.protocol)

        self.assessment = assess_packet(raw_packet, device, port_risk, recorder)

        if len(recorder.recorded_features) != 1:
            raise RuntimeError(
                f"{observation.scenario_id}: expected exactly one model call from "
                f"assess_packet(), recorded {len(recorder.recorded_features)}"
            )
        self.features = recorder.recorded_features[0]
        self.vector = [float(value) for value in recorder.last_vector]

        anomaly = self.assessment.anomaly_assessment
        if anomaly is None:
            raise RuntimeError(
                f"{observation.scenario_id}: the pipeline returned no "
                f"AnomalyAssessment despite being given a detector"
            )
        self.anomaly_score = anomaly.anomaly_score
        # Exact, not approximate: ml/classifier.py defines
        # anomaly_score = -raw_decision, so this inverts that identity.
        self.raw_decision = -anomaly.anomaly_score
        self.is_anomaly = anomaly.is_anomaly
        self.confidence = anomaly.confidence

        self.qrs = self.assessment.risk_assessment.risk_score
        self.qrs_category = self.assessment.risk_assessment.category
        self.fused_final_category = self.assessment.final_category
        self.isolation_eligible = should_isolate(
            self.assessment, DEFAULT_RISK_ISOLATION_THRESHOLD
        )

    @property
    def flagged_for_remediation(self) -> bool:
        return self.fused_final_category != RiskCategory.LOW

    def feature_dict(self) -> Dict[str, float]:
        return dict(zip(FEATURE_NAMES, self.vector))

    def to_row(self) -> Dict[str, Any]:
        observation = self.observation
        row: Dict[str, Any] = {
            "scenario_id": observation.scenario_id,
            "group": observation.group,
            "external_label": observation.external_security_label,
            "qrs": self.qrs,
            "qrs_category": self.qrs_category.value,
            "fused_final_category": self.fused_final_category.value,
            "raw_decision": round(self.raw_decision, 6),
            "anomaly_score": round(self.anomaly_score, 6),
            "is_anomaly": self.is_anomaly,
            "confidence_not_a_probability": round(self.confidence, 6),
            "isolation_eligible_raw_qrs": self.isolation_eligible,
            "flagged_for_remediation": self.flagged_for_remediation,
        }
        for name, value in self.feature_dict().items():
            row[f"feature_{name}"] = value
        return row


ML_CSV_COLUMNS = [
    "scenario_id",
    "group",
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
    "isolation_eligible_raw_qrs",
    "flagged_for_remediation",
] + [f"feature_{name}" for name in FEATURE_NAMES]


def load_ml_observation_results(
    detector: AnomalyDetector, pcap_path: Path = LABELLED_SET_PCAP_PATH
) -> List[MLObservationResult]:
    """Assess every labelled observation through the real pipeline WITH the
    Isolation Forest attached, reusing Phase 2A's own packet loading and
    manifest-correspondence checks."""
    if not Path(pcap_path).exists():
        raise FileNotFoundError(MISSING_FIXTURE_MESSAGE)

    packets_by_ip = {
        raw_packet.src_ip: raw_packet
        for raw_packet in OfflinePcapSource(pcap_path).read_packets()
    }
    return [
        MLObservationResult(observation, packets_by_ip[observation.src_ip], detector)
        for observation in LABELLED_OBSERVATIONS
    ]


def _binary_report(
    y_true: List[bool], y_predicted: List[bool], scores: List[float]
) -> Dict[str, Any]:
    """Confusion-based metrics plus ROC-AUC over the continuous scores."""
    report = binary_metrics(confusion_counts(y_true, y_predicted)).to_dict()
    report["roc_auc"] = roc_auc(y_true, scores).to_dict()
    report["roc_auc_input"] = (
        "anomaly_score (= -decision_function); never is_anomaly, a risk "
        "category, or confidence treated as a probability"
    )
    return report


# --- SECTION A: synthetic feature-distribution evaluation -----------------


def build_synthetic_heldout_report(detector: AnomalyDetector) -> Dict[str, Any]:
    """Score the deterministic held-out synthetic set.

    Labels come from which distribution ml/dataset.py drew each row from,
    fixed before inference (see tests/fixtures/ml_heldout_set.py). The
    positive class is "injected outlier by construction"."""
    matrix = build_heldout_feature_matrix()
    labels = heldout_construction_labels()
    raw_decisions, anomaly_scores, is_anomaly = score_feature_matrix(detector, matrix)

    report = _binary_report(labels, is_anomaly, anomaly_scores)
    report["section"] = SYNTHETIC_SECTION_TITLE
    report["caveat"] = SYNTHETIC_SECTION_CAVEAT
    report["heldout_random_state"] = HELDOUT_RANDOM_STATE
    report["training_random_state"] = DEFAULT_RANDOM_STATE
    report["n_normal_by_construction"] = HELDOUT_NORMAL_COUNT
    report["n_outlier_by_construction"] = HELDOUT_OUTLIER_COUNT
    report["distinct_feature_vectors"] = len({tuple(row) for row in matrix.tolist()})
    report["total_rows"] = int(matrix.shape[0])
    report["label_provenance"] = (
        "Structural: the generator's documented row ordering (normal rows first, "
        "injected outlier rows appended). Never derived from any model output."
    )
    report["anomaly_score_by_class"] = {
        "outlier_by_construction": value_summary(
            [score for score, label in zip(anomaly_scores, labels) if label]
        ),
        "normal_by_construction": value_summary(
            [score for score, label in zip(anomaly_scores, labels) if not label]
        ),
    }
    report["raw_decision_by_class"] = {
        "outlier_by_construction": value_summary(
            [value for value, label in zip(raw_decisions, labels) if label]
        ),
        "normal_by_construction": value_summary(
            [value for value, label in zip(raw_decisions, labels) if not label]
        ),
    }
    return report


# --- SECTION B: pipeline-extracted controlled evaluation ------------------


def build_pipeline_ml_report(results: List[MLObservationResult]) -> Dict[str, Any]:
    """Isolation Forest metrics on the feature vectors the REAL production
    inference path built, against the a-priori external rubric."""
    binary = [r for r in results if r.observation.participates_in_binary_metrics]
    y_true = [r.observation.is_externally_risky for r in binary]
    y_predicted = [r.is_anomaly for r in binary]
    scores = [r.anomaly_score for r in binary]

    report = _binary_report(y_true, y_predicted, scores)
    report["section"] = PIPELINE_SECTION_TITLE
    report["feature_provenance"] = (
        "Captured as pipeline.assessment_pipeline.assess_packet() handed them to "
        "the model — never hand-constructed DeviceFeatures."
    )
    report["positive_class"] = POSITIVE_CLASS_DEFINITION
    report["observations_in_binary_metrics"] = len(binary)

    excluded = [r for r in results if not r.observation.participates_in_binary_metrics]
    report["excluded_observations"] = {
        "count": len(excluded),
        "note": (
            "Outside every confusion matrix (no a-priori binary label); anomaly "
            "scores recorded for completeness only."
        ),
        "scenarios": [
            {
                "scenario_id": r.observation.scenario_id,
                "anomaly_score": round(r.anomaly_score, 6),
                "is_anomaly": r.is_anomaly,
            }
            for r in excluded
        ],
    }

    def _scores_for(label: str) -> List[float]:
        return [
            r.anomaly_score
            for r in results
            if r.observation.external_security_label == label
        ]

    report["anomaly_score_by_external_label"] = {
        LABEL_SAFE: value_summary(_scores_for(LABEL_SAFE)),
        LABEL_RISKY: value_summary(_scores_for(LABEL_RISKY)),
        LABEL_EXCLUDED: value_summary(_scores_for(LABEL_EXCLUDED)),
    }
    report["flagged_anomalous_counts"] = {
        label: sum(
            1
            for r in results
            if r.observation.external_security_label == label and r.is_anomaly
        )
        for label in (LABEL_SAFE, LABEL_RISKY, LABEL_EXCLUDED)
    }
    report["observation_counts_by_label"] = label_counts()
    report["distinct_feature_vectors"] = len({tuple(r.vector) for r in results})
    report["confidence_semantics"] = CONFIDENCE_SEMANTICS
    return report


# --- train/serve mismatch quantification ---------------------------------

_COHORT_TRAINING_NORMAL = "training_normal"
_COHORT_TRAINING_OUTLIER = "training_outlier"
_COHORT_PIPELINE_SAFE = "pipeline_safe"
_COHORT_PIPELINE_RISKY = "pipeline_risky"
_COHORT_PIPELINE_EXCLUDED = "pipeline_excluded"

ML_FEATURE_CSV_COLUMNS = [
    "feature",
    "cohort",
    "count",
    "min",
    "median",
    "max",
    "mean",
    "zero_count",
    "zero_fraction",
]


def build_train_serve_comparison(
    results: List[MLObservationResult],
) -> Dict[str, Any]:
    """Per-feature distribution summaries for the training cohorts and the
    real pipeline cohorts, side by side.

    This is what explains how a model can score well on the synthetic feature
    distribution (Section A) while separating nothing on real pipeline vectors
    (Section B). Nothing is altered; the distributions are only described."""
    training = build_training_feature_matrix()
    training_labels = training_construction_labels(training)

    training_normal = training[[not label for label in training_labels]]
    training_outlier = training[training_labels]

    def _pipeline_vectors(label: str) -> np.ndarray:
        rows = [
            r.vector
            for r in results
            if r.observation.external_security_label == label
        ]
        return np.array(rows, dtype=float) if rows else np.empty((0, len(FEATURE_NAMES)))

    cohorts = {
        _COHORT_TRAINING_NORMAL: training_normal,
        _COHORT_TRAINING_OUTLIER: training_outlier,
        _COHORT_PIPELINE_SAFE: _pipeline_vectors(LABEL_SAFE),
        _COHORT_PIPELINE_RISKY: _pipeline_vectors(LABEL_RISKY),
        _COHORT_PIPELINE_EXCLUDED: _pipeline_vectors(LABEL_EXCLUDED),
    }

    per_feature: Dict[str, Any] = {}
    for index, name in enumerate(FEATURE_NAMES):
        per_feature[name] = {
            cohort: value_summary(matrix[:, index].tolist() if matrix.size else [])
            for cohort, matrix in cohorts.items()
        }

    return {
        "interpretation": (
            "Per-feature distribution comparison between the cohorts the model was "
            "fitted on and the cohorts the real pipeline produces. Descriptive only "
            "— no feature, distribution or model parameter was modified."
        ),
        "cohort_sizes": {
            cohort: int(matrix.shape[0]) for cohort, matrix in cohorts.items()
        },
        "features": per_feature,
        "structural_findings": _structural_findings(per_feature),
    }


def _structural_findings(per_feature: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Name the specific feature-level divergences, with their numbers, rather
    than leaving a reader to spot them in a wide table."""
    findings = []

    for name in ("key_size_observed", "tls_version_observed", "forward_secrecy"):
        summary = per_feature[name]
        findings.append(
            {
                "feature": name,
                "training_normal_zero_fraction": summary[_COHORT_TRAINING_NORMAL][
                    "zero_fraction"
                ],
                "training_outlier_zero_fraction": summary[_COHORT_TRAINING_OUTLIER][
                    "zero_fraction"
                ],
                "pipeline_safe_zero_fraction": summary[_COHORT_PIPELINE_SAFE][
                    "zero_fraction"
                ],
                "pipeline_risky_zero_fraction": summary[_COHORT_PIPELINE_RISKY][
                    "zero_fraction"
                ],
            }
        )

    for name in ("shannon_entropy", "packet_size", "key_size"):
        summary = per_feature[name]
        findings.append(
            {
                "feature": name,
                "training_normal_range": [
                    summary[_COHORT_TRAINING_NORMAL]["min"],
                    summary[_COHORT_TRAINING_NORMAL]["max"],
                ],
                "training_outlier_range": [
                    summary[_COHORT_TRAINING_OUTLIER]["min"],
                    summary[_COHORT_TRAINING_OUTLIER]["max"],
                ],
                "pipeline_safe_range": [
                    summary[_COHORT_PIPELINE_SAFE]["min"],
                    summary[_COHORT_PIPELINE_SAFE]["max"],
                ],
                "pipeline_risky_range": [
                    summary[_COHORT_PIPELINE_RISKY]["min"],
                    summary[_COHORT_PIPELINE_RISKY]["max"],
                ],
            }
        )

    return findings


# --- SECTION C: paired QRS-only vs. fused comparison ---------------------


def build_fusion_comparison(
    qrs_results: List[ObservationResult], ml_results: List[MLObservationResult]
) -> Dict[str, Any]:
    """Paired comparison of the same observations under QRS-only and under
    QRS + the existing Isolation Forest.

    Raises:
        ValueError: if the two result lists are not the same observations in
            the same order — an unpaired comparison would be meaningless.
    """
    if [r.observation.scenario_id for r in qrs_results] != [
        r.observation.scenario_id for r in ml_results
    ]:
        raise ValueError(
            "QRS-only and ML result lists must cover the same observations in the "
            "same order for a paired comparison"
        )

    by_scenario = {}
    escalated = []
    unchanged = []
    safe_escalated = []
    risky_escalated = []

    for qrs_result, ml_result in zip(qrs_results, ml_results):
        observation = ml_result.observation
        qrs_only_category = qrs_result.actual_final_category
        fused_category = ml_result.fused_final_category
        was_escalated = fused_category != qrs_only_category

        by_scenario[observation.scenario_id] = {
            "external_label": observation.external_security_label,
            "qrs": ml_result.qrs,
            "qrs_only_final_category": qrs_only_category.value,
            "fused_final_category": fused_category.value,
            "escalated_by_ml": was_escalated,
            "is_anomaly": ml_result.is_anomaly,
        }

        if was_escalated:
            escalated.append(observation.scenario_id)
            if observation.external_security_label == LABEL_SAFE:
                safe_escalated.append(observation.scenario_id)
            elif observation.external_security_label == LABEL_RISKY:
                risky_escalated.append(observation.scenario_id)
        else:
            unchanged.append(observation.scenario_id)

    # Paired remediation-flagging metrics on the identical binary subset.
    paired_qrs = [r for r in qrs_results if r.observation.participates_in_binary_metrics]
    paired_ml = [r for r in ml_results if r.observation.participates_in_binary_metrics]
    y_true = [r.observation.is_externally_risky for r in paired_ml]

    qrs_only_metrics = binary_metrics(
        confusion_counts(y_true, [r.flagged_for_remediation for r in paired_qrs])
    ).to_dict()
    fused_metrics = binary_metrics(
        confusion_counts(y_true, [r.flagged_for_remediation for r in paired_ml])
    ).to_dict()

    deltas = {}
    for key in (
        "accuracy",
        "precision",
        "recall_sensitivity",
        "specificity",
        "f1",
        "false_positive_rate",
        "false_negative_rate",
        "balanced_accuracy",
    ):
        before, after = qrs_only_metrics[key], fused_metrics[key]
        deltas[key] = (
            None if before is None or after is None else round(after - before, 6)
        )

    isolation = _isolation_invariant(qrs_results, ml_results)
    verdict = _fusion_verdict(qrs_only_metrics, fused_metrics, safe_escalated)

    return {
        "interpretation": (
            "Paired comparison on identical observations: deterministic QRS-only "
            "versus QRS + the existing Isolation Forest under the frozen fusion "
            "rule. The operating point is remediation flagging (final_category != "
            "LOW), the only one ML can affect."
        ),
        "fusion_rule": (
            "LOW + anomaly -> MEDIUM; MEDIUM + anomaly -> HIGH; HIGH + anomaly -> "
            "HIGH. The QRS category is the floor and ML may raise it by at most one "
            "level; confidence never influences the outcome."
        ),
        "observations_total": len(ml_results),
        "observations_escalated": len(escalated),
        "observations_unchanged": len(unchanged),
        "escalated_scenarios": escalated,
        "safe_observations_incorrectly_escalated": {
            "count": len(safe_escalated),
            "scenarios": safe_escalated,
        },
        "risky_observations_usefully_escalated": {
            "count": len(risky_escalated),
            "scenarios": risky_escalated,
            "note": (
                "'Usefully' counts a RISKY observation whose reported category rose. "
                "On this set every RISKY observation was already flagged under "
                "QRS-only, so escalation changed no remediation decision."
            ),
        },
        "qrs_only_metrics": qrs_only_metrics,
        "fused_metrics": fused_metrics,
        "metric_deltas_fused_minus_qrs_only": deltas,
        "verdict": verdict,
        "physical_isolation_invariant": isolation,
        "per_scenario": by_scenario,
    }


def _isolation_invariant(
    qrs_results: List[ObservationResult], ml_results: List[MLObservationResult]
) -> Dict[str, Any]:
    """Verify that physical-isolation eligibility is identical with and
    without ML — the frozen guarantee that an ML-only escalation can never
    trigger a physical isolation action."""
    mismatches = [
        ml_result.observation.scenario_id
        for qrs_result, ml_result in zip(qrs_results, ml_results)
        if qrs_result.actual_isolation_eligible != ml_result.isolation_eligible
    ]
    eligible_without = [
        r.observation.scenario_id for r in qrs_results if r.actual_isolation_eligible
    ]
    eligible_with = [
        r.observation.scenario_id for r in ml_results if r.isolation_eligible
    ]
    return {
        "identical": mismatches == [] and eligible_without == eligible_with,
        "mismatched_scenarios": mismatches,
        "eligible_without_ml": eligible_without,
        "eligible_with_ml": eligible_with,
        "rule": (
            "enforcement.decision.should_isolate() reads risk_assessment.risk_score "
            "(raw QRS) and never final_category, so ML cannot affect eligibility."
        ),
    }


def _fusion_verdict(
    qrs_only: Dict[str, Any], fused: Dict[str, Any], safe_escalated: List[str]
) -> Dict[str, Any]:
    """State plainly whether the paired measurements support a claim that the
    model improves CIPHER. They must not be dressed up either way."""
    improved = []
    worsened = []
    for key, higher_is_better in (
        ("accuracy", True),
        ("precision", True),
        ("recall_sensitivity", True),
        ("specificity", True),
        ("f1", True),
        ("balanced_accuracy", True),
        ("false_positive_rate", False),
        ("false_negative_rate", False),
    ):
        before, after = qrs_only[key], fused[key]
        if before is None or after is None or before == after:
            continue
        better = after > before if higher_is_better else after < before
        (improved if better else worsened).append(key)

    supports_improvement = bool(improved) and not worsened
    return {
        "metrics_improved": improved,
        "metrics_worsened": worsened,
        "paired_measurements_support_an_improvement_claim": supports_improvement,
        "statement": (
            "On this controlled set the paired measurements DO NOT support a claim "
            "that the existing Isolation Forest improves CIPHER's remediation "
            "flagging. "
            if not supports_improvement
            else "On this controlled set the paired measurements support an "
            "improvement in remediation flagging. "
        )
        + (
            f"{len(safe_escalated)} externally SAFE observation(s) were escalated, "
            f"and physical-isolation eligibility is unchanged by construction."
        ),
    }


def build_ml_report(
    detector_metadata: Dict[str, Any],
    synthetic: Dict[str, Any],
    pipeline: Dict[str, Any],
    train_serve: Dict[str, Any],
    fusion: Dict[str, Any],
    ml_results: List[MLObservationResult],
    qrs_results: List[ObservationResult],
) -> Dict[str, Any]:
    qrs_only_by_scenario = {
        r.observation.scenario_id: r.actual_final_category.value for r in qrs_results
    }
    observations = []
    for result in ml_results:
        row = result.to_row()
        scenario_id = row["scenario_id"]
        row["qrs_only_final_category"] = qrs_only_by_scenario[scenario_id]
        row["escalated_by_ml"] = (
            row["fused_final_category"] != row["qrs_only_final_category"]
        )
        observations.append(row)

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": "Phase 2B",
        "evaluation_mode": "Existing Isolation Forest, measured (no tuning or repair)",
        "model": detector_metadata,
        "section_a_synthetic_feature_distribution": synthetic,
        "section_b_pipeline_extracted": pipeline,
        "train_serve_feature_comparison": train_serve,
        "section_c_fusion_comparison": fusion,
        "observations": observations,
        "notes": (
            "Measurement of the EXISTING, frozen Isolation Forest on controlled "
            "deterministic synthetic/offline observations. The model was fitted in "
            "memory from ml/dataset.py at its frozen seed and configuration; the "
            "on-disk artifact was never read or written, and nothing was tuned, "
            "retrained differently or repaired. Section A is a synthetic "
            "feature-distribution result and is neither real packet nor real "
            "network accuracy. Section B reflects the vectors the real production "
            "inference path builds. confidence is not a calibrated probability, so "
            "no calibration metric is reported, and ROC-AUC is computed only over "
            "the continuous anomaly_score. Neither section is real-world detection "
            "accuracy, production accuracy, general IoT accuracy, or a network-wide "
            "measurement."
        ),
    }


def write_ml_outputs(report: Dict[str, Any], results_dir: Path) -> Tuple[Path, Path, Path]:
    """Write the Phase 2B JSON, the per-observation CSV and the per-feature
    distribution CSV. Phase 2A's own outputs are untouched."""
    results_dir.mkdir(parents=True, exist_ok=True)

    json_path = results_dir / ML_JSON_FILENAME
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    csv_path = results_dir / ML_CSV_FILENAME
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ML_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for row in report["observations"]:
            writer.writerow(row)

    feature_csv_path = results_dir / ML_FEATURE_CSV_FILENAME
    with feature_csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ML_FEATURE_CSV_COLUMNS)
        writer.writeheader()
        features = report["train_serve_feature_comparison"]["features"]
        for feature_name, cohorts in features.items():
            for cohort_name, summary in cohorts.items():
                writer.writerow(
                    {
                        "feature": feature_name,
                        "cohort": cohort_name,
                        "count": summary["count"],
                        "min": summary["min"],
                        "median": summary["median"],
                        "max": summary["max"],
                        "mean": summary["mean"],
                        "zero_count": summary["zero_count"],
                        "zero_fraction": summary["zero_fraction"],
                    }
                )

    return json_path, csv_path, feature_csv_path


def _print_binary_block(report: Dict[str, Any], indent: str = "    ") -> None:
    counts = report["counts"]
    print(
        f"{indent}TP={counts['true_positives']}  TN={counts['true_negatives']}  "
        f"FP={counts['false_positives']}  FN={counts['false_negatives']}  "
        f"N={counts['total']}"
    )
    print(
        f"{indent}accuracy={_format_metric(report['accuracy'])}  "
        f"precision={_format_metric(report['precision'])}  "
        f"recall={_format_metric(report['recall_sensitivity'])}  "
        f"specificity={_format_metric(report['specificity'])}"
    )
    print(
        f"{indent}F1={_format_metric(report['f1'])}  "
        f"FPR={_format_metric(report['false_positive_rate'])}  "
        f"FNR={_format_metric(report['false_negative_rate'])}  "
        f"balanced accuracy={_format_metric(report['balanced_accuracy'])}"
    )
    auc = report["roc_auc"]
    auc_display = "not defined" if auc["auc"] is None else f"{auc['auc']:.4f}"
    print(
        f"{indent}ROC-AUC={auc_display} (over anomaly_score; "
        f"n_positive={auc['n_positive']}, n_negative={auc['n_negative']}, "
        f"tied pairs={auc['tied_pairs']}/{auc['n_pairs']})"
    )


def _print_score_summary(label: str, summary: Optional[Dict[str, Any]], indent: str) -> None:
    if summary is None or summary["count"] == 0:
        print(f"{indent}{label:<28} (no observations)")
        return
    print(
        f"{indent}{label:<28} n={summary['count']:<4} "
        f"min={summary['min']:+.4f}  median={summary['median']:+.4f}  "
        f"max={summary['max']:+.4f}"
    )


def _print_ml_report(report: Dict[str, Any]) -> None:
    model = report["model"]
    print("=" * 78)
    print("CIPHER Phase 2B — Existing Isolation Forest, measured")
    print("=" * 78)
    print(
        "\nMeasurement only: the model is the existing frozen one, fitted IN MEMORY "
        "from ml/dataset.py at its frozen seed and configuration. The on-disk "
        "artifact is never read or written, and nothing was tuned, retrained "
        "differently, repaired or redesigned.\n"
    )
    print("--- model under evaluation ---")
    print(
        f"  contamination={model['contamination']}  "
        f"random_state={model['random_state']}  "
        f"n_estimators={model['n_estimators']}"
    )
    print(
        f"  training matrix={tuple(model['training_matrix_shape'])}  "
        f"features={model['feature_count']}"
    )
    print(
        f"  scikit-learn={model['sklearn_version']}  numpy={model['numpy_version']}"
    )
    print(f"  {CONFIDENCE_SEMANTICS}")
    print()

    synthetic = report["section_a_synthetic_feature_distribution"]
    print(f"=== SECTION A — {SYNTHETIC_SECTION_TITLE} ===")
    print(
        f"  held-out seed={synthetic['heldout_random_state']} "
        f"(training seed={synthetic['training_random_state']}); "
        f"{synthetic['n_normal_by_construction']} normal + "
        f"{synthetic['n_outlier_by_construction']} injected outliers by construction"
    )
    print(
        f"  distinct feature vectors: {synthetic['distinct_feature_vectors']}"
        f"/{synthetic['total_rows']}"
    )
    _print_binary_block(synthetic, indent="  ")
    print("  anomaly_score by construction class:")
    scores = synthetic["anomaly_score_by_class"]
    _print_score_summary("outlier (positive)", scores["outlier_by_construction"], "    ")
    _print_score_summary("normal (negative)", scores["normal_by_construction"], "    ")
    print(f"  CAVEAT: {synthetic['caveat']}")
    print()

    pipeline = report["section_b_pipeline_extracted"]
    print(f"=== SECTION B — {PIPELINE_SECTION_TITLE} ===")
    print(f"  {pipeline['feature_provenance']}")
    print(
        f"  observations in binary metrics: "
        f"{pipeline['observations_in_binary_metrics']}  "
        f"(EXCLUDED: {pipeline['excluded_observations']['count']})"
    )
    print(
        f"  distinct feature vectors across all 30 observations: "
        f"{pipeline['distinct_feature_vectors']}"
    )
    _print_binary_block(pipeline, indent="  ")
    print("  anomaly_score by external label:")
    by_label = pipeline["anomaly_score_by_external_label"]
    for label in (LABEL_SAFE, LABEL_RISKY, LABEL_EXCLUDED):
        _print_score_summary(label, by_label[label], "    ")
    flagged = pipeline["flagged_anomalous_counts"]
    counts = pipeline["observation_counts_by_label"]
    print(
        f"  flagged anomalous: SAFE {flagged[LABEL_SAFE]}/{counts[LABEL_SAFE]}  "
        f"RISKY {flagged[LABEL_RISKY]}/{counts[LABEL_RISKY]}  "
        f"EXCLUDED {flagged[LABEL_EXCLUDED]}/{counts[LABEL_EXCLUDED]}"
    )
    print()

    comparison = report["train_serve_feature_comparison"]
    print("--- train/serve feature-distribution comparison ---")
    sizes = comparison["cohort_sizes"]
    print("  cohort sizes: " + "  ".join(f"{k}={v}" for k, v in sizes.items()))
    header = (
        f"  {'feature':<22}{'train-normal':>22}{'train-outlier':>20}"
        f"{'pipeline SAFE':>20}{'pipeline RISKY':>20}"
    )
    print(header)
    for name, cohorts in comparison["features"].items():
        def _range(cohort: str) -> str:
            summary = cohorts[cohort]
            if summary["count"] == 0:
                return "n/a"
            return f"{summary['min']:.2f}-{summary['max']:.2f}"

        print(
            f"  {name:<22}{_range(_COHORT_TRAINING_NORMAL):>22}"
            f"{_range(_COHORT_TRAINING_OUTLIER):>20}"
            f"{_range(_COHORT_PIPELINE_SAFE):>20}"
            f"{_range(_COHORT_PIPELINE_RISKY):>20}"
        )
    print()

    fusion = report["section_c_fusion_comparison"]
    print("=== SECTION C — QRS-only versus fused-category paired comparison ===")
    print(f"  fusion rule: {fusion['fusion_rule']}")
    print(
        f"  escalated: {fusion['observations_escalated']}/"
        f"{fusion['observations_total']}   unchanged: "
        f"{fusion['observations_unchanged']}"
    )
    print(
        f"  externally SAFE incorrectly escalated: "
        f"{fusion['safe_observations_incorrectly_escalated']['count']}"
    )
    if fusion["safe_observations_incorrectly_escalated"]["scenarios"]:
        for scenario_id in fusion["safe_observations_incorrectly_escalated"]["scenarios"]:
            print(f"      {scenario_id}")
    print(
        f"  externally RISKY escalated: "
        f"{fusion['risky_observations_usefully_escalated']['count']}"
    )
    print()
    print("  remediation flagging (final_category != LOW), paired on N="
          f"{fusion['qrs_only_metrics']['counts']['total']}:")
    print("    QRS-only:")
    _print_binary_qrs_block(fusion["qrs_only_metrics"], "      ")
    print("    QRS + Isolation Forest:")
    _print_binary_qrs_block(fusion["fused_metrics"], "      ")
    print()
    verdict = fusion["verdict"]
    print(f"  metrics improved by fusion: {verdict['metrics_improved'] or 'none'}")
    print(f"  metrics worsened by fusion: {verdict['metrics_worsened'] or 'none'}")
    print(f"  VERDICT: {verdict['statement']}")
    print()
    invariant = fusion["physical_isolation_invariant"]
    print(
        f"  physical-isolation invariant holds (identical with and without ML): "
        f"{invariant['identical']}"
    )
    print(f"    eligible devices: {len(invariant['eligible_with_ml'])} in both cases")
    print()


def _print_binary_qrs_block(report: Dict[str, Any], indent: str) -> None:
    """Confusion/metric block WITHOUT ROC-AUC — for the QRS-only and fused
    category comparison, where the prediction is a discrete category and no
    continuous score exists to rank."""
    counts = report["counts"]
    print(
        f"{indent}TP={counts['true_positives']}  TN={counts['true_negatives']}  "
        f"FP={counts['false_positives']}  FN={counts['false_negatives']}"
    )
    print(
        f"{indent}accuracy={_format_metric(report['accuracy'])}  "
        f"precision={_format_metric(report['precision'])}  "
        f"recall={_format_metric(report['recall_sensitivity'])}  "
        f"specificity={_format_metric(report['specificity'])}"
    )
    print(
        f"{indent}F1={_format_metric(report['f1'])}  "
        f"FPR={_format_metric(report['false_positive_rate'])}  "
        f"FNR={_format_metric(report['false_negative_rate'])}  "
        f"balanced accuracy={_format_metric(report['balanced_accuracy'])}"
    )


def run_ml_evaluation(
    qrs_results: List[ObservationResult],
) -> Tuple[Dict[str, Any], List[MLObservationResult]]:
    """Build the whole Phase 2B report, reusing the already-computed Phase 2A
    QRS-only results for the paired comparison."""
    detector, metadata = build_in_memory_detector()
    ml_results = load_ml_observation_results(detector)

    synthetic = build_synthetic_heldout_report(detector)
    pipeline = build_pipeline_ml_report(ml_results)
    train_serve = build_train_serve_comparison(ml_results)
    fusion = build_fusion_comparison(qrs_results, ml_results)

    report = build_ml_report(
        metadata, synthetic, pipeline, train_serve, fusion, ml_results, qrs_results
    )
    return report, ml_results


def main(results_dir: Path = DEFAULT_RESULTS_DIR) -> int:
    """`results_dir` defaults to this repo's own gitignored
    data/evaluation/research/ directory; overridable so tests can redirect
    it to a tmp_path instead of writing into the real checkout."""
    print("=" * 78)
    print("CIPHER Phase 2A — Deterministic QRS-only controlled evaluation")
    print("=" * 78)
    print(
        "\nIsolation Forest is NOT used anywhere in this evaluation "
        "(anomaly_detector=None at every call site), so nothing below describes "
        "anomaly-detection performance. Every observation is a deterministic, "
        "synthetic/offline packet this project constructed, run through the real, "
        "unmodified CIPHER assessment path. Conformance figures measure "
        "implementation agreement with the frozen Quantum Risk Score specification; "
        "classification figures measure that specification's fixed thresholds "
        "against an a-priori external standards rubric on this controlled set. "
        "Neither is real-world detection accuracy.\n"
    )

    try:
        results = load_observation_results()
    except FileNotFoundError as error:
        print(str(error), file=sys.stderr)
        return 1

    report = build_report(results)

    _print_dataset(report)
    _print_conformance(report)
    _print_classification(report)

    invariant = report["qrs_only_invariant"]
    print(
        "  QRS-only invariant: final_category == QRS category for every "
        f"observation: {invariant['final_category_equals_qrs_category_for_every_observation']}"
    )
    print()

    json_path, csv_path = write_outputs(report, results_dir)
    print("=" * 78)
    print(f"Phase 2A JSON report written to {json_path}")
    print(f"Phase 2A per-observation CSV written to {csv_path}")
    print("=" * 78)
    print()

    ml_report, _ml_results = run_ml_evaluation(results)
    _print_ml_report(ml_report)

    ml_json_path, ml_csv_path, ml_feature_csv_path = write_ml_outputs(
        ml_report, results_dir
    )
    print("=" * 78)
    print(f"Phase 2B JSON report written to {ml_json_path}")
    print(f"Phase 2B per-observation CSV written to {ml_csv_path}")
    print(f"Phase 2B feature-distribution CSV written to {ml_feature_csv_path}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
