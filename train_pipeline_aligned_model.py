"""train_pipeline_aligned_model.py — Phase 2D pipeline-aligned Isolation Forest
training, threshold calibration and a single final frozen-test evaluation
(docs/SDD.md's Phase 2D addendum).

    python train_pipeline_aligned_model.py

WHAT THIS CORRECTS. Phase 2B measured the existing synthetically-trained
Isolation Forest on real pipeline vectors at 58.33% accuracy and 9.09%
specificity, with a 90.91% controlled false-positive rate, and traced it to a
train/serve feature-distribution mismatch: every row of the synthetic training
matrix carried both a TLS version and an RSA key size, which no single real
packet can, and 83% carried forward secrecy, which no real pipeline vector ever
does. This phase keeps the model, the features, the fusion rule and the Quantum
Risk Score exactly as they are, and changes only WHAT the model is fitted on and
WHERE its operating point sits.

TRAINING RUNS THROUGH THE REAL PRODUCTION PATH. Controlled packets are written
to a pcap, read back by capture.offline_source.OfflinePcapSource, and passed to
pipeline.assessment_pipeline.assess_packet. The DeviceFeatures objects are
captured as assess_packet hands them to the model, via a transparent collector
proxy, so the training vectors are byte-for-byte the ones production inference
builds. No DeviceFeatures is ever constructed here.

DATA SEPARATION IS THE LOAD-BEARING DISCIPLINE. Three cohorts, three disjoint
seed namespaces:

    train       SAFE only, 700 observations     seeds `p2d-train-*`
    validation  SAFE + RISKY, 160 observations  seeds `p2d-val-*`
    frozen test the Phase 2A/2B N=24 cohort     seeds `labelled-*`

The frozen test set is used EXACTLY ONCE, at the end, after the training corpus
and the threshold are both final. It never informs fitting, contamination,
feature choice, threshold choice, or any dataset-construction decision. The
threshold is selected on the validation cohort alone, by a pre-declared
deterministic objective with pre-declared tie-breaks.

MODEL PARAMETERS ARE UNCHANGED. contamination=0.05 and random_state=42, the
frozen values, with scikit-learn's own defaults for everything else. The
operating point is moved instead, through the estimator's `offset_` — which is
precisely the mechanism scikit-learn itself uses to apply `contamination`, so
`AnomalyDetector.predict_one`, the feature interface, the fusion rule and the
enforcement rule all keep working untouched.

ARTIFACT SAFETY. The candidate model is written to
ml/artifacts/candidates/anomaly_detector_phase2d.joblib. The production artifact
at ml/artifacts/anomaly_detector.joblib is never read or written by this script.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import sklearn

from capture.offline_source import OfflinePcapSource
from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD
from enforcement.decision import should_isolate
from evaluation.metrics import binary_metrics, confusion_counts, roc_auc, value_summary
from fingerprint.protocol import fingerprint_packet
from fusion.risk_fusion import _ESCALATE_ONE_LEVEL  # noqa: F401  (documented invariant check)
from ml.classifier import DEFAULT_CONTAMINATION, DEFAULT_RANDOM_STATE, AnomalyDetector
from ml.features import FEATURE_NAMES, vectorize_features
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.enums import RiskCategory
from pipeline.assessment_pipeline import assess_packet
from risk.port_risk import port_risk_for_protocol
from tests.fixtures.labelled_evaluation_manifest import (
    LABEL_EXCLUDED,
    LABEL_RISKY as TEST_LABEL_RISKY,
    LABEL_SAFE as TEST_LABEL_SAFE,
    LABELLED_OBSERVATIONS,
    LABELLED_SET_PCAP_PATH,
)
from tests.fixtures.pipeline_cohorts import (
    LABEL_RISKY,
    LABEL_SAFE,
    TRAIN_PCAP,
    VALIDATION_PCAP,
    build_training_observations,
    build_validation_observations,
    write_cohort_pcap,
)

REPO_ROOT = Path(__file__).resolve().parent
RESULTS_DIR = REPO_ROOT / "data" / "evaluation" / "research"
PHASE_2D_JSON = RESULTS_DIR / "latest_phase2d_evaluation.json"

CANDIDATE_DIR = REPO_ROOT / "ml" / "artifacts" / "candidates"
CANDIDATE_ARTIFACT = CANDIDATE_DIR / "anomaly_detector_phase2d.joblib"
PRODUCTION_ARTIFACT = REPO_ROOT / "ml" / "artifacts" / "anomaly_detector.joblib"

# The Phase 2B result, preserved verbatim for the before/after record. These are
# NOT recomputed here; they are the published Phase 2B measurements.
PHASE_2B_BASELINE = {
    "true_positives": 13,
    "true_negatives": 1,
    "false_positives": 10,
    "false_negatives": 0,
    "accuracy": 0.5833,
    "precision": 0.5652,
    "recall_sensitivity": 1.0000,
    "specificity": 0.0909,
    "f1": 0.7222,
    "false_positive_rate": 0.9091,
    "balanced_accuracy": 0.5455,
    "roc_auc": 0.9371,
    "source": "docs/SDD.md Phase 2B addendum; synthetically-trained Isolation Forest",
}

# Pre-declared acceptance criteria, frozen before any model was fitted.
ACCEPTANCE_CRITERIA = {
    "accuracy": (">=", 0.80),
    "precision": (">=", 0.80),
    "recall_sensitivity": (">=", 0.80),
    "specificity": (">=", 0.80),
    "f1": (">=", 0.80),
    "false_positive_rate": ("<=", 0.20),
    "balanced_accuracy": (">=", 0.80),
}

THRESHOLD_OBJECTIVE = (
    "Maximize balanced accuracy (equivalently Youden J = sensitivity + "
    "specificity - 1) on the VALIDATION cohort only. Ties are broken "
    "deterministically, in order: (1) highest balanced accuracy, (2) highest "
    "F1, (3) lowest false-positive rate, (4) smallest absolute distance from "
    "the original zero operating point. Candidates are the midpoints between "
    "consecutive distinct validation anomaly scores, plus one point below the "
    "minimum and one above the maximum."
)


class _FeatureCollector:
    """A transparent proxy that records the DeviceFeatures the production
    pipeline builds, then returns a placeholder assessment.

    assess_packet() constructs DeviceFeatures itself and hands it to
    `anomaly_detector.predict_one(...)`; intercepting exactly that call is how
    this script obtains training vectors without ever constructing a
    DeviceFeatures of its own. The returned AnomalyAssessment is a fixed
    placeholder that is discarded by the caller — during feature collection
    there is no fitted model yet, and nothing downstream of the recorded
    features is used.
    """

    def __init__(self) -> None:
        self.features: List[Any] = []

    def predict_one(self, features) -> AnomalyAssessment:
        self.features.append(features)
        return AnomalyAssessment(anomaly_score=0.0, is_anomaly=False, confidence=0.5)


@dataclass
class ExtractedObservation:
    """One observation after it has been through the real pipeline."""

    observation_id: str
    cohort: str
    label: str
    family: str
    vector: Tuple[float, ...]
    qrs: int
    qrs_category: RiskCategory
    isolation_eligible: bool

    @property
    def is_risky(self) -> bool:
        return self.label == LABEL_RISKY


def extract_cohort(observations, pcap_path: Path) -> List[ExtractedObservation]:
    """Write a cohort to a pcap, read it back through the production reader, and
    collect each observation's production feature vector."""
    write_cohort_pcap(observations, pcap_path)
    by_ip = {o.src_ip: o for o in observations}

    extracted: List[ExtractedObservation] = []
    for raw_packet in OfflinePcapSource(pcap_path).read_packets():
        source = by_ip.get(raw_packet.src_ip)
        if source is None:
            raise RuntimeError(
                f"{pcap_path} produced an unexpected source IP {raw_packet.src_ip}"
            )
        collector = _FeatureCollector()
        device = Device.first_contact(raw_packet.src_ip, raw_packet.timestamp)
        fingerprint = fingerprint_packet(raw_packet.payload)
        port_risk = port_risk_for_protocol(fingerprint.protocol)
        assessment = assess_packet(raw_packet, device, port_risk, collector)

        if len(collector.features) != 1:
            raise RuntimeError(
                f"{source.observation_id}: expected one model call, got "
                f"{len(collector.features)}"
            )
        vector = tuple(float(v) for v in vectorize_features(collector.features[0]))
        extracted.append(
            ExtractedObservation(
                observation_id=source.observation_id,
                cohort=source.cohort,
                label=source.label,
                family=source.family,
                vector=vector,
                qrs=assessment.risk_assessment.risk_score,
                qrs_category=assessment.risk_assessment.category,
                isolation_eligible=should_isolate(
                    assessment, DEFAULT_RISK_ISOLATION_THRESHOLD
                ),
            )
        )

    if len(extracted) != len(observations):
        raise RuntimeError(
            f"{pcap_path}: wrote {len(observations)} observations but the production "
            f"reader yielded {len(extracted)} — every observation must survive the "
            f"reader for the cohort to be the one that was declared"
        )
    return extracted


def extract_frozen_test_cohort() -> List[ExtractedObservation]:
    """The Phase 2A/2B N=24 binary cohort plus its EXCLUDED observations, read
    from the existing frozen fixture. Touched exactly once, at the end."""
    if not LABELLED_SET_PCAP_PATH.exists():
        raise FileNotFoundError(
            "The frozen Phase 2A labelled dataset is missing. Generate it with:\n"
            "    python -m tests.fixtures.generate_labelled_evaluation_fixtures"
        )
    by_ip = {o.src_ip: o for o in LABELLED_OBSERVATIONS}
    extracted: List[ExtractedObservation] = []
    for raw_packet in OfflinePcapSource(LABELLED_SET_PCAP_PATH).read_packets():
        source = by_ip[raw_packet.src_ip]
        collector = _FeatureCollector()
        device = Device.first_contact(raw_packet.src_ip, raw_packet.timestamp)
        fingerprint = fingerprint_packet(raw_packet.payload)
        port_risk = port_risk_for_protocol(fingerprint.protocol)
        assessment = assess_packet(raw_packet, device, port_risk, collector)
        vector = tuple(float(v) for v in vectorize_features(collector.features[0]))
        extracted.append(
            ExtractedObservation(
                observation_id=source.scenario_id,
                cohort="frozen_test",
                label=source.external_security_label,
                family=source.group,
                vector=vector,
                qrs=assessment.risk_assessment.risk_score,
                qrs_category=assessment.risk_assessment.category,
                isolation_eligible=should_isolate(
                    assessment, DEFAULT_RISK_ISOLATION_THRESHOLD
                ),
            )
        )
    return extracted


def prove_separation(
    train: List[ExtractedObservation],
    validation: List[ExtractedObservation],
    frozen: List[ExtractedObservation],
) -> Dict[str, Any]:
    """Positive proof that no cohort shares a feature vector with another.

    Vector-level, not merely seed-level: two differently-seeded packets could in
    principle vectorize identically, and that would still be leakage.
    """
    train_v = {o.vector for o in train}
    validation_v = {o.vector for o in validation}
    frozen_v = {o.vector for o in frozen}
    return {
        "train_observations": len(train),
        "validation_observations": len(validation),
        "frozen_test_observations": len(frozen),
        "distinct_train_vectors": len(train_v),
        "distinct_validation_vectors": len(validation_v),
        "distinct_frozen_test_vectors": len(frozen_v),
        "train_validation_vector_overlap": len(train_v & validation_v),
        "train_frozen_vector_overlap": len(train_v & frozen_v),
        "validation_frozen_vector_overlap": len(validation_v & frozen_v),
        "duplicate_train_vectors": len(train) - len(train_v),
        "duplicate_validation_vectors": len(validation) - len(validation_v),
        "seed_namespaces": {
            "train": "p2d-train-*",
            "validation": "p2d-val-*",
            "frozen_test": "labelled-* (built by a different module)",
        },
    }


def fit_candidate(train: List[ExtractedObservation]) -> Tuple[AnomalyDetector, Dict[str, Any]]:
    """Fit the frozen AnomalyDetector on the pipeline-extracted SAFE corpus.

    Parameters are unchanged from production: contamination=0.05,
    random_state=42, scikit-learn defaults elsewhere.
    """
    matrix = np.array([o.vector for o in train], dtype=float)
    detector = AnomalyDetector(
        contamination=DEFAULT_CONTAMINATION, random_state=DEFAULT_RANDOM_STATE
    )
    detector.fit(matrix)
    metadata = {
        "estimator": "sklearn.ensemble.IsolationForest via ml.classifier.AnomalyDetector",
        "contamination": DEFAULT_CONTAMINATION,
        "random_state": DEFAULT_RANDOM_STATE,
        "n_estimators": detector._model.get_params()["n_estimators"],
        "max_features": detector._model.get_params()["max_features"],
        "bootstrap": detector._model.get_params()["bootstrap"],
        "max_samples_resolved": int(detector._model.max_samples_),
        "training_matrix_shape": list(matrix.shape),
        "feature_names": list(FEATURE_NAMES),
        "offset_after_fit": float(detector._model.offset_),
        "training_score_std": float(detector._score_std),
        "sklearn_version": sklearn.__version__,
        "numpy_version": np.__version__,
        "parameter_changes_vs_production": "none — only the training data and the operating point changed",
    }
    return detector, metadata


def anomaly_scores(detector: AnomalyDetector, observations: Sequence[ExtractedObservation]) -> List[float]:
    """anomaly_score = -decision_function, exactly as
    AnomalyDetector.predict_one defines it."""
    matrix = np.array([o.vector for o in observations], dtype=float)
    return [-float(v) for v in detector._model.decision_function(matrix)]


def _metrics_at(threshold: float, labels: List[bool], scores: List[float]) -> Dict[str, Any]:
    predictions = [score > threshold for score in scores]
    return binary_metrics(confusion_counts(labels, predictions)).to_dict()


def calibrate_threshold(
    detector: AnomalyDetector, validation: List[ExtractedObservation]
) -> Dict[str, Any]:
    """Select the anomaly-score threshold on the VALIDATION cohort only.

    Deterministic: candidates are the midpoints between consecutive distinct
    validation scores plus one point outside each end, and the winner is chosen
    by the pre-declared objective and tie-break order. No manual choice, and the
    frozen test set is not consulted.
    """
    scores = anomaly_scores(detector, validation)
    labels = [o.is_risky for o in validation]

    distinct = sorted(set(scores))
    candidates = [distinct[0] - 1e-6]
    candidates += [
        (distinct[i] + distinct[i + 1]) / 2.0 for i in range(len(distinct) - 1)
    ]
    candidates.append(distinct[-1] + 1e-6)

    evaluated = []
    for threshold in candidates:
        metrics = _metrics_at(threshold, labels, scores)
        evaluated.append((threshold, metrics))

    def sort_key(item):
        threshold, m = item
        balanced = m["balanced_accuracy"] if m["balanced_accuracy"] is not None else -1.0
        f1 = m["f1"] if m["f1"] is not None else -1.0
        fpr = m["false_positive_rate"] if m["false_positive_rate"] is not None else 2.0
        # Maximize balanced accuracy, then F1; minimize FPR; then prefer the
        # threshold closest to the original zero operating point.
        return (-balanced, -f1, fpr, abs(threshold - 0.0))

    evaluated.sort(key=sort_key)
    best_threshold, best_metrics = evaluated[0]

    return {
        "objective": THRESHOLD_OBJECTIVE,
        "candidates_evaluated": len(candidates),
        "selected_threshold": best_threshold,
        "selected_validation_metrics": best_metrics,
        "original_zero_operating_point_metrics": _metrics_at(0.0, labels, scores),
        "validation_score_summary": {
            LABEL_SAFE: value_summary([s for s, o in zip(scores, validation) if not o.is_risky]),
            LABEL_RISKY: value_summary([s for s, o in zip(scores, validation) if o.is_risky]),
        },
        "validation_roc_auc": roc_auc(labels, scores).to_dict(),
        "cohort_used": "validation only — the frozen test set was not consulted",
    }


def apply_threshold(detector: AnomalyDetector, threshold: float) -> float:
    """Bake the calibrated threshold into the estimator's `offset_`.

    decision_function(x) = score_samples(x) - offset_, and
    anomaly_score(x) = offset_ - score_samples(x), so setting

        offset_new = offset_old - threshold

    makes `anomaly_score_new > 0` exactly equivalent to
    `anomaly_score_old > threshold`. This is the same lever scikit-learn pulls
    to implement `contamination`, so every downstream consumer —
    AnomalyDetector.predict_one, fusion, enforcement — keeps working with no
    code change at all. Returns the new offset.
    """
    previous = float(detector._model.offset_)
    detector._model.offset_ = previous - threshold
    return float(detector._model.offset_)


def evaluate_cohort(
    detector: AnomalyDetector,
    observations: List[ExtractedObservation],
    binary_labels: Tuple[str, str] = (LABEL_SAFE, LABEL_RISKY),
) -> Dict[str, Any]:
    """Score a cohort and compute the full metric set over its binary subset."""
    scores = anomaly_scores(detector, observations)
    flags = [score > 0.0 for score in scores]  # post-calibration operating point

    binary = [
        (o, s, f) for o, s, f in zip(observations, scores, flags) if o.label in binary_labels
    ]
    labels = [o.label == binary_labels[1] for o, _, _ in binary]
    predictions = [f for _, _, f in binary]
    binary_scores = [s for _, s, _ in binary]

    report = binary_metrics(confusion_counts(labels, predictions)).to_dict()
    report["roc_auc"] = roc_auc(labels, binary_scores).to_dict()
    report["observations_in_binary_metrics"] = len(binary)

    by_label: Dict[str, Any] = {}
    for label in sorted({o.label for o in observations}):
        by_label[label] = value_summary(
            [s for o, s in zip(observations, scores) if o.label == label]
        )
    report["anomaly_score_by_label"] = by_label
    report["flagged_counts_by_label"] = {
        label: sum(
            1 for o, f in zip(observations, flags) if o.label == label and f
        )
        for label in sorted({o.label for o in observations})
    }
    report["observation_counts_by_label"] = {
        label: sum(1 for o in observations if o.label == label)
        for label in sorted({o.label for o in observations})
    }
    report["per_observation"] = [
        {
            "observation_id": o.observation_id,
            "label": o.label,
            "family": o.family,
            "qrs": o.qrs,
            "qrs_category": o.qrs_category.value,
            "anomaly_score": round(s, 6),
            "is_anomaly": f,
            "isolation_eligible_raw_qrs": o.isolation_eligible,
        }
        for o, s, f in zip(observations, scores, flags)
    ]
    return report


def check_acceptance(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Compare the final metrics against the pre-declared criteria."""
    results = {}
    for name, (direction, bound) in ACCEPTANCE_CRITERIA.items():
        value = metrics.get(name)
        if value is None:
            passed = None
        elif direction == ">=":
            passed = value >= bound
        else:
            passed = value <= bound
        results[name] = {
            "measured": value,
            "criterion": f"{direction} {bound:.0%}",
            "passed": passed,
        }
    decided = [r["passed"] for r in results.values() if r["passed"] is not None]
    return {
        "criteria": results,
        "all_passed": bool(decided) and all(decided),
        "note": (
            "Criteria were frozen before any model was fitted. They are evaluation "
            "goals, never a licence to tune against the frozen test set."
        ),
    }


def fusion_comparison(
    detector: AnomalyDetector, frozen: List[ExtractedObservation]
) -> Dict[str, Any]:
    """Paired QRS-only versus QRS + Phase-2D Isolation Forest on the frozen
    cohort, at the remediation-flagging operating point.

    Applies the frozen fusion rule directly to already-computed values rather
    than re-running the pipeline, so the comparison is exactly paired.
    """
    scores = anomaly_scores(detector, frozen)
    one_level = {
        RiskCategory.LOW: RiskCategory.MEDIUM,
        RiskCategory.MEDIUM: RiskCategory.HIGH,
        RiskCategory.HIGH: RiskCategory.HIGH,
    }

    binary = [(o, s) for o, s in zip(frozen, scores) if o.label in (TEST_LABEL_SAFE, TEST_LABEL_RISKY)]
    labels = [o.label == TEST_LABEL_RISKY for o, _ in binary]

    qrs_only_flags = [o.qrs_category != RiskCategory.LOW for o, _ in binary]
    fused_flags = []
    escalated_safe: List[str] = []
    escalated_risky: List[str] = []
    for o, s in binary:
        is_anomaly = s > 0.0
        fused = one_level[o.qrs_category] if is_anomaly else o.qrs_category
        fused_flags.append(fused != RiskCategory.LOW)
        if is_anomaly and fused != o.qrs_category:
            (escalated_safe if o.label == TEST_LABEL_SAFE else escalated_risky).append(
                o.observation_id
            )

    qrs_only = binary_metrics(confusion_counts(labels, qrs_only_flags)).to_dict()
    fused = binary_metrics(confusion_counts(labels, fused_flags)).to_dict()

    deltas = {}
    for key in (
        "accuracy", "precision", "recall_sensitivity", "specificity", "f1",
        "false_positive_rate", "false_negative_rate", "balanced_accuracy",
    ):
        before, after = qrs_only[key], fused[key]
        deltas[key] = None if before is None or after is None else round(after - before, 6)

    improved = [k for k, v in deltas.items() if v is not None and (
        (v > 0 and k not in ("false_positive_rate", "false_negative_rate"))
        or (v < 0 and k in ("false_positive_rate", "false_negative_rate"))
    )]
    worsened = [k for k, v in deltas.items() if v is not None and (
        (v < 0 and k not in ("false_positive_rate", "false_negative_rate"))
        or (v > 0 and k in ("false_positive_rate", "false_negative_rate"))
    )]

    isolation_identical = all(
        o.isolation_eligible == (o.qrs >= DEFAULT_RISK_ISOLATION_THRESHOLD) for o in frozen
    )

    return {
        "operating_point": "remediation flagging (final_category != LOW)",
        "qrs_only_metrics": qrs_only,
        "fused_metrics": fused,
        "metric_deltas_fused_minus_qrs_only": deltas,
        "metrics_improved": improved,
        "metrics_worsened": worsened,
        "paired_measurements_support_an_improvement_claim": bool(improved) and not worsened,
        "safe_observations_escalated": {"count": len(escalated_safe), "scenarios": escalated_safe},
        "risky_observations_escalated": {"count": len(escalated_risky), "scenarios": escalated_risky},
        "physical_isolation_invariant": {
            "identical_with_and_without_ml": isolation_identical,
            "eligible_observations": [o.observation_id for o in frozen if o.isolation_eligible],
            "rule": (
                "enforcement.decision.should_isolate() reads the raw Quantum Risk "
                "Score and never final_category, so no ML change can affect it."
            ),
        },
    }


def train_serve_comparison(
    train: List[ExtractedObservation], frozen: List[ExtractedObservation]
) -> Dict[str, Any]:
    """The Phase 2B distribution table, recomputed for the NEW training corpus
    against the frozen cohort's SAFE and RISKY vectors."""
    index = {name: i for i, name in enumerate(FEATURE_NAMES)}
    cohorts = {
        "new_training_normal": [o.vector for o in train],
        "pipeline_safe": [o.vector for o in frozen if o.label == TEST_LABEL_SAFE],
        "pipeline_risky": [o.vector for o in frozen if o.label == TEST_LABEL_RISKY],
    }
    features: Dict[str, Any] = {}
    for name in FEATURE_NAMES:
        column = index[name]
        features[name] = {
            cohort: value_summary([row[column] for row in rows])
            for cohort, rows in cohorts.items()
        }

    headline = {}
    for name in ("key_size_observed", "forward_secrecy"):
        headline[f"{name}_zero_fraction"] = {
            cohort: features[name][cohort]["zero_fraction"] for cohort in cohorts
        }
    for name in ("key_size", "shannon_entropy", "packet_size"):
        headline[f"{name}_median"] = {
            cohort: features[name][cohort]["median"] for cohort in cohorts
        }

    return {
        "cohort_sizes": {k: len(v) for k, v in cohorts.items()},
        "headline": headline,
        "features": features,
        "phase_2b_old_training_normal_for_comparison": {
            "key_size_observed_zero_fraction": 0.0,
            "key_size_median": 3072.0,
            "forward_secrecy_zero_fraction": 0.1722,
            "shannon_entropy_median": 7.479,
            "packet_size_median": 863.4,
            "source": "docs/SDD.md Phase 2B addendum",
        },
    }


def _fmt(value: Optional[float], percent: bool = True) -> str:
    if value is None:
        return "undefined"
    return f"{value:.2%}" if percent else f"{value:.4f}"


def print_report(report: Dict[str, Any]) -> None:
    print("=" * 78)
    print("CIPHER Phase 2D — Pipeline-aligned Isolation Forest")
    print("=" * 78)

    sep = report["separation"]
    print("\n--- cohort separation ---")
    print(f"  train      N={sep['train_observations']:4d}  distinct vectors={sep['distinct_train_vectors']}")
    print(f"  validation N={sep['validation_observations']:4d}  distinct vectors={sep['distinct_validation_vectors']}")
    print(f"  frozen test N={sep['frozen_test_observations']:3d}  distinct vectors={sep['distinct_frozen_test_vectors']}")
    print(f"  overlaps: train/val={sep['train_validation_vector_overlap']}  "
          f"train/test={sep['train_frozen_vector_overlap']}  "
          f"val/test={sep['validation_frozen_vector_overlap']}")

    model = report["model"]
    print("\n--- model (parameters unchanged) ---")
    print(f"  contamination={model['contamination']}  random_state={model['random_state']}  "
          f"n_estimators={model['n_estimators']}")
    print(f"  training matrix={tuple(model['training_matrix_shape'])}")
    print(f"  offset after fit={model['offset_after_fit']:.6f}")

    cal = report["calibration"]
    print("\n--- threshold calibration (validation only) ---")
    print(f"  candidates evaluated: {cal['candidates_evaluated']}")
    print(f"  selected threshold:   {cal['selected_threshold']:+.6f}")
    print(f"  offset after applying: {report['calibrated_offset']:.6f}")
    vm = cal["selected_validation_metrics"]
    print(f"  validation at selected threshold: balanced={_fmt(vm['balanced_accuracy'])}  "
          f"acc={_fmt(vm['accuracy'])}  spec={_fmt(vm['specificity'])}  rec={_fmt(vm['recall_sensitivity'])}")
    zm = cal["original_zero_operating_point_metrics"]
    print(f"  validation at original zero point: balanced={_fmt(zm['balanced_accuracy'])}  "
          f"spec={_fmt(zm['specificity'])}")

    print("\n--- train/serve distribution (new training corpus) ---")
    head = report["train_serve"]["headline"]
    old = report["train_serve"]["phase_2b_old_training_normal_for_comparison"]
    print(f"  {'metric':34}{'OLD train':>12}{'NEW train':>12}{'pipe SAFE':>12}{'pipe RISKY':>12}")
    rows = [
        ("key_size_observed zero-fraction", "key_size_observed_zero_fraction", "key_size_observed_zero_fraction"),
        ("forward_secrecy zero-fraction", "forward_secrecy_zero_fraction", "forward_secrecy_zero_fraction"),
        ("key_size median", "key_size_median", "key_size_median"),
        ("shannon_entropy median", "shannon_entropy_median", "shannon_entropy_median"),
        ("packet_size median", "packet_size_median", "packet_size_median"),
    ]
    for label, key, oldkey in rows:
        h = head[key]
        def f(v):
            return "n/a" if v is None else f"{v:.4f}"
        print(f"  {label:34}{f(old[oldkey]):>12}{f(h['new_training_normal']):>12}"
              f"{f(h['pipeline_safe']):>12}{f(h['pipeline_risky']):>12}")

    final = report["frozen_test"]
    counts = final["counts"]
    print("\n=== FINAL FROZEN TEST (N=24 binary), evaluated once ===")
    print(f"  TP={counts['true_positives']}  TN={counts['true_negatives']}  "
          f"FP={counts['false_positives']}  FN={counts['false_negatives']}")
    print(f"  accuracy={_fmt(final['accuracy'])}  precision={_fmt(final['precision'])}  "
          f"recall={_fmt(final['recall_sensitivity'])}  specificity={_fmt(final['specificity'])}")
    print(f"  F1={_fmt(final['f1'])}  FPR={_fmt(final['false_positive_rate'])}  "
          f"FNR={_fmt(final['false_negative_rate'])}  balanced={_fmt(final['balanced_accuracy'])}")
    auc = final["roc_auc"]
    print(f"  ROC-AUC={_fmt(auc['auc'], percent=False)} "
          f"(n_pos={auc['n_positive']}, n_neg={auc['n_negative']}, ties={auc['tied_pairs']})")

    print("\n--- before / after ---")
    base = report["phase_2b_baseline"]
    print(f"  {'metric':22}{'Original IF':>14}{'Phase 2D IF':>14}")
    for key, label in (
        ("accuracy", "Accuracy"), ("precision", "Precision"),
        ("recall_sensitivity", "Recall"), ("specificity", "Specificity"),
        ("f1", "F1"), ("false_positive_rate", "FPR"),
        ("balanced_accuracy", "Balanced accuracy"),
    ):
        print(f"  {label:22}{_fmt(base[key]):>14}{_fmt(final[key]):>14}")
    print(f"  {'ROC-AUC':22}{base['roc_auc']:>14.4f}{auc['auc']:>14.4f}")

    print("\n--- acceptance criteria (pre-declared) ---")
    for name, item in report["acceptance"]["criteria"].items():
        status = "PASS" if item["passed"] else ("FAIL" if item["passed"] is False else "N/A")
        print(f"  {name:22}{_fmt(item['measured']):>10}  need {item['criterion']:>7}  {status}")
    print(f"  ALL CRITERIA PASSED: {report['acceptance']['all_passed']}")

    fus = report["fusion"]
    print("\n--- QRS-only versus QRS + Phase-2D IF (paired, frozen cohort) ---")
    print(f"  {'metric':22}{'QRS-only':>12}{'fused':>12}")
    for key, label in (
        ("accuracy", "Accuracy"), ("precision", "Precision"),
        ("recall_sensitivity", "Recall"), ("specificity", "Specificity"),
        ("f1", "F1"), ("false_positive_rate", "FPR"),
        ("balanced_accuracy", "Balanced accuracy"),
    ):
        print(f"  {label:22}{_fmt(fus['qrs_only_metrics'][key]):>12}{_fmt(fus['fused_metrics'][key]):>12}")
    print(f"  improved: {fus['metrics_improved'] or 'none'}")
    print(f"  worsened: {fus['metrics_worsened'] or 'none'}")
    print(f"  SAFE escalated: {fus['safe_observations_escalated']['count']}  "
          f"RISKY escalated: {fus['risky_observations_escalated']['count']}")
    print(f"  isolation invariant holds: "
          f"{fus['physical_isolation_invariant']['identical_with_and_without_ml']}")

    print("\n--- frozen-cohort score distributions ---")
    for label, summary in final["anomaly_score_by_label"].items():
        if summary["count"]:
            print(f"  {label:10} n={summary['count']:3d}  min={summary['min']:+.5f}  "
                  f"median={summary['median']:+.5f}  max={summary['max']:+.5f}")
    print()


def main() -> int:
    print("Building cohorts and extracting features through the production pipeline...")
    train_obs = build_training_observations()
    validation_obs = build_validation_observations()

    train = extract_cohort(train_obs, TRAIN_PCAP)
    validation = extract_cohort(validation_obs, VALIDATION_PCAP)

    detector, model_metadata = fit_candidate(train)
    calibration = calibrate_threshold(detector, validation)
    calibrated_offset = apply_threshold(detector, calibration["selected_threshold"])

    CANDIDATE_DIR.mkdir(parents=True, exist_ok=True)
    detector.save(CANDIDATE_ARTIFACT)

    # The frozen test set is touched here, once, and only after the corpus and
    # the threshold are both final.
    frozen = extract_frozen_test_cohort()
    separation = prove_separation(train, validation, frozen)
    if (
        separation["train_frozen_vector_overlap"]
        or separation["validation_frozen_vector_overlap"]
        or separation["train_validation_vector_overlap"]
    ):
        raise RuntimeError(f"cohort leakage detected: {separation}")

    final = evaluate_cohort(detector, frozen, binary_labels=(TEST_LABEL_SAFE, TEST_LABEL_RISKY))
    acceptance = check_acceptance(final)
    fusion = fusion_comparison(detector, frozen)
    serve = train_serve_comparison(train, frozen)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "phase": "Phase 2D",
        "separation": separation,
        "model": model_metadata,
        "calibration": calibration,
        "calibrated_offset": calibrated_offset,
        "candidate_artifact": str(CANDIDATE_ARTIFACT),
        "production_artifact_untouched": str(PRODUCTION_ARTIFACT),
        "train_serve": serve,
        "frozen_test": final,
        "acceptance": acceptance,
        "phase_2b_baseline": PHASE_2B_BASELINE,
        "fusion": fusion,
        "notes": (
            "Phase 2D keeps Isolation Forest, its parameters, the 12-feature "
            "interface, the fusion rule, the Quantum Risk Score and the "
            "isolation threshold unchanged. Only the training corpus (now "
            "pipeline-extracted, SAFE-only) and the operating point (calibrated "
            "on a held-out validation cohort) differ. The frozen N=24 cohort was "
            "evaluated exactly once, after both were final. All figures are "
            "controlled evaluations on deterministic synthetic/offline "
            "observations; none is real-world deployment accuracy."
        ),
    }

    print_report(report)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    PHASE_2D_JSON.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"Phase 2D report written to {PHASE_2D_JSON}")
    print(f"Candidate artifact written to {CANDIDATE_ARTIFACT}")
    print(f"Production artifact untouched: {PRODUCTION_ARTIFACT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
