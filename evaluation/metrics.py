"""Classification and conformance metrics — pure, dependency-light, deterministic.

Standard library only (no numpy, no scikit-learn, no pandas): these are
small closed-form formulas over short label sequences, so a heavyweight
dependency would buy nothing and would add ARM64/Raspberry Pi risk for no
benefit. Tests cross-check several of these against `sklearn.metrics`
(already a project dependency, used in tests ONLY) to prove the
hand-written formulas are right.

UNDEFINED IS NOT ZERO. Every ratio here returns `None` when its
denominator is 0, never 0.0. A precision of "0.0" asserts that the system
made positive predictions and every one was wrong; `None` correctly says
the system made no positive predictions at all, so precision is not
defined for this run. Silently collapsing the second case into the first
would fabricate a measurement, and in a small controlled evaluation
(N in the tens) empty cells are common enough that the distinction
materially changes how a table should be read.

ROC-AUC (added in Phase 2B) is valid for exactly one thing here: a
CONTINUOUS score. It is computed only over Isolation Forest's
`anomaly_score` (= -decision_function), never over a thresholded
`is_anomaly` flag, never over a discrete risk category, and never over
`confidence` treated as a calibrated probability — Isolation Forest is not
a probabilistic estimator, so no calibration metric (Brier score, log
loss, reliability curve) is offered or appropriate. An integer Quantum
Risk Score over a designed scenario set likewise does not give a
meaningful ROC curve, which is why Phase 2A reports none (see docs/SDD.md's
Phase 2A addendum).

This module contains no CIPHER domain logic: it never imports risk/,
ml/, fusion/, fingerprint/, entropy/, or models/, and it has no notion of
what a "packet" or a "Quantum Risk Score" means beyond the plain numbers
and labels it is handed.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

__all__ = [
    "ConfusionCounts",
    "BinaryMetrics",
    "CategoryConfusion",
    "QRSConformance",
    "RocAuc",
    "confusion_counts",
    "binary_metrics",
    "category_confusion",
    "qrs_conformance",
    "exact_agreement",
    "roc_auc",
    "value_summary",
    "safe_ratio",
]


def safe_ratio(numerator: float, denominator: float) -> Optional[float]:
    """`numerator / denominator`, or None when `denominator` is 0.

    The single choke point for this module's "undefined is not zero"
    rule (see module docstring) — every derived metric below routes its
    division through here rather than guarding inline, so no future
    metric can accidentally reintroduce a fabricated 0.0.
    """
    if denominator == 0:
        return None
    return numerator / denominator


@dataclass(frozen=True)
class ConfusionCounts:
    """The four binary confusion-matrix cells.

    Positive/negative are caller-defined: this class attaches no meaning
    to which class is "positive" (see confusion_counts()).
    """

    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int

    @property
    def total(self) -> int:
        return (
            self.true_positives
            + self.true_negatives
            + self.false_positives
            + self.false_negatives
        )

    @property
    def actual_positives(self) -> int:
        return self.true_positives + self.false_negatives

    @property
    def actual_negatives(self) -> int:
        return self.true_negatives + self.false_positives

    @property
    def predicted_positives(self) -> int:
        return self.true_positives + self.false_positives

    def to_dict(self) -> Dict[str, int]:
        return {
            "true_positives": self.true_positives,
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "total": self.total,
        }


@dataclass(frozen=True)
class BinaryMetrics:
    """Derived binary-classification metrics. Every field is Optional:
    None means "not defined for this run" (zero denominator), never 0."""

    counts: ConfusionCounts
    accuracy: Optional[float]
    precision: Optional[float]
    recall: Optional[float]
    specificity: Optional[float]
    f1: Optional[float]
    false_positive_rate: Optional[float]
    false_negative_rate: Optional[float]
    balanced_accuracy: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "counts": self.counts.to_dict(),
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall_sensitivity": self.recall,
            "specificity": self.specificity,
            "f1": self.f1,
            "false_positive_rate": self.false_positive_rate,
            "false_negative_rate": self.false_negative_rate,
            "balanced_accuracy": self.balanced_accuracy,
        }


def confusion_counts(
    y_true: Sequence[bool], y_predicted: Sequence[bool]
) -> ConfusionCounts:
    """Count TP/TN/FP/FN for two equal-length boolean sequences.

    `True` is the positive class in both sequences. Which real-world
    condition that represents is entirely the caller's choice — for
    Phase 2A, "positive" means "this observation is RISKY under the
    external security rubric" and the prediction is a deterministic
    operating point on CIPHER's own output (see evaluate_research.py).

    Raises:
        ValueError: if the two sequences differ in length — a silent
            zip() truncation would quietly discard observations and
            report metrics over a subset without saying so.
        TypeError: if any element is not a bool. Accepting truthy
            values (0/1/None/"") would let an unlabelled or
            wrongly-typed observation pass as a negative.
    """
    if len(y_true) != len(y_predicted):
        raise ValueError(
            f"y_true and y_predicted must have equal length, got "
            f"{len(y_true)} and {len(y_predicted)}"
        )
    for name, sequence in (("y_true", y_true), ("y_predicted", y_predicted)):
        for index, value in enumerate(sequence):
            if not isinstance(value, bool):
                raise TypeError(
                    f"{name}[{index}] must be a bool, got "
                    f"{type(value).__name__} ({value!r})"
                )

    true_positives = true_negatives = false_positives = false_negatives = 0
    for actual, predicted in zip(y_true, y_predicted):
        if actual and predicted:
            true_positives += 1
        elif actual and not predicted:
            false_negatives += 1
        elif not actual and predicted:
            false_positives += 1
        else:
            true_negatives += 1

    return ConfusionCounts(
        true_positives=true_positives,
        true_negatives=true_negatives,
        false_positives=false_positives,
        false_negatives=false_negatives,
    )


def binary_metrics(counts: ConfusionCounts) -> BinaryMetrics:
    """Derive the standard binary metrics from confusion counts.

        accuracy           = (TP + TN) / (TP + TN + FP + FN)
        precision          = TP / (TP + FP)
        recall/sensitivity = TP / (TP + FN)
        specificity        = TN / (TN + FP)
        F1                 = 2 * precision * recall / (precision + recall)
        FPR                = FP / (FP + TN)   [= 1 - specificity]
        FNR                = FN / (FN + TP)   [= 1 - recall]
        balanced accuracy  = (recall + specificity) / 2

    F1 is computed from precision and recall rather than the algebraically
    equivalent 2TP/(2TP+FP+FN) specifically so that it inherits their
    undefinedness: if either component is None, F1 is None. It is also
    None when precision and recall are both defined but sum to 0 (TP=0
    with at least one FP and one FN) — the harmonic mean genuinely does
    not exist there, and reporting 0.0 would imply a measured worst-case
    score rather than an undefined one.

    balanced_accuracy requires BOTH recall and specificity, so it is None
    if either class is absent from `y_true` — which is exactly when plain
    accuracy becomes most misleading.
    """
    tp = counts.true_positives
    tn = counts.true_negatives
    fp = counts.false_positives
    fn = counts.false_negatives

    accuracy = safe_ratio(tp + tn, counts.total)
    precision = safe_ratio(tp, tp + fp)
    recall = safe_ratio(tp, tp + fn)
    specificity = safe_ratio(tn, tn + fp)
    false_positive_rate = safe_ratio(fp, fp + tn)
    false_negative_rate = safe_ratio(fn, fn + tp)

    f1: Optional[float] = None
    if precision is not None and recall is not None:
        f1 = safe_ratio(2.0 * precision * recall, precision + recall)

    balanced_accuracy: Optional[float] = None
    if recall is not None and specificity is not None:
        balanced_accuracy = (recall + specificity) / 2.0

    return BinaryMetrics(
        counts=counts,
        accuracy=accuracy,
        precision=precision,
        recall=recall,
        specificity=specificity,
        f1=f1,
        false_positive_rate=false_positive_rate,
        false_negative_rate=false_negative_rate,
        balanced_accuracy=balanced_accuracy,
    )


@dataclass(frozen=True)
class QRSConformance:
    """Agreement between manifest-declared expected Quantum Risk Scores
    and the scores the real engine actually produced.

    This measures IMPLEMENTATION CONFORMANCE to a frozen specification —
    never "detection accuracy" (see docs/SDD.md's Phase 2A addendum).
    """

    observation_count: int
    exact_matches: int
    exact_match_rate: Optional[float]
    mean_absolute_error: Optional[float]
    max_absolute_error: Optional[int]
    mismatches: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observation_count": self.observation_count,
            "exact_matches": self.exact_matches,
            "exact_match_rate": self.exact_match_rate,
            "mean_absolute_error": self.mean_absolute_error,
            "max_absolute_error": self.max_absolute_error,
            "mismatch_count": len(self.mismatches),
            "mismatches": self.mismatches,
        }


def qrs_conformance(
    expected: Sequence[int],
    actual: Sequence[int],
    identifiers: Optional[Sequence[str]] = None,
) -> QRSConformance:
    """Compare expected vs. actual integer scores position-by-position.

    Every disagreement is recorded individually in `mismatches` (with its
    identifier when one is supplied) rather than only summarized: a
    conformance failure needs to name the specific observation that
    failed, or it cannot be investigated.

    Raises:
        ValueError: if the sequences (or `identifiers`, when given)
            differ in length.
    """
    if len(expected) != len(actual):
        raise ValueError(
            f"expected and actual must have equal length, got "
            f"{len(expected)} and {len(actual)}"
        )
    if identifiers is not None and len(identifiers) != len(expected):
        raise ValueError(
            f"identifiers must match the number of observations "
            f"({len(expected)}), got {len(identifiers)}"
        )

    absolute_errors: List[int] = []
    mismatches: List[Dict[str, Any]] = []
    exact_matches = 0

    for index, (expected_score, actual_score) in enumerate(zip(expected, actual)):
        error = abs(int(actual_score) - int(expected_score))
        absolute_errors.append(error)
        if error == 0:
            exact_matches += 1
        else:
            mismatch: Dict[str, Any] = {
                "expected_qrs": int(expected_score),
                "actual_qrs": int(actual_score),
                "absolute_error": error,
            }
            mismatch["scenario_id"] = (
                identifiers[index] if identifiers is not None else f"index_{index}"
            )
            mismatches.append(mismatch)

    count = len(absolute_errors)
    return QRSConformance(
        observation_count=count,
        exact_matches=exact_matches,
        exact_match_rate=safe_ratio(exact_matches, count),
        mean_absolute_error=safe_ratio(sum(absolute_errors), count),
        max_absolute_error=max(absolute_errors) if absolute_errors else None,
        mismatches=mismatches,
    )


@dataclass(frozen=True)
class CategoryConfusion:
    """A multi-class confusion matrix plus per-class precision/recall.

    `matrix[expected_label][actual_label]` is a count. `labels` fixes the
    row/column order so a rendered table is stable across runs.
    """

    labels: List[str]
    matrix: Dict[str, Dict[str, int]]
    per_class: Dict[str, Dict[str, Any]]
    observation_count: int
    correct: int
    accuracy: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "labels": self.labels,
            "matrix": self.matrix,
            "per_class": self.per_class,
            "observation_count": self.observation_count,
            "correct": self.correct,
            "accuracy": self.accuracy,
        }


def category_confusion(
    expected: Sequence[str], actual: Sequence[str], labels: Sequence[str]
) -> CategoryConfusion:
    """Build a confusion matrix over `labels` (fixed order), with
    per-class precision, recall and support.

    Per class c, treating c as the positive class one-vs-rest:
        precision(c) = matrix[c][c] / (column c total)
        recall(c)    = matrix[c][c] / (row c total)
        support(c)   = row c total  (how many observations truly are c)

    Both are None when the corresponding total is 0 — a label that never
    appears as an expectation has no defined recall, and one the system
    never predicts has no defined precision.

    Raises:
        ValueError: if the sequences differ in length, if `labels`
            contains duplicates, or if any observed value is absent from
            `labels` (a silently-dropped class would understate error).
    """
    if len(expected) != len(actual):
        raise ValueError(
            f"expected and actual must have equal length, got "
            f"{len(expected)} and {len(actual)}"
        )
    ordered_labels = list(labels)
    if len(set(ordered_labels)) != len(ordered_labels):
        raise ValueError(f"labels must be unique, got {ordered_labels}")

    known = set(ordered_labels)
    for name, sequence in (("expected", expected), ("actual", actual)):
        unknown = sorted(set(sequence) - known)
        if unknown:
            raise ValueError(
                f"{name} contains labels not present in `labels`: {unknown}"
            )

    matrix = {row: {column: 0 for column in ordered_labels} for row in ordered_labels}
    for expected_label, actual_label in zip(expected, actual):
        matrix[expected_label][actual_label] += 1

    per_class: Dict[str, Dict[str, Any]] = {}
    correct = 0
    for label in ordered_labels:
        on_diagonal = matrix[label][label]
        correct += on_diagonal
        row_total = sum(matrix[label].values())
        column_total = sum(matrix[row][label] for row in ordered_labels)
        per_class[label] = {
            "support": row_total,
            "predicted": column_total,
            "correct": on_diagonal,
            "precision": safe_ratio(on_diagonal, column_total),
            "recall": safe_ratio(on_diagonal, row_total),
        }

    count = len(expected)
    return CategoryConfusion(
        labels=ordered_labels,
        matrix=matrix,
        per_class=per_class,
        observation_count=count,
        correct=correct,
        accuracy=safe_ratio(correct, count),
    )


@dataclass(frozen=True)
class RocAuc:
    """A ROC-AUC result together with everything needed to read it honestly.

    `auc` is None when the measurement is not defined — when either class
    is absent, there are no pairs to rank, and an AUC of 0.5 (or 0.0) would
    be a fabricated value rather than a measurement.

    `tied_pairs` is reported because ties are not a rounding detail: a model
    that returns one identical score for many inputs is genuinely unable to
    rank them, and an AUC that leans on the 0.5-per-tie convention should be
    read with that in view rather than as clean separation.
    """

    auc: Optional[float]
    n_positive: int
    n_negative: int
    n_pairs: int
    tied_pairs: int
    tie_handling: str
    positive_score_summary: Optional[Dict[str, Any]]
    negative_score_summary: Optional[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "auc": self.auc,
            "n_positive": self.n_positive,
            "n_negative": self.n_negative,
            "n_pairs": self.n_pairs,
            "tied_pairs": self.tied_pairs,
            "tie_handling": self.tie_handling,
            "positive_score_summary": self.positive_score_summary,
            "negative_score_summary": self.negative_score_summary,
        }


_TIE_HANDLING = (
    "Each positive/negative pair contributes 1.0 when the positive score is "
    "strictly higher, 0.0 when it is strictly lower, and 0.5 when the two "
    "scores are exactly equal (the standard Mann-Whitney convention)."
)


def roc_auc(y_true: Sequence[bool], scores: Sequence[float]) -> RocAuc:
    """Area under the ROC curve, in its Mann-Whitney U form:

        AUC = [ #(s+ > s-) + 0.5 * #(s+ == s-) ] / (P * N)

    over all P*N positive/negative score pairs. This is the probability that
    a uniformly chosen positive observation outscores a uniformly chosen
    negative one, which depends only on the ORDERING of `scores` — so it is
    invariant to any monotone rescaling of them, and says nothing about
    whether their absolute values are calibrated.

    `scores` must be a CONTINUOUS score where HIGHER means "more likely
    positive". For Isolation Forest that is `anomaly_score`
    (= -decision_function), whose sign convention already points that way.
    Passing a thresholded boolean flag, a discrete category, or a confidence
    value interpreted as a probability would each be a misuse (see the module
    docstring).

    Computed by direct pair enumeration rather than a rank formula: it is
    O(P*N), which is trivial at this project's evaluation sizes (tens to a
    few hundred observations), and it implements the definition literally,
    including exact tie handling, with nothing to get subtly wrong in a
    rank-averaging step.

    Returns:
        A RocAuc whose `auc` is None if either class is absent.

    Raises:
        ValueError: if the sequences differ in length.
        TypeError: if any label is not a bool, or any score is not a real
            number (bool is rejected as a score — passing `is_anomaly` in
            place of `anomaly_score` is exactly the misuse this guards).
    """
    if len(y_true) != len(scores):
        raise ValueError(
            f"y_true and scores must have equal length, got "
            f"{len(y_true)} and {len(scores)}"
        )
    for index, label in enumerate(y_true):
        if not isinstance(label, bool):
            raise TypeError(
                f"y_true[{index}] must be a bool, got {type(label).__name__}"
            )
    for index, score in enumerate(scores):
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise TypeError(
                f"scores[{index}] must be a real number, got "
                f"{type(score).__name__} ({score!r}) — ROC-AUC requires a "
                f"continuous score, never a thresholded flag"
            )

    positives = [float(score) for label, score in zip(y_true, scores) if label]
    negatives = [float(score) for label, score in zip(y_true, scores) if not label]

    n_positive = len(positives)
    n_negative = len(negatives)
    n_pairs = n_positive * n_negative

    positive_summary = value_summary(positives) if positives else None
    negative_summary = value_summary(negatives) if negatives else None

    if n_pairs == 0:
        return RocAuc(
            auc=None,
            n_positive=n_positive,
            n_negative=n_negative,
            n_pairs=0,
            tied_pairs=0,
            tie_handling=_TIE_HANDLING,
            positive_score_summary=positive_summary,
            negative_score_summary=negative_summary,
        )

    concordant = 0.0
    tied_pairs = 0
    for positive_score in positives:
        for negative_score in negatives:
            if positive_score > negative_score:
                concordant += 1.0
            elif positive_score == negative_score:
                concordant += 0.5
                tied_pairs += 1

    return RocAuc(
        auc=concordant / n_pairs,
        n_positive=n_positive,
        n_negative=n_negative,
        n_pairs=n_pairs,
        tied_pairs=tied_pairs,
        tie_handling=_TIE_HANDLING,
        positive_score_summary=positive_summary,
        negative_score_summary=negative_summary,
    )


def value_summary(values: Sequence[float]) -> Dict[str, Any]:
    """Distribution summary for one sequence of numbers.

    Reports min/median/max/mean plus `zero_count`/`zero_fraction`, which
    exist for the train-versus-serve feature comparison: several of the
    Isolation Forest's features are "observed" indicators or values that are
    exactly 0.0 when the underlying evidence is absent, and how OFTEN that
    happens is the substantive fact about them, which min/median/max alone
    can obscure.

    Every field is None for empty input rather than 0 (see module docstring).
    """
    if not values:
        return {
            "count": 0,
            "min": None,
            "median": None,
            "max": None,
            "mean": None,
            "zero_count": 0,
            "zero_fraction": None,
        }

    numeric = [float(value) for value in values]
    zero_count = sum(1 for value in numeric if value == 0.0)
    return {
        "count": len(numeric),
        "min": min(numeric),
        "median": statistics.median(numeric),
        "max": max(numeric),
        "mean": statistics.fmean(numeric),
        "zero_count": zero_count,
        "zero_fraction": safe_ratio(zero_count, len(numeric)),
    }


def exact_agreement(
    expected: Sequence[Any],
    actual: Sequence[Any],
    identifiers: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Plain element-wise agreement rate, for any comparable values.

    Used for the per-component Quantum Risk Score contributions (TLS,
    key size, forward secrecy, entropy, port) and for boolean
    isolation-eligibility expectations, where an absolute error would be
    meaningless but "did every observation match?" is exactly the
    question. Disagreements are listed individually, as in
    qrs_conformance().

    Raises:
        ValueError: if the sequences (or `identifiers`, when given)
            differ in length.
    """
    if len(expected) != len(actual):
        raise ValueError(
            f"expected and actual must have equal length, got "
            f"{len(expected)} and {len(actual)}"
        )
    if identifiers is not None and len(identifiers) != len(expected):
        raise ValueError(
            f"identifiers must match the number of observations "
            f"({len(expected)}), got {len(identifiers)}"
        )

    matches = 0
    mismatches: List[Dict[str, Any]] = []
    for index, (expected_value, actual_value) in enumerate(zip(expected, actual)):
        if expected_value == actual_value:
            matches += 1
        else:
            mismatches.append(
                {
                    "scenario_id": (
                        identifiers[index]
                        if identifiers is not None
                        else f"index_{index}"
                    ),
                    "expected": expected_value,
                    "actual": actual_value,
                }
            )

    count = len(expected)
    return {
        "observation_count": count,
        "matches": matches,
        "agreement_rate": safe_ratio(matches, count),
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
    }
