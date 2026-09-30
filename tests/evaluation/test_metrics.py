"""Unit tests for evaluation/metrics.py.

Every derived metric is checked against a HAND-COMPUTED value on a small
fixed confusion matrix, not against a second implementation of the same
formula — a metric module verified only against itself would pass while
being uniformly wrong. Several results are then independently cross-checked
against `sklearn.metrics` (a dependency this project already has, used here
in TESTS ONLY — evaluation/metrics.py itself remains standard-library only).
"""
from __future__ import annotations

import pytest

from evaluation.metrics import (
    ConfusionCounts,
    binary_metrics,
    category_confusion,
    confusion_counts,
    exact_agreement,
    qrs_conformance,
    roc_auc,
    safe_ratio,
    value_summary,
)

# The reference matrix used throughout: TP=6, TN=3, FP=2, FN=1 (N=12).
#   accuracy    = (6+3)/12 = 0.75
#   precision   = 6/(6+2)  = 0.75
#   recall      = 6/(6+1)  = 6/7
#   specificity = 3/(3+2)  = 0.6
#   F1          = 2*0.75*(6/7) / (0.75 + 6/7) = 0.8
#   FPR         = 2/(2+3)  = 0.4
#   FNR         = 1/(1+6)  = 1/7
#   balanced    = (6/7 + 0.6)/2 = 0.7285714285714285
_REFERENCE = ConfusionCounts(
    true_positives=6, true_negatives=3, false_positives=2, false_negatives=1
)


def test_safe_ratio_divides_normally() -> None:
    assert safe_ratio(3, 4) == 0.75


def test_safe_ratio_returns_none_for_zero_denominator() -> None:
    """Undefined is None, never 0.0 — the module's central rule."""
    assert safe_ratio(0, 0) is None
    assert safe_ratio(5, 0) is None


def test_confusion_counts_hand_computed() -> None:
    y_true = [True, True, True, False, False, True]
    y_predicted = [True, False, True, True, False, True]
    counts = confusion_counts(y_true, y_predicted)

    assert counts.true_positives == 3
    assert counts.false_negatives == 1
    assert counts.false_positives == 1
    assert counts.true_negatives == 1
    assert counts.total == 6


def test_confusion_counts_derived_totals() -> None:
    assert _REFERENCE.total == 12
    assert _REFERENCE.actual_positives == 7
    assert _REFERENCE.actual_negatives == 5
    assert _REFERENCE.predicted_positives == 8


def test_confusion_counts_rejects_length_mismatch() -> None:
    with pytest.raises(ValueError, match="equal length"):
        confusion_counts([True, False], [True])


@pytest.mark.parametrize("bad_value", [1, 0, None, "True", 1.0])
def test_confusion_counts_rejects_non_bool_elements(bad_value) -> None:
    """Truthy values must not pass as labels: an unlabelled or
    wrongly-typed observation would silently become a negative."""
    with pytest.raises(TypeError, match="must be a bool"):
        confusion_counts([True, bad_value], [True, True])
    with pytest.raises(TypeError, match="must be a bool"):
        confusion_counts([True, True], [True, bad_value])


def test_binary_metrics_all_hand_computed() -> None:
    metrics = binary_metrics(_REFERENCE)

    assert metrics.accuracy == pytest.approx(0.75)
    assert metrics.precision == pytest.approx(0.75)
    assert metrics.recall == pytest.approx(6 / 7)
    assert metrics.specificity == pytest.approx(0.6)
    assert metrics.f1 == pytest.approx(0.8)
    assert metrics.false_positive_rate == pytest.approx(0.4)
    assert metrics.false_negative_rate == pytest.approx(1 / 7)
    assert metrics.balanced_accuracy == pytest.approx((6 / 7 + 0.6) / 2)


def test_binary_metrics_identities_hold() -> None:
    metrics = binary_metrics(_REFERENCE)
    assert metrics.false_positive_rate == pytest.approx(1.0 - metrics.specificity)
    assert metrics.false_negative_rate == pytest.approx(1.0 - metrics.recall)


def test_perfect_classifier_scores_one() -> None:
    metrics = binary_metrics(
        ConfusionCounts(
            true_positives=5, true_negatives=5, false_positives=0, false_negatives=0
        )
    )
    assert metrics.accuracy == 1.0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.specificity == 1.0
    assert metrics.f1 == 1.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.false_negative_rate == 0.0
    assert metrics.balanced_accuracy == 1.0


def test_no_positive_predictions_makes_precision_undefined_not_zero() -> None:
    """TP=0, FP=0: the system predicted nothing positive, so precision is
    undefined. Reporting 0.0 would assert it made positive predictions and
    got them all wrong — a different, false claim."""
    metrics = binary_metrics(
        ConfusionCounts(
            true_positives=0, true_negatives=4, false_positives=0, false_negatives=3
        )
    )
    assert metrics.precision is None
    assert metrics.recall == 0.0  # genuinely 0: there were 3 positives, none found
    assert metrics.f1 is None  # inherits precision's undefinedness
    assert metrics.specificity == 1.0
    assert metrics.accuracy == pytest.approx(4 / 7)
    assert metrics.balanced_accuracy == pytest.approx(0.5)


def test_no_actual_positives_makes_recall_undefined_not_zero() -> None:
    metrics = binary_metrics(
        ConfusionCounts(
            true_positives=0, true_negatives=4, false_positives=2, false_negatives=0
        )
    )
    assert metrics.recall is None
    assert metrics.false_negative_rate is None
    assert metrics.precision == 0.0  # 2 positive predictions, both wrong
    assert metrics.f1 is None
    assert metrics.balanced_accuracy is None  # needs recall


def test_no_actual_negatives_makes_specificity_undefined_not_zero() -> None:
    metrics = binary_metrics(
        ConfusionCounts(
            true_positives=4, true_negatives=0, false_positives=0, false_negatives=1
        )
    )
    assert metrics.specificity is None
    assert metrics.false_positive_rate is None
    assert metrics.balanced_accuracy is None
    assert metrics.recall == pytest.approx(0.8)


def test_f1_is_undefined_when_precision_and_recall_are_both_zero() -> None:
    """TP=0 with both FP and FN present: precision and recall are each
    defined and equal 0, so their harmonic mean genuinely does not exist."""
    metrics = binary_metrics(
        ConfusionCounts(
            true_positives=0, true_negatives=2, false_positives=3, false_negatives=4
        )
    )
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1 is None


def test_empty_counts_leave_accuracy_undefined() -> None:
    metrics = binary_metrics(
        ConfusionCounts(
            true_positives=0, true_negatives=0, false_positives=0, false_negatives=0
        )
    )
    assert metrics.accuracy is None
    assert metrics.precision is None
    assert metrics.recall is None
    assert metrics.f1 is None
    assert metrics.balanced_accuracy is None


def test_binary_metrics_to_dict_names_recall_explicitly() -> None:
    payload = binary_metrics(_REFERENCE).to_dict()
    assert payload["recall_sensitivity"] == pytest.approx(6 / 7)
    assert payload["counts"]["true_positives"] == 6
    assert set(payload) == {
        "counts",
        "accuracy",
        "precision",
        "recall_sensitivity",
        "specificity",
        "f1",
        "false_positive_rate",
        "false_negative_rate",
        "balanced_accuracy",
    }


# --- independent cross-checks against scikit-learn ------------------------


def test_binary_metrics_match_sklearn() -> None:
    """Cross-check against an independent implementation. sklearn is used
    in this test only; evaluation/metrics.py imports nothing but the
    standard library."""
    from sklearn.metrics import (
        accuracy_score,
        balanced_accuracy_score,
        f1_score,
        precision_score,
        recall_score,
    )

    y_true = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
    y_predicted = [1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0]

    counts = confusion_counts(
        [bool(value) for value in y_true], [bool(value) for value in y_predicted]
    )
    assert (counts.true_positives, counts.false_negatives) == (6, 1)
    assert (counts.false_positives, counts.true_negatives) == (2, 3)

    metrics = binary_metrics(counts)
    assert metrics.accuracy == pytest.approx(accuracy_score(y_true, y_predicted))
    assert metrics.precision == pytest.approx(precision_score(y_true, y_predicted))
    assert metrics.recall == pytest.approx(recall_score(y_true, y_predicted))
    assert metrics.f1 == pytest.approx(f1_score(y_true, y_predicted))
    assert metrics.balanced_accuracy == pytest.approx(
        balanced_accuracy_score(y_true, y_predicted)
    )


def test_confusion_counts_match_sklearn_confusion_matrix() -> None:
    from sklearn.metrics import confusion_matrix

    y_true = [True, False, True, True, False, False, True]
    y_predicted = [True, True, False, True, False, False, True]

    counts = confusion_counts(y_true, y_predicted)
    (tn, fp), (fn, tp) = confusion_matrix(y_true, y_predicted, labels=[False, True])

    assert (counts.true_negatives, counts.false_positives) == (tn, fp)
    assert (counts.false_negatives, counts.true_positives) == (fn, tp)


def test_category_confusion_matches_sklearn_multiclass() -> None:
    from sklearn.metrics import confusion_matrix

    labels = ["LOW", "MEDIUM", "HIGH"]
    expected = ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "MEDIUM"]
    actual = ["LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "HIGH", "MEDIUM"]

    result = category_confusion(expected, actual, labels)
    reference = confusion_matrix(expected, actual, labels=labels)

    for row_index, expected_label in enumerate(labels):
        for column_index, actual_label in enumerate(labels):
            assert (
                result.matrix[expected_label][actual_label]
                == reference[row_index][column_index]
            )


# --- QRS conformance -----------------------------------------------------


def test_qrs_conformance_perfect_agreement() -> None:
    result = qrs_conformance([2, 6, 7, 9], [2, 6, 7, 9], ["a", "b", "c", "d"])

    assert result.observation_count == 4
    assert result.exact_matches == 4
    assert result.exact_match_rate == 1.0
    assert result.mean_absolute_error == 0.0
    assert result.max_absolute_error == 0
    assert result.mismatches == []


def test_qrs_conformance_hand_computed_errors() -> None:
    """Errors of 0, 1, 3, 0 -> 2/4 exact, MAE = 4/4 = 1.0, max = 3."""
    result = qrs_conformance([2, 6, 7, 9], [2, 7, 4, 9], ["a", "b", "c", "d"])

    assert result.exact_matches == 2
    assert result.exact_match_rate == 0.5
    assert result.mean_absolute_error == pytest.approx(1.0)
    assert result.max_absolute_error == 3
    assert [m["scenario_id"] for m in result.mismatches] == ["b", "c"]
    assert result.mismatches[1] == {
        "scenario_id": "c",
        "expected_qrs": 7,
        "actual_qrs": 4,
        "absolute_error": 3,
    }


def test_qrs_conformance_uses_index_when_no_identifiers_given() -> None:
    result = qrs_conformance([1, 2], [1, 5])
    assert result.mismatches[0]["scenario_id"] == "index_1"


def test_qrs_conformance_empty_input_is_undefined_not_zero() -> None:
    result = qrs_conformance([], [])
    assert result.observation_count == 0
    assert result.exact_match_rate is None
    assert result.mean_absolute_error is None
    assert result.max_absolute_error is None


def test_qrs_conformance_rejects_length_mismatch() -> None:
    with pytest.raises(ValueError, match="equal length"):
        qrs_conformance([1, 2], [1])


def test_qrs_conformance_rejects_identifier_length_mismatch() -> None:
    with pytest.raises(ValueError, match="identifiers must match"):
        qrs_conformance([1, 2], [1, 2], ["only-one"])


# --- category confusion --------------------------------------------------


def test_category_confusion_hand_computed() -> None:
    labels = ["LOW", "MEDIUM", "HIGH"]
    expected = ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH"]
    actual = ["LOW", "MEDIUM", "MEDIUM", "MEDIUM", "HIGH"]

    result = category_confusion(expected, actual, labels)

    assert result.matrix["LOW"] == {"LOW": 1, "MEDIUM": 1, "HIGH": 0}
    assert result.matrix["MEDIUM"] == {"LOW": 0, "MEDIUM": 2, "HIGH": 0}
    assert result.matrix["HIGH"] == {"LOW": 0, "MEDIUM": 0, "HIGH": 1}

    assert result.correct == 4
    assert result.accuracy == pytest.approx(0.8)

    # LOW: 1 correct of 2 actually LOW (recall 1/2); 1 predicted LOW, correct
    # (precision 1/1). MEDIUM: 2 of 2 (recall 1.0); 3 predicted (precision 2/3).
    assert result.per_class["LOW"]["recall"] == pytest.approx(0.5)
    assert result.per_class["LOW"]["precision"] == pytest.approx(1.0)
    assert result.per_class["LOW"]["support"] == 2
    assert result.per_class["MEDIUM"]["recall"] == pytest.approx(1.0)
    assert result.per_class["MEDIUM"]["precision"] == pytest.approx(2 / 3)
    assert result.per_class["MEDIUM"]["predicted"] == 3


def test_category_confusion_absent_class_has_undefined_rates() -> None:
    labels = ["LOW", "MEDIUM", "HIGH"]
    result = category_confusion(["LOW", "LOW"], ["LOW", "LOW"], labels)

    assert result.per_class["HIGH"]["support"] == 0
    assert result.per_class["HIGH"]["recall"] is None
    assert result.per_class["HIGH"]["precision"] is None
    assert result.per_class["LOW"]["recall"] == 1.0


def test_category_confusion_preserves_label_order() -> None:
    labels = ["HIGH", "LOW", "MEDIUM"]
    result = category_confusion(["LOW"], ["LOW"], labels)
    assert result.labels == labels
    assert list(result.matrix) == labels


def test_category_confusion_rejects_duplicate_labels() -> None:
    with pytest.raises(ValueError, match="labels must be unique"):
        category_confusion(["LOW"], ["LOW"], ["LOW", "LOW"])


def test_category_confusion_rejects_unknown_observed_label() -> None:
    """A silently dropped class would understate error."""
    with pytest.raises(ValueError, match="expected contains labels"):
        category_confusion(["CRITICAL"], ["LOW"], ["LOW", "MEDIUM", "HIGH"])
    with pytest.raises(ValueError, match="actual contains labels"):
        category_confusion(["LOW"], ["CRITICAL"], ["LOW", "MEDIUM", "HIGH"])


def test_category_confusion_rejects_length_mismatch() -> None:
    with pytest.raises(ValueError, match="equal length"):
        category_confusion(["LOW", "LOW"], ["LOW"], ["LOW"])


def test_category_confusion_empty_input_is_undefined_not_zero() -> None:
    result = category_confusion([], [], ["LOW", "MEDIUM", "HIGH"])
    assert result.observation_count == 0
    assert result.accuracy is None


# --- exact agreement -----------------------------------------------------


def test_exact_agreement_hand_computed() -> None:
    result = exact_agreement([1, 2, 3, 4], [1, 9, 3, 9], ["a", "b", "c", "d"])

    assert result["observation_count"] == 4
    assert result["matches"] == 2
    assert result["agreement_rate"] == pytest.approx(0.5)
    assert result["mismatch_count"] == 2
    assert result["mismatches"][0] == {"scenario_id": "b", "expected": 2, "actual": 9}


def test_exact_agreement_works_for_booleans_and_strings() -> None:
    booleans = exact_agreement([True, False], [True, True], ["a", "b"])
    assert booleans["matches"] == 1
    assert booleans["mismatches"][0]["expected"] is False

    strings = exact_agreement(["HTTPS", "HTTP"], ["HTTPS", "HTTPS"], ["a", "b"])
    assert strings["matches"] == 1


def test_exact_agreement_empty_input_is_undefined_not_zero() -> None:
    result = exact_agreement([], [])
    assert result["agreement_rate"] is None
    assert result["matches"] == 0


def test_exact_agreement_rejects_length_mismatch() -> None:
    with pytest.raises(ValueError, match="equal length"):
        exact_agreement([1, 2], [1])


def test_exact_agreement_rejects_identifier_length_mismatch() -> None:
    with pytest.raises(ValueError, match="identifiers must match"):
        exact_agreement([1, 2], [1, 2], ["only-one"])


# --- ROC-AUC -------------------------------------------------------------


def test_roc_auc_perfect_separation_is_one() -> None:
    """Every positive outscores every negative."""
    result = roc_auc([True, True, False, False], [0.9, 0.8, 0.2, 0.1])
    assert result.auc == 1.0
    assert result.n_positive == 2
    assert result.n_negative == 2
    assert result.n_pairs == 4
    assert result.tied_pairs == 0


def test_roc_auc_perfectly_inverted_separation_is_zero() -> None:
    result = roc_auc([True, True, False, False], [0.1, 0.2, 0.8, 0.9])
    assert result.auc == 0.0


def test_roc_auc_hand_computed_partial_ordering() -> None:
    """Positives {3, 1}, negatives {2, 0}. Pairs: 3>2, 3>0, 1<2, 1>0
    -> 3 concordant of 4 -> AUC = 0.75."""
    result = roc_auc([True, False, True, False], [3.0, 2.0, 1.0, 0.0])
    assert result.auc == pytest.approx(0.75)
    assert result.n_pairs == 4
    assert result.tied_pairs == 0


def test_roc_auc_counts_ties_as_half() -> None:
    """Positives {2, 1}, negatives {2, 0}. Pairs: 2==2 (0.5), 2>0 (1),
    1<2 (0), 1>0 (1) -> 2.5/4 = 0.625, with exactly one tied pair."""
    result = roc_auc([True, True, False, False], [2.0, 1.0, 2.0, 0.0])
    assert result.auc == pytest.approx(0.625)
    assert result.tied_pairs == 1
    assert "0.5" in result.tie_handling


def test_roc_auc_all_scores_identical_is_one_half_and_all_pairs_tied() -> None:
    """A model returning one constant score cannot rank anything. AUC 0.5
    here is entirely the tie convention, which is why tied_pairs is
    reported alongside it."""
    result = roc_auc([True, True, False, False, False], [0.3] * 5)
    assert result.auc == pytest.approx(0.5)
    assert result.tied_pairs == result.n_pairs == 6


def test_roc_auc_is_invariant_under_monotone_rescaling() -> None:
    """AUC depends only on ordering — the property that makes it valid for
    Isolation Forest's uncalibrated anomaly score."""
    labels = [True, False, True, False, True]
    scores = [0.9, 0.4, 0.6, 0.1, 0.5]
    baseline = roc_auc(labels, scores).auc
    shifted = roc_auc(labels, [value * 37.0 - 12.0 for value in scores]).auc
    assert baseline == pytest.approx(shifted)


def test_roc_auc_is_undefined_when_a_class_is_absent() -> None:
    """Not 0.5, not 0.0 — there are no pairs to rank, so there is no
    measurement to report."""
    only_positive = roc_auc([True, True], [0.4, 0.9])
    assert only_positive.auc is None
    assert only_positive.n_pairs == 0
    assert only_positive.n_negative == 0

    only_negative = roc_auc([False, False], [0.4, 0.9])
    assert only_negative.auc is None
    assert only_negative.n_positive == 0

    empty = roc_auc([], [])
    assert empty.auc is None
    assert empty.n_pairs == 0


def test_roc_auc_reports_per_class_score_summaries() -> None:
    result = roc_auc([True, True, False], [1.0, 3.0, -2.0])
    assert result.positive_score_summary["count"] == 2
    assert result.positive_score_summary["min"] == 1.0
    assert result.positive_score_summary["max"] == 3.0
    assert result.negative_score_summary["count"] == 1
    assert result.negative_score_summary["median"] == -2.0


def test_roc_auc_summaries_are_none_when_a_class_is_absent() -> None:
    result = roc_auc([True, True], [0.1, 0.2])
    assert result.negative_score_summary is None
    assert result.positive_score_summary is not None


def test_roc_auc_handles_negative_scores() -> None:
    """Isolation Forest anomaly scores are routinely negative for normal
    points; only the ordering matters."""
    result = roc_auc([True, False, True, False], [-0.01, -0.12, 0.05, -0.20])
    assert result.auc == 1.0


def test_roc_auc_rejects_length_mismatch() -> None:
    with pytest.raises(ValueError, match="equal length"):
        roc_auc([True, False], [0.5])


def test_roc_auc_rejects_non_bool_labels() -> None:
    with pytest.raises(TypeError, match="must be a bool"):
        roc_auc([1, 0], [0.5, 0.2])


def test_roc_auc_rejects_boolean_scores() -> None:
    """Guards the documented misuse: passing the thresholded `is_anomaly`
    flag where the continuous anomaly_score belongs."""
    with pytest.raises(TypeError, match="continuous score"):
        roc_auc([True, False], [True, False])


def test_roc_auc_rejects_non_numeric_scores() -> None:
    with pytest.raises(TypeError, match="real number"):
        roc_auc([True, False], ["0.9", "0.1"])


def test_roc_auc_to_dict_exposes_tie_handling_and_counts() -> None:
    payload = roc_auc([True, False], [0.9, 0.1]).to_dict()
    assert payload["auc"] == 1.0
    assert payload["n_positive"] == 1
    assert payload["n_negative"] == 1
    assert payload["n_pairs"] == 1
    assert payload["tied_pairs"] == 0
    assert "Mann-Whitney" in payload["tie_handling"]


def test_roc_auc_matches_sklearn_on_clean_scores() -> None:
    from sklearn.metrics import roc_auc_score

    labels = [True, False, True, True, False, False, True, False]
    scores = [0.91, 0.42, 0.63, 0.11, 0.35, 0.77, 0.58, 0.05]

    assert roc_auc(labels, scores).auc == pytest.approx(roc_auc_score(labels, scores))


def test_roc_auc_matches_sklearn_with_ties() -> None:
    """sklearn's trapezoidal implementation and this Mann-Whitney one agree
    on tied scores too — the case most likely to diverge."""
    from sklearn.metrics import roc_auc_score

    labels = [True, True, False, False, True, False]
    scores = [0.5, 0.5, 0.5, 0.2, 0.8, 0.8]

    result = roc_auc(labels, scores)
    assert result.tied_pairs > 0
    assert result.auc == pytest.approx(roc_auc_score(labels, scores))


def test_roc_auc_matches_sklearn_on_negative_isolation_forest_style_scores() -> None:
    from sklearn.metrics import roc_auc_score

    labels = [False] * 6 + [True] * 4
    scores = [-0.19, -0.12, -0.08, -0.03, 0.01, 0.02, 0.03, 0.07, 0.10, 0.13]

    assert roc_auc(labels, scores).auc == pytest.approx(roc_auc_score(labels, scores))


# --- value summaries -----------------------------------------------------


def test_value_summary_hand_computed() -> None:
    summary = value_summary([0.0, 2.0, 4.0, 6.0])
    assert summary["count"] == 4
    assert summary["min"] == 0.0
    assert summary["median"] == 3.0
    assert summary["max"] == 6.0
    assert summary["mean"] == 3.0
    assert summary["zero_count"] == 1
    assert summary["zero_fraction"] == pytest.approx(0.25)


def test_value_summary_zero_fraction_captures_unobserved_features() -> None:
    """The substantive fact about an "observed" indicator column is how often
    it is 0, which min/median/max alone can hide."""
    summary = value_summary([0.0] * 11)
    assert summary["zero_fraction"] == 1.0
    assert summary["min"] == summary["max"] == 0.0


def test_value_summary_empty_input_is_undefined_not_zero() -> None:
    summary = value_summary([])
    assert summary["count"] == 0
    assert summary["min"] is None
    assert summary["median"] is None
    assert summary["max"] is None
    assert summary["mean"] is None
    assert summary["zero_fraction"] is None


def test_value_summary_median_of_even_count_is_interpolated() -> None:
    assert value_summary([1.0, 2.0])["median"] == pytest.approx(1.5)


# --- module hygiene ------------------------------------------------------


def test_metrics_module_imports_only_the_standard_library() -> None:
    """Keeps this module Raspberry Pi-safe and dependency-free: no numpy,
    no scikit-learn, no pandas, and no CIPHER domain module (which would
    risk circularity and let scoring logic leak into measurement)."""
    import ast
    from pathlib import Path

    import evaluation.metrics as metrics_module

    source = Path(metrics_module.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert imported <= {"dataclasses", "statistics", "typing", "__future__"}, imported
    forbidden = {"numpy", "sklearn", "pandas", "scipy", "risk", "ml", "models", "fusion"}
    assert not (imported & forbidden)
