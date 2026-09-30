"""Tests for the Phase 2B deterministic held-out synthetic feature set
(tests/fixtures/ml_heldout_set.py).

The central property under test is that the labels are STRUCTURAL: they
follow from which distribution ml/dataset.py drew each row from, and are
verifiable from the feature VALUES alone, with no model involved. A held-out
set whose labels came (even indirectly) from model output would make every
metric in Section A circular.
"""
from __future__ import annotations

import numpy as np
import pytest

from ml.classifier import DEFAULT_RANDOM_STATE
from ml.features import FEATURE_NAMES, NUM_FEATURES
from tests.fixtures.ml_heldout_set import (
    HELDOUT_NORMAL_COUNT,
    HELDOUT_OUTLIER_COUNT,
    HELDOUT_RANDOM_STATE,
    HELDOUT_TOTAL,
    TRAINING_RANDOM_STATE,
    build_heldout_feature_matrix,
    build_training_feature_matrix,
    heldout_construction_labels,
    training_construction_labels,
)

_ENTROPY = FEATURE_NAMES.index("shannon_entropy")
_PACKET_SIZE = FEATURE_NAMES.index("packet_size")
_KEY_SIZE = FEATURE_NAMES.index("key_size")
_FORWARD_SECRECY = FEATURE_NAMES.index("forward_secrecy")
_IS_HTTPS = FEATURE_NAMES.index("protocol_is_https")
_IS_HTTP = FEATURE_NAMES.index("protocol_is_http")


# --- shape and determinism ------------------------------------------------


def test_heldout_matrix_has_the_expected_shape() -> None:
    matrix = build_heldout_feature_matrix()
    assert matrix.shape == (HELDOUT_TOTAL, NUM_FEATURES)
    assert HELDOUT_TOTAL == HELDOUT_NORMAL_COUNT + HELDOUT_OUTLIER_COUNT


def test_heldout_matrix_generation_is_deterministic() -> None:
    assert np.array_equal(build_heldout_feature_matrix(), build_heldout_feature_matrix())


def test_heldout_labels_are_deterministic_and_correctly_sized() -> None:
    labels = heldout_construction_labels()
    assert labels == heldout_construction_labels()
    assert len(labels) == HELDOUT_TOTAL
    assert sum(labels) == HELDOUT_OUTLIER_COUNT
    assert labels.count(False) == HELDOUT_NORMAL_COUNT


def test_every_label_is_a_real_bool() -> None:
    """evaluation.metrics rejects non-bool labels, so this keeps the two in
    step rather than relying on truthiness."""
    assert all(isinstance(label, bool) for label in heldout_construction_labels())


# --- genuinely held out ---------------------------------------------------


def test_heldout_seed_differs_from_the_training_seed() -> None:
    assert HELDOUT_RANDOM_STATE != TRAINING_RANDOM_STATE
    assert TRAINING_RANDOM_STATE == DEFAULT_RANDOM_STATE


def test_no_heldout_row_appears_in_the_training_matrix() -> None:
    """The load-bearing check behind calling this set "held out"."""
    heldout = build_heldout_feature_matrix()
    training = build_training_feature_matrix()

    training_rows = {tuple(row) for row in training.tolist()}
    overlapping = [row for row in heldout.tolist() if tuple(row) in training_rows]
    assert overlapping == []


def test_heldout_rows_are_all_distinct() -> None:
    """A set of near-duplicates would inflate N without adding information."""
    matrix = build_heldout_feature_matrix()
    assert len({tuple(row) for row in matrix.tolist()}) == HELDOUT_TOTAL


# --- labels are verifiable from the feature values, not from a model ------


def test_outlier_labelled_rows_really_carry_the_outlier_distribution() -> None:
    """Validates the row-ordering assumption the labels rest on, using only
    the generator's own documented distributions: outlier rows have low
    entropy, tiny payloads, weak keys, no forward secrecy and are HTTP."""
    matrix = build_heldout_feature_matrix()
    labels = heldout_construction_labels()
    outliers = matrix[labels]

    assert outliers.shape[0] == HELDOUT_OUTLIER_COUNT
    assert outliers[:, _ENTROPY].max() < 3.0
    assert outliers[:, _PACKET_SIZE].max() < 60.0
    assert outliers[:, _KEY_SIZE].max() < 1024.0
    assert (outliers[:, _FORWARD_SECRECY] == 0.0).all()
    assert (outliers[:, _IS_HTTP] == 1.0).all()
    assert (outliers[:, _IS_HTTPS] == 0.0).all()


def test_normal_labelled_rows_really_carry_the_normal_distribution() -> None:
    matrix = build_heldout_feature_matrix()
    labels = heldout_construction_labels()
    normals = matrix[[not label for label in labels]]

    assert normals.shape[0] == HELDOUT_NORMAL_COUNT
    assert normals[:, _ENTROPY].min() > 7.0
    assert normals[:, _PACKET_SIZE].min() > 200.0
    assert normals[:, _KEY_SIZE].min() >= 2048.0
    assert (normals[:, _IS_HTTPS] == 1.0).all()
    assert (normals[:, _IS_HTTP] == 0.0).all()


def test_the_two_classes_are_separated_on_entropy_by_construction() -> None:
    """Not a model result: the generator's two distributions do not overlap
    on this feature, which is why Section A's near-perfect scores say more
    about the synthetic data than about the model."""
    matrix = build_heldout_feature_matrix()
    labels = heldout_construction_labels()
    outlier_max = matrix[labels][:, _ENTROPY].max()
    normal_min = matrix[[not label for label in labels]][:, _ENTROPY].min()
    assert outlier_max < normal_min


def test_heldout_module_never_touches_a_model() -> None:
    """Static guard: the label source must be construction, never inference.
    Any import of ml.classifier beyond the seed constant, or any call to a
    scoring method, would break the independence Section A depends on."""
    import ast
    from pathlib import Path

    import tests.fixtures.ml_heldout_set as module

    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))

    # Inspect the parsed CODE, never the raw text: this module's own
    # docstring names these methods in order to explain that it never calls
    # them, and a substring scan would flag that prose.
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    plain_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    referenced = attributes | plain_names

    for forbidden in ("predict", "predict_one", "decision_function", "score_samples", "fit"):
        assert forbidden not in referenced, forbidden

    imported_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported_names.update(alias.name for alias in node.names)
            assert "joblib" not in node.module
        elif isinstance(node, ast.Import):
            imported_names.update(alias.name for alias in node.names)
    assert "joblib" not in imported_names
    # Only the seed constant may come from ml.classifier.
    assert imported_names & {"DEFAULT_RANDOM_STATE"}
    assert "AnomalyDetector" not in imported_names


# --- training-matrix helpers ---------------------------------------------


def test_training_matrix_matches_the_frozen_configuration() -> None:
    matrix = build_training_feature_matrix()
    assert matrix.shape == (190, NUM_FEATURES)


def test_training_matrix_generation_is_deterministic() -> None:
    assert np.array_equal(
        build_training_feature_matrix(), build_training_feature_matrix()
    )


def test_training_construction_labels_split_180_normal_and_10_outliers() -> None:
    matrix = build_training_feature_matrix()
    labels = training_construction_labels(matrix)
    assert len(labels) == 190
    assert sum(labels) == 10
    assert labels.count(False) == 180


def test_training_construction_labels_are_verifiable_from_values() -> None:
    matrix = build_training_feature_matrix()
    labels = training_construction_labels(matrix)
    assert matrix[labels][:, _ENTROPY].max() < 3.0
    assert matrix[[not label for label in labels]][:, _ENTROPY].min() > 7.0


def test_training_construction_labels_reject_an_impossibly_small_matrix() -> None:
    with pytest.raises(ValueError, match="too few to contain"):
        training_construction_labels(np.zeros((5, NUM_FEATURES)))
