"""Deterministic held-out synthetic feature set for the Phase 2B Isolation
Forest evaluation (docs/SDD.md's Phase 2B addendum).

Ground truth only, fixed BEFORE any inference runs — the same discipline
tests/fixtures/labelled_evaluation_manifest.py applies to the Phase 2A
packet dataset.

REUSES ml/dataset.py UNMODIFIED. `generate_synthetic_feature_matrix()`
already builds exactly the two distributions the Isolation Forest was
trained on, and its documented construction stacks `n_normal` "normal"
rows FIRST and `n_outliers` injected-outlier rows AFTER them. That row
ordering is the label: row index < n_normal means the generator built it
from the normal distribution, index >= n_normal means it built the row from
the deliberately weak/legacy outlier distribution. No new distribution is
invented here, and no parameter of the generator's distributions is
changed.

LABELS ARE STRUCTURAL, NEVER MODEL-DERIVED. They come from which
distribution the generator drew each row from, which is known before the
model sees anything. Nothing here calls predict, decision_function,
score_samples, or reads a fitted model in any way — and
tests/fixtures/test_ml_heldout_set.py independently verifies the
row-to-distribution correspondence from the feature VALUES (entropy band,
key size, protocol one-hot), so the labels do not rest on an unchecked
assumption about the generator's internal ordering either.

HELD OUT BY SEED. HELDOUT_RANDOM_STATE is deliberately different from the
training seed (ml.classifier.DEFAULT_RANDOM_STATE = 42), so no row here was
in the matrix the model was fitted on. Same distributions, disjoint
samples: this measures generalization within the synthetic feature
distribution, and nothing more. It is NOT a measurement of real packet or
network behavior — for that, see the pipeline-extracted evaluation
(Section B of evaluate_research.py), which is what exposes the
train/serve mismatch.
"""
from __future__ import annotations

from typing import List

import numpy as np

from ml.classifier import DEFAULT_RANDOM_STATE
from ml.dataset import generate_synthetic_feature_matrix
from ml.features import FEATURE_NAMES, NUM_FEATURES

# Deliberately not 42 (ml.classifier.DEFAULT_RANDOM_STATE, the training
# seed), so every row below is genuinely held out from training.
HELDOUT_RANDOM_STATE = 1042

TRAINING_RANDOM_STATE = DEFAULT_RANDOM_STATE

# Mirrors ml/dataset.py's own defaults (180 normal + 10 outliers), so the
# held-out set has the same size, shape and class balance as the training
# matrix and the two are directly comparable.
HELDOUT_NORMAL_COUNT = 180
HELDOUT_OUTLIER_COUNT = 10
HELDOUT_TOTAL = HELDOUT_NORMAL_COUNT + HELDOUT_OUTLIER_COUNT

HELDOUT_FEATURE_NAMES = list(FEATURE_NAMES)


def build_heldout_feature_matrix() -> np.ndarray:
    """The held-out matrix: (HELDOUT_TOTAL, NUM_FEATURES), deterministic.

    Raises:
        AssertionError: if the generator returns an unexpected shape — the
            labels below depend on the documented row ordering and count, so
            a silent change there must fail loudly rather than mislabel.
    """
    matrix = generate_synthetic_feature_matrix(
        n_normal=HELDOUT_NORMAL_COUNT,
        n_outliers=HELDOUT_OUTLIER_COUNT,
        random_state=HELDOUT_RANDOM_STATE,
    )
    assert matrix.shape == (HELDOUT_TOTAL, NUM_FEATURES), matrix.shape
    return matrix


def heldout_construction_labels() -> List[bool]:
    """The positive class is "injected outlier by construction".

    True for rows the generator drew from its weak/legacy outlier
    distribution, False for rows drawn from its normal distribution — fixed
    by the generator's documented row ordering, never by any model output.
    """
    return [False] * HELDOUT_NORMAL_COUNT + [True] * HELDOUT_OUTLIER_COUNT


def build_training_feature_matrix() -> np.ndarray:
    """The exact matrix the model under evaluation is fitted on — the
    generator's defaults at the training seed.

    Provided here so the train-versus-serve feature comparison can summarize
    the training distribution without re-deriving its parameters, and so
    tests can assert the held-out set is genuinely disjoint from it.
    """
    return generate_synthetic_feature_matrix(random_state=TRAINING_RANDOM_STATE)


def training_construction_labels(matrix: np.ndarray) -> List[bool]:
    """Construction labels for `matrix` from build_training_feature_matrix().

    ml/dataset.py's defaults are 180 normal + 10 outliers; this derives the
    split from the actual row count so it cannot silently desynchronize if
    those defaults ever change.

    Raises:
        ValueError: if `matrix` has fewer rows than the 10 outliers
            ml/dataset.py appends by default.
    """
    outlier_count = 10
    normal_count = matrix.shape[0] - outlier_count
    if normal_count <= 0:
        raise ValueError(
            f"matrix has {matrix.shape[0]} rows; too few to contain "
            f"{outlier_count} appended outlier rows"
        )
    return [False] * normal_count + [True] * outlier_count


__all__ = [
    "HELDOUT_RANDOM_STATE",
    "TRAINING_RANDOM_STATE",
    "HELDOUT_NORMAL_COUNT",
    "HELDOUT_OUTLIER_COUNT",
    "HELDOUT_TOTAL",
    "HELDOUT_FEATURE_NAMES",
    "build_heldout_feature_matrix",
    "heldout_construction_labels",
    "build_training_feature_matrix",
    "training_construction_labels",
]
