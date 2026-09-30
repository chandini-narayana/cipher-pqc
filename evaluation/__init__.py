"""evaluation — offline research/evaluation metrics, invoked explicitly only.

This package exists solely to produce defensible quantitative figures for
the revised research paper. It is NEVER imported by CIPHER's runtime: not
by main.py, run_demo.py, run_api.py, run_live_demo.py, pipeline/,
dashboard/, or any module they import (enforced by a static AST test in
tests/test_evaluate_research.py). Nothing here can therefore add any
overhead to a normal CIPHER run.

It contains measurement only — no scoring, fingerprinting, entropy,
fusion, enforcement, or ML logic of its own, and it never modifies the
frozen architecture it measures. Every metric is computed from values the
REAL production modules returned.

Scope so far (see docs/SDD.md's Phase 2A and Phase 2B addenda):
deterministic Quantum Risk Score specification conformance and controlled
security-classification metrics (Phase 2A, QRS-only), plus ROC-AUC and
distribution summaries for the existing Isolation Forest's continuous
anomaly score (Phase 2B). CPU/RAM and Raspberry Pi hardware benchmarking
are deliberately NOT part of either phase and are not implemented here.

This package holds MEASUREMENT PRIMITIVES ONLY, and deliberately imports
no risk/, ml/, fusion/, fingerprint/, entropy/ or pipeline/ module (also
enforced by a test): measurement must not contain, or depend on, the logic
it measures. The orchestration that drives CIPHER's real modules and feeds
their output to these functions lives in evaluate_research.py.
"""

from evaluation.metrics import (
    BinaryMetrics,
    CategoryConfusion,
    ConfusionCounts,
    QRSConformance,
    RocAuc,
    binary_metrics,
    category_confusion,
    confusion_counts,
    exact_agreement,
    qrs_conformance,
    roc_auc,
    value_summary,
)

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
]
