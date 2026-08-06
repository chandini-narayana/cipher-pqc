"""ml — dataset loading, feature engineering, training, and prediction.

MLClassifier falls back to a rule-based category (from risk.scoring
thresholds) when no trained model is present at startup (SDD D4) — this
is never a startup failure.
"""
