"""Unit tests for risk.scoring — the QRS formula components.

Every assertion uses an explicit, hand-derived expected value — never
"is a float" or "does not crash".
"""
import pytest

from models.enums import RiskCategory, TLSVersion
from risk.scoring import (
    category_for_score,
    entropy_risk,
    key_size_risk,
    quantum_risk_score,
    tls_version_risk,
)


# --- TLS version component (exact table) ---


def test_tls_version_risk_exact_table() -> None:
    assert tls_version_risk(TLSVersion.TLS_1_0) == 4
    assert tls_version_risk(TLSVersion.TLS_1_1) == 3
    assert tls_version_risk(TLSVersion.TLS_1_2) == 1
    assert tls_version_risk(TLSVersion.TLS_1_3) == 0


def test_tls_version_risk_unknown_uses_approved_fallback_of_two() -> None:
    """None (undetected/unknown) uses the approved formula's own
    documented .get(tls_ver, 2) fallback — preserved, not invented."""
    assert tls_version_risk(None) == 2


# --- RSA key size component (exact table + the one open decision) ---


def test_key_size_risk_exact_table() -> None:
    assert key_size_risk(512) == 4
    assert key_size_risk(1536) == 3
    assert key_size_risk(2560) == 2
    assert key_size_risk(4096) == 0


def test_key_size_risk_boundaries() -> None:
    assert key_size_risk(1023) == 4
    assert key_size_risk(1024) == 3
    assert key_size_risk(2047) == 3
    assert key_size_risk(2048) == 2
    assert key_size_risk(3071) == 2
    assert key_size_risk(3072) == 0


def test_key_size_risk_none_contributes_zero() -> None:
    """Documented open decision (docs/SDD.md Section 20): unknown key
    size contributes 0, not a fabricated penalty — see module
    docstring for why (avoids punishing TLS 1.3 for a structural
    visibility limit that isn't a real weakness)."""
    assert key_size_risk(None) == 0


def test_key_size_risk_rejects_non_positive() -> None:
    with pytest.raises(ValueError, match="positive"):
        key_size_risk(0)
    with pytest.raises(ValueError, match="positive"):
        key_size_risk(-2048)


# --- Entropy component (exact table) ---


def test_entropy_risk_exact_table() -> None:
    assert entropy_risk(3.0) == 2
    assert entropy_risk(6.5) == 1
    assert entropy_risk(7.9) == 0


def test_entropy_risk_boundaries() -> None:
    assert entropy_risk(5.99) == 2
    assert entropy_risk(6.0) == 1
    assert entropy_risk(6.99) == 1
    assert entropy_risk(7.0) == 0
    assert entropy_risk(8.0) == 0
    assert entropy_risk(0.0) == 2


def test_entropy_risk_rejects_out_of_range() -> None:
    with pytest.raises(ValueError, match="0.0, 8.0"):
        entropy_risk(-0.1)
    with pytest.raises(ValueError, match="0.0, 8.0"):
        entropy_risk(8.1)


# --- Full formula: lowest / highest / boundary / combinations ---


def test_lowest_risk_valid_input() -> None:
    """TLS 1.3, strong key, PFS present, high entropy, no protocol
    exposure: every component contributes 0."""
    score = quantum_risk_score(TLSVersion.TLS_1_3, 3072, True, 7.9, 0)
    assert score == 0
    assert category_for_score(score) == RiskCategory.LOW


def test_highest_risk_valid_input_is_capped_at_ten() -> None:
    """TLS 1.0(4) + key<1024(4) + no PFS(1) + entropy<6(2) + port_risk(2)
    = 13, capped to the model's maximum of 10."""
    score = quantum_risk_score(TLSVersion.TLS_1_0, 512, False, 3.0, 2)
    assert score == 10
    assert category_for_score(score) == RiskCategory.HIGH


def test_score_is_sum_of_components_when_under_the_cap() -> None:
    """TLS 1.2(1) + key 2048(2) + PFS present(0) + entropy 6.5(1) +
    port_risk(0) = 4, well under the cap — exact, uncapped sum."""
    score = quantum_risk_score(TLSVersion.TLS_1_2, 2048, True, 6.5, 0)
    assert score == 4


def test_combination_of_two_weak_factors() -> None:
    """TLS 1.1(3) + key 1024(3) + PFS present(0) + entropy 7.5(0) +
    port_risk(1) = 7."""
    score = quantum_risk_score(TLSVersion.TLS_1_1, 1024, True, 7.5, 1)
    assert score == 7


def test_quantum_risk_score_rejects_negative_port_risk() -> None:
    with pytest.raises(ValueError, match="port_risk"):
        quantum_risk_score(TLSVersion.TLS_1_3, 3072, True, 7.9, -1)


def test_quantum_risk_score_is_deterministic() -> None:
    args = (TLSVersion.TLS_1_1, 1536, False, 5.5, 1)
    assert quantum_risk_score(*args) == quantum_risk_score(*args)


# --- Category boundaries ---


@pytest.mark.parametrize(
    "score,expected",
    [
        (0, RiskCategory.LOW),
        (1, RiskCategory.LOW),
        (2, RiskCategory.LOW),
        (3, RiskCategory.MEDIUM),
        (6, RiskCategory.MEDIUM),
        (7, RiskCategory.HIGH),
        (10, RiskCategory.HIGH),
    ],
)
def test_category_for_score_boundaries(score: int, expected: RiskCategory) -> None:
    assert category_for_score(score) == expected


def test_category_for_score_rejects_out_of_range() -> None:
    with pytest.raises(ValueError, match="0, 10"):
        category_for_score(-1)
    with pytest.raises(ValueError, match="0, 10"):
        category_for_score(11)


# --- No ML, no network dependency (static import check) ---


def test_risk_scoring_has_no_ml_or_network_imports() -> None:
    """Statically parses risk/scoring.py's own source and asserts no
    forbidden import appears — a real check, not a trust-me comment."""
    import ast
    import inspect

    import risk.scoring as scoring_module

    source = inspect.getsource(scoring_module)
    tree = ast.parse(source)

    forbidden = {"sklearn", "socket", "requests", "urllib", "http", "scapy", "flask"}
    found_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found_modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found_modules.add(node.module.split(".")[0])

    assert not (found_modules & forbidden), f"forbidden imports found: {found_modules & forbidden}"