"""Unit tests for risk.nist_mapping — remediation text and NIST
reference generation."""
from models.enums import TLSVersion
from risk.nist_mapping import build_remediation_and_reference, contributing_findings


def test_no_findings_when_everything_is_safe() -> None:
    findings = contributing_findings(TLSVersion.TLS_1_3, 3072, True, 7.9, 0)
    assert findings == []


def test_single_finding_for_weak_tls_version() -> None:
    findings = contributing_findings(TLSVersion.TLS_1_0, 3072, True, 7.9, 0)
    assert len(findings) == 1
    text, ref = findings[0]
    assert "TLS 1.0" in text
    assert "TLS 1.3" in text
    assert ref == "NIST SP 800-52r2"


def test_single_finding_for_weak_key_size() -> None:
    findings = contributing_findings(TLSVersion.TLS_1_3, 1024, True, 7.9, 0)
    assert len(findings) == 1
    text, ref = findings[0]
    assert "1024" in text
    assert "3072" in text
    assert ref == "NIST SP 800-131A"


def test_single_finding_for_missing_forward_secrecy() -> None:
    findings = contributing_findings(TLSVersion.TLS_1_3, 3072, False, 7.9, 0)
    assert len(findings) == 1
    text, ref = findings[0]
    assert "forward secrecy" in text.lower()
    assert ref == "NIST SP 800-52r2"


def test_single_finding_for_low_entropy() -> None:
    findings = contributing_findings(TLSVersion.TLS_1_3, 3072, True, 4.0, 0)
    assert len(findings) == 1
    text, ref = findings[0]
    assert "4.00" in text
    assert "Shannon" in ref


def test_single_finding_for_protocol_exposure() -> None:
    findings = contributing_findings(TLSVersion.TLS_1_3, 3072, True, 7.9, 2)
    assert len(findings) == 1
    text, ref = findings[0]
    assert "protocol" in text.lower()
    assert ref == "NIST SP 800-41"


def test_multiple_findings_combine_in_formula_order() -> None:
    findings = contributing_findings(TLSVersion.TLS_1_0, 512, False, 3.0, 1)
    assert len(findings) == 5  # every component contributes here
    refs_in_order = [ref for _, ref in findings]
    assert refs_in_order == [
        "NIST SP 800-52r2",  # TLS
        "NIST SP 800-131A",  # key size
        "NIST SP 800-52r2",  # PFS
        "Shannon (1948), A Mathematical Theory of Communication",  # entropy
        "NIST SP 800-41",  # protocol
    ]


def test_build_remediation_and_reference_deduplicates_repeated_nist_refs() -> None:
    """TLS weakness and missing PFS both cite SP 800-52r2 — the
    combined reference string must not repeat it."""
    _, nist_reference = build_remediation_and_reference(TLSVersion.TLS_1_0, 3072, False, 7.9, 0)
    assert nist_reference.count("NIST SP 800-52r2") == 1


def test_build_remediation_and_reference_no_findings_case() -> None:
    remediation, nist_reference = build_remediation_and_reference(
        TLSVersion.TLS_1_3, 3072, True, 7.9, 0
    )
    assert "no remediation needed" in remediation.lower()
    assert "n/a" in nist_reference.lower()


def test_build_remediation_and_reference_is_deterministic() -> None:
    args = (TLSVersion.TLS_1_1, 1536, False, 5.5, 1)
    first = build_remediation_and_reference(*args)
    second = build_remediation_and_reference(*args)
    assert first == second


def test_key_size_none_produces_no_key_size_finding() -> None:
    """Consistent with key_size_risk(None) == 0 (Section 20): an
    unobserved key size shouldn't generate a remediation claim about
    a key size that was never actually measured."""
    findings = contributing_findings(TLSVersion.TLS_1_3, None, True, 7.9, 0)
    assert findings == []