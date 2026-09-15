"""Unit tests for reports.pdf_generator — one concise 3-page PDF
security report per flagged device (docs/SDD.md Phase 10 addendum).

Structural/content checks only — no OCR, no brittle visual assertions.
The generator disables PDF stream compression specifically so expected
text can be located directly in the raw file bytes.
"""
from __future__ import annotations

import dataclasses
import re
from datetime import datetime, timezone

import pytest

from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.report_metadata import ReportMetadata
from models.risk_assessment import RiskAssessment
from reports.pdf_generator import (
    generate_report,
    generate_report_id,
    is_flagged_device,
    verify_report,
)
from signing import generate_keypair

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

_PAGE_TYPE_RE = re.compile(rb"/Type\s*/Page(?!s)")


def _low_assessment() -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact("10.0.0.5", TS),
        risk_assessment=RiskAssessment(
            1,
            RiskCategory.LOW,
            "No remediation needed. All assessed factors (TLS version, key size, "
            "forward secrecy, entropy, protocol exposure) are within the safe "
            "thresholds defined by the approved risk model.",
            "N/A — no findings triggered a NIST reference.",
        ),
        anomaly_assessment=None,
        final_category=RiskCategory.LOW,
        assessed_at=TS,
    )


def _medium_assessment() -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact("10.0.0.6", TS),
        risk_assessment=RiskAssessment(
            5,
            RiskCategory.MEDIUM,
            "Increase RSA key size to at least 3072 bits (observed: 1536 bits). "
            "Enable forward secrecy (e.g., ECDHE cipher suites) instead of "
            "static RSA key exchange.",
            "NIST SP 800-131A, NIST SP 800-52r2",
        ),
        anomaly_assessment=AnomalyAssessment(anomaly_score=0.1, is_anomaly=False, confidence=0.3),
        final_category=RiskCategory.MEDIUM,
        assessed_at=TS,
    )


def _high_assessment() -> DeviceAssessment:
    return DeviceAssessment(
        device=Device.first_contact("192.168.1.10", TS),
        risk_assessment=RiskAssessment(
            9,
            RiskCategory.HIGH,
            "Upgrade from TLS 1.0 to TLS 1.3. Increase RSA key size to at least "
            "3072 bits (observed: 512 bits). Enable forward secrecy (e.g., ECDHE "
            "cipher suites) instead of static RSA key exchange.",
            "NIST SP 800-52r2, NIST SP 800-131A",
        ),
        anomaly_assessment=AnomalyAssessment(anomaly_score=0.87, is_anomaly=True, confidence=0.93),
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    )


def _page_count(pdf_bytes: bytes) -> int:
    return len(_PAGE_TYPE_RE.findall(pdf_bytes))


# --- 1-3. basic PDF structure ---


def test_valid_pdf_created(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    path, _ = generate_report(_high_assessment(), secret_key, public_key, output_dir=tmp_path)
    assert path.exists()
    assert path.suffix == ".pdf"


def test_pdf_header_is_valid(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    path, _ = generate_report(_high_assessment(), secret_key, public_key, output_dir=tmp_path)
    assert path.read_bytes()[:5] == b"%PDF-"


def test_page_count_is_at_most_three(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    path, metadata = generate_report(_high_assessment(), secret_key, public_key, output_dir=tmp_path)
    page_count = _page_count(path.read_bytes())
    assert page_count <= 3
    assert page_count == metadata.page_count


# --- 4. metadata validity ---


def test_report_metadata_is_valid(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    _, metadata = generate_report(_high_assessment(), secret_key, public_key, output_dir=tmp_path)
    assert isinstance(metadata, ReportMetadata)
    assert 1 <= metadata.page_count <= 3


# --- 5-13. required rendered content ---


def test_device_ip_appears(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _high_assessment()
    path, _ = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)
    assert assessment.device.ip.encode() in path.read_bytes()


def test_risk_score_appears(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _high_assessment()
    path, _ = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)
    assert f"{assessment.risk_assessment.risk_score} / 10".encode() in path.read_bytes()


def test_risk_level_appears(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _high_assessment()
    path, _ = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)
    assert assessment.final_category.value.encode() in path.read_bytes()


def test_remediation_text_appears(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _high_assessment()
    path, _ = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)
    assert b"Upgrade from TLS 1.0" in path.read_bytes()


def test_nist_reference_appears(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _high_assessment()
    path, _ = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)
    assert b"NIST SP 800-52r2" in path.read_bytes()


def test_anomaly_details_appear_when_available(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _high_assessment()
    path, _ = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)
    data = path.read_bytes()
    assert b"Anomalous" in data
    assert b"0.8700" in data  # anomaly_score formatted
    assert b"0.9300" in data  # confidence formatted


def test_not_available_appears_when_anomaly_assessment_is_none(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _low_assessment()
    assert assessment.anomaly_assessment is None
    path, _ = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)
    assert b"Not available" in path.read_bytes()


# --- expanded Page 1 executive summary content ---


def test_page_1_has_the_expanded_executive_summary_sections(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    path, _ = generate_report(_high_assessment(), secret_key, public_key, output_dir=tmp_path)
    data = path.read_bytes()
    for heading in (
        b"Assessment Overview",
        b"Key Findings",
        b"Recommended Action",
        b"Anomaly Analysis",
        b"Applicable Guidance",
    ):
        assert heading in data


def test_key_findings_are_bulleted_verbatim_remediation_sentences(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _high_assessment()
    path, _ = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)
    data = path.read_bytes()

    assert b"- Upgrade from TLS 1.0" in data  # a real bulleted list, not bare prose
    for sentence in (
        "Upgrade from TLS 1.0 to TLS 1.3.",
        "Enable forward secrecy",
        "Increase RSA key size",
    ):
        assert sentence.encode() in data


def test_assessment_overview_uses_real_device_and_score_values(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _high_assessment()
    path, _ = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)
    data = path.read_bytes()

    assert assessment.device.ip.encode() in data
    assert b"9/10" in data  # Assessment Overview's own risk-score phrasing
    assert b"Quantum Risk Score" in data


def test_no_invented_technical_field_labels_are_introduced(tmp_path) -> None:
    """Only fields already available on DeviceAssessment/RiskAssessment
    may be rendered as labeled fields — TLS version, RSA key size, PFS,
    protocol, cipher suite, and entropy are not on that model and must
    never appear as an invented "Label:" field."""
    public_key, secret_key = generate_keypair()
    path, _ = generate_report(_high_assessment(), secret_key, public_key, output_dir=tmp_path)
    data = path.read_bytes()

    for forbidden_label in (
        b"TLS Version:",
        b"RSA Key Size:",
        b"Key Size:",
        b"Forward Secrecy:",
        b"Protocol:",
        b"Cipher Suite:",
        b"Entropy:",
        b"Packet Count:",
    ):
        assert forbidden_label not in data


def test_signing_algorithm_appears(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    path, metadata = generate_report(_high_assessment(), secret_key, public_key, output_dir=tmp_path)
    # PDF content strings escape literal parentheses (\( \)), so check the
    # algorithm's core identifier rather than the full, parenthesis-bearing
    # ALGORITHM_NAME string verbatim.
    assert b"ML-DSA-44" in path.read_bytes()
    assert "ML-DSA-44" in metadata.signing_algorithm


def test_verification_status_appears(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    path, _ = generate_report(_high_assessment(), secret_key, public_key, output_dir=tmp_path)
    data = path.read_bytes()
    assert b"Verified" in data or b"Failed" in data


# --- 14-15. hash/signature are real, not placeholders ---


def test_report_hash_is_real_not_placeholder(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    _, metadata = generate_report(_high_assessment(), secret_key, public_key, output_dir=tmp_path)
    assert metadata.report_hash not in ("", "0" * 64, "deadbeef")
    assert len(metadata.report_hash) == 64  # SHA-256 hex digest length
    bytes.fromhex(metadata.report_hash)


def test_signature_is_real_not_placeholder(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    _, metadata = generate_report(_high_assessment(), secret_key, public_key, output_dir=tmp_path)
    assert metadata.signature_hex not in ("", "deadbeef")
    assert len(metadata.signature_hex) > 100
    bytes.fromhex(metadata.signature_hex)


# --- 16-20. verification behavior ---


def test_verification_succeeds_for_untouched_report(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _high_assessment()
    _, metadata = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)
    assert verify_report(metadata, assessment, public_key) is True
    assert metadata.verification_status is True


def test_changed_assessment_fails_verification(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _high_assessment()
    _, metadata = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)

    tampered = dataclasses.replace(assessment, final_category=RiskCategory.LOW)
    assert verify_report(metadata, tampered, public_key) is False


def test_changed_hash_fails_verification(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _high_assessment()
    _, metadata = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)

    tampered_metadata = dataclasses.replace(metadata, report_hash="0" * 64)
    assert verify_report(tampered_metadata, assessment, public_key) is False


def test_changed_signature_fails_verification(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    assessment = _high_assessment()
    _, metadata = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)

    corrupted = bytearray.fromhex(metadata.signature_hex)
    corrupted[0] ^= 0xFF
    tampered_metadata = dataclasses.replace(metadata, signature_hex=bytes(corrupted).hex())
    assert verify_report(tampered_metadata, assessment, public_key) is False


def test_wrong_public_key_fails_verification(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    other_public_key, _ = generate_keypair()
    assessment = _high_assessment()
    _, metadata = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)

    assert verify_report(metadata, assessment, other_public_key) is False


# --- 21-23. flagged-device rule ---


def test_low_is_not_flagged() -> None:
    assert is_flagged_device(_low_assessment()) is False


def test_medium_is_flagged() -> None:
    assert is_flagged_device(_medium_assessment()) is True


def test_high_is_flagged() -> None:
    assert is_flagged_device(_high_assessment()) is True


# --- 24. report id determinism ---


def test_report_id_is_deterministic_given_the_same_timestamp() -> None:
    first = generate_report_id("192.168.1.10", TS)
    second = generate_report_id("192.168.1.10", TS)
    assert first == second


def test_report_id_differs_for_different_devices_or_timestamps() -> None:
    base = generate_report_id("192.168.1.10", TS)
    other_device = generate_report_id("192.168.1.11", TS)
    other_time = generate_report_id("192.168.1.10", datetime(2027, 1, 1, tzinfo=timezone.utc))
    assert base != other_device
    assert base != other_time


# --- 25. tests use tmp_path only ---


def test_report_written_only_under_tmp_path(tmp_path) -> None:
    public_key, secret_key = generate_keypair()
    path, _ = generate_report(_high_assessment(), secret_key, public_key, output_dir=tmp_path)
    assert str(tmp_path) in str(path)


# --- required project deliverable: >=3 reports across distinct devices/risk levels ---


@pytest.mark.parametrize(
    "assessment_factory",
    [_low_assessment, _medium_assessment, _high_assessment],
)
def test_generates_a_valid_report_for_each_representative_risk_level(tmp_path, assessment_factory) -> None:
    """Demonstrates the project deliverable: at least 3 reports across
    distinct synthetic devices/risk levels, each independently valid
    and verifiable. These are synthetic test fixtures, not claims
    about real network traffic."""
    public_key, secret_key = generate_keypair()
    assessment = assessment_factory()

    path, metadata = generate_report(
        assessment, secret_key, public_key, output_dir=tmp_path / assessment.device.ip.replace(".", "_")
    )

    assert path.exists()
    assert path.read_bytes()[:5] == b"%PDF-"
    assert _page_count(path.read_bytes()) <= 3
    assert verify_report(metadata, assessment, public_key) is True


def test_no_pdf_left_in_the_real_default_output_directory() -> None:
    """Sentinel: this test suite must never create files under the real
    data/reports/ default — every generation test above passes an
    explicit tmp_path-derived output_dir."""
    from pathlib import Path

    default_dir = Path("data/reports")
    if default_dir.exists():
        assert not any(default_dir.glob("CIPHER-*.pdf"))
