"""Phase 3B tests for the Autonomous Isolation Enforcement block in the
signed PDF report (docs/SDD.md Phase 3B addendum).

Same conventions as tests/reports/test_pdf_generator.py: structural and
raw-byte content checks only (the generator disables stream compression
so drawn text is locatable in the file bytes), no OCR, no visual
assertions. Long narrative text is wrapped across lines by the generator,
so assertions target phrases short enough to stay on one line.
"""
from __future__ import annotations

import io
import re
from datetime import datetime, timezone

import pytest

from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
from models.risk_assessment import RiskAssessment
from reports.pdf_generator import generate_report, verify_report
from signing import generate_keypair

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

_PAGE_TYPE_RE = re.compile(rb"/Type\s*/Page(?!s)")


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair()


def _assessment(isolation: IsolationStatus | None, risk_score: int = 9) -> DeviceAssessment:
    assessment = DeviceAssessment(
        device=Device.first_contact("10.0.0.5", TS),
        risk_assessment=RiskAssessment(
            risk_score, RiskCategory.HIGH, "Upgrade from TLS 1.0 to TLS 1.3.", "NIST SP 800-52r2"
        ),
        anomaly_assessment=None,
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    )
    return assessment if isolation is None else assessment.with_isolation(isolation)


def _status(**overrides) -> IsolationStatus:
    kwargs = {
        "requested": True,
        "enforced": False,
        "backend": "noop",
        "reason": "Hardware enforcement unavailable in current deployment",
        "requested_at": TS,
        "enforcement_capable": False,
    }
    kwargs.update(overrides)
    return IsolationStatus(**kwargs)


def _render(keypair, isolation, tmp_path, risk_score: int = 9) -> bytes:
    public_key, secret_key = keypair
    path, _metadata = generate_report(
        _assessment(isolation, risk_score), secret_key, public_key, output_dir=tmp_path
    )
    return path.read_bytes()


# --- the section exists on every report ---


def test_isolation_section_heading_appears(keypair, tmp_path) -> None:
    assert b"Autonomous Isolation Enforcement" in _render(keypair, _status(), tmp_path)


def test_the_three_facts_are_reported_separately(keypair, tmp_path) -> None:
    """Eligible, requested and enforced are three distinct labelled
    fields — never collapsed into one claim."""
    content = _render(keypair, _status(), tmp_path)
    assert b"Isolation Eligible" in content
    assert b"Isolation Requested" in content
    assert b"Isolation Enforced" in content


def test_the_backend_is_named(keypair, tmp_path) -> None:
    content = _render(keypair, _status(), tmp_path)
    assert b"Enforcement Backend" in content
    assert b"noop" in content


# --- not eligible ---


def test_not_eligible_wording(keypair, tmp_path) -> None:
    """A flagged MEDIUM device below the isolation threshold: no isolation
    state, and the report says so rather than leaving it ambiguous."""
    content = _render(keypair, None, tmp_path, risk_score=5)
    assert b"No - raw QRS below the isolation threshold" in content
    assert b"not eligible for isolation" in content


def test_not_eligible_report_never_says_requested_or_enforced(keypair, tmp_path) -> None:
    content = _render(keypair, None, tmp_path, risk_score=5)
    assert b"no isolation was requested" in content
    assert b"Isolation requested and enforced" not in content


# --- requested but not enforced (NoOp / Windows) ---


def test_requested_not_enforced_wording(keypair, tmp_path) -> None:
    content = _render(keypair, _status(), tmp_path)
    assert b"Isolation requested but not enforced by the current backend." in content


def test_requested_not_enforced_states_eligibility_and_the_request(keypair, tmp_path) -> None:
    content = _render(keypair, _status(), tmp_path)
    assert b"Yes - raw QRS reached the isolation threshold" in content


def test_noop_report_explicitly_denies_physical_isolation(keypair, tmp_path) -> None:
    """The report must never let a NoOp outcome read as a real network
    action on Windows."""
    content = _render(keypair, _status(), tmp_path)
    assert b"NOT physically" in content
    assert b"Isolation requested and enforced" not in content


# --- enforced ---


def test_enforced_wording(keypair, tmp_path) -> None:
    status = _status(enforced=True, backend="linux", enforcement_capable=True, reason="rule applied")
    content = _render(keypair, status, tmp_path)
    assert b"Isolation requested and enforced by the 'linux' backend." in content


def test_enforced_report_does_not_also_claim_non_enforcement(keypair, tmp_path) -> None:
    status = _status(enforced=True, backend="linux", enforcement_capable=True, reason="rule applied")
    content = _render(keypair, status, tmp_path)
    assert b"not enforced by the current backend" not in content
    assert b"NOT physically" not in content


# --- failed ---


def test_failed_enforcement_wording(keypair, tmp_path) -> None:
    """A capable backend that did not enforce is reported as a failure,
    distinct from a deployment that does not enforce at all."""
    status = _status(backend="linux", enforcement_capable=True, reason="permission denied")
    content = _render(keypair, status, tmp_path)
    assert b"enforcement FAILED" in content
    assert b"permission denied" in content


def test_failed_enforcement_is_not_worded_as_a_noop_deployment(keypair, tmp_path) -> None:
    status = _status(backend="linux", enforcement_capable=True, reason="permission denied")
    content = _render(keypair, status, tmp_path)
    assert b"does not perform physical network enforcement" not in content


# --- structure, signing and verification are unchanged ---


def test_report_is_still_three_pages(keypair, tmp_path) -> None:
    assert len(_PAGE_TYPE_RE.findall(_render(keypair, _status(), tmp_path))) == 3


def test_isolation_state_is_covered_by_the_signature(keypair, tmp_path) -> None:
    """The enforcement result is signed evidence, not decoration: the
    report verifies, and a report generated with different isolation
    state has a different hash."""
    public_key, secret_key = keypair
    enforced_assessment = _assessment(
        _status(enforced=True, backend="linux", enforcement_capable=True)
    )
    noop_assessment = _assessment(_status())

    _path, enforced_meta = generate_report(
        enforced_assessment, secret_key, public_key, output_dir=tmp_path / "a"
    )
    _path, noop_meta = generate_report(
        noop_assessment, secret_key, public_key, output_dir=tmp_path / "b"
    )

    assert verify_report(enforced_meta, enforced_assessment, public_key) is True
    assert verify_report(noop_meta, noop_assessment, public_key) is True
    # Different isolation state => different signed payload.
    assert enforced_meta.report_hash != noop_meta.report_hash
    # And the enforced report does not verify against the NoOp assessment.
    assert verify_report(enforced_meta, noop_assessment, public_key) is False


def test_a_report_without_isolation_state_still_verifies(keypair, tmp_path) -> None:
    """Backward compatibility: the pre-Phase-3B shape (isolation=None)
    signs and verifies exactly as before."""
    public_key, secret_key = keypair
    assessment = _assessment(None, risk_score=5)
    _path, metadata = generate_report(assessment, secret_key, public_key, output_dir=tmp_path)
    assert verify_report(metadata, assessment, public_key) is True


def test_existing_report_content_is_untouched(keypair, tmp_path) -> None:
    content = _render(keypair, _status(), tmp_path)
    assert b"Upgrade from TLS 1.0" in content
    assert b"NIST SP 800-52r2" in content
    assert b"Isolation Forest Anomaly Analysis" in content


def test_pdf_generator_does_not_import_enforcement() -> None:
    """reports/ reads DeviceAssessment.isolation; it never recomputes
    eligibility or reaches into the enforcement layer."""
    import ast
    import inspect

    import reports.pdf_generator as module

    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert "enforcement" not in imported


def test_page_2_layout_does_not_overflow_with_worst_case_text() -> None:
    """The new section is the last block on page 2, so long remediation,
    NIST and reason text must still leave it above the bottom margin.
    Guards future wording changes against silently running off the page."""
    from reportlab.pdfgen.canvas import Canvas

    import reports.pdf_generator as generator
    from models.anomaly_assessment import AnomalyAssessment
    from models.report_metadata import ReportMetadata

    long_remediation = (
        "Upgrade this device from TLS 1.0 to TLS 1.3 and replace the 1024-bit RSA key with a "
        "3072-bit key or an ECDSA P-256 key; disable all static key exchange so that forward "
        "secrecy is negotiated for every session, then re-run the assessment to confirm. "
    ) * 2
    long_reason = "isolate command did not succeed: " + "permission denied for a long reason " * 4
    assessment = DeviceAssessment(
        device=Device.first_contact("10.0.0.5", TS),
        risk_assessment=RiskAssessment(
            9,
            RiskCategory.HIGH,
            long_remediation,
            "NIST SP 800-52r2; NIST SP 800-57 Part 1 Rev. 5; NIST IR 8413",
        ),
        anomaly_assessment=AnomalyAssessment(anomaly_score=-0.5, is_anomaly=True, confidence=0.95),
        final_category=RiskCategory.HIGH,
        assessed_at=TS,
    ).with_isolation(_status(backend="linux", enforcement_capable=True, reason=long_reason))

    metadata = ReportMetadata(
        "CIPHER-10-0-0-5-20260101T120000Z",
        "10.0.0.5",
        TS,
        3,
        "ab" * 32,
        "cd" * 32,
        "Dilithium2",
        "Verified",
    )
    # Measured through the real page-2 renderer (in memory, nothing
    # written to disk) so the section starts where it actually starts,
    # below every preceding block.
    captured = {}
    real_section = generator._draw_isolation_section

    def spy(canvas, y, drawn_assessment):
        end = real_section(canvas, y, drawn_assessment)
        captured["end"] = end
        return end

    canvas = Canvas(io.BytesIO())
    try:
        generator._draw_isolation_section = spy
        generator._draw_page_2_technical_findings(canvas, assessment, metadata)
    finally:
        generator._draw_isolation_section = real_section

    assert captured["end"] > generator._MARGIN
