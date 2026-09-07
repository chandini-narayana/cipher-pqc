"""generate_report — one concise, professional 3-page PDF security report
per flagged device, plus its detached, non-self-referential audit record.

Renders exactly the fields already available on an already-produced
DeviceAssessment (see models/device_assessment.py) — this module
contains no risk scoring, no NIST-mapping, and no cryptographic
signing logic of its own; it reuses risk_assessment.remediation/
.nist_reference verbatim and delegates all signing/verification to
signing.sign()/signing.verify() unchanged.

Report-signing / self-reference note: the PDF cannot contain the
hash/signature of its own final rendered bytes (writing that value
onto the page would change the bytes it was computed from). Instead,
a stable CANONICAL REPORT CONTENT payload — report_id, device_ip,
generated_at, and DeviceAssessment.to_dict(), JSON-encoded with the
same sort-keys/compact-separator convention Phase 9 already froze for
DeviceAssessment — is hashed (SHA-256) and that digest is what gets
signed. This value is fully known before any page is drawn, so it can
be rendered onto Page 3 with no circularity. `report_hash` is labeled
"Report Integrity Hash (SHA-256)" throughout — it is a hash of the
report's canonical DATA, never a claim about the final PDF byte
stream.
"""
from __future__ import annotations

import hashlib
import json
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, Union

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen.canvas import Canvas

import signing
from config.constants import APP_NAME, APP_TAGLINE
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.report_metadata import ReportMetadata

DEFAULT_REPORT_OUTPUT_DIR = "data/reports"

_PAGE_COUNT = 3
_MARGIN = 0.75 * inch
_PAGE_WIDTH, _PAGE_HEIGHT = letter
_TEXT_WIDTH_CHARS = 95


def is_flagged_device(assessment: DeviceAssessment) -> bool:
    """A device is flagged for report generation iff its final category
    is not LOW (the frozen, approved eligibility rule) — MEDIUM and HIGH
    are both flagged, LOW is not. No risk threshold is changed here."""
    return assessment.final_category != RiskCategory.LOW


def generate_report_id(device_ip: str, generated_at: datetime) -> str:
    """Deterministic Phase-1 report id: CIPHER-<device-ip>-<UTC timestamp>.

    Purely a function of its two inputs — no randomness, no registry.
    """
    ip_component = device_ip.replace(".", "-").replace(":", "-")
    timestamp_component = generated_at.strftime("%Y%m%dT%H%M%SZ")
    return f"CIPHER-{ip_component}-{timestamp_component}"


def _canonicalize_report_content(
    report_id: str,
    device_ip: str,
    generated_at: datetime,
    assessment: DeviceAssessment,
) -> bytes:
    """The stable, non-self-referential payload that is hashed and
    signed — report identity + timing + the full DeviceAssessment,
    never any rendered PDF bytes. Same sort-keys/compact-separator
    convention as signing.canonicalize_assessment()."""
    payload = {
        "report_id": report_id,
        "device_ip": device_ip,
        "generated_at": generated_at.isoformat(),
        "assessment": assessment.to_dict(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_report(
    assessment: DeviceAssessment,
    secret_key: bytes,
    public_key: bytes,
    output_dir: Union[str, Path] = DEFAULT_REPORT_OUTPUT_DIR,
    report_id: Optional[str] = None,
    generated_at: Optional[datetime] = None,
) -> Tuple[Path, ReportMetadata]:
    """Render one 3-page PDF security report for `assessment` and return
    (pdf_path, metadata).

    `report_id`/`generated_at` are preserved if explicitly supplied,
    otherwise `generated_at` defaults to the current UTC time and
    `report_id` is derived from it via generate_report_id(). Neither
    `assessment` nor its nested objects are mutated.
    """
    generated_at = generated_at if generated_at is not None else datetime.now(timezone.utc)
    report_id = (
        report_id if report_id is not None else generate_report_id(assessment.device.ip, generated_at)
    )

    canonical_content = _canonicalize_report_content(
        report_id, assessment.device.ip, generated_at, assessment
    )
    report_hash = hashlib.sha256(canonical_content).hexdigest()
    signature = signing.sign(bytes.fromhex(report_hash), secret_key)
    verification_status = signing.verify(bytes.fromhex(report_hash), signature, public_key)

    metadata = ReportMetadata(
        report_id=report_id,
        device_ip=assessment.device.ip,
        generated_at=generated_at,
        page_count=_PAGE_COUNT,
        report_hash=report_hash,
        signature_hex=signature.hex(),
        signing_algorithm=signing.ALGORITHM_NAME,
        verification_status=verification_status,
    )

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = output_dir / f"{report_id}.pdf"
    _render_pdf(pdf_path, assessment, metadata)

    return pdf_path, metadata


def verify_report(
    metadata: ReportMetadata,
    assessment: DeviceAssessment,
    public_key: bytes,
) -> bool:
    """Independently verify a previously-generated report record.

    Reconstructs the canonical report content from `metadata` and
    `assessment`, recomputes its SHA-256 hash, confirms it matches
    `metadata.report_hash`, and verifies `metadata.signature_hex`
    against `public_key` via the existing signing.verify() — no
    cryptographic logic is duplicated here.

    Returns False for any mismatch: altered assessment data, a hash
    that no longer matches, a tampered signature, the wrong public
    key, or a signing_algorithm that isn't signing.ALGORITHM_NAME.
    """
    if metadata.signing_algorithm != signing.ALGORITHM_NAME:
        return False

    canonical_content = _canonicalize_report_content(
        metadata.report_id, metadata.device_ip, metadata.generated_at, assessment
    )
    recomputed_hash = hashlib.sha256(canonical_content).hexdigest()
    if recomputed_hash != metadata.report_hash:
        return False

    signature = bytes.fromhex(metadata.signature_hex)
    return signing.verify(bytes.fromhex(recomputed_hash), signature, public_key)


# --- PDF rendering (no findings/scoring/signing logic below this line) ---


def _render_pdf(pdf_path: Path, assessment: DeviceAssessment, metadata: ReportMetadata) -> None:
    canvas = Canvas(str(pdf_path), pagesize=letter, pageCompression=0)
    _draw_page_1_executive_summary(canvas, assessment, metadata)
    canvas.showPage()
    _draw_page_2_technical_findings(canvas, assessment, metadata)
    canvas.showPage()
    _draw_page_3_audit_and_verification(canvas, assessment, metadata)
    canvas.showPage()
    canvas.save()


def _new_cursor() -> float:
    return _PAGE_HEIGHT - _MARGIN


def _draw_heading(canvas: Canvas, y: float, text: str) -> float:
    canvas.setFont("Helvetica-Bold", 16)
    canvas.drawString(_MARGIN, y, text)
    return y - 0.35 * inch


def _draw_subheading(canvas: Canvas, y: float, text: str) -> float:
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(_MARGIN, y, text)
    return y - 0.25 * inch


def _draw_field(canvas: Canvas, y: float, label: str, value: str) -> float:
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(_MARGIN, y, f"{label}:")
    canvas.setFont("Helvetica", 10)
    canvas.drawString(_MARGIN + 1.8 * inch, y, str(value))
    return y - 0.22 * inch


def _draw_paragraph(canvas: Canvas, y: float, text: str) -> float:
    canvas.setFont("Helvetica", 10)
    for line in textwrap.wrap(text, width=_TEXT_WIDTH_CHARS) or [""]:
        canvas.drawString(_MARGIN, y, line)
        y -= 0.18 * inch
    return y


def _anomaly_status_text(assessment: DeviceAssessment) -> str:
    if assessment.anomaly_assessment is None:
        return "Not available"
    return "Anomalous" if assessment.anomaly_assessment.is_anomaly else "Not anomalous"


def _draw_page_1_executive_summary(
    canvas: Canvas, assessment: DeviceAssessment, metadata: ReportMetadata
) -> None:
    y = _new_cursor()
    y = _draw_heading(canvas, y, APP_NAME)
    canvas.setFont("Helvetica-Oblique", 9)
    canvas.drawString(_MARGIN, y, APP_TAGLINE)
    y -= 0.35 * inch

    y = _draw_subheading(canvas, y, "Executive Summary")
    y -= 0.05 * inch

    y = _draw_field(canvas, y, "Report ID", metadata.report_id)
    y = _draw_field(canvas, y, "Generated", metadata.generated_at.isoformat())
    y = _draw_field(canvas, y, "Device IP", assessment.device.ip)
    y = _draw_field(canvas, y, "First Seen", assessment.device.first_seen.isoformat())
    y = _draw_field(canvas, y, "Last Seen", assessment.device.last_seen.isoformat())
    y -= 0.1 * inch

    y = _draw_field(canvas, y, "Final Risk Level", assessment.final_category.value)
    y = _draw_field(canvas, y, "QRS Score", f"{assessment.risk_assessment.risk_score} / 10")
    y = _draw_field(canvas, y, "QRS Category", assessment.risk_assessment.category.value)
    y = _draw_field(canvas, y, "Anomaly Status", _anomaly_status_text(assessment))
    y -= 0.2 * inch

    y = _draw_subheading(canvas, y, "Summary")
    summary = (
        f"This device was assessed at {assessment.final_category.value} risk. "
        "See Technical Findings (Page 2) for the specific weak configuration(s) "
        "identified and NIST-referenced remediation guidance."
    )
    _draw_paragraph(canvas, y, summary)


def _draw_page_2_technical_findings(
    canvas: Canvas, assessment: DeviceAssessment, metadata: ReportMetadata
) -> None:
    y = _new_cursor()
    y = _draw_heading(canvas, y, "Technical Findings & NIST Remediation")
    y -= 0.1 * inch

    y = _draw_field(canvas, y, "Risk Score", f"{assessment.risk_assessment.risk_score} / 10")
    y = _draw_field(canvas, y, "Risk Category", assessment.risk_assessment.category.value)
    y -= 0.15 * inch

    y = _draw_subheading(canvas, y, "Weak Configuration / Finding")
    y = _draw_paragraph(canvas, y, assessment.risk_assessment.remediation)
    y -= 0.15 * inch

    y = _draw_subheading(canvas, y, "NIST Reference")
    y = _draw_paragraph(canvas, y, assessment.risk_assessment.nist_reference)
    y -= 0.2 * inch

    y = _draw_subheading(canvas, y, "Isolation Forest Anomaly Analysis")
    anomaly = assessment.anomaly_assessment
    if anomaly is None:
        y = _draw_field(canvas, y, "Status", "Not available")
    else:
        y = _draw_field(canvas, y, "Status", _anomaly_status_text(assessment))
        y = _draw_field(canvas, y, "Anomaly Score", f"{anomaly.anomaly_score:.4f}")
        y = _draw_field(canvas, y, "Confidence", f"{anomaly.confidence:.4f}")


def _draw_page_3_audit_and_verification(
    canvas: Canvas, assessment: DeviceAssessment, metadata: ReportMetadata
) -> None:
    y = _new_cursor()
    y = _draw_heading(canvas, y, "Audit & Verification")
    y -= 0.1 * inch

    y = _draw_field(canvas, y, "Report ID", metadata.report_id)
    y = _draw_field(canvas, y, "Assessment Timestamp", assessment.assessed_at.isoformat())
    y = _draw_field(canvas, y, "Generation Timestamp", metadata.generated_at.isoformat())
    y -= 0.15 * inch

    y = _draw_subheading(canvas, y, "Report Integrity Hash (SHA-256)")
    y = _draw_paragraph(canvas, y, metadata.report_hash)
    y -= 0.1 * inch

    y = _draw_field(canvas, y, "Signing Algorithm", metadata.signing_algorithm)
    y = _draw_field(
        canvas, y, "Verification Status", "Verified" if metadata.verification_status else "Failed"
    )
    y -= 0.15 * inch

    y = _draw_subheading(canvas, y, "Signature Preview")
    preview = metadata.signature_hex[:32] + ("..." if len(metadata.signature_hex) > 32 else "")
    y = _draw_paragraph(canvas, y, preview)
    y -= 0.1 * inch

    note = (
        f"The {metadata.signing_algorithm} signature protects the canonical report "
        "content (report ID, device IP, generation time, and the full signed "
        "device assessment) — not the rendered PDF byte stream. The full "
        "signature is retained in this report's ReportMetadata record."
    )
    _draw_paragraph(canvas, y, note)
