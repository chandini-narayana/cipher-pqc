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

Visual design note: branding/layout below (colors, boxes, banner,
footer) is presentation only — every value rendered still comes from
the same DeviceAssessment/ReportMetadata fields as before, in the same
formats existing tests already assert on (e.g. "9 / 10", "0.8700",
"Verified"/"Failed"). No field was added, removed, or reformatted to
carry different information.
"""
from __future__ import annotations

import hashlib
import json
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from reportlab.lib import colors
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

# --- brand palette ---------------------------------------------------
# A dark navy / cyan pairing, chosen to read as a serious security
# product rather than a generic document — used consistently across
# the banner, section markers, and accent details on every page.
_COLOR_NAVY = colors.HexColor("#0B2545")
_COLOR_CYAN = colors.HexColor("#22D3EE")
_COLOR_TEXT = colors.HexColor("#0F172A")
_COLOR_SLATE = colors.HexColor("#334155")
_COLOR_MUTED = colors.HexColor("#64748B")
_COLOR_LIGHT_BG = colors.HexColor("#F1F5F9")
_COLOR_BORDER = colors.HexColor("#CBD5E1")

# (accent, tint) pairs — used for both the risk-level box on Page 1 and
# any other risk-colored element. Deliberately traffic-light-adjacent
# (green/amber/red) without changing what LOW/MEDIUM/HIGH mean.
_CATEGORY_COLORS: Dict[RiskCategory, Tuple[colors.Color, colors.Color]] = {
    RiskCategory.LOW: (colors.HexColor("#15803D"), colors.HexColor("#DCFCE7")),
    RiskCategory.MEDIUM: (colors.HexColor("#B45309"), colors.HexColor("#FEF3C7")),
    RiskCategory.HIGH: (colors.HexColor("#B91C1C"), colors.HexColor("#FEE2E2")),
}
_STATUS_COLORS: Dict[bool, Tuple[colors.Color, colors.Color]] = {
    True: (colors.HexColor("#15803D"), colors.HexColor("#DCFCE7")),
    False: (colors.HexColor("#B91C1C"), colors.HexColor("#FEE2E2")),
}

# Fixed, category-keyed explanatory sentences — wording only, never a
# scoring/threshold decision. What triggers LOW/MEDIUM/HIGH is decided
# entirely by risk/ and fusion/; this only explains the result in plain
# language on the Executive Summary.
_RISK_INTERPRETATION: Dict[RiskCategory, str] = {
    RiskCategory.LOW: "Low cryptographic risk identified in the assessed observation.",
    RiskCategory.MEDIUM: "Cryptographic weaknesses were identified and remediation is recommended.",
    RiskCategory.HIGH: (
        "Significant cryptographic weaknesses were identified and should be "
        "prioritised for remediation."
    ),
}

_PAGE_KICKERS = {
    1: "EXECUTIVE SUMMARY",
    2: "TECHNICAL FINDINGS",
    3: "AUDIT & VERIFICATION",
}

_MARGIN = 0.75 * inch
_PAGE_WIDTH, _PAGE_HEIGHT = letter
_CONTENT_WIDTH = _PAGE_WIDTH - 2 * _MARGIN
_TEXT_WIDTH_CHARS = 95
_BANNER_HEIGHT = 1.1 * inch


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

    # Resolved to absolute here, at the point of creation, so every Path
    # this function ever returns is safe to hand to Flask's send_file()
    # later — Flask resolves a relative filename against the app's
    # root_path, not the process's working directory, which otherwise
    # makes a real download 500 even though the file genuinely exists.
    output_dir = Path(output_dir).resolve()
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
    _draw_footer(canvas, 1)
    canvas.showPage()
    _draw_page_2_technical_findings(canvas, assessment, metadata)
    _draw_footer(canvas, 2)
    canvas.showPage()
    _draw_page_3_audit_and_verification(canvas, assessment, metadata)
    _draw_footer(canvas, 3)
    canvas.showPage()
    canvas.save()


# --- shared drawing primitives ---


def _draw_banner(canvas: Canvas, page_number: int) -> float:
    """Full-width navy brand banner with a cyan accent rule and a
    per-page kicker on the right (e.g. "EXECUTIVE SUMMARY"). Returns
    the y-coordinate where page content should start below it."""
    banner_bottom = _PAGE_HEIGHT - _BANNER_HEIGHT

    canvas.saveState()
    canvas.setFillColor(_COLOR_NAVY)
    canvas.rect(0, banner_bottom, _PAGE_WIDTH, _BANNER_HEIGHT, fill=1, stroke=0)
    canvas.setFillColor(_COLOR_CYAN)
    canvas.rect(0, banner_bottom, _PAGE_WIDTH, 0.045 * inch, fill=1, stroke=0)

    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 24)
    canvas.drawString(_MARGIN, _PAGE_HEIGHT - 0.6 * inch, APP_NAME)

    canvas.setFillColor(_COLOR_CYAN)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(_MARGIN, _PAGE_HEIGHT - 0.82 * inch, APP_TAGLINE)

    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawRightString(
        _PAGE_WIDTH - _MARGIN, _PAGE_HEIGHT - 0.6 * inch, _PAGE_KICKERS[page_number]
    )
    canvas.restoreState()

    return banner_bottom - 0.35 * inch


def _draw_footer(canvas: Canvas, page_number: int) -> None:
    canvas.saveState()
    canvas.setStrokeColor(_COLOR_BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(_MARGIN, 0.55 * inch, _PAGE_WIDTH - _MARGIN, 0.55 * inch)
    canvas.setFillColor(_COLOR_MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(_MARGIN, 0.38 * inch, f"{APP_NAME} — Confidential Security Report")
    canvas.drawRightString(_PAGE_WIDTH - _MARGIN, 0.38 * inch, f"Page {page_number} of {_PAGE_COUNT}")
    canvas.restoreState()


def _draw_section_heading(canvas: Canvas, y: float, text: str) -> float:
    canvas.saveState()
    canvas.setFillColor(_COLOR_CYAN)
    canvas.rect(_MARGIN, y - 0.03 * inch, 0.05 * inch, 0.2 * inch, fill=1, stroke=0)
    canvas.setFillColor(_COLOR_NAVY)
    canvas.setFont("Helvetica-Bold", 12)
    canvas.drawString(_MARGIN + 0.14 * inch, y, text)
    canvas.restoreState()
    return y - 0.28 * inch


def _draw_field(canvas: Canvas, y: float, label: str, value: str) -> float:
    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(_COLOR_SLATE)
    canvas.drawString(_MARGIN, y, f"{label}:")
    canvas.setFont("Helvetica", 10)
    canvas.setFillColor(_COLOR_TEXT)
    canvas.drawString(_MARGIN + 1.9 * inch, y, str(value))
    return y - 0.22 * inch


def _draw_paragraph(canvas: Canvas, y: float, text: str) -> float:
    canvas.setFont("Helvetica", 10)
    canvas.setFillColor(_COLOR_TEXT)
    for line in textwrap.wrap(text, width=_TEXT_WIDTH_CHARS) or [""]:
        canvas.drawString(_MARGIN, y, line)
        y -= 0.18 * inch
    return y


def _draw_card(canvas: Canvas, y: float, heading: str, body_text: str) -> float:
    """A light, bordered card used to make one finding (remediation
    guidance, a NIST reference) visually distinct from surrounding
    fields — same text as a plain paragraph would carry, just framed."""
    lines = textwrap.wrap(body_text, width=_TEXT_WIDTH_CHARS - 4) or [""]
    line_height = 0.18 * inch
    box_height = 0.32 * inch + line_height * len(lines) + 0.12 * inch
    box_bottom = y - box_height

    canvas.saveState()
    canvas.setFillColor(_COLOR_LIGHT_BG)
    canvas.setStrokeColor(_COLOR_BORDER)
    canvas.setLineWidth(0.75)
    canvas.roundRect(_MARGIN, box_bottom, _CONTENT_WIDTH, box_height, 4, fill=1, stroke=1)

    inner_y = y - 0.26 * inch
    canvas.setFillColor(_COLOR_NAVY)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(_MARGIN + 0.16 * inch, inner_y, heading)

    inner_y -= line_height
    canvas.setFont("Helvetica", 10)
    canvas.setFillColor(_COLOR_TEXT)
    for line in lines:
        canvas.drawString(_MARGIN + 0.16 * inch, inner_y, line)
        inner_y -= line_height
    canvas.restoreState()

    return box_bottom - 0.22 * inch


def _draw_mono_box(canvas: Canvas, y: float, text: str) -> float:
    """A shaded, bordered, monospace block for hash/signature values —
    reads as a "code" element, distinct from prose fields."""
    lines = textwrap.wrap(text, width=70) or [""]
    line_height = 0.17 * inch
    box_height = 0.16 * inch + line_height * len(lines) + 0.1 * inch
    box_bottom = y - box_height

    canvas.saveState()
    canvas.setFillColor(_COLOR_LIGHT_BG)
    canvas.setStrokeColor(_COLOR_BORDER)
    canvas.setLineWidth(0.75)
    canvas.roundRect(_MARGIN, box_bottom, _CONTENT_WIDTH, box_height, 4, fill=1, stroke=1)

    canvas.setFont("Courier", 9)
    canvas.setFillColor(_COLOR_SLATE)
    inner_y = y - 0.22 * inch
    for line in lines:
        canvas.drawString(_MARGIN + 0.14 * inch, inner_y, line)
        inner_y -= line_height
    canvas.restoreState()

    return box_bottom - 0.2 * inch


def _draw_status_badge(canvas: Canvas, x: float, y: float, text: str, ok: bool) -> None:
    accent, tint = _STATUS_COLORS[ok]
    padding = 0.16 * inch
    width = canvas.stringWidth(text, "Helvetica-Bold", 10) + 2 * padding

    canvas.saveState()
    canvas.setFillColor(tint)
    canvas.setStrokeColor(accent)
    canvas.setLineWidth(0.75)
    canvas.roundRect(x, y - 0.06 * inch, width, 0.24 * inch, 4, fill=1, stroke=1)
    canvas.setFillColor(accent)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(x + padding, y, text)
    canvas.restoreState()


def _draw_risk_box(canvas: Canvas, y: float, assessment: DeviceAssessment) -> float:
    accent, tint = _CATEGORY_COLORS[assessment.final_category]
    box_height = 1.05 * inch
    box_bottom = y - box_height

    canvas.saveState()
    canvas.setFillColor(tint)
    canvas.setStrokeColor(accent)
    canvas.setLineWidth(1)
    canvas.roundRect(_MARGIN, box_bottom, _CONTENT_WIDTH, box_height, 6, fill=1, stroke=1)
    canvas.setFillColor(accent)
    canvas.rect(_MARGIN, box_bottom, 0.08 * inch, box_height, fill=1, stroke=0)
    canvas.restoreState()

    inner_x = _MARGIN + 0.3 * inch
    inner_y = y - 0.32 * inch

    canvas.setFillColor(accent)
    canvas.setFont("Helvetica-Bold", 15)
    canvas.drawString(inner_x, inner_y, f"Final Risk Level: {assessment.final_category.value}")

    inner_y -= 0.28 * inch
    canvas.setFillColor(_COLOR_TEXT)
    canvas.setFont("Helvetica", 10)
    canvas.drawString(
        inner_x,
        inner_y,
        f"QRS Score: {assessment.risk_assessment.risk_score} / 10"
        f"    QRS Category: {assessment.risk_assessment.category.value}",
    )

    inner_y -= 0.24 * inch
    canvas.drawString(inner_x, inner_y, f"Anomaly Status: {_anomaly_status_text(assessment)}")

    return box_bottom - 0.28 * inch


def _anomaly_status_text(assessment: DeviceAssessment) -> str:
    if assessment.anomaly_assessment is None:
        return "Not available"
    return "Anomalous" if assessment.anomaly_assessment.is_anomaly else "Not anomalous"


def _split_into_sentences(text: str) -> List[str]:
    """Split an existing remediation string into its constituent
    sentences, verbatim — no rewriting, no summarization, no invented
    wording. risk/nist_mapping.py already builds `remediation` by
    joining complete, already-imperative sentences with a single space
    (see build_remediation_and_reference()), so splitting on a period
    followed by whitespace losslessly recovers each original finding
    exactly as written (a decimal like "3072" or "1.25 bits/byte" has
    no period-then-space, so it is never mistaken for a boundary)."""
    sentences = [s.strip() for s in re.split(r"(?<=[.])\s+", text.strip()) if s.strip()]
    return sentences if sentences else [text.strip()]


def _split_nist_references(nist_reference: str) -> List[str]:
    """Split the existing nist_reference string back into its
    individual references — risk/nist_mapping.py builds it via
    ", ".join(references), so splitting on ", " losslessly recovers
    the original list without inventing or reformatting any reference."""
    return [ref.strip() for ref in nist_reference.split(", ") if ref.strip()]


def _draw_bullet_list(canvas: Canvas, y: float, items: List[str]) -> float:
    # A plain hyphen, not a Unicode bullet glyph: reportlab's base-14
    # Helvetica/WinAnsiEncoding does not reliably encode "•" (it
    # was observed to emit an unrenderable byte) — a hyphen is
    # unambiguous and renders correctly in every viewer.
    canvas.setFont("Helvetica", 10)
    canvas.setFillColor(_COLOR_TEXT)
    for item in items:
        wrapped = textwrap.wrap(item, width=_TEXT_WIDTH_CHARS - 3) or [""]
        canvas.drawString(_MARGIN, y, f"- {wrapped[0]}")
        y -= 0.18 * inch
        for line in wrapped[1:]:
            canvas.drawString(_MARGIN + 0.16 * inch, y, line)
            y -= 0.18 * inch
    return y


def _draw_anomaly_summary(canvas: Canvas, y: float, assessment: DeviceAssessment) -> float:
    anomaly = assessment.anomaly_assessment
    if anomaly is None:
        y = _draw_field(canvas, y, "Anomaly Analysis", "Not available")
        y = _draw_paragraph(
            canvas,
            y,
            "The final classification is therefore based on the explainable QRS assessment.",
        )
        return y

    y = _draw_field(canvas, y, "Anomaly Detected", "Yes" if anomaly.is_anomaly else "No")
    y = _draw_field(canvas, y, "Anomaly Score", f"{anomaly.anomaly_score:.4f}")
    y = _draw_field(canvas, y, "Confidence", f"{anomaly.confidence:.4f}")
    return y


# --- page layouts ---


def _draw_page_1_executive_summary(
    canvas: Canvas, assessment: DeviceAssessment, metadata: ReportMetadata
) -> None:
    y = _draw_banner(canvas, 1)

    y = _draw_section_heading(canvas, y, "Device & Report Information")
    y -= 0.04 * inch
    y = _draw_field(canvas, y, "Report ID", metadata.report_id)
    y = _draw_field(canvas, y, "Generated", metadata.generated_at.isoformat())
    y = _draw_field(canvas, y, "Device IP", assessment.device.ip)
    y = _draw_field(canvas, y, "First Seen", assessment.device.first_seen.isoformat())
    y = _draw_field(canvas, y, "Last Seen", assessment.device.last_seen.isoformat())
    y -= 0.16 * inch

    y = _draw_section_heading(canvas, y, "Risk Assessment")
    y -= 0.08 * inch
    y = _draw_risk_box(canvas, y, assessment)
    y -= 0.16 * inch

    findings = _split_into_sentences(assessment.risk_assessment.remediation)

    # 1 + 6: what was found and how risky it is, in one place, using
    # only real values (device IP, QRS score, final category) plus the
    # fixed, category-keyed interpretation sentence — never a new
    # scoring decision.
    y = _draw_section_heading(canvas, y, "Assessment Overview")
    y -= 0.04 * inch
    overview = (
        f"Device {assessment.device.ip} was assessed by {APP_NAME} and received a "
        f"Quantum Risk Score of {assessment.risk_assessment.risk_score}/10, resulting in a "
        f"{assessment.final_category.value} final risk classification. "
        f"{_RISK_INTERPRETATION[assessment.final_category]}"
    )
    y = _draw_paragraph(canvas, y, overview)
    y -= 0.1 * inch

    # 2: each bullet is a verbatim sentence lifted from
    # risk_assessment.remediation — no paraphrasing, no new findings.
    y = _draw_section_heading(canvas, y, "Key Findings")
    y -= 0.04 * inch
    y = _draw_bullet_list(canvas, y, findings)
    y -= 0.08 * inch

    # 3: the lead finding is already phrased as an action (existing
    # remediation sentences are written in imperative voice) — reused
    # verbatim, condensed to just the primary one for Page 1.
    y = _draw_section_heading(canvas, y, "Recommended Action")
    y -= 0.04 * inch
    y = _draw_paragraph(canvas, y, findings[0])
    y -= 0.08 * inch

    # 5: anomaly detail if ML ran for this device, else an explicit
    # "Not available" — never fabricated.
    y = _draw_section_heading(canvas, y, "Anomaly Analysis")
    y -= 0.04 * inch
    y = _draw_anomaly_summary(canvas, y, assessment)
    y -= 0.08 * inch

    # 4: risk_assessment.nist_reference, split back into its individual
    # references and shown directly — nothing added beyond what's there.
    y = _draw_section_heading(canvas, y, "Applicable Guidance")
    y -= 0.04 * inch
    canvas.setFont("Helvetica", 10)
    canvas.setFillColor(_COLOR_TEXT)
    for reference in _split_nist_references(assessment.risk_assessment.nist_reference):
        canvas.drawString(_MARGIN, y, reference)
        y -= 0.18 * inch


def _draw_page_2_technical_findings(
    canvas: Canvas, assessment: DeviceAssessment, metadata: ReportMetadata
) -> None:
    y = _draw_banner(canvas, 2)

    y = _draw_section_heading(canvas, y, "Risk Overview")
    y -= 0.04 * inch
    y = _draw_field(canvas, y, "Risk Score", f"{assessment.risk_assessment.risk_score} / 10")
    y = _draw_field(canvas, y, "Risk Category", assessment.risk_assessment.category.value)
    y -= 0.16 * inch

    y = _draw_section_heading(canvas, y, "Weak Configuration / Finding")
    y -= 0.04 * inch
    y = _draw_card(canvas, y, "Remediation Guidance", assessment.risk_assessment.remediation)
    y -= 0.1 * inch

    y = _draw_section_heading(canvas, y, "NIST Reference")
    y -= 0.04 * inch
    y = _draw_card(canvas, y, "Applicable Standards", assessment.risk_assessment.nist_reference)
    y -= 0.1 * inch

    y = _draw_section_heading(canvas, y, "Isolation Forest Anomaly Analysis")
    y -= 0.04 * inch
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
    y = _draw_banner(canvas, 3)

    y = _draw_section_heading(canvas, y, "Report Identity")
    y -= 0.04 * inch
    y = _draw_field(canvas, y, "Report ID", metadata.report_id)
    y = _draw_field(canvas, y, "Assessment Timestamp", assessment.assessed_at.isoformat())
    y = _draw_field(canvas, y, "Generation Timestamp", metadata.generated_at.isoformat())
    y -= 0.16 * inch

    y = _draw_section_heading(canvas, y, "Report Integrity Hash (SHA-256)")
    y -= 0.04 * inch
    y = _draw_mono_box(canvas, y, metadata.report_hash)
    y -= 0.16 * inch

    y = _draw_section_heading(canvas, y, "Digital Signature")
    y -= 0.04 * inch
    y = _draw_field(canvas, y, "Signing Algorithm", metadata.signing_algorithm)

    canvas.setFont("Helvetica-Bold", 10)
    canvas.setFillColor(_COLOR_SLATE)
    canvas.drawString(_MARGIN, y, "Verification Status:")
    status_text = "Verified" if metadata.verification_status else "Failed"
    _draw_status_badge(canvas, _MARGIN + 1.9 * inch, y - 0.03 * inch, status_text, metadata.verification_status)
    y -= 0.32 * inch

    y = _draw_section_heading(canvas, y, "Signature Preview")
    y -= 0.04 * inch
    preview = metadata.signature_hex[:32] + ("..." if len(metadata.signature_hex) > 32 else "")
    y = _draw_mono_box(canvas, y, preview)
    y -= 0.16 * inch

    note = (
        f"The {metadata.signing_algorithm} signature protects the canonical report "
        "content (report ID, device IP, generation time, and the full signed "
        "device assessment) — not the rendered PDF byte stream. The full "
        "signature is retained in this report's ReportMetadata record."
    )
    _draw_paragraph(canvas, y, note)
