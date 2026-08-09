"""ReportMetadata — metadata describing one generated PDF report.

Populated by reports/ (not implemented in this step) after it renders
a PDF; contains no PDF-generation logic itself. Deliberately flat
(signature fields inlined rather than nesting a full SignedEvent) so
this stays a lightweight, independently-usable record for the REST
API and audit lookups, rather than requiring the full assessment
object graph just to check a report's provenance.

`page_count` is validated against the frozen 3-page report structure
(docs/SDD.md addendum) — this is the one place that architectural
limit is encoded as an enforced invariant rather than just a comment.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict

from models._validation import validate_hex, validate_ip, validate_non_empty, validate_range


@dataclass(frozen=True, slots=True)
class ReportMetadata:
    """Metadata for one generated per-device PDF report.

    Raises:
        ValueError: if `report_id` is empty, `device_ip` is not a
            valid IP, `page_count` is outside [1, 3] (the frozen
            report-length limit), `report_hash`/`signature_hex` are
            not valid hexadecimal, or `signing_algorithm` is empty.
    """

    report_id: str
    device_ip: str
    generated_at: datetime
    page_count: int
    report_hash: str
    signature_hex: str
    signing_algorithm: str
    verification_status: bool

    def __post_init__(self) -> None:
        validate_non_empty("report_id", self.report_id)
        validate_ip("device_ip", self.device_ip)
        validate_range("page_count", self.page_count, 1, 3)
        validate_hex("report_hash", self.report_hash)
        validate_hex("signature_hex", self.signature_hex)
        validate_non_empty("signing_algorithm", self.signing_algorithm)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "device_ip": self.device_ip,
            "generated_at": self.generated_at.isoformat(),
            "page_count": self.page_count,
            "report_hash": self.report_hash,
            "signature_hex": self.signature_hex,
            "signing_algorithm": self.signing_algorithm,
            "verification_status": self.verification_status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReportMetadata":
        return cls(
            report_id=data["report_id"],
            device_ip=data["device_ip"],
            generated_at=datetime.fromisoformat(data["generated_at"]),
            page_count=data["page_count"],
            report_hash=data["report_hash"],
            signature_hex=data["signature_hex"],
            signing_algorithm=data["signing_algorithm"],
            verification_status=data["verification_status"],
        )