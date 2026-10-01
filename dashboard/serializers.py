"""Explicit REST DTO serializers — plain functions, no Marshmallow/Pydantic.

Each function builds a deliberate, stable JSON shape from an
already-computed domain object. This is the seam that keeps the
frontend decoupled from models/'s internal field names/nesting (see
docs/SDD.md's Phase 12 addendum): a future change to
DeviceAssessment.to_dict() does not silently reshape the REST
contract, because these functions are not that method.

No business logic here — no scoring, no ML, no signing, no
recomputation of anything. Every value below is read directly off an
already-produced DeviceAssessment/ReportMetadata.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from models.anomaly_assessment import AnomalyAssessment
from models.device_assessment import DeviceAssessment
from models.isolation_status import NOT_REQUESTED, IsolationStatus
from models.report_metadata import ReportMetadata

_SIGNATURE_PREVIEW_LENGTH = 32


def _serialize_anomaly(anomaly: Optional[AnomalyAssessment]) -> Optional[Dict[str, Any]]:
    if anomaly is None:
        return None
    return {
        "is_anomaly": anomaly.is_anomaly,
        "anomaly_score": anomaly.anomaly_score,
        "confidence": anomaly.confidence,
    }


def _serialize_isolation(isolation: Optional[IsolationStatus]) -> Dict[str, Any]:
    """The `isolation` sub-object, always present so the frontend never
    has to branch on a missing key.

    `requested=False` with a null backend/reason/timestamp is how "this
    device was never isolation-eligible" is reported — the absence of an
    IsolationStatus, not an absent field. `status` is the compact display
    label, derived once here from the model rather than re-derived by
    each client; `enforcement_capable` is included so a client can see
    *why* an attempt did not enforce without parsing prose.

    Note what is NOT here: nothing in this function knows the isolation
    threshold, the QRS, or any backend name. dashboard/ never imports
    enforcement/ — it reads an already-decided result, like every other
    value in this module.
    """
    if isolation is None:
        return {
            "requested": False,
            "enforced": False,
            "backend": None,
            "reason": None,
            "requested_at": None,
            "enforcement_capable": False,
            "status": NOT_REQUESTED,
        }
    return {
        "requested": isolation.requested,
        "enforced": isolation.enforced,
        "backend": isolation.backend,
        "reason": isolation.reason,
        "requested_at": isolation.requested_at.isoformat(),
        "enforcement_capable": isolation.enforcement_capable,
        "status": isolation.status_label,
    }


def serialize_device_summary(assessment: DeviceAssessment, has_report: bool) -> Dict[str, Any]:
    """The `/api/devices` list-item shape (docs/SDD.md's Phase 12 addendum)."""
    return {
        "device_ip": assessment.device.ip,
        "first_seen": assessment.device.first_seen.isoformat(),
        "last_seen": assessment.device.last_seen.isoformat(),
        "final_category": assessment.final_category.value,
        "risk_score": assessment.risk_assessment.risk_score,
        "risk_category": assessment.risk_assessment.category.value,
        "anomaly": _serialize_anomaly(assessment.anomaly_assessment),
        "assessed_at": assessment.assessed_at.isoformat(),
        "has_report": has_report,
        "isolation": _serialize_isolation(assessment.isolation),
    }


def serialize_device_detail(assessment: DeviceAssessment, has_report: bool) -> Dict[str, Any]:
    """The `/api/devices/<ip>` shape: the summary plus remediation text."""
    detail = serialize_device_summary(assessment, has_report)
    detail["remediation"] = assessment.risk_assessment.remediation
    detail["nist_reference"] = assessment.risk_assessment.nist_reference
    return detail


def serialize_report_metadata(metadata: ReportMetadata, download_url: str) -> Dict[str, Any]:
    """The `/api/devices/<ip>/report` shape. Never includes the full,
    multi-thousand-character signature_hex — only a short preview. The
    complete cryptographic evidence remains in the generated PDF and in
    ReportMetadata itself (not exposed verbatim over REST)."""
    signature_hex = metadata.signature_hex
    preview = signature_hex[:_SIGNATURE_PREVIEW_LENGTH]
    if len(signature_hex) > _SIGNATURE_PREVIEW_LENGTH:
        preview += "..."

    return {
        "report_id": metadata.report_id,
        "device_ip": metadata.device_ip,
        "generated_at": metadata.generated_at.isoformat(),
        "page_count": metadata.page_count,
        "report_hash": metadata.report_hash,
        "signature_preview": preview,
        "signing_algorithm": metadata.signing_algorithm,
        "verification_status": metadata.verification_status,
        "download_url": download_url,
    }
