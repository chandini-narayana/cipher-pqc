"""run_capture — the synchronous, single-pass offline runtime orchestrator.

Wires together the already-implemented per-stage components into one
end-to-end run over a CaptureSource:

    CaptureSource.read_packets()
        -> for each RawPacket:
             resolve/update the observed device (local, in-run state only)
             fingerprint_packet(payload) -> port_risk_for_protocol(...)
             assess_packet(...) -> DeviceAssessment
             retain the strongest representative DeviceAssessment per device
        -> after EOF, for each retained MEDIUM/HIGH device:
             generate_report(...) -> one PDF

No new algorithm lives here — entropy, fingerprinting, QRS, Isolation
Forest, fusion, signing, and PDF generation are all unchanged, existing
modules. This module only sequences already-tested calls to them and
holds the small amount of per-run state needed to do so.

Deliberately synchronous, no thread, no background lifecycle: Phase 11
is offline-only (see docs/SDD.md's Phase 11 addendum) — there is no
live capture and no dashboard running concurrently that would justify
a `start()`/`stop()` background-thread design. `KeyboardInterrupt` and
`SystemExit` are never caught here (only `Exception` is), so they are
never silently suppressed.

Phase-1 device-identity convention (frozen, NOT specified by the
Execution Report — see docs/SDD.md's Phase 11 addendum): the observed
device is identified by `RawPacket.src_ip`. No subnet inference, no MAC
discovery, no src/dst heuristics, no vendor lookup, no network-direction
analysis. State is a small local dict, held only for the duration of
one `run_capture()` call — this is explicitly not `DeviceRegistry`
(utils/registry.py remains an unimplemented stub; no persistence, no
locking, no query API, no cross-run history).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from fingerprint.protocol import fingerprint_packet
from ml.classifier import AnomalyDetector
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from pipeline.assessment_pipeline import assess_packet
from reports.pdf_generator import DEFAULT_REPORT_OUTPUT_DIR, generate_report, is_flagged_device
from risk.port_risk import port_risk_for_protocol

logger = logging.getLogger(__name__)

_CATEGORY_RANK = {
    RiskCategory.LOW: 0,
    RiskCategory.MEDIUM: 1,
    RiskCategory.HIGH: 2,
}


def run_capture(
    capture_source: CaptureSource,
    anomaly_detector: Optional[AnomalyDetector],
    public_key: bytes,
    secret_key: bytes,
    report_output_dir: Union[str, Path] = DEFAULT_REPORT_OUTPUT_DIR,
) -> Tuple[List[DeviceAssessment], List[Path]]:
    """Run one full pass over `capture_source` and generate reports for
    every device whose final, retained assessment is flagged.

    `anomaly_detector` (already loaded once by the caller, or `None` if
    unavailable — never loaded here), `public_key`/`secret_key` (already
    loaded/created once by the caller) are injected, not acquired by
    this function.

    Exactly one retained DeviceAssessment is kept per observed device
    (keyed by `RawPacket.src_ip`) across the whole run — the strongest
    one, per the frozen representative-selection rule (see
    `_is_stronger`). A device with multiple flagged packets still
    produces exactly one PDF; a device that is never flagged produces
    none.

    Per-packet and per-report-generation failures are isolated: one bad
    packet or one failed report is logged at ERROR and skipped, and the
    run continues. `KeyboardInterrupt`/`SystemExit` are never caught
    here and always propagate.

    Returns:
        (retained_assessments, report_paths) — one assessment per
        observed device (in first-seen order), and the path of every
        PDF actually written.
    """
    devices: Dict[str, Device] = {}
    representatives: Dict[str, DeviceAssessment] = {}

    for raw_packet in capture_source.read_packets():
        try:
            _process_packet(raw_packet, devices, representatives, anomaly_detector)
        except Exception:  # noqa: BLE001 - one bad packet must not abort the run
            logger.error(
                "Failed to process packet from %s:%s -> %s:%s; skipping.",
                raw_packet.src_ip,
                raw_packet.src_port,
                raw_packet.dst_ip,
                raw_packet.dst_port,
                exc_info=True,
            )

    report_paths: List[Path] = []
    for ip, assessment in representatives.items():
        if not is_flagged_device(assessment):
            continue
        try:
            path, _metadata = generate_report(
                assessment, secret_key, public_key, output_dir=report_output_dir
            )
            report_paths.append(path)
        except Exception:  # noqa: BLE001 - one failed report must not abort the rest
            logger.error("Failed to generate report for device %s; skipping.", ip, exc_info=True)

    return list(representatives.values()), report_paths


def _process_packet(
    raw_packet: RawPacket,
    devices: Dict[str, Device],
    representatives: Dict[str, DeviceAssessment],
    anomaly_detector: Optional[AnomalyDetector],
) -> None:
    device = _resolve_device(raw_packet, devices)

    fingerprint = fingerprint_packet(raw_packet.payload)
    port_risk = port_risk_for_protocol(fingerprint.protocol)

    assessment = assess_packet(raw_packet, device, port_risk, anomaly_detector)

    _update_representative(representatives, device.ip, assessment)


def _resolve_device(raw_packet: RawPacket, devices: Dict[str, Device]) -> Device:
    """Phase-1 device resolution: RawPacket.src_ip identifies the
    device. First contact establishes first_seen; a later packet only
    ever advances last_seen forward, never backwards for an
    out-of-order packet."""
    ip = raw_packet.src_ip
    existing = devices.get(ip)

    if existing is None:
        device = Device.first_contact(ip, raw_packet.timestamp)
    elif raw_packet.timestamp > existing.last_seen:
        device = existing.with_last_seen(raw_packet.timestamp)
    else:
        device = existing

    devices[ip] = device
    return device


def _update_representative(
    representatives: Dict[str, DeviceAssessment], ip: str, candidate: DeviceAssessment
) -> None:
    """Retain the strongest DeviceAssessment seen so far for `ip`, per
    the frozen runtime representative-selection rule. This is a
    runtime selection policy only — it does not change QRS, Isolation
    Forest, or Risk Fusion."""
    current = representatives.get(ip)
    if current is None or _is_stronger(candidate, current):
        representatives[ip] = candidate


def _is_stronger(candidate: DeviceAssessment, current: DeviceAssessment) -> bool:
    """1) higher final_category wins; 2) tie -> higher risk_score wins;
    3) tie -> later assessed_at wins."""
    candidate_rank = _CATEGORY_RANK[candidate.final_category]
    current_rank = _CATEGORY_RANK[current.final_category]
    if candidate_rank != current_rank:
        return candidate_rank > current_rank

    if candidate.risk_assessment.risk_score != current.risk_assessment.risk_score:
        return candidate.risk_assessment.risk_score > current.risk_assessment.risk_score

    return candidate.assessed_at > current.assessed_at
