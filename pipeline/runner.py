"""run_capture — the synchronous, single-pass offline runtime orchestrator.

Wires together the already-implemented per-stage components into one
end-to-end run over a CaptureSource:

    CaptureSource.read_packets()
        -> for each RawPacket:
             resolve/update the observed device (local, in-run state only)
             fingerprint_packet(payload) -> port_risk_for_protocol(...)
             assess_packet(...) -> DeviceAssessment
             should_isolate(...) -> isolation_backend.isolate(...) if eligible
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

Phase 14 enforcement timing (see docs/SDD.md's Phase 14 addendum):
`should_isolate()` is evaluated immediately after each individual
`assess_packet()` call — never deferred to end-of-capture representative
selection, which is a reporting concern with a different (and looser)
timing requirement than the Execution Report's detection-to-isolation
target. `isolation_backend` is injected by the caller (main.py /
run_api.py); this module never constructs a hardware backend itself.

`assessment_observer` (Phase 3F, optional and None by default) is a
purely passive hook: each freshly-produced DeviceAssessment is handed to
it after representative selection, its return value is discarded, and any
exception it raises is logged and swallowed. It exists so the Raspberry
Pi status display can show live progress; it can neither change nor
delay an assessment, an isolation decision or a report, and with no
observer supplied this module behaves exactly as before.

Phase 3B isolation-state propagation (see docs/SDD.md's Phase 3B
addendum): each isolation attempt's `IsolationOutcome` is recorded per
device IP for the duration of the run and, after EOF but *before* report
generation, attached to that device's retained representative assessment
as `DeviceAssessment.isolation`. That is the single seam by which
enforcement state reaches the REST API, the dashboard and the signed
PDF. Tracking it per device rather than per packet is deliberate and
load-bearing — see `_attach_isolation_state`.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from config.constants import DEFAULT_RISK_ISOLATION_THRESHOLD
from enforcement.backends import IsolationBackend
from enforcement.decision import should_isolate
from fingerprint.protocol import fingerprint_packet
from ml.classifier import AnomalyDetector
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.isolation_status import IsolationStatus
from models.report_metadata import ReportMetadata
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
    isolation_backend: IsolationBackend,
    risk_isolation_threshold: int = DEFAULT_RISK_ISOLATION_THRESHOLD,
    report_output_dir: Union[str, Path] = DEFAULT_REPORT_OUTPUT_DIR,
    assessment_observer: Optional[Callable[[DeviceAssessment], None]] = None,
) -> Tuple[List[DeviceAssessment], List[Tuple[Path, ReportMetadata]]]:
    """Run one full pass over `capture_source`, isolating (per
    `isolation_backend`) every device whose raw QRS reaches
    `risk_isolation_threshold` as soon as it's observed, and generating
    reports for every device whose final, retained assessment is flagged.

    `anomaly_detector` (already loaded once by the caller, or `None` if
    unavailable — never loaded here), `public_key`/`secret_key` (already
    loaded/created once by the caller), and `isolation_backend` (never
    constructed here — see module docstring) are injected, not acquired
    by this function.

    Isolation eligibility is `assessment.risk_assessment.risk_score >=
    risk_isolation_threshold` — the raw QRS score, never
    `final_category` (see enforcement/decision.py's should_isolate for
    why: an ML-only escalation to HIGH must not trigger physical
    isolation). Each device is isolated at most once per run, the first
    time it becomes eligible, regardless of how many further high-risk
    packets it produces afterward.

    Exactly one retained DeviceAssessment is kept per observed device
    (keyed by `RawPacket.src_ip`) across the whole run — the strongest
    one, per the frozen representative-selection rule (see
    `_is_stronger`). A device with multiple flagged packets still
    produces exactly one PDF; a device that is never flagged produces
    none. This representative-selection/reporting behavior is
    unaffected by isolation — enforcement acts on each individual
    assessment as it's produced, not on the eventual representative.

    Per-packet, per-isolation-attempt, and per-report-generation
    failures are isolated: one bad packet, one failed isolation
    attempt, or one failed report is logged at ERROR and skipped, and
    the run continues. `KeyboardInterrupt`/`SystemExit` are never
    caught here and always propagate.

    Returns:
        (retained_assessments, reports) — one assessment per observed
        device (in first-seen order), and one (path, ReportMetadata)
        pair for every PDF actually written. Every returned assessment for a
        device that was handed to the backend carries that attempt's
        `isolation` state; every other assessment carries `None`.
        Phase 12's REST API needs
        the ReportMetadata that Phase 11 previously discarded; this is
        the smallest change that retains it — no scoring, ML, signing,
        or reporting behavior is altered.
    """
    devices: Dict[str, Device] = {}
    representatives: Dict[str, DeviceAssessment] = {}
    enforcement_attempted_ips: Set[str] = set()
    isolation_by_ip: Dict[str, IsolationStatus] = {}

    for raw_packet in capture_source.read_packets():
        try:
            _process_packet(
                raw_packet,
                devices,
                representatives,
                anomaly_detector,
                isolation_backend,
                risk_isolation_threshold,
                enforcement_attempted_ips,
                isolation_by_ip,
                assessment_observer,
            )
        except Exception:  # noqa: BLE001 - one bad packet must not abort the run
            logger.error(
                "Failed to process packet from %s:%s -> %s:%s; skipping.",
                raw_packet.src_ip,
                raw_packet.src_port,
                raw_packet.dst_ip,
                raw_packet.dst_port,
                exc_info=True,
            )

    _attach_isolation_state(representatives, isolation_by_ip)

    reports: List[Tuple[Path, ReportMetadata]] = []
    for ip, assessment in representatives.items():
        if not is_flagged_device(assessment):
            continue
        try:
            path, metadata = generate_report(
                assessment, secret_key, public_key, output_dir=report_output_dir
            )
            reports.append((path, metadata))
        except Exception:  # noqa: BLE001 - one failed report must not abort the rest
            logger.error("Failed to generate report for device %s; skipping.", ip, exc_info=True)

    return list(representatives.values()), reports


def _process_packet(
    raw_packet: RawPacket,
    devices: Dict[str, Device],
    representatives: Dict[str, DeviceAssessment],
    anomaly_detector: Optional[AnomalyDetector],
    isolation_backend: IsolationBackend,
    risk_isolation_threshold: int,
    enforcement_attempted_ips: Set[str],
    isolation_by_ip: Dict[str, IsolationStatus],
    assessment_observer: Optional[Callable[[DeviceAssessment], None]] = None,
) -> None:
    device = _resolve_device(raw_packet, devices)

    fingerprint = fingerprint_packet(raw_packet.payload)
    port_risk = port_risk_for_protocol(fingerprint.protocol)

    assessment = assess_packet(raw_packet, device, port_risk, anomaly_detector)

    _maybe_enforce_isolation(
        assessment,
        isolation_backend,
        risk_isolation_threshold,
        enforcement_attempted_ips,
        isolation_by_ip,
    )

    _update_representative(representatives, device.ip, assessment)

    _notify_observer(assessment_observer, assessment)


def _maybe_enforce_isolation(
    assessment: DeviceAssessment,
    isolation_backend: IsolationBackend,
    threshold: int,
    enforcement_attempted_ips: Set[str],
    isolation_by_ip: Dict[str, IsolationStatus],
) -> None:
    """Isolate `assessment`'s device if it just became eligible — at
    most once per device per run. Marking the device as attempted
    happens before calling the backend, so a raising/failing attempt
    still counts as "the one attempt" (no retries) and never blocks
    this packet's assessment from still being considered for
    representative selection/reporting.

    The resulting IsolationStatus is recorded in `isolation_by_ip` (per
    device, not per packet) and attached to the retained representative
    after EOF by `_attach_isolation_state`. A backend that raises records
    nothing — the failure is logged, and no isolation state is fabricated
    for that device: the attempt is recorded as requested-but-not-enforced
    with the exception as its reason, and `enforced` is never
    synthesized as True."""
    ip = assessment.device.ip
    if ip in enforcement_attempted_ips:
        return
    if not should_isolate(assessment, threshold):
        return

    enforcement_attempted_ips.add(ip)
    risk_score = assessment.risk_assessment.risk_score

    try:
        outcome = isolation_backend.isolate(ip, risk_score)
    except Exception as exc:  # noqa: BLE001 - one failed isolation attempt must not abort the run
        logger.error(
            "Isolation backend raised while handling device %s (QRS=%d, threshold=%d); "
            "continuing.",
            ip,
            risk_score,
            threshold,
            exc_info=True,
        )
        # A raising backend produced no outcome of its own, so the
        # attempt is recorded here as the failure it was: requested, not
        # enforced, with the exception as the reason. `enforced` is never
        # synthesized as True — the only thing this fabricates is an
        # honest record that an attempt was made and failed.
        isolation_by_ip[ip] = IsolationStatus(
            requested=True,
            enforced=False,
            backend=isolation_backend.backend_name,
            reason=f"Isolation backend raised: {exc}",
            requested_at=datetime.now(timezone.utc),
            enforcement_capable=isolation_backend.enforcement_capable,
        )
        return

    isolation_by_ip[ip] = outcome.to_status()

    logger.info(
        "Isolation decision for device %s: QRS=%d, threshold=%d, requested=%s, "
        "enforced=%s, reason=%s",
        ip,
        risk_score,
        threshold,
        outcome.requested,
        outcome.enforced,
        outcome.reason,
    )


def _notify_observer(
    observer: Optional[Callable[[DeviceAssessment], None]], assessment: DeviceAssessment
) -> None:
    """Hand a freshly-produced assessment to an optional, purely passive
    observer — currently the Raspberry Pi status display.

    Deliberately shaped so it cannot affect anything: the observer gets a
    read-only view of an already-final assessment, its return value is
    discarded, and any exception it raises is logged and swallowed here. An
    output device that misbehaves must never cost a packet, an isolation
    decision or a report. There is no observer by default, so every
    existing caller's behavior is bit-for-bit unchanged.
    """
    if observer is None:
        return
    try:
        observer(assessment)
    except Exception:  # noqa: BLE001 - an output device is never allowed to break the run
        logger.warning(
            "Assessment observer failed for device %s; continuing.",
            assessment.device.ip,
            exc_info=True,
        )


def _attach_isolation_state(
    representatives: Dict[str, DeviceAssessment],
    isolation_by_ip: Dict[str, IsolationStatus],
) -> None:
    """Stamp each device's recorded IsolationStatus onto that device's
    retained representative assessment, in place.

    Why isolation is tracked per *device* and only attached at the end,
    rather than being set on the one assessment that triggered it: an
    isolation attempt is a device-level runtime event, while a
    representative is re-selected packet by packet. A later packet from
    the same device can legitimately displace the triggering assessment
    (`_is_stronger` breaks a category+score tie on the later
    `assessed_at` — and repeated identical high-risk packets tie exactly
    that way), so an outcome attached to a single packet's assessment
    would be silently dropped the moment that happened. Recording per IP
    and attaching after EOF makes that loss impossible, regardless of
    how many packets a device produces or in what order.

    Runs *before* the report-generation loop, so the enforcement result
    is rendered into the PDF and covered by its signature. Per-run local
    state only — no registry, no persistence, no database.
    """
    for ip, isolation in isolation_by_ip.items():
        representative = representatives.get(ip)
        if representative is None:
            # Defensive only: a device cannot be isolated without having
            # produced an assessment. Never fabricate a representative.
            logger.warning(
                "Isolation was recorded for device %s but no retained assessment "
                "exists for it; isolation state not attached.",
                ip,
            )
            continue
        representatives[ip] = representative.with_isolation(isolation)


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
