"""assess_packet — the single-observation assessment composition function.

Wires the already-implemented per-stage modules into one deterministic
sequence for a single captured packet:

    RawPacket.payload -> compute_entropy_metrics -> EntropyMetrics
    RawPacket.payload -> fingerprint_packet       -> ProtocolFingerprint
    RawPacket.to_metadata()                       -> PacketMetadata
    Device + PacketMetadata + ProtocolFingerprint + EntropyMetrics
                                                   -> DeviceFeatures
    DeviceFeatures + port_risk -> evaluate_risk   -> RiskAssessment
    DeviceFeatures (if anomaly_detector given)    -> AnomalyAssessment | None
    RiskAssessment + AnomalyAssessment(?) + Device + assessed_at
                                  -> fuse_assessments -> DeviceAssessment

This module composes existing modules only — it contains no entropy,
fingerprinting, scoring, ML, or fusion logic of its own, and does not
modify any of it.

Deliberately stateless and single-observation: it does not identify
devices (a `Device` is a required, externally-supplied argument — see
models/device.py and docs/SDD.md's Step 11 addendum for why this isn't
derived from RawPacket.src_ip/dst_ip here), does not derive `port_risk`
(also externally supplied — see risk/scoring.py's own docstring on why
no protocol-to-port-risk mapping is approved yet), and does not
aggregate observations across packets or devices (no DeviceRegistry —
that remains a later step). It also never constructs, fits, loads, or
falls back to a substitute `AnomalyDetector`: `anomaly_detector=None`
means ML is simply unavailable for this observation, and that `None`
is passed straight through to fusion, which already defines that
exact behavior.

`pipeline.runner.Pipeline` (not implemented yet) remains reserved for
the later runtime driver that will iterate a CaptureSource and call
this function once per packet; this module has no loop, no thread, no
capture source, and no registry.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from capture.raw_packet import RawPacket
from entropy.engine import compute_entropy_metrics
from fingerprint.protocol import fingerprint_packet
from fusion.risk_fusion import fuse_assessments
from ml.classifier import AnomalyDetector
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.device_features import DeviceFeatures
from risk.engine import evaluate_risk


def assess_packet(
    raw_packet: RawPacket,
    device: Device,
    port_risk: int,
    anomaly_detector: Optional[AnomalyDetector] = None,
    assessed_at: Optional[datetime] = None,
) -> DeviceAssessment:
    """Run one captured packet through entropy, fingerprinting, QRS,
    optional anomaly detection, and fusion, producing the final
    DeviceAssessment for that single observation.

    `device` and `port_risk` are required, externally-supplied inputs
    (see module docstring — neither is derived here). `anomaly_detector`
    is optional and dependency-injected: when None, ML is unavailable
    for this observation and `fuse_assessments` receives
    anomaly_assessment=None, preserving the QRS category unchanged.
    `assessed_at` is the assessment's execution time, passed through to
    fuse_assessments unchanged (its own default applies when None) —
    not automatically substituted with the packet's observation time.

    Raises:
        Propagates whatever entropy.compute_entropy_metrics,
        fingerprint.fingerprint_packet, risk.evaluate_risk,
        anomaly_detector.predict_one, or fusion.fuse_assessments raise —
        no error is caught or re-wrapped here.
    """
    entropy_metrics = compute_entropy_metrics(raw_packet.payload)
    fingerprint = fingerprint_packet(raw_packet.payload)
    packet_metadata = raw_packet.to_metadata()

    features = DeviceFeatures(
        device=device,
        packet=packet_metadata,
        fingerprint=fingerprint,
        entropy=entropy_metrics,
    )

    risk_assessment = evaluate_risk(features, port_risk)

    anomaly_assessment = (
        anomaly_detector.predict_one(features) if anomaly_detector is not None else None
    )

    return fuse_assessments(
        risk_assessment=risk_assessment,
        anomaly_assessment=anomaly_assessment,
        device=device,
        assessed_at=assessed_at,
    )
