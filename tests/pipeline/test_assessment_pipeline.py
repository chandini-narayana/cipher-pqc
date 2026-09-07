"""Unit tests for pipeline.assessment_pipeline.assess_packet — the
single-observation composition of entropy -> fingerprint -> DeviceFeatures
-> QRS -> optional anomaly detection -> fusion.

These tests exercise orchestration, not the algorithms each stage
already has its own unit tests for (entropy/, fingerprint/, risk/, ml/,
fusion/ each have their own test suites) — see docs/SDD.md's Step 11
addendum.
"""
from __future__ import annotations

import inspect
from dataclasses import fields
from datetime import datetime, timezone
from typing import List, Optional

import pytest

from capture.raw_packet import RawPacket
from ml.classifier import AnomalyDetector
from ml.dataset import generate_synthetic_feature_matrix
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.device_features import DeviceFeatures
from models.enums import RiskCategory
from pipeline.assessment_pipeline import assess_packet

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

_ESCALATE_ONE_LEVEL = {
    RiskCategory.LOW: RiskCategory.MEDIUM,
    RiskCategory.MEDIUM: RiskCategory.HIGH,
    RiskCategory.HIGH: RiskCategory.HIGH,
}


def _raw_packet() -> RawPacket:
    return RawPacket(
        src_ip="192.168.1.10",
        dst_ip="93.184.216.34",
        src_port=51000,
        dst_port=80,
        payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        timestamp=TS,
    )


def _device() -> Device:
    return Device.first_contact("192.168.1.10", TS)


class _StubAnomalyDetector:
    """Minimal stand-in providing only the predict_one contract
    assess_packet actually uses — deliberately has no fit/load/model
    machinery, so any pipeline code path that tried to use more than
    predict_one() would fail loudly."""

    def __init__(
        self,
        is_anomaly: bool,
        anomaly_score: float = 0.7,
        confidence: float = 0.5,
        call_log: Optional[List[str]] = None,
    ) -> None:
        self._is_anomaly = is_anomaly
        self._anomaly_score = anomaly_score
        self._confidence = confidence
        self._call_log = call_log
        self.received_features: List[DeviceFeatures] = []

    def predict_one(self, features: DeviceFeatures) -> AnomalyAssessment:
        self.received_features.append(features)
        if self._call_log is not None:
            self._call_log.append("ml")
        return AnomalyAssessment(
            anomaly_score=self._anomaly_score,
            is_anomaly=self._is_anomaly,
            confidence=self._confidence,
        )


# --- 1. normal orchestration without ML ---


def test_normal_orchestration_without_ml_matches_qrs_category() -> None:
    result = assess_packet(_raw_packet(), _device(), port_risk=0)

    assert isinstance(result, DeviceAssessment)
    assert result.anomaly_assessment is None
    assert result.final_category == result.risk_assessment.category


# --- 2 & 3. fusion behavior wired correctly through the pipeline ---


def test_anomalous_ml_result_escalates_exactly_one_level() -> None:
    baseline = assess_packet(_raw_packet(), _device(), port_risk=0)
    qrs_category = baseline.risk_assessment.category

    result = assess_packet(
        _raw_packet(), _device(), port_risk=0, anomaly_detector=_StubAnomalyDetector(is_anomaly=True)
    )

    assert result.final_category == _ESCALATE_ONE_LEVEL[qrs_category]


def test_non_anomalous_ml_result_keeps_qrs_category() -> None:
    baseline = assess_packet(_raw_packet(), _device(), port_risk=0)
    qrs_category = baseline.risk_assessment.category

    result = assess_packet(
        _raw_packet(), _device(), port_risk=0, anomaly_detector=_StubAnomalyDetector(is_anomaly=False)
    )

    assert result.final_category == qrs_category


# --- 4 & 5. feature integrity: one DeviceFeatures, no leakage ---


def test_same_device_features_object_passed_to_risk_and_ml(monkeypatch) -> None:
    import pipeline.assessment_pipeline as ap

    captured_for_risk: List[DeviceFeatures] = []
    real_evaluate_risk = ap.evaluate_risk

    def spy_evaluate_risk(features: DeviceFeatures, port_risk: int):
        captured_for_risk.append(features)
        return real_evaluate_risk(features, port_risk)

    monkeypatch.setattr(ap, "evaluate_risk", spy_evaluate_risk)

    stub = _StubAnomalyDetector(is_anomaly=False)
    ap.assess_packet(_raw_packet(), _device(), port_risk=0, anomaly_detector=stub)

    assert len(captured_for_risk) == 1
    assert len(stub.received_features) == 1
    assert captured_for_risk[0] is stub.received_features[0]


def test_device_features_schema_has_no_risk_derived_fields() -> None:
    """Static contract check: DeviceFeatures (what both evaluate_risk and
    predict_one consume) carries only raw observation data — never a
    RiskAssessment, risk_score, or category — so there is structurally
    no channel for QRS output to leak into the ML feature vector."""
    field_names = {f.name for f in fields(DeviceFeatures)}
    assert field_names == {"device", "packet", "fingerprint", "entropy"}


# --- 6 & 7. device and assessed_at preserved ---


def test_device_is_preserved_in_final_assessment() -> None:
    device = _device()
    result = assess_packet(_raw_packet(), device, port_risk=0)
    assert result.device == device


def test_explicit_assessed_at_is_preserved() -> None:
    explicit_ts = datetime(2027, 6, 15, 8, 30, 0, tzinfo=timezone.utc)
    result = assess_packet(_raw_packet(), _device(), port_risk=0, assessed_at=explicit_ts)
    assert result.assessed_at == explicit_ts


# --- 8. default assessed_at, via fusion's own existing behavior ---


def test_default_assessed_at_is_timezone_aware_utc() -> None:
    before = datetime.now(timezone.utc)
    result = assess_packet(_raw_packet(), _device(), port_risk=0)
    after = datetime.now(timezone.utc)

    assert result.assessed_at.tzinfo is not None
    assert result.assessed_at.utcoffset() == timezone.utc.utcoffset(None)
    assert before <= result.assessed_at <= after
    # Not silently substituted with the packet's own (2026-01-01) observation time.
    assert result.assessed_at != _raw_packet().timestamp


# --- 9. determinism with fixed inputs and an explicit assessed_at ---


def test_deterministic_with_fixed_inputs_and_explicit_assessed_at() -> None:
    detector = AnomalyDetector(random_state=42)
    detector.fit(generate_synthetic_feature_matrix())

    first = assess_packet(_raw_packet(), _device(), port_risk=1, anomaly_detector=detector, assessed_at=TS)
    second = assess_packet(_raw_packet(), _device(), port_risk=1, anomaly_detector=detector, assessed_at=TS)

    assert first == second


# --- 10. no input mutation ---


def test_raw_packet_and_device_are_not_mutated() -> None:
    raw_packet = _raw_packet()
    device = _device()
    raw_packet_copy = RawPacket(
        src_ip=raw_packet.src_ip,
        dst_ip=raw_packet.dst_ip,
        src_port=raw_packet.src_port,
        dst_port=raw_packet.dst_port,
        payload=raw_packet.payload,
        timestamp=raw_packet.timestamp,
    )
    device_copy = Device(ip=device.ip, first_seen=device.first_seen, last_seen=device.last_seen)

    assess_packet(raw_packet, device, port_risk=0, anomaly_detector=_StubAnomalyDetector(is_anomaly=True))

    assert raw_packet == raw_packet_copy
    assert device == device_copy


# --- 11. existing errors propagate untouched ---


def test_invalid_port_risk_propagates_value_error() -> None:
    with pytest.raises(ValueError, match="port_risk"):
        assess_packet(_raw_packet(), _device(), port_risk=-1)


def test_unfitted_detector_propagates_runtime_error() -> None:
    unfitted = AnomalyDetector()
    with pytest.raises(RuntimeError, match="fit"):
        assess_packet(_raw_packet(), _device(), port_risk=0, anomaly_detector=unfitted)


# --- 12. never trains or loads a model itself ---


def test_pipeline_source_never_constructs_a_detector_itself() -> None:
    import pipeline.assessment_pipeline as ap

    source = inspect.getsource(ap)
    assert "AnomalyDetector(" not in source


def test_never_fits_or_loads_a_model_at_runtime(monkeypatch) -> None:
    def _forbidden(*args, **kwargs):
        raise AssertionError("assess_packet must not fit/load/train a model")

    monkeypatch.setattr(AnomalyDetector, "fit", _forbidden)
    monkeypatch.setattr(AnomalyDetector, "load", _forbidden)
    monkeypatch.setattr("ml.dataset.generate_synthetic_feature_matrix", _forbidden)

    assess_packet(_raw_packet(), _device(), port_risk=0)
    assess_packet(_raw_packet(), _device(), port_risk=0, anomaly_detector=_StubAnomalyDetector(False))


# --- 13. static dependency check: no frontend/reporting/signing/training ---


def test_no_frontend_reporting_signing_or_training_dependency() -> None:
    import ast

    import pipeline.assessment_pipeline as ap

    tree = ast.parse(inspect.getsource(ap))
    top_level_modules = set()
    full_module_paths = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level_modules.add(alias.name.split(".")[0])
                full_module_paths.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_level_modules.add(node.module.split(".")[0])
            full_module_paths.add(node.module)

    forbidden_top_level = {"dashboard", "reports", "signing", "flask", "frontend"}
    forbidden_exact = {"ml.dataset", "ml.train"}

    assert not (top_level_modules & forbidden_top_level)
    assert not (full_module_paths & forbidden_exact)


# --- 14. no registry or aggregation introduced ---


def test_no_registry_or_runner_dependency() -> None:
    import ast

    import pipeline.assessment_pipeline as ap

    tree = ast.parse(inspect.getsource(ap))
    full_module_paths = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            full_module_paths.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            full_module_paths.add(node.module)

    assert "utils.registry" not in full_module_paths
    assert "pipeline.runner" not in full_module_paths


def test_pipeline_is_stateless_across_independent_calls() -> None:
    """Two independent observations must not influence each other —
    there is no accumulating registry or shared state between calls."""
    device_a = Device.first_contact("10.0.0.5", TS)
    device_b = Device.first_contact("10.0.0.6", TS)

    result_a1 = assess_packet(_raw_packet(), device_a, port_risk=0)
    assess_packet(_raw_packet(), device_b, port_risk=2, anomaly_detector=_StubAnomalyDetector(True))
    result_a2 = assess_packet(_raw_packet(), device_a, port_risk=0)

    assert result_a1 == result_a2
