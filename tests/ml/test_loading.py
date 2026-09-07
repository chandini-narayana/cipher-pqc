"""Unit tests for ml.loading.load_anomaly_detector — the approved
fail-open-for-ML runtime loading policy (docs/SDD.md Step 12A addendum):
present -> load; missing -> warn + None; corrupt/incompatible -> the
genuine loading error propagates, never silently downgraded to None.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

import joblib
import pytest

from ml.classifier import AnomalyDetector
from ml.dataset import generate_synthetic_feature_matrix
from ml.loading import load_anomaly_detector
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_features import DeviceFeatures
from models.entropy_metrics import EntropyMetrics
from models.enums import ProtocolType, TLSVersion
from models.packet_metadata import PacketMetadata
from models.protocol_fingerprint import ProtocolFingerprint

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _device_features() -> DeviceFeatures:
    return DeviceFeatures(
        device=Device.first_contact("192.168.1.10", TS),
        packet=PacketMetadata(
            src_ip="192.168.1.10", dst_ip="192.168.1.1", src_port=51000,
            dst_port=443, packet_size=800, timestamp=TS,
        ),
        fingerprint=ProtocolFingerprint(
            protocol=ProtocolType.HTTPS, tls_version=TLSVersion.TLS_1_3,
            key_size=3072, forward_secrecy=True,
        ),
        entropy=EntropyMetrics(shannon_entropy=7.8, sample_size=800),
    )


def _fitted_detector() -> AnomalyDetector:
    detector = AnomalyDetector()
    detector.fit(generate_synthetic_feature_matrix())
    return detector


# --- valid artifact ---


def test_valid_artifact_loads_successfully(tmp_path) -> None:
    saved = _fitted_detector()
    path = tmp_path / "anomaly_detector.joblib"
    saved.save(path)

    loaded = load_anomaly_detector(path)

    assert isinstance(loaded, AnomalyDetector)
    assert loaded.is_fitted is True


def test_loaded_detector_remains_usable_for_predict_one(tmp_path) -> None:
    saved = _fitted_detector()
    path = tmp_path / "anomaly_detector.joblib"
    saved.save(path)

    loaded = load_anomaly_detector(path)
    result = loaded.predict_one(_device_features())

    assert isinstance(result, AnomalyAssessment)


# --- missing artifact: fail-open ---


def test_missing_artifact_returns_none(tmp_path) -> None:
    missing_path = tmp_path / "does_not_exist.joblib"
    assert load_anomaly_detector(missing_path) is None


def test_missing_artifact_emits_exactly_one_warning(tmp_path, caplog) -> None:
    missing_path = tmp_path / "does_not_exist.joblib"

    with caplog.at_level(logging.WARNING, logger="ml.loading"):
        load_anomaly_detector(missing_path)

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert str(missing_path) in warnings[0].getMessage()


def test_missing_artifact_never_trains_or_generates_synthetic_data(tmp_path, monkeypatch) -> None:
    def _forbidden(*args, **kwargs):
        raise AssertionError("must not train/generate data for a missing artifact")

    monkeypatch.setattr(AnomalyDetector, "fit", _forbidden)
    monkeypatch.setattr("ml.dataset.generate_synthetic_feature_matrix", _forbidden)

    missing_path = tmp_path / "does_not_exist.joblib"
    assert load_anomaly_detector(missing_path) is None


# --- corrupt / incompatible artifact: never downgraded to None ---


def test_corrupt_artifact_propagates_error_not_none(tmp_path) -> None:
    corrupt_path = tmp_path / "corrupt.joblib"
    corrupt_path.write_bytes(b"not a valid joblib or pickle stream at all")

    with pytest.raises(Exception):
        load_anomaly_detector(corrupt_path)


def test_wrong_object_type_propagates_existing_type_error(tmp_path) -> None:
    wrong_path = tmp_path / "not_a_detector.joblib"
    joblib.dump({"just": "a dict"}, wrong_path)

    with pytest.raises(TypeError):
        load_anomaly_detector(wrong_path)


# --- never trains/saves, even on the success path ---


def test_never_fits_or_saves_when_loading_a_valid_artifact(tmp_path, monkeypatch) -> None:
    saved = _fitted_detector()
    path = tmp_path / "anomaly_detector.joblib"
    saved.save(path)

    def _forbidden(*args, **kwargs):
        raise AssertionError("loader must not fit/save/train")

    monkeypatch.setattr(AnomalyDetector, "fit", _forbidden)
    monkeypatch.setattr(AnomalyDetector, "save", _forbidden)
    monkeypatch.setattr("ml.dataset.generate_synthetic_feature_matrix", _forbidden)

    loaded = load_anomaly_detector(path)
    assert isinstance(loaded, AnomalyDetector)


def test_loading_module_has_no_training_dependencies() -> None:
    """Static check: ml/loading.py must never import ml.dataset or
    ml.train — it only loads an already-trained artifact."""
    import ast
    import inspect

    import ml.loading as loading_module

    tree = ast.parse(inspect.getsource(loading_module))
    full_module_paths = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            full_module_paths.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            full_module_paths.add(node.module)

    assert "ml.dataset" not in full_module_paths
    assert "ml.train" not in full_module_paths
