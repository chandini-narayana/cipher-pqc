"""Unit tests for ml.classifier.AnomalyDetector.

Covers all 18 categories required for Step 9: initialization, fitting,
prediction, labels/scores, determinism, invalid dimensions, empty
input, insufficient training data, contamination validation,
not-fitted behavior, save/load, AnomalyAssessment construction, and
independence from Scapy/network/frontend/Risk Fusion.
"""
from datetime import datetime, timezone

import numpy as np
import pytest

from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_features import DeviceFeatures
from models.entropy_metrics import EntropyMetrics
from models.enums import ProtocolType, TLSVersion
from models.packet_metadata import PacketMetadata
from models.protocol_fingerprint import ProtocolFingerprint
from ml.classifier import AnomalyDetector
from ml.dataset import generate_synthetic_feature_matrix
from ml.features import NUM_FEATURES

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _device_features(tls_version=TLSVersion.TLS_1_3, key_size=3072, forward_secrecy=True,
                      entropy=7.8, protocol=ProtocolType.HTTPS, packet_size=800) -> DeviceFeatures:
    return DeviceFeatures(
        device=Device.first_contact("192.168.1.10", TS),
        packet=PacketMetadata(
            src_ip="192.168.1.10", dst_ip="192.168.1.1", src_port=51000,
            dst_port=443, packet_size=packet_size, timestamp=TS,
        ),
        fingerprint=ProtocolFingerprint(
            protocol=protocol, tls_version=tls_version, key_size=key_size,
            forward_secrecy=forward_secrecy,
        ),
        entropy=EntropyMetrics(shannon_entropy=entropy, sample_size=packet_size),
    )


def test_initializes_unfitted() -> None:
    detector = AnomalyDetector()
    assert detector.is_fitted is False


def test_accepts_explicit_contamination_and_random_state() -> None:
    detector = AnomalyDetector(contamination=0.1, random_state=7)
    assert detector._contamination == 0.1
    assert detector._random_state == 7


def test_fit_succeeds_on_valid_matrix() -> None:
    detector = AnomalyDetector()
    detector.fit(generate_synthetic_feature_matrix())
    assert detector.is_fitted is True


def test_predict_returns_anomaly_assessment_with_expected_direction() -> None:
    detector = AnomalyDetector()
    detector.fit(generate_synthetic_feature_matrix())

    normal = detector.predict_one(_device_features())
    weird = detector.predict_one(_device_features(
        tls_version=TLSVersion.TLS_1_0, key_size=512, forward_secrecy=False,
        entropy=2.0, protocol=ProtocolType.HTTP, packet_size=30,
    ))

    assert isinstance(normal, AnomalyAssessment)
    assert isinstance(weird, AnomalyAssessment)
    assert weird.anomaly_score > normal.anomaly_score
    assert weird.is_anomaly is True
    assert normal.is_anomaly is False


def test_confidence_is_higher_for_more_anomalous_points() -> None:
    detector = AnomalyDetector()
    detector.fit(generate_synthetic_feature_matrix())

    normal = detector.predict_one(_device_features())
    weird = detector.predict_one(_device_features(
        tls_version=TLSVersion.TLS_1_0, key_size=512, forward_secrecy=False,
        entropy=2.0, protocol=ProtocolType.HTTP, packet_size=30,
    ))
    assert weird.confidence > normal.confidence
    assert 0.0 <= normal.confidence <= 1.0
    assert 0.0 <= weird.confidence <= 1.0


def test_deterministic_with_fixed_random_state() -> None:
    matrix = generate_synthetic_feature_matrix()
    features = _device_features()

    detector_a = AnomalyDetector(random_state=42)
    detector_a.fit(matrix)
    result_a = detector_a.predict_one(features)

    detector_b = AnomalyDetector(random_state=42)
    detector_b.fit(matrix)
    result_b = detector_b.predict_one(features)

    assert result_a == result_b


def test_different_random_state_is_not_required_to_match() -> None:
    matrix = generate_synthetic_feature_matrix()
    features = _device_features()

    detector_a = AnomalyDetector(random_state=1)
    detector_a.fit(matrix)
    result_a = detector_a.predict_one(features)

    detector_b = AnomalyDetector(random_state=2)
    detector_b.fit(matrix)
    result_b = detector_b.predict_one(features)

    assert isinstance(result_a, AnomalyAssessment)
    assert isinstance(result_b, AnomalyAssessment)


def test_fit_rejects_wrong_column_count() -> None:
    detector = AnomalyDetector()
    bad_matrix = np.ones((50, NUM_FEATURES - 1))
    with pytest.raises(ValueError, match="columns"):
        detector.fit(bad_matrix)


def test_fit_rejects_1d_input() -> None:
    detector = AnomalyDetector()
    with pytest.raises(ValueError):
        detector.fit(np.ones(NUM_FEATURES))


def test_fit_rejects_empty_matrix() -> None:
    detector = AnomalyDetector()
    empty_matrix = np.empty((0, NUM_FEATURES))
    with pytest.raises(ValueError, match="rows"):
        detector.fit(empty_matrix)


def test_fit_rejects_too_few_rows() -> None:
    detector = AnomalyDetector()
    tiny_matrix = np.random.default_rng(1).random((3, NUM_FEATURES))
    with pytest.raises(ValueError, match="rows"):
        detector.fit(tiny_matrix)


def test_invalid_contamination_raises_on_fit() -> None:
    detector = AnomalyDetector(contamination=0.9)
    with pytest.raises(ValueError):
        detector.fit(generate_synthetic_feature_matrix())


def test_predict_before_fit_raises_runtime_error() -> None:
    detector = AnomalyDetector()
    with pytest.raises(RuntimeError, match="fit"):
        detector.predict_one(_device_features())


def test_save_before_fit_raises_runtime_error() -> None:
    detector = AnomalyDetector()
    with pytest.raises(RuntimeError, match="fit"):
        detector.save("/tmp/should-not-be-created.joblib")


def test_save_and_load_round_trip_produces_identical_predictions(tmp_path) -> None:
    detector = AnomalyDetector()
    detector.fit(generate_synthetic_feature_matrix())
    features = _device_features(tls_version=TLSVersion.TLS_1_0, key_size=512, forward_secrecy=False, entropy=2.0)
    original_result = detector.predict_one(features)

    save_path = tmp_path / "detector.joblib"
    detector.save(save_path)
    loaded = AnomalyDetector.load(save_path)

    assert loaded.is_fitted is True
    assert loaded.predict_one(features) == original_result


def test_load_rejects_non_anomaly_detector_file(tmp_path) -> None:
    import joblib

    bad_path = tmp_path / "not-a-detector.joblib"
    joblib.dump({"just": "a dict"}, bad_path)
    with pytest.raises(TypeError):
        AnomalyDetector.load(bad_path)


def test_predict_one_returns_a_valid_anomaly_assessment_instance() -> None:
    detector = AnomalyDetector()
    detector.fit(generate_synthetic_feature_matrix())
    result = detector.predict_one(_device_features())
    assert isinstance(result, AnomalyAssessment)
    assert isinstance(result.anomaly_score, float)
    assert isinstance(result.is_anomaly, bool)
    assert isinstance(result.confidence, float)


def test_classifier_module_has_no_forbidden_dependencies() -> None:
    import ast
    import inspect

    import ml.classifier as classifier_module

    tree = ast.parse(inspect.getsource(classifier_module))
    imported_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module.split(".")[0])

    forbidden = {"scapy", "socket", "requests", "urllib", "http", "flask", "risk", "capture", "fingerprint"}
    assert not (imported_modules & forbidden), f"forbidden imports: {imported_modules & forbidden}"