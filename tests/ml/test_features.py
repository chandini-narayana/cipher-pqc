"""Unit tests for ml.features.vectorize_features — deterministic
feature vectorization, no risk-score leakage."""
from datetime import datetime, timezone

import numpy as np

from models.device import Device
from models.device_features import DeviceFeatures
from models.entropy_metrics import EntropyMetrics
from models.enums import ProtocolType, TLSVersion
from models.packet_metadata import PacketMetadata
from models.protocol_fingerprint import ProtocolFingerprint
from ml.features import FEATURE_NAMES, NUM_FEATURES, vectorize_features

TS = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _features(**overrides) -> DeviceFeatures:
    defaults = dict(
        protocol=ProtocolType.HTTPS,
        tls_version=TLSVersion.TLS_1_3,
        key_size=3072,
        forward_secrecy=True,
        entropy=7.8,
        packet_size=800,
    )
    defaults.update(overrides)
    return DeviceFeatures(
        device=Device.first_contact("192.168.1.10", TS),
        packet=PacketMetadata(
            src_ip="192.168.1.10", dst_ip="192.168.1.1", src_port=51000,
            dst_port=443, packet_size=defaults["packet_size"], timestamp=TS,
        ),
        fingerprint=ProtocolFingerprint(
            protocol=defaults["protocol"], tls_version=defaults["tls_version"],
            key_size=defaults["key_size"], forward_secrecy=defaults["forward_secrecy"],
        ),
        entropy=EntropyMetrics(shannon_entropy=defaults["entropy"], sample_size=defaults["packet_size"]),
    )


def test_vector_has_correct_length_and_dtype() -> None:
    vector = vectorize_features(_features())
    assert vector.shape == (NUM_FEATURES,)
    assert vector.dtype == np.float64
    assert len(FEATURE_NAMES) == NUM_FEATURES


def test_known_values_map_to_correct_columns() -> None:
    vector = vectorize_features(_features(
        entropy=6.5, packet_size=1234, tls_version=TLSVersion.TLS_1_2,
        key_size=2048, forward_secrecy=False, protocol=ProtocolType.MQTT,
    ))
    as_dict = dict(zip(FEATURE_NAMES, vector))
    assert as_dict["shannon_entropy"] == 6.5
    assert as_dict["packet_size"] == 1234.0
    assert as_dict["tls_version_value"] == 1.2
    assert as_dict["tls_version_observed"] == 1.0
    assert as_dict["key_size"] == 2048.0
    assert as_dict["key_size_observed"] == 1.0
    assert as_dict["forward_secrecy"] == 0.0
    assert as_dict["protocol_is_mqtt"] == 1.0
    assert as_dict["protocol_is_https"] == 0.0
    assert as_dict["protocol_is_http"] == 0.0
    assert as_dict["protocol_is_telnet"] == 0.0
    assert as_dict["protocol_is_other"] == 0.0


def test_unobserved_tls_version_and_key_size_use_zero_with_indicator() -> None:
    vector = vectorize_features(_features(
        tls_version=None, key_size=None, protocol=ProtocolType.HTTPS,
    ))
    as_dict = dict(zip(FEATURE_NAMES, vector))
    assert as_dict["tls_version_value"] == 0.0
    assert as_dict["tls_version_observed"] == 0.0
    assert as_dict["key_size"] == 0.0
    assert as_dict["key_size_observed"] == 0.0


def test_protocol_one_hot_is_mutually_exclusive_and_sums_to_one() -> None:
    for protocol in (ProtocolType.HTTPS, ProtocolType.HTTP, ProtocolType.MQTT, ProtocolType.TELNET, ProtocolType.OTHER):
        vector = vectorize_features(_features(protocol=protocol, tls_version=None, key_size=None))
        as_dict = dict(zip(FEATURE_NAMES, vector))
        one_hot_sum = sum(as_dict[f"protocol_is_{p.value.lower()}"] for p in
                           (ProtocolType.HTTPS, ProtocolType.HTTP, ProtocolType.MQTT, ProtocolType.TELNET, ProtocolType.OTHER))
        assert one_hot_sum == 1.0


def test_deterministic_output_for_same_input() -> None:
    features = _features()
    first = vectorize_features(features)
    second = vectorize_features(features)
    np.testing.assert_array_equal(first, second)


def test_no_risk_score_or_risk_module_import_in_features() -> None:
    """Static check: ml/features.py must never import risk/ — the raw
    features feeding ML must be independent of the rule engine's
    output (see module docstring's no-leakage note)."""
    import ast
    import inspect

    import ml.features as features_module

    tree = ast.parse(inspect.getsource(features_module))
    imported_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module.split(".")[0])

    assert "risk" not in imported_modules