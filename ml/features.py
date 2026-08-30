"""DeviceFeatures -> numeric feature vector for the Isolation Forest.

Pure vectorization only — no model logic, no fitting, no prediction.
Feature order is fixed and documented (FEATURE_NAMES) so training and
inference always agree on which column means what, per docs/SDD.md
Section 21's reproducibility requirement.

No risk-score leakage: every feature here is a RAW observation
(entropy, key size, TLS version, forward secrecy, protocol, packet
size) — never the Quantum Risk Score or any of its component values
from risk/. The rule engine and this module consume the same raw
inputs independently; neither feeds the other's output back in.
"""
from __future__ import annotations

import numpy as np

from models.device_features import DeviceFeatures
from models.enums import ProtocolType

FEATURE_NAMES = [
    "shannon_entropy",
    "packet_size",
    "tls_version_value",
    "tls_version_observed",
    "key_size",
    "key_size_observed",
    "forward_secrecy",
    "protocol_is_https",
    "protocol_is_http",
    "protocol_is_mqtt",
    "protocol_is_telnet",
    "protocol_is_other",
]

NUM_FEATURES = len(FEATURE_NAMES)

_PROTOCOL_ONE_HOT_ORDER = [
    ProtocolType.HTTPS,
    ProtocolType.HTTP,
    ProtocolType.MQTT,
    ProtocolType.TELNET,
    ProtocolType.OTHER,
]


def vectorize_features(features: DeviceFeatures) -> np.ndarray:
    """Convert one DeviceFeatures observation into the fixed-order
    numeric feature vector Isolation Forest consumes.

    Missing values (tls_version=None, key_size=None) are encoded as
    0.0 plus a companion "*_observed" indicator (0.0 if missing) —
    0.0 never collides with a real value for either field (TLSVersion
    is always >= 1.0; key_size is always > 0, per Step 4's own
    validation), so the encoding is unambiguous even without the
    indicator, but the indicator makes "not observed" explicit rather
    than implicit in a code review or a future reader's head.

    protocol is one-hot encoded (5 binary columns) rather than given
    an arbitrary integer, since ProtocolType has no genuine ordinal
    relationship between its members (MQTT is not "between" HTTPS and
    Telnet) — an integer encoding would impose a false ordering that
    Isolation Forest's splits could spuriously exploit. One-hot avoids
    that at the cost of 5 columns instead of 1, the trade-off judged
    acceptable given ProtocolType only has 5 possible values.

    Returns:
        A 1-D numpy array of length NUM_FEATURES, dtype float64, in
        the exact order FEATURE_NAMES documents.
    """
    fingerprint = features.fingerprint
    entropy = features.entropy

    tls_version = fingerprint.tls_version
    tls_version_value = tls_version.value if tls_version is not None else 0.0
    tls_version_observed = 1.0 if tls_version is not None else 0.0

    key_size = fingerprint.key_size
    key_size_value = float(key_size) if key_size is not None else 0.0
    key_size_observed = 1.0 if key_size is not None else 0.0

    one_hot = [1.0 if fingerprint.protocol == p else 0.0 for p in _PROTOCOL_ONE_HOT_ORDER]

    vector = [
        entropy.shannon_entropy,
        float(entropy.sample_size),
        tls_version_value,
        tls_version_observed,
        key_size_value,
        key_size_observed,
        1.0 if fingerprint.forward_secrecy else 0.0,
        *one_hot,
    ]
    return np.array(vector, dtype=np.float64)