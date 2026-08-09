"""Unit tests for models.device_features.DeviceFeatures."""
from datetime import datetime

from models.device import Device
from models.device_features import DeviceFeatures
from models.entropy_metrics import EntropyMetrics
from models.enums import ProtocolType, TLSVersion
from models.packet_metadata import PacketMetadata
from models.protocol_fingerprint import ProtocolFingerprint

TS = datetime(2026, 1, 1, 12, 0, 0)


def _build() -> DeviceFeatures:
    return DeviceFeatures(
        device=Device.first_contact("192.168.1.10", TS),
        packet=PacketMetadata(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.1",
            src_port=51000,
            dst_port=80,
            packet_size=300,
            timestamp=TS,
        ),
        fingerprint=ProtocolFingerprint(
            protocol=ProtocolType.HTTP,
            tls_version=None,
            key_size=None,
            forward_secrecy=False,
        ),
        entropy=EntropyMetrics(shannon_entropy=4.2, sample_size=300),
    )


def test_constructs_from_valid_parts() -> None:
    features = _build()
    assert features.device.ip == "192.168.1.10"
    assert features.fingerprint.protocol == ProtocolType.HTTP


def test_timestamp_property_passes_through_packet_timestamp() -> None:
    features = _build()
    assert features.timestamp == features.packet.timestamp == TS


def test_round_trip_serialization() -> None:
    f1 = _build()
    f2 = DeviceFeatures.from_dict(f1.to_dict())
    assert f1 == f2