"""DeviceFeatures — the aggregated feature-extraction output for one
observation of a device.

Composes Device + PacketMetadata + ProtocolFingerprint + EntropyMetrics
into the single object that both the rule-based Quantum Risk Score
engine and the Isolation Forest anomaly detector consume (see the
frozen ML pipeline in docs/SDD.md: Feature Extraction sits between
Entropy Analysis and the Rule-Based Quantum Risk Score / Isolation
Forest branches). Pure composition — no feature-engineering logic.
"""
from __future__ import annotations

from datetime import datetime
from dataclasses import dataclass
from typing import Any, Dict

from models.device import Device
from models.entropy_metrics import EntropyMetrics
from models.packet_metadata import PacketMetadata
from models.protocol_fingerprint import ProtocolFingerprint


@dataclass(frozen=True, slots=True)
class DeviceFeatures:
    """One device observation's full feature set, ready for scoring.

    No additional validation beyond composing already-validated parts:
    each nested model validates itself in its own __post_init__.
    """

    device: Device
    packet: PacketMetadata
    fingerprint: ProtocolFingerprint
    entropy: EntropyMetrics

    @property
    def timestamp(self) -> datetime:
        """Convenience passthrough — avoids duplicating the packet's
        timestamp as a separate field that could drift out of sync."""
        return self.packet.timestamp

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device": self.device.to_dict(),
            "packet": self.packet.to_dict(),
            "fingerprint": self.fingerprint.to_dict(),
            "entropy": self.entropy.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DeviceFeatures":
        return cls(
            device=Device.from_dict(data["device"]),
            packet=PacketMetadata.from_dict(data["packet"]),
            fingerprint=ProtocolFingerprint.from_dict(data["fingerprint"]),
            entropy=EntropyMetrics.from_dict(data["entropy"]),
        )