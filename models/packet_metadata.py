"""PacketMetadata — metadata describing a single captured packet.

Deliberately holds no raw payload bytes and no capture/parsing logic:
capture/ (not implemented in this step) is responsible for producing
this from a real packet; entropy/ and fingerprint/ (also not
implemented) consume the packet's raw bytes separately to produce
EntropyMetrics and ProtocolFingerprint. This model is metadata only.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict

from models._validation import validate_ip, validate_range


@dataclass(frozen=True, slots=True)
class PacketMetadata:
    """Metadata for one captured packet.

    Raises:
        ValueError: if `src_ip`/`dst_ip` are not valid IP addresses, if
            either port is outside [0, 65535], or if `packet_size` is
            not positive.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    packet_size: int
    timestamp: datetime

    def __post_init__(self) -> None:
        validate_ip("src_ip", self.src_ip)
        validate_ip("dst_ip", self.dst_ip)
        validate_range("src_port", self.src_port, 0, 65535)
        validate_range("dst_port", self.dst_port, 0, 65535)
        if self.packet_size <= 0:
            raise ValueError(f"packet_size must be positive, got {self.packet_size}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "packet_size": self.packet_size,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PacketMetadata":
        return cls(
            src_ip=data["src_ip"],
            dst_ip=data["dst_ip"],
            src_port=data["src_port"],
            dst_port=data["dst_port"],
            packet_size=data["packet_size"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
        )