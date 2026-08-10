"""RawPacket — capture-layer internal representation: metadata + raw payload.

NOT a models/ domain object: models.PacketMetadata deliberately
excludes payload bytes (see its own docstring, Step 4). RawPacket is
what capture/ actually produces from a .pcap file or (once
implemented) a live NIC; it is consumed by entropy/ and fingerprint/
(not built yet) for their own analysis of `payload`, and reduced to
PacketMetadata via `to_metadata()` for anything that only needs
metadata. This keeps the Step 4 model unchanged while still giving
capture/ somewhere to carry the bytes downstream analysis needs.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from models._validation import validate_ip, validate_range
from models.packet_metadata import PacketMetadata


@dataclass(frozen=True, slots=True)
class RawPacket:
    """One packet as capture/ produces it, before entropy/fingerprint
    analysis reduces it to metadata.

    Raises:
        ValueError: if `src_ip`/`dst_ip` are not valid IP addresses, if
            either port is outside [0, 65535], or if `payload` is empty.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes
    timestamp: datetime

    def __post_init__(self) -> None:
        validate_ip("src_ip", self.src_ip)
        validate_ip("dst_ip", self.dst_ip)
        validate_range("src_port", self.src_port, 0, 65535)
        validate_range("dst_port", self.dst_port, 0, 65535)
        if not self.payload:
            raise ValueError("payload must not be empty")

    def to_metadata(self) -> PacketMetadata:
        """Reduce this RawPacket to the models.PacketMetadata shape —
        metadata only, no payload bytes."""
        return PacketMetadata(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            packet_size=len(self.payload),
            timestamp=self.timestamp,
        )