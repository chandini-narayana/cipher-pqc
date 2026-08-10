"""capture — where CIPHER's packets come from, behind one interface.

OfflinePcapSource is fully implemented in Phase 1 (streams a .pcap
file via scapy's PcapReader). LiveCaptureSource is a documented
scaffold in Phase 1 (see docs/SDD.md D2) — it implements the same
CaptureSource interface but raises LiveCaptureNotImplementedError
immediately from read_packets().

Both yield RawPacket (capture/raw_packet.py) — a capture-layer type
distinct from models.PacketMetadata, since PacketMetadata deliberately
excludes payload bytes.
"""

from capture.base import CaptureSource
from capture.factory import get_capture_source
from capture.live_source import LiveCaptureSource
from capture.offline_source import OfflinePcapSource
from capture.raw_packet import RawPacket

__all__ = [
    "CaptureSource",
    "OfflinePcapSource",
    "LiveCaptureSource",
    "RawPacket",
    "get_capture_source",
]