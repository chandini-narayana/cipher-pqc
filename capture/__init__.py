"""capture — where CIPHER's packets come from, behind one interface.

OfflinePcapSource is fully implemented in Phase 1 (streams a .pcap
file via scapy's PcapReader). LiveCaptureSource is a documented
scaffold in Phase 1 (see docs/SDD.md D2) — it implements the same
CaptureSource interface but raises LiveCaptureNotImplementedError
immediately from read_packets().

capture.host_live_source.LiveCaptureSource (host-level Windows demo
capture) and capture.network_live_source.NetworkLiveCaptureSource
(Linux/Raspberry-Pi interface capture) are two further implementations,
each composed directly by its own entry point rather than through the
factory. They differ in exactly one respect, deliberately: the host
source normalizes device identity to the local machine (the one
monitored endpoint), while the network source preserves every packet's
true source address, because on a monitored network path each distinct
source genuinely is a different device — and that address is what a
later Linux enforcement backend would isolate.

All of them yield RawPacket (capture/raw_packet.py) — a capture-layer type
distinct from models.PacketMetadata, since PacketMetadata deliberately
excludes payload bytes.
"""

from capture.base import CaptureSource
from capture.factory import get_capture_source
from capture.live_source import LiveCaptureSource
from capture.network_live_source import CaptureCounters, NetworkLiveCaptureSource
from capture.offline_source import OfflinePcapSource
from capture.raw_packet import RawPacket

__all__ = [
    "CaptureSource",
    "OfflinePcapSource",
    "LiveCaptureSource",
    "NetworkLiveCaptureSource",
    "CaptureCounters",
    "RawPacket",
    "get_capture_source",
]