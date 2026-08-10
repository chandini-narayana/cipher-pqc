"""OfflinePcapSource — fully implemented in Phase 1.

Reads a .pcap file via scapy's PcapReader as a stream (not rdpcap(),
which loads the whole file into memory — see docs/SDD.md Section 16).
This is the capture path exercised by the test suite and the
deterministic demo flow.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from scapy.all import IP, TCP, UDP, PcapReader

from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from utils.exceptions import CaptureError, ParsingError

logger = logging.getLogger(__name__)


class OfflinePcapSource(CaptureSource):
    """Reads packets from a saved .pcap file, one at a time.

    Only IP packets carrying a TCP or UDP payload are yielded — packets
    with no IP layer (e.g., ARP) or with an empty payload (e.g., a bare
    TCP SYN) carry nothing CIPHER can analyze and are silently skipped;
    that is expected filtering, not an error.

    Raises:
        CaptureError: if `path` does not exist, or the file cannot be
            read as a pcap.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        if not self._path.exists():
            raise CaptureError(f"pcap file not found: {self._path}")

    def read_packets(self) -> Iterator[RawPacket]:
        try:
            with PcapReader(str(self._path)) as reader:
                for scapy_packet in reader:
                    raw = self._to_raw_packet(scapy_packet)
                    if raw is not None:
                        yield raw
        except CaptureError:
            raise
        except ParsingError:
            raise
        except Exception as exc:  # noqa: BLE001 - convert any scapy/file error
            raise CaptureError(
                f"failed to read pcap file {self._path}: {exc}"
            ) from exc

    @staticmethod
    def _to_raw_packet(scapy_packet) -> Optional[RawPacket]:
        """Convert one scapy packet into a RawPacket, or None if it has
        no IP layer, no TCP/UDP transport, or an empty payload — none
        of which are error conditions, just packets out of scope."""
        if IP not in scapy_packet:
            return None

        ip_layer = scapy_packet[IP]
        if TCP in scapy_packet:
            transport = scapy_packet[TCP]
        elif UDP in scapy_packet:
            transport = scapy_packet[UDP]
        else:
            return None

        payload = bytes(transport.payload)
        if not payload:
            return None

        timestamp = datetime.fromtimestamp(float(scapy_packet.time), tz=timezone.utc)

        try:
            return RawPacket(
                src_ip=ip_layer.src,
                dst_ip=ip_layer.dst,
                src_port=int(transport.sport),
                dst_port=int(transport.dport),
                payload=payload,
                timestamp=timestamp,
            )
        except ValueError as exc:
            raise ParsingError(f"failed to parse packet into RawPacket: {exc}") from exc