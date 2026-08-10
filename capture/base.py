"""CaptureSource — the abstract interface both capture implementations satisfy.

Nothing downstream of capture/ can tell which implementation is
running; both OfflinePcapSource and LiveCaptureSource yield the same
RawPacket shape (see capture/raw_packet.py).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from capture.raw_packet import RawPacket


class CaptureSource(ABC):
    """Abstract source of packets for the (future) pipeline to consume."""

    @abstractmethod
    def read_packets(self) -> Iterator[RawPacket]:
        """Yield a RawPacket for each packet this source provides."""
        raise NotImplementedError  # pragma: no cover - interface only