"""entropy — Shannon entropy calculation for packet payloads.

Operates purely on bytes: no Scapy dependency, no awareness of
capture.RawPacket or models.PacketMetadata (see entropy/engine.py).
"""

from entropy.engine import compute_entropy_metrics, shannon_entropy

__all__ = ["shannon_entropy", "compute_entropy_metrics"]