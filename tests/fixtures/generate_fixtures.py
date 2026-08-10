"""Generates tests/fixtures/sample.pcap — a small, deterministic packet
capture used by OfflinePcapSource's tests.

Run manually if ever needed:

    python tests/fixtures/generate_fixtures.py

In normal use you don't need to run this yourself: tests/conftest.py
generates the fixture automatically the first time the test suite
needs it. It's committed as a generator rather than a binary .pcap
blob so the fixture's contents are transparent and reproducible
instead of an opaque checked-in binary.

Contents (5 packets, chosen to exercise OfflinePcapSource's filtering):
1. TCP packet with a payload           -> yielded as a RawPacket
2. TCP packet with a payload           -> yielded as a RawPacket
3. UDP packet with a payload           -> yielded as a RawPacket
4. TCP packet with an EMPTY payload    -> filtered out (no payload)
5. ARP packet (no IP layer at all)     -> filtered out (not IP)
"""
from __future__ import annotations

from pathlib import Path

from scapy.all import ARP, IP, TCP, UDP, Ether, wrpcap

FIXTURES_DIR = Path(__file__).resolve().parent
SAMPLE_PCAP_PATH = FIXTURES_DIR / "sample.pcap"


def build_sample_packets() -> list:
    """Build the in-memory scapy packets that make up sample.pcap."""
    packets = []

    # 1. TCP packet with a payload (destined for port 443, TLS-shaped).
    packets.append(
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.1")
        / TCP(sport=51000, dport=443)
        / (b"\x16\x03\x03\x00\x10" + b"A" * 16)
    )

    # 2. TCP packet with a payload (destined for port 80, HTTP-shaped).
    packets.append(
        Ether()
        / IP(src="192.168.1.11", dst="192.168.1.1")
        / TCP(sport=51010, dport=80)
        / b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )

    # 3. UDP packet with a payload (destined for port 1883, MQTT-shaped).
    packets.append(
        Ether()
        / IP(src="192.168.1.12", dst="192.168.1.1")
        / UDP(sport=51020, dport=1883)
        / b"MQTT-CONNECT-PAYLOAD"
    )

    # 4. TCP packet with an empty payload (e.g., a bare SYN) — should be
    #    filtered out by OfflinePcapSource, not yielded.
    packets.append(
        Ether() / IP(src="192.168.1.13", dst="192.168.1.1") / TCP(sport=51030, dport=22)
    )

    # 5. ARP packet — no IP layer at all — should be filtered out.
    packets.append(Ether() / ARP(psrc="192.168.1.14", pdst="192.168.1.1"))

    return packets


def main() -> Path:
    """Write the sample packets to tests/fixtures/sample.pcap and
    return the path written to."""
    packets = build_sample_packets()
    wrpcap(str(SAMPLE_PCAP_PATH), packets)
    print(f"Wrote {len(packets)} packets to {SAMPLE_PCAP_PATH}")
    return SAMPLE_PCAP_PATH


if __name__ == "__main__":
    main()