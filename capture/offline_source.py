"""OfflinePcapSource — fully implemented in Phase 1.

Reads a .pcap file via scapy's PcapReader as a stream (not rdpcap(), which
loads the whole file into memory — see SDD Section 16). This is the
capture path exercised by the test suite and by the deterministic demo flow.

Implemented in a later step.
"""

# TODO: implement OfflinePcapSource(CaptureSource) (Step: capture)
