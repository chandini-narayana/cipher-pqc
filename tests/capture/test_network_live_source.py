"""Unit tests for capture.network_live_source — Linux/Raspberry-Pi live
capture that preserves the true source device identity (docs/SDD.md
Phase 3C addendum).

scapy's sniff() is always stubbed and every packet is built
deterministically with scapy: no test here needs a real interface, a
capture backend, root, or any network access.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from scapy.all import ARP, DNS, DNSQR, IP, TCP, UDP, Dot11, Dot11Deauth, Ether, RadioTap, Raw

import capture.network_live_source as network_live_source
from capture.base import CaptureSource
from capture.network_live_source import (
    CaptureCounters,
    NetworkLiveCaptureSource,
    available_interface_names,
    interface_exists,
)
from capture.raw_packet import RawPacket
from utils.exceptions import CaptureError

_PI_IP = "192.168.50.1"
_DEVICE_A = "192.168.50.21"
_DEVICE_B = "192.168.50.22"
_SERVER = "93.184.216.34"

_TLS_PAYLOAD = bytes.fromhex("160301002a0100002603") + b"\x00" * 20

_CAPTURE_EPOCH = 1767182400.0
_CAPTURE_TIME = datetime.fromtimestamp(_CAPTURE_EPOCH, tz=timezone.utc)


class _FakeIface:
    def __init__(self, name: str) -> None:
        self.name = name


@pytest.fixture(autouse=True)
def _fake_interfaces(monkeypatch):
    """A fixed, fake interface list for every test, so nothing depends on
    this machine's real adapters."""
    monkeypatch.setattr(
        network_live_source.conf,
        "ifaces",
        {1: _FakeIface("lo"), 2: _FakeIface("eth0"), 3: _FakeIface("wlan1")},
        raising=False,
    )


def _stub_sniff(monkeypatch, packets, kwargs_out=None):
    """Replace scapy.sniff with a stub that records its kwargs and feeds
    `packets` synchronously through the prn callback."""

    def _fake_sniff(**kwargs):
        if kwargs_out is not None:
            kwargs_out.update(kwargs)
        for packet in packets:
            kwargs["prn"](packet)

    monkeypatch.setattr(network_live_source, "sniff", _fake_sniff)


def _tcp_packet(src: str, dst: str, sport: int, dport: int, payload: bytes = _TLS_PAYLOAD):
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(load=payload)
    packet.time = _CAPTURE_EPOCH  # fixed capture time, deterministic
    return packet


def _capture(monkeypatch, packets, **kwargs):
    _stub_sniff(monkeypatch, packets)
    source = NetworkLiveCaptureSource(interface="eth0", **kwargs)
    return source, list(source.read_packets())


# --- interface handling ---------------------------------------------------


def test_is_a_capture_source() -> None:
    assert isinstance(NetworkLiveCaptureSource("eth0"), CaptureSource)


def test_requires_an_explicit_interface_name() -> None:
    with pytest.raises(CaptureError):
        NetworkLiveCaptureSource("")


def test_blank_interface_is_rejected() -> None:
    with pytest.raises(CaptureError):
        NetworkLiveCaptureSource("   ")


def test_unknown_interface_is_rejected_with_the_available_names() -> None:
    with pytest.raises(CaptureError) as excinfo:
        NetworkLiveCaptureSource("wlan9")
    assert "wlan9" in str(excinfo.value)
    assert "eth0" in str(excinfo.value)


def test_the_explicit_interface_is_passed_to_the_capture_layer(monkeypatch) -> None:
    kwargs = {}
    _stub_sniff(monkeypatch, [_tcp_packet(_DEVICE_A, _SERVER, 40000, 443)], kwargs)

    source = NetworkLiveCaptureSource(interface="wlan1", timeout=5, packet_limit=7)
    list(source.read_packets())

    assert kwargs["iface"] == "wlan1"
    assert kwargs["timeout"] == 5.0
    assert kwargs["count"] == 7


def test_no_interface_name_is_hardcoded_in_the_module() -> None:
    """Interface names belong to the operator and the composition root,
    never to reusable capture code.

    Checks executable string literals only — the module docstring names
    wlan0/wlan1 in prose to explain precisely why this rule exists, and
    prose cannot select an interface."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(network_live_source))
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                docstrings.add(doc)

    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value in docstrings:
                continue
            lowered = node.value.lower()
            for name in ("wlan0", "wlan1", "eth0"):
                assert name not in lowered, f"hardcoded interface name {name!r}"


def test_the_interface_is_exposed_for_reporting() -> None:
    assert NetworkLiveCaptureSource("eth0").interface == "eth0"


def test_a_bpf_filter_is_only_passed_when_given(monkeypatch) -> None:
    kwargs = {}
    _stub_sniff(monkeypatch, [], kwargs)
    list(NetworkLiveCaptureSource("eth0").read_packets())
    assert "filter" not in kwargs

    kwargs.clear()
    _stub_sniff(monkeypatch, [], kwargs)
    list(NetworkLiveCaptureSource("eth0", bpf_filter="ip").read_packets())
    assert kwargs["filter"] == "ip"


@pytest.mark.parametrize("timeout", [0, -1])
def test_non_positive_timeout_is_rejected(timeout) -> None:
    with pytest.raises(CaptureError):
        NetworkLiveCaptureSource("eth0", timeout=timeout)


@pytest.mark.parametrize("limit", [0, -5])
def test_non_positive_packet_limit_is_rejected(limit) -> None:
    with pytest.raises(CaptureError):
        NetworkLiveCaptureSource("eth0", packet_limit=limit)


def test_interface_helpers_do_not_raise_on_a_hostile_environment(monkeypatch) -> None:
    class _Exploding(dict):
        def values(self):
            raise RuntimeError("scapy enumeration failed")

    monkeypatch.setattr(network_live_source.conf, "ifaces", _Exploding(), raising=False)
    # Best-effort: an unusable enumeration must not block capture, and
    # must not crash the listing helper either.
    assert interface_exists("eth0") is True
    assert available_interface_names() == []


def test_an_empty_enumeration_does_not_reject_the_interface(monkeypatch) -> None:
    monkeypatch.setattr(network_live_source.conf, "ifaces", {}, raising=False)
    assert interface_exists("eth0") is True
    NetworkLiveCaptureSource("eth0")  # must not raise


# --- conversion: the RawPacket contract ----------------------------------


def test_ipv4_tcp_packet_becomes_a_rawpacket(monkeypatch) -> None:
    _source, packets = _capture(monkeypatch, [_tcp_packet(_DEVICE_A, _SERVER, 40000, 443)])

    assert len(packets) == 1
    assert isinstance(packets[0], RawPacket)


def test_src_ip_is_the_real_source_device(monkeypatch) -> None:
    """The core Phase 3C requirement: the assessed identity must be the
    device that sent the packet."""
    _source, packets = _capture(monkeypatch, [_tcp_packet(_DEVICE_A, _SERVER, 40000, 443)])
    assert packets[0].src_ip == _DEVICE_A


def test_dst_ip_is_preserved(monkeypatch) -> None:
    _source, packets = _capture(monkeypatch, [_tcp_packet(_DEVICE_A, _SERVER, 40000, 443)])
    assert packets[0].dst_ip == _SERVER


def test_ports_are_preserved_in_order(monkeypatch) -> None:
    _source, packets = _capture(monkeypatch, [_tcp_packet(_DEVICE_A, _SERVER, 40000, 443)])
    assert (packets[0].src_port, packets[0].dst_port) == (40000, 443)


def test_payload_bytes_are_preserved_exactly(monkeypatch) -> None:
    _source, packets = _capture(monkeypatch, [_tcp_packet(_DEVICE_A, _SERVER, 40000, 443)])
    assert packets[0].payload == _TLS_PAYLOAD


def test_udp_packets_are_converted_too(monkeypatch) -> None:
    dns = IP(src=_DEVICE_A, dst="8.8.8.8") / UDP(sport=51000, dport=53) / DNS(qd=DNSQR(qname="a.test"))
    dns.time = _CAPTURE_EPOCH
    _source, packets = _capture(monkeypatch, [dns])

    assert len(packets) == 1
    assert (packets[0].src_port, packets[0].dst_port) == (51000, 53)


def test_the_capture_timestamp_is_used_and_utc(monkeypatch) -> None:
    _source, packets = _capture(monkeypatch, [_tcp_packet(_DEVICE_A, _SERVER, 40000, 443)])
    assert packets[0].timestamp.tzinfo is not None
    assert packets[0].timestamp == _CAPTURE_TIME


def test_a_frame_with_no_usable_timestamp_is_still_converted(monkeypatch) -> None:
    """A missing/garbage capture time is never a reason to drop an
    otherwise-valid packet."""
    packet = _tcp_packet(_DEVICE_A, _SERVER, 40000, 443)
    packet.time = "not-a-time"
    _source, packets = _capture(monkeypatch, [packet])
    assert len(packets) == 1


# --- device identity: no normalization -----------------------------------


def test_multiple_source_devices_stay_distinct(monkeypatch) -> None:
    _source, packets = _capture(
        monkeypatch,
        [
            _tcp_packet(_DEVICE_A, _SERVER, 40000, 443),
            _tcp_packet(_DEVICE_B, _SERVER, 41000, 8883),
        ],
    )

    assert [p.src_ip for p in packets] == [_DEVICE_A, _DEVICE_B]


def test_nothing_is_normalized_to_the_capturing_hosts_own_ip(monkeypatch) -> None:
    """Traffic between two other hosts must be reported as-is, and the
    capturing host's address must never appear in a packet it was not
    part of."""
    _source, packets = _capture(
        monkeypatch,
        [
            _tcp_packet(_DEVICE_A, _SERVER, 40000, 443),
            _tcp_packet(_DEVICE_B, _DEVICE_A, 41000, 1883),
        ],
    )

    assert len(packets) == 2
    for packet in packets:
        assert packet.src_ip != _PI_IP
        assert packet.dst_ip != _PI_IP


def test_a_response_packet_is_not_swapped_to_keep_a_local_host_as_source(monkeypatch) -> None:
    """Unlike host-live capture, an inbound packet keeps its own
    direction: the server really is the source of its own response."""
    _source, packets = _capture(monkeypatch, [_tcp_packet(_SERVER, _DEVICE_A, 443, 40000)])

    assert packets[0].src_ip == _SERVER
    assert packets[0].dst_ip == _DEVICE_A
    assert (packets[0].src_port, packets[0].dst_port) == (443, 40000)


def test_traffic_between_two_other_hosts_is_not_discarded(monkeypatch) -> None:
    """Host-live capture drops these; a monitored network path must not,
    or a Pi would observe nothing at all."""
    _source, packets = _capture(monkeypatch, [_tcp_packet(_DEVICE_A, _DEVICE_B, 40000, 1883)])
    assert len(packets) == 1


# --- filtering: unusable frames are skipped, never fatal -----------------


def test_a_non_ip_frame_is_skipped(monkeypatch) -> None:
    arp = Ether() / ARP(pdst="192.168.50.99")
    arp.time = _CAPTURE_EPOCH
    source, packets = _capture(monkeypatch, [arp])

    assert packets == []
    assert source.counters.skipped_non_ip == 1


def test_a_protected_dot11_frame_without_ip_is_skipped(monkeypatch) -> None:
    """A monitor-mode frame that exposes no decodable IP layer is skipped
    cleanly. No decryption is ever attempted."""
    frame = RadioTap() / Dot11(
        type=2, subtype=0, FCfield="protected", addr1="00:11:22:33:44:55",
        addr2="66:77:88:99:aa:bb", addr3="cc:dd:ee:ff:00:11",
    ) / Raw(load=b"\x00" * 48)
    frame.time = _CAPTURE_EPOCH
    source, packets = _capture(monkeypatch, [frame])

    assert packets == []
    assert source.counters.skipped_non_ip == 1


def test_an_802_11_management_frame_is_skipped(monkeypatch) -> None:
    frame = RadioTap() / Dot11(
        addr1="00:11:22:33:44:55", addr2="66:77:88:99:aa:bb", addr3="cc:dd:ee:ff:00:11"
    ) / Dot11Deauth(reason=7)
    frame.time = _CAPTURE_EPOCH
    source, packets = _capture(monkeypatch, [frame])

    assert packets == []
    assert source.counters.skipped_non_ip == 1


def test_a_monitor_mode_frame_carrying_ip_is_converted(monkeypatch) -> None:
    """Radiotap/802.11 encapsulation is supported when, and only when, the
    frame already exposes a decodable IP layer."""
    frame = (
        RadioTap()
        / Dot11(addr1="00:11:22:33:44:55", addr2="66:77:88:99:aa:bb", addr3="cc:dd:ee:ff:00:11")
        / IP(src=_DEVICE_A, dst=_SERVER)
        / TCP(sport=40000, dport=443)
        / Raw(load=_TLS_PAYLOAD)
    )
    frame.time = _CAPTURE_EPOCH
    _source, packets = _capture(monkeypatch, [frame])

    assert len(packets) == 1
    assert packets[0].src_ip == _DEVICE_A


def test_an_ip_frame_with_no_tcp_or_udp_layer_is_skipped(monkeypatch) -> None:
    icmp_like = IP(src=_DEVICE_A, dst=_SERVER, proto=1) / Raw(load=b"\x08\x00abcd")
    icmp_like.time = _CAPTURE_EPOCH
    source, packets = _capture(monkeypatch, [icmp_like])

    assert packets == []
    assert source.counters.skipped_no_transport == 1


def test_an_empty_payload_is_skipped(monkeypatch) -> None:
    """A bare SYN carries nothing to fingerprint — the same rule
    OfflinePcapSource already applies."""
    syn = IP(src=_DEVICE_A, dst=_SERVER) / TCP(sport=40000, dport=443, flags="S")
    syn.time = _CAPTURE_EPOCH
    source, packets = _capture(monkeypatch, [syn])

    assert packets == []
    assert source.counters.skipped_no_transport == 1


class _MalformedSrcFrame:
    """A real scapy packet presenting a malformed IP source address.

    scapy refuses to *build* an invalid address (inet_aton rejects it), so
    a captured frame carrying one has to be simulated at the layer-access
    boundary rather than constructed. Everything else about the frame is
    a genuine scapy packet."""

    def __init__(self, packet) -> None:
        self._packet = packet
        self.time = packet.time

    def __contains__(self, layer):
        return layer in self._packet

    def __getitem__(self, layer):
        inner = self._packet[layer]
        if layer is IP:
            class _BadIP:
                src = "not-an-ip-address"
                dst = inner.dst

            return _BadIP()
        return inner


def test_a_malformed_packet_is_skipped_without_crashing_the_loop(monkeypatch) -> None:
    """A frame whose IP fields RawPacket rejects is counted and skipped,
    and the packets after it are still captured."""
    bad = _MalformedSrcFrame(_tcp_packet(_DEVICE_A, _SERVER, 40000, 443))
    good = _tcp_packet(_DEVICE_B, _SERVER, 41000, 443)

    source, packets = _capture(monkeypatch, [bad, good])

    assert [p.src_ip for p in packets] == [_DEVICE_B]
    assert source.counters.parse_failures == 1


def test_a_frame_that_explodes_during_conversion_is_skipped(monkeypatch) -> None:
    """Any unexpected error from one frame is contained: it never reaches
    the generator and never stops the capture."""

    class _Hostile:
        time = _CAPTURE_EPOCH

        def __contains__(self, _layer):
            raise RuntimeError("scapy layer lookup exploded")

    source, packets = _capture(monkeypatch, [_Hostile(), _tcp_packet(_DEVICE_A, _SERVER, 1, 443)])

    assert [p.src_ip for p in packets] == [_DEVICE_A]
    assert source.counters.parse_failures == 1


def test_an_out_of_range_port_is_skipped(monkeypatch) -> None:
    packet = _tcp_packet(_DEVICE_A, _SERVER, 40000, 443)
    packet[TCP].sport = 99999
    source, packets = _capture(monkeypatch, [packet])

    assert packets == []
    assert source.counters.parse_failures == 1


# --- backend failures ARE fatal, and clearly reported --------------------


def test_a_capture_permission_error_becomes_a_clear_capture_error(monkeypatch) -> None:
    def _exploding_sniff(**kwargs):
        raise PermissionError("Operation not permitted")

    monkeypatch.setattr(network_live_source, "sniff", _exploding_sniff)
    source = NetworkLiveCaptureSource("eth0")

    with pytest.raises(CaptureError) as excinfo:
        list(source.read_packets())

    message = str(excinfo.value)
    assert "eth0" in message
    assert "Operation not permitted" in message
    assert "CAP_NET_RAW" in message


def test_a_nonexistent_interface_at_sniff_time_becomes_a_capture_error(monkeypatch) -> None:
    def _exploding_sniff(**kwargs):
        raise OSError("No such device")

    monkeypatch.setattr(network_live_source, "sniff", _exploding_sniff)

    with pytest.raises(CaptureError):
        list(NetworkLiveCaptureSource("eth0").read_packets())


# --- counters -------------------------------------------------------------


def test_counters_account_for_every_frame_seen(monkeypatch) -> None:
    arp = Ether() / ARP(pdst="192.168.50.99")
    arp.time = _CAPTURE_EPOCH
    syn = IP(src=_DEVICE_A, dst=_SERVER) / TCP(sport=1, dport=443, flags="S")
    syn.time = _CAPTURE_EPOCH

    source, packets = _capture(
        monkeypatch, [_tcp_packet(_DEVICE_A, _SERVER, 40000, 443), arp, syn]
    )

    counters = source.counters
    assert counters.seen == 3
    assert counters.yielded == 1
    assert counters.skipped_non_ip == 1
    assert counters.skipped_no_transport == 1
    assert len(packets) == 1


def test_counters_start_at_zero_and_summarize() -> None:
    counters = CaptureCounters()
    assert (counters.seen, counters.yielded, counters.parse_failures) == (0, 0, 0)
    assert "seen=0" in counters.summary()


def test_an_empty_capture_yields_nothing_and_does_not_raise(monkeypatch) -> None:
    source, packets = _capture(monkeypatch, [])
    assert packets == []
    assert source.counters.seen == 0
