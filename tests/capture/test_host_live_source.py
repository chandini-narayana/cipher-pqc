"""Unit tests for capture.host_live_source — the temporary host-level
Windows live-capture implementation used only by run_live_demo.py.

scapy's own sniff() is always mocked here: no test in this file
requires a real network interface, Npcap, or elevated privileges.
"""
from __future__ import annotations

import threading

import pytest
from scapy.all import ARP, IP, TCP, UDP

import capture.host_live_source as host_live_source
from capture.base import CaptureSource
from capture.host_live_source import (
    InterfaceInfo,
    LiveCaptureSource,
    check_capture_backend_available,
    list_interfaces,
    resolve_interface,
)
from capture.raw_packet import RawPacket
from utils.exceptions import CaptureError


def _fake_interfaces():
    return [
        InterfaceInfo(index=1, name="Loopback", description="Software Loopback", ipv4="127.0.0.1"),
        InterfaceInfo(index=3, name="Wi-Fi", description="Test Wireless NIC", ipv4="10.0.0.5"),
    ]


@pytest.fixture(autouse=True)
def _stub_interfaces_and_backend(monkeypatch):
    """Every test in this file runs against a fixed, fake interface
    list and a healthy capture backend unless it explicitly overrides
    one of these — no test depends on this machine's real adapters."""
    monkeypatch.setattr(host_live_source, "list_interfaces", _fake_interfaces)
    monkeypatch.setattr(host_live_source.conf, "use_pcap", True, raising=False)


def _make_sniff_stub(packets, kwargs_out):
    """Build a fake scapy.sniff() that records the kwargs it was called
    with and synchronously feeds `packets` through the `prn` callback
    before returning — simulating a fast, complete capture without any
    real timing or threading race."""

    def _fake_sniff(**kwargs):
        kwargs_out.update(kwargs)
        prn = kwargs["prn"]
        for pkt in packets:
            prn(pkt)

    return _fake_sniff


# --- interface discovery / validation --------------------------------------


def test_resolve_interface_finds_exact_match() -> None:
    info = resolve_interface("Wi-Fi")
    assert info.name == "Wi-Fi"
    assert info.ipv4 == "10.0.0.5"


def test_resolve_interface_raises_clear_failure_for_unknown_name() -> None:
    with pytest.raises(CaptureError, match="was not found"):
        resolve_interface("NoSuchAdapter")


def test_check_capture_backend_available_raises_when_pcap_missing(monkeypatch) -> None:
    monkeypatch.setattr(host_live_source.conf, "use_pcap", False, raising=False)
    with pytest.raises(CaptureError, match="Npcap"):
        check_capture_backend_available()


def test_check_capture_backend_available_passes_when_pcap_present() -> None:
    check_capture_backend_available()  # must not raise (autouse fixture sets use_pcap=True)


# --- LiveCaptureSource construction -----------------------------------------


def test_satisfies_capture_source_interface() -> None:
    source = LiveCaptureSource(interface="Wi-Fi")
    assert isinstance(source, CaptureSource)


def test_construction_raises_for_invalid_interface() -> None:
    with pytest.raises(CaptureError, match="was not found"):
        LiveCaptureSource(interface="NoSuchAdapter")


def test_construction_raises_for_unavailable_backend(monkeypatch) -> None:
    monkeypatch.setattr(host_live_source.conf, "use_pcap", False, raising=False)
    with pytest.raises(CaptureError, match="Npcap"):
        LiveCaptureSource(interface="Wi-Fi")


def test_construction_raises_for_empty_interface() -> None:
    with pytest.raises(CaptureError, match="interface"):
        LiveCaptureSource(interface="")


@pytest.mark.parametrize("bad_value", [0, -1])
def test_construction_raises_for_non_positive_timeout(bad_value) -> None:
    with pytest.raises(CaptureError, match="timeout"):
        LiveCaptureSource(interface="Wi-Fi", timeout=bad_value)


@pytest.mark.parametrize("bad_value", [0, -5])
def test_construction_raises_for_non_positive_packet_limit(bad_value) -> None:
    with pytest.raises(CaptureError, match="packet_limit"):
        LiveCaptureSource(interface="Wi-Fi", packet_limit=bad_value)


# --- interface / bound propagation into scapy.sniff -------------------------


def test_selected_interface_propagated_to_sniff(monkeypatch) -> None:
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub([], kwargs_out))

    source = LiveCaptureSource(interface="Wi-Fi", timeout=5, packet_limit=10)
    list(source.read_packets())

    assert kwargs_out["iface"] == "Wi-Fi"


def test_timeout_propagated_to_sniff(monkeypatch) -> None:
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub([], kwargs_out))

    source = LiveCaptureSource(interface="Wi-Fi", timeout=17.5, packet_limit=10)
    list(source.read_packets())

    assert kwargs_out["timeout"] == 17.5


def test_packet_limit_propagated_to_sniff(monkeypatch) -> None:
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub([], kwargs_out))

    source = LiveCaptureSource(interface="Wi-Fi", timeout=5, packet_limit=42)
    list(source.read_packets())

    assert kwargs_out["count"] == 42


def test_sniff_is_never_run_in_promiscuous_mode(monkeypatch) -> None:
    """Host-level scope, not a full network tap — see module docstring."""
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub([], kwargs_out))

    source = LiveCaptureSource(interface="Wi-Fi")
    list(source.read_packets())

    assert kwargs_out["promisc"] is False


# --- RawPacket conversion / streaming ---------------------------------------


def test_scapy_packet_converted_to_raw_packet(monkeypatch) -> None:
    """Outbound packet (local is the IP source): fields pass through
    unchanged — see the dedicated normalization tests below for the
    inbound (swapped) case."""
    tcp_packet = IP(src="10.0.0.5", dst="192.168.1.1") / TCP(sport=51000, dport=443) / (
        b"\x16\x03\x03\x00\x10" + b"A" * 16
    )
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub([tcp_packet], kwargs_out))

    source = LiveCaptureSource(interface="Wi-Fi")
    packets = list(source.read_packets())

    assert len(packets) == 1
    raw = packets[0]
    assert isinstance(raw, RawPacket)
    assert raw.src_ip == "10.0.0.5"
    assert raw.dst_ip == "192.168.1.1"
    assert raw.src_port == 51000
    assert raw.dst_port == 443
    assert raw.payload.startswith(b"\x16\x03\x03")


def test_packets_captured_counter_matches_yielded_count(monkeypatch) -> None:
    packets = [
        IP(src="10.0.0.5", dst="192.168.1.1") / TCP(sport=51010, dport=80) / b"GET / HTTP/1.1\r\n\r\n",
        IP(src="192.168.1.61", dst="10.0.0.5") / UDP(sport=1883, dport=51020) / b"MQTT",
    ]
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub(packets, kwargs_out))

    source = LiveCaptureSource(interface="Wi-Fi")
    yielded = list(source.read_packets())

    assert source.packets_captured == len(yielded) == 2


def test_empty_payload_and_non_ip_packets_are_filtered_like_offline_mode(monkeypatch) -> None:
    packets = [
        IP(src="10.0.0.5", dst="192.168.1.1") / TCP(sport=51030, dport=22),  # bare SYN, no payload
        ARP(psrc="192.168.1.71", pdst="192.168.1.1"),  # no IP layer
        IP(src="10.0.0.5", dst="192.168.1.1") / TCP(sport=51040, dport=443) / b"payload",
    ]
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub(packets, kwargs_out))

    source = LiveCaptureSource(interface="Wi-Fi")
    yielded = list(source.read_packets())

    assert len(yielded) == 1
    assert yielded[0].dst_port == 443


def test_read_packets_is_a_fresh_generator_each_call(monkeypatch) -> None:
    packets = [IP(src="10.0.0.5", dst="192.168.1.1") / TCP(sport=51050, dport=443) / b"x"]
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub(packets, kwargs_out))

    source = LiveCaptureSource(interface="Wi-Fi")
    first_pass = list(source.read_packets())
    second_pass = list(source.read_packets())
    assert len(first_pass) == 1
    assert len(second_pass) == 1


# --- device-identity normalization (host-live-specific) ---------------------
#
# Host-level capture sees BOTH directions of the monitored host's own
# traffic (local->remote and remote->local). The unmodified downstream
# pipeline identifies a "device" by RawPacket.src_ip, so every captured
# packet is normalized around the interface's own local IPv4 address —
# see capture/host_live_source.py's module docstring and
# _to_raw_packet's docstring. This is deliberately NOT applied to
# capture/offline_source.py, where distinct src_ip values genuinely are
# distinct monitored IoT devices.


def test_outbound_packet_keeps_local_host_as_src_ip(monkeypatch) -> None:
    packet = IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=53142, dport=443) / b"client-hello"
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub([packet], kwargs_out))

    yielded = list(LiveCaptureSource(interface="Wi-Fi").read_packets())

    assert len(yielded) == 1
    assert yielded[0].src_ip == "10.0.0.5"
    assert yielded[0].dst_ip == "93.184.216.34"


def test_inbound_packet_is_normalized_with_local_host_as_src_ip(monkeypatch) -> None:
    packet = IP(src="93.184.216.34", dst="10.0.0.5") / TCP(sport=443, dport=53142) / b"server-hello"
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub([packet], kwargs_out))

    yielded = list(LiveCaptureSource(interface="Wi-Fi").read_packets())

    assert len(yielded) == 1
    raw = yielded[0]
    assert raw.src_ip == "10.0.0.5"
    assert raw.dst_ip == "93.184.216.34"


def test_inbound_payload_bytes_are_preserved_unchanged(monkeypatch) -> None:
    inbound_payload = b"\x16\x03\x03\x00\x20" + b"SERVERHELLO-CERTIFICATE-BYTES..."
    packet = IP(src="93.184.216.34", dst="10.0.0.5") / TCP(sport=443, dport=53142) / inbound_payload
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub([packet], kwargs_out))

    yielded = list(LiveCaptureSource(interface="Wi-Fi").read_packets())

    assert yielded[0].payload == inbound_payload


def test_port_semantics_preserve_remote_service_port_in_both_directions(monkeypatch) -> None:
    outbound = IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=53142, dport=443) / b"client-hello"
    inbound = IP(src="93.184.216.34", dst="10.0.0.5") / TCP(sport=443, dport=53142) / b"server-hello"
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub([outbound, inbound], kwargs_out))

    yielded = list(LiveCaptureSource(interface="Wi-Fi").read_packets())

    assert len(yielded) == 2
    for raw in yielded:
        assert raw.src_ip == "10.0.0.5"
        assert raw.src_port == 53142
        assert raw.dst_ip == "93.184.216.34"
        assert raw.dst_port == 443  # remote HTTPS service port, both directions


def test_packet_unrelated_to_local_interface_is_discarded(monkeypatch) -> None:
    """Traffic between two other hosts (e.g. a LAN broadcast/multicast
    neither sent by nor addressed to this interface) is not a second
    monitored device — it's simply not ours to report."""
    packet = IP(src="192.168.1.2", dst="192.168.1.3") / TCP(sport=1234, dport=443) / b"unrelated"
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub([packet], kwargs_out))

    yielded = list(LiveCaptureSource(interface="Wi-Fi").read_packets())

    assert yielded == []


def test_multiple_remote_servers_produce_same_monitored_device_identity(monkeypatch) -> None:
    packets = [
        IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=50000, dport=443) / b"a",
        IP(src="52.2.2.2", dst="10.0.0.5") / TCP(sport=443, dport=50010) / b"b",
        IP(src="10.0.0.5", dst="140.82.112.3") / TCP(sport=50020, dport=443) / b"c",
    ]
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub(packets, kwargs_out))

    yielded = list(LiveCaptureSource(interface="Wi-Fi").read_packets())

    assert len(yielded) == 3
    assert {raw.src_ip for raw in yielded} == {"10.0.0.5"}  # one identity
    assert {raw.dst_ip for raw in yielded} == {"93.184.216.34", "52.2.2.2", "140.82.112.3"}


def test_construction_fails_clearly_when_interface_has_no_ipv4(monkeypatch) -> None:
    def _interfaces_without_ipv4():
        return [InterfaceInfo(index=16, name="No-IP-Adapter", description="", ipv4=None)]

    monkeypatch.setattr(host_live_source, "list_interfaces", _interfaces_without_ipv4)

    with pytest.raises(CaptureError, match="no IPv4 address"):
        LiveCaptureSource(interface="No-IP-Adapter")


def test_offline_pcap_source_has_no_coupling_to_host_live_normalization() -> None:
    """Static confirmation that OfflinePcapSource (frozen) was never
    touched to reference this module's local-IP normalization."""
    import ast
    import inspect

    from capture import offline_source

    tree = ast.parse(inspect.getsource(offline_source))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    assert "capture.host_live_source" not in imported


# --- capture-backend / sniff failures propagate clearly ---------------------


def test_sniff_failure_raises_capture_error(monkeypatch) -> None:
    def _raising_sniff(**kwargs):
        raise OSError("Npcap driver not responding")

    monkeypatch.setattr(host_live_source, "sniff", _raising_sniff)

    source = LiveCaptureSource(interface="Wi-Fi")
    with pytest.raises(CaptureError, match="Live capture failed"):
        list(source.read_packets())


# --- clean shutdown ----------------------------------------------------------


def test_background_thread_is_joined_after_generator_completes(monkeypatch) -> None:
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub([], kwargs_out))

    source = LiveCaptureSource(interface="Wi-Fi")
    list(source.read_packets())

    assert not any(
        t.name == "cipher-live-sniff" and t.is_alive() for t in threading.enumerate()
    )


def test_keyboard_interrupt_during_iteration_propagates_and_cleans_up(monkeypatch) -> None:
    """Ctrl+C must stop cleanly: the generator's `finally` still signals
    stop_event and joins the background thread even when the consumer
    raises KeyboardInterrupt mid-iteration."""
    packets = [
        IP(src="10.0.0.5", dst="192.168.1.1") / TCP(sport=51060, dport=443) / b"x",
        IP(src="10.0.0.5", dst="192.168.1.1") / TCP(sport=51070, dport=443) / b"y",
    ]
    kwargs_out = {}
    monkeypatch.setattr(host_live_source, "sniff", _make_sniff_stub(packets, kwargs_out))

    source = LiveCaptureSource(interface="Wi-Fi")
    generator = source.read_packets()
    next(generator)  # consume one packet successfully

    with pytest.raises(KeyboardInterrupt):
        generator.throw(KeyboardInterrupt)

    # The generator's finally block must have run (stop_event set,
    # thread joined) without swallowing the KeyboardInterrupt itself.
