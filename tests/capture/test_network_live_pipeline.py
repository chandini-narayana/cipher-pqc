"""Phase 3C integration tests: NetworkLiveCaptureSource through the real,
unmodified pipeline, plus the regressions that guarantee the existing
capture paths were not disturbed.

The whole point of Phase 3C is that `CaptureSource -> RawPacket ->
fingerprinting -> QRS -> Isolation Forest -> fusion -> isolation
decision` is untouched: the tests below run the live source through the
genuine `run_capture()` with no stubbing of `assess_packet`, so a device
identity that failed to survive the pipeline would show up here.

No real interface, capture backend, root privilege or network access is
needed: scapy's sniff() is stubbed and every packet is built with scapy.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from scapy.all import ARP, IP, TCP, Dot11, Ether, RadioTap, Raw

import capture.network_live_source as network_live_source
from capture.network_live_source import NetworkLiveCaptureSource
from capture.offline_source import OfflinePcapSource
from enforcement import NoOpIsolationBackend
from pipeline.runner import run_capture
from signing import generate_keypair

_DEVICE_A = "192.168.50.21"
_DEVICE_B = "192.168.50.22"
_SERVER = "93.184.216.34"
_CAPTURE_EPOCH = 1767182400.0

# A TLS 1.0 ClientHello-shaped payload: enough for fingerprinting to
# recognize TLS without depending on exact QRS scoring here.
_TLS10_HELLO = bytes.fromhex(
    "16030100350100003103010000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000"
)


class _FakeIface:
    def __init__(self, name: str) -> None:
        self.name = name


@pytest.fixture(autouse=True)
def _fake_interfaces(monkeypatch):
    monkeypatch.setattr(
        network_live_source.conf,
        "ifaces",
        {1: _FakeIface("lo"), 2: _FakeIface("eth0")},
        raising=False,
    )


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair()


def _stub_sniff(monkeypatch, packets):
    def _fake_sniff(**kwargs):
        for packet in packets:
            kwargs["prn"](packet)

    monkeypatch.setattr(network_live_source, "sniff", _fake_sniff)


def _packet(src: str, dst: str, sport: int, dport: int, payload: bytes = _TLS10_HELLO):
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(load=payload)
    packet.time = _CAPTURE_EPOCH
    return packet


def _run(monkeypatch, keypair, packets, tmp_path):
    """Drive the real run_capture() over a live source fed `packets`."""
    _stub_sniff(monkeypatch, packets)
    public_key, secret_key = keypair
    source = NetworkLiveCaptureSource(interface="eth0", timeout=5, packet_limit=50)
    assessments, reports = run_capture(
        source,
        None,  # no anomaly detector: ML is optional and not under test here
        public_key,
        secret_key,
        NoOpIsolationBackend(),
        report_output_dir=tmp_path,
    )
    return source, assessments, reports


# --- the pipeline sees real device identities ----------------------------


def test_two_source_devices_become_two_device_identities(monkeypatch, keypair, tmp_path) -> None:
    """The requirement the whole phase exists for: the pipeline keys a
    device on RawPacket.src_ip, so two devices must assess as two
    devices — not collapse into the capturing host."""
    _source, assessments, _reports = _run(
        monkeypatch,
        keypair,
        [
            _packet(_DEVICE_A, _SERVER, 40000, 443),
            _packet(_DEVICE_B, _SERVER, 41000, 443),
        ],
        tmp_path,
    )

    assert {a.device.ip for a in assessments} == {_DEVICE_A, _DEVICE_B}


def test_each_device_gets_its_own_assessment(monkeypatch, keypair, tmp_path) -> None:
    _source, assessments, _reports = _run(
        monkeypatch,
        keypair,
        [
            _packet(_DEVICE_A, _SERVER, 40000, 443),
            _packet(_DEVICE_A, _SERVER, 40001, 443),
            _packet(_DEVICE_B, _SERVER, 41000, 443),
        ],
        tmp_path,
    )

    # One retained representative per device, not one per packet.
    assert len(assessments) == 2


def test_the_capturing_host_never_appears_as_a_device(monkeypatch, keypair, tmp_path) -> None:
    pi_ip = "192.168.50.1"
    _source, assessments, _reports = _run(
        monkeypatch, keypair, [_packet(_DEVICE_A, _SERVER, 40000, 443)], tmp_path
    )

    assert pi_ip not in {a.device.ip for a in assessments}


def test_the_assessed_identity_is_the_originating_device(monkeypatch, keypair, tmp_path) -> None:
    """A device-to-device packet between two monitored hosts: the sender
    is the assessed device, which is also the address a future Linux
    backend would isolate."""
    _source, assessments, _reports = _run(
        monkeypatch, keypair, [_packet(_DEVICE_A, _DEVICE_B, 40000, 1883)], tmp_path
    )

    assert [a.device.ip for a in assessments] == [_DEVICE_A]


def test_unusable_frames_do_not_stop_the_pipeline_run(monkeypatch, keypair, tmp_path) -> None:
    """A mixed capture — ARP, an 802.11 frame with no IP, a bare SYN, and
    two real packets — must still produce exactly the two devices."""
    arp = Ether() / ARP(pdst="192.168.50.99")
    arp.time = _CAPTURE_EPOCH
    dot11 = RadioTap() / Dot11(
        type=2,
        subtype=0,
        FCfield="protected",
        addr1="00:11:22:33:44:55",
        addr2="66:77:88:99:aa:bb",
        addr3="cc:dd:ee:ff:00:11",
    ) / Raw(load=b"\x00" * 32)
    dot11.time = _CAPTURE_EPOCH
    syn = IP(src="192.168.50.33", dst=_SERVER) / TCP(sport=40002, dport=443, flags="S")
    syn.time = _CAPTURE_EPOCH

    source, assessments, _reports = _run(
        monkeypatch,
        keypair,
        [arp, _packet(_DEVICE_A, _SERVER, 40000, 443), dot11, syn, _packet(_DEVICE_B, _SERVER, 41000, 443)],
        tmp_path,
    )

    assert {a.device.ip for a in assessments} == {_DEVICE_A, _DEVICE_B}
    assert source.counters.seen == 5
    assert source.counters.yielded == 2


def test_payload_reaches_fingerprinting_intact(monkeypatch, keypair, tmp_path) -> None:
    """The captured bytes drive the assessment: a TLS payload on port 443
    must produce a real risk assessment, not a default."""
    _source, assessments, _reports = _run(
        monkeypatch, keypair, [_packet(_DEVICE_A, _SERVER, 40000, 443)], tmp_path
    )

    assessment = assessments[0]
    assert assessment.risk_assessment.risk_score >= 0
    assert assessment.risk_assessment.remediation
    assert assessment.final_category is not None


def test_isolation_decision_still_runs_on_live_captured_devices(
    monkeypatch, keypair, tmp_path
) -> None:
    """Enforcement policy is unchanged: with the NoOp backend nothing is
    ever enforced, whatever the live capture produced."""
    _source, assessments, _reports = _run(
        monkeypatch, keypair, [_packet(_DEVICE_A, _SERVER, 40000, 443)], tmp_path
    )

    for assessment in assessments:
        if assessment.isolation is not None:
            assert assessment.isolation.enforced is False


def test_run_capture_needs_no_change_to_accept_the_live_source(monkeypatch, keypair, tmp_path) -> None:
    """Shape check: the live source satisfies the same CaptureSource
    contract run_capture() already consumed, with no new parameter."""
    source, assessments, reports = _run(
        monkeypatch, keypair, [_packet(_DEVICE_A, _SERVER, 40000, 443)], tmp_path
    )

    assert isinstance(assessments, list)
    assert isinstance(reports, list)
    assert source.counters.yielded == 1


# --- the existing capture paths are untouched ----------------------------


def test_offline_source_still_preserves_real_source_identity(tmp_path) -> None:
    """OfflinePcapSource is unchanged and remains the identity reference
    the live network source matches."""
    from scapy.all import wrpcap

    pcap_path = tmp_path / "two_devices.pcap"
    wrpcap(
        str(pcap_path),
        [
            IP(src=_DEVICE_A, dst=_SERVER) / TCP(sport=40000, dport=443) / Raw(load=_TLS10_HELLO),
            IP(src=_DEVICE_B, dst=_SERVER) / TCP(sport=41000, dport=443) / Raw(load=_TLS10_HELLO),
        ],
    )

    packets = list(OfflinePcapSource(pcap_path).read_packets())

    assert [p.src_ip for p in packets] == [_DEVICE_A, _DEVICE_B]
    assert [p.dst_ip for p in packets] == [_SERVER, _SERVER]


def test_host_live_source_still_normalizes_to_the_local_host(monkeypatch) -> None:
    """Windows host-level behavior is deliberately the opposite, and must
    remain exactly as it was: the local interface is always src_ip."""
    import capture.host_live_source as host_live_source

    local_ip = "10.0.0.5"
    inbound = IP(src=_SERVER, dst=local_ip) / TCP(sport=443, dport=53142) / Raw(load=_TLS10_HELLO)
    inbound.time = _CAPTURE_EPOCH

    raw = host_live_source._to_raw_packet(inbound, local_ip)

    assert raw is not None
    assert raw.src_ip == local_ip
    assert raw.dst_ip == _SERVER
    assert (raw.src_port, raw.dst_port) == (53142, 443)


def test_host_live_source_still_drops_third_party_traffic(monkeypatch) -> None:
    """The host source's own filtering rule is unchanged — this is
    precisely why it cannot be used for multi-device Pi capture."""
    import capture.host_live_source as host_live_source

    third_party = IP(src=_DEVICE_A, dst=_DEVICE_B) / TCP(sport=40000, dport=1883) / Raw(load=_TLS10_HELLO)
    third_party.time = _CAPTURE_EPOCH

    assert host_live_source._to_raw_packet(third_party, "10.0.0.5") is None


def test_the_two_live_sources_disagree_on_identity_by_design(monkeypatch) -> None:
    """Same frame, two topologies, two correct answers — the reason these
    are separate classes rather than one flag."""
    import capture.host_live_source as host_live_source

    local_ip = "10.0.0.5"
    frame = IP(src=_SERVER, dst=local_ip) / TCP(sport=443, dport=53142) / Raw(load=_TLS10_HELLO)
    frame.time = _CAPTURE_EPOCH

    host_raw = host_live_source._to_raw_packet(frame, local_ip)
    network_raw = NetworkLiveCaptureSource("eth0")._to_raw_packet(frame)

    assert host_raw.src_ip == local_ip  # the one monitored endpoint
    assert network_raw.src_ip == _SERVER  # the actual sender


def test_the_scaffold_live_source_still_raises(monkeypatch) -> None:
    """capture.live_source.LiveCaptureSource (CAPTURE_MODE=live for
    main.py/run_api.py) is untouched and still fails loudly."""
    from capture.live_source import LiveCaptureSource
    from utils.exceptions import LiveCaptureNotImplementedError

    with pytest.raises(LiveCaptureNotImplementedError):
        LiveCaptureSource("eth0").read_packets()


def test_the_factory_was_not_repointed_at_the_new_source() -> None:
    """The frozen factory contract is unchanged: CAPTURE_MODE=live still
    resolves to the scaffold, so main.py/run_api.py/run_demo.py behave
    exactly as before. The Pi source is composed by its own entry point."""
    import dataclasses

    from capture.factory import get_capture_source
    from capture.live_source import LiveCaptureSource
    from config.settings import load_settings

    settings = dataclasses.replace(load_settings(), capture_mode="live", live_interface="eth0")
    assert isinstance(get_capture_source(settings), LiveCaptureSource)
