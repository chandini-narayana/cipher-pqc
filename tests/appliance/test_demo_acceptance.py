"""Pre-demo acceptance tests: the live appliance end to end, with only the
physical edges faked.

Real: `ApplianceCaptureWorker`, `pipeline.runner.run_capture` (entropy,
fingerprinting, QRS, fusion, should_isolate), the protected scope exactly as
`run_appliance` builds it, `IptablesIsolationBackend` behind the appliance
self-isolation guard, `ApplicationStateStore`, `HardwareOutputGate` with the
real observer fan-out and the real OLED-frame / LED-lamp mappings, and real
ML-DSA-44 signed PDF reports written to a temporary directory.

Faked: the capture source (scripted RawPackets), the iptables binary (a
stateful in-memory model), and the physical OLED panel and LED pins
(recorders). No interface, root, I2C, GPIO or network access is used.

Topology under test: Pi/AP 192.168.50.1 on the capture interface, protected
subnet 192.168.50.0/24, controlled Windows device 192.168.50.24.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import List, Optional, Sequence

import pytest

import run_appliance
from appliance.output_gate import HardwareOutputGate
from appliance.worker import ApplianceCaptureWorker
from capture.base import CaptureSource
from capture.raw_packet import RawPacket
from dashboard.serializers import serialize_device_summary
from dashboard.state_store import ApplicationStateStore
from enforcement.command_runner import CommandResult, CommandRunner
from enforcement.decision import should_isolate
from enforcement.iptables_backend import IptablesIsolationBackend
from hardware.display import StatusDisplay
from hardware.indicator import StatusIndicator
from models.anomaly_assessment import AnomalyAssessment
from models.device import Device
from models.device_assessment import DeviceAssessment
from models.enums import RiskCategory
from models.risk_assessment import RiskAssessment
from pipeline.runner import run_capture
from run_pi_live import _build_assessment_observer, _safe_display
from signing import load_or_create_keypair

PI = "192.168.50.1"
PI_MGMT = "10.20.30.40"  # the wlan0 management address, outside the lab
WINDOWS = "192.168.50.24"
OTHER_STATION = "192.168.50.77"
REMOTE = "93.184.216.34"
SUBNET = "192.168.50.0/24"

#: IAC WILL TERMINAL-TYPE, IAC DO ECHO — Telnet option negotiation.
#: TLS unknown 2 + key 0 + no PFS 1 + entropy < 6 -> 2 + Telnet 2 = QRS 7.
TELNET_TRIGGER = bytes([0xFF, 0xFB, 0x18, 0xFF, 0xFD, 0x01])

#: A DNS-shaped payload: protocol OTHER, low entropy -> QRS 5 (MEDIUM).
DNS_LIKE = (
    b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x07example\x03com\x00\x00\x01\x00\x01"
)


# --- fakes for the physical edges -------------------------------------------


class _Counters:
    def __init__(self, seen: int) -> None:
        self.seen = seen


class _ScriptedSource(CaptureSource):
    def __init__(self, packets: Sequence[RawPacket]) -> None:
        self._packets = list(packets)
        self.counters = _Counters(len(self._packets))

    def read_packets(self):
        yield from self._packets


class _Iptables(CommandRunner):
    """A stateful in-memory iptables: checks consult what actions added."""

    def __init__(self) -> None:
        self.commands: List[tuple] = []
        self.present = set()

    def run(self, command: Sequence[str]) -> CommandResult:
        argv = tuple(command)
        self.commands.append(argv)
        op, rest = argv[2], argv[3:]
        if op == "-L":
            return CommandResult(argv, True, 0 if ("CHAIN",) + rest[:1] in self.present else 1)
        if op == "-C":
            return CommandResult(argv, True, 0 if rest in self.present else 1)
        if op == "-N":
            self.present.add(("CHAIN",) + rest[:1])
        elif op in ("-A", "-I"):
            self.present.add(rest if op == "-A" else (rest[0],) + rest[2:])
        elif op == "-D":
            self.present.discard(rest)
        return CommandResult(argv, True, 0)

    def isolated_targets(self) -> List[str]:
        return [argv[5] for argv in self.commands if argv[2] == "-A"]


class _Panel(StatusDisplay):
    display_name = "panel"

    def __init__(self) -> None:
        self.frames: List[List[str]] = []

    def start(self) -> bool:
        return True

    def show_lines(self, lines) -> None:
        self.frames.append(list(lines))

    def close(self) -> None:
        pass


class _Lamps(StatusIndicator):
    indicator_name = "lamps"

    def __init__(self) -> None:
        self.lit: List[Optional[str]] = []

    def start(self) -> bool:
        return True

    def show_lamp(self, lamp) -> None:
        self.lit.append(lamp)

    def close(self) -> None:
        pass


class _AlwaysAnomalous:
    """An Isolation Forest stand-in that flags every observation."""

    def predict_one(self, features) -> AnomalyAssessment:
        return AnomalyAssessment(anomaly_score=0.9, is_anomaly=True, confidence=0.99)


def _packet(src: str, dst: str, payload: bytes, sport: int = 50000, dport: int = 2323) -> RawPacket:
    return RawPacket(src, dst, sport, dport, payload, datetime.now(timezone.utc))


# --- the appliance, composed as run_appliance composes it -------------------


@pytest.fixture
def appliance(monkeypatch, tmp_path):
    # Debian-like host: hostname resolution misses the lab address entirely.
    monkeypatch.setattr(run_appliance, "local_ipv4_addresses", lambda: {"127.0.1.1"})
    interface_addresses = {PI}

    scope = run_appliance._build_protected_scope(SUBNET, interface_addresses)
    iptables = _Iptables()
    backend = run_appliance._guard_against_self_isolation(
        IptablesIsolationBackend(command_runner=iptables, local_address_provider=lambda: {"127.0.1.1"}),
        interface_addresses,
        scope,
    )
    public_key, secret_key = load_or_create_keypair(tmp_path / "keys")

    panel, lamps = _Panel(), _Lamps()
    gate = HardwareOutputGate(
        observer=_build_assessment_observer(panel, lamps), close_calls=[], safe_call=_safe_display
    )
    store = ApplicationStateStore()
    cycles: List[List[RawPacket]] = []

    class _Appliance:
        pass

    app = _Appliance()
    app.store, app.panel, app.lamps, app.gate, app.iptables, app.scope = (
        store, panel, lamps, gate, iptables, scope,
    )
    app.cycles = cycles
    app.capture_kwargs = {
        "anomaly_detector": None,
        "public_key": public_key,
        "secret_key": secret_key,
        "isolation_backend": backend,
        "risk_isolation_threshold": 7,
        "report_output_dir": tmp_path / "reports",
        "assessment_observer": gate.observe,
        "device_resolver": scope.resolve,
    }

    def _worker(**overrides):
        kwargs = dict(app.capture_kwargs, **overrides)
        return ApplianceCaptureWorker(
            store=store,
            source_factory=lambda: _ScriptedSource(cycles.pop(0)),
            run_capture_fn=run_capture,
            capture_kwargs=kwargs,
            on_cycle_published=lambda state: gate.hold_isolated(state.list_assessments()),
        )

    app.worker = _worker
    return app


# --- the two-cycle demo scenario --------------------------------------------


def test_two_cycle_demo_isolation_stays_represented_everywhere(appliance) -> None:
    worker = appliance.worker()

    # Cycle 1: the controlled device emits the QRS-7 Telnet trigger.
    appliance.cycles.append([_packet(WINDOWS, PI, TELNET_TRIGGER), _packet(WINDOWS, PI, DNS_LIKE, dport=53)])
    assert worker.run_cycle() is True

    state = appliance.store.get()
    device = state.get_assessment(WINDOWS)
    assert device.risk_assessment.risk_score == 7
    assert device.final_category is RiskCategory.HIGH
    assert device.isolation.enforced is True
    assert serialize_device_summary(device, True)["isolation"]["status"] == "Enforced"
    report1_path, report1 = state.get_report(WINDOWS)
    assert report1_path.exists() and report1.verification_status
    assert appliance.panel.frames[-1][-1] == "Isolation: ISOLATED"
    assert appliance.panel.frames[-1][3] == "Risk: HIGH"
    assert appliance.lamps.lit[-1] == "red"
    assert appliance.iptables.isolated_targets() == [WINDOWS, WINDOWS]  # -s and -d

    time.sleep(1.1)  # report filenames carry a whole-second timestamp

    # Cycle 2: the isolated device produces only MEDIUM traffic, and the Pi
    # answers it.
    appliance.cycles.append(
        [_packet(WINDOWS, PI, DNS_LIKE, dport=53), _packet(PI, WINDOWS, DNS_LIKE, sport=53)]
    )
    assert worker.run_cycle() is True

    state = appliance.store.get()
    device = state.get_assessment(WINDOWS)
    assert device.isolation is not None and device.isolation.enforced is True
    assert device.final_category is RiskCategory.HIGH
    assert serialize_device_summary(device, True)["isolation"]["status"] == "Enforced"
    assert state.get_report(WINDOWS)[1].report_id == report1.report_id
    assert appliance.panel.frames[-1][-1] == "Isolation: ISOLATED"
    assert appliance.lamps.lit[-1] == "red"
    assert set(state.assessments_by_ip) == {WINDOWS}  # the Pi never became a device


def test_before_isolation_the_lamps_follow_the_category(appliance) -> None:
    worker = appliance.worker()
    appliance.cycles.append([_packet(WINDOWS, PI, DNS_LIKE, dport=53)])

    worker.run_cycle()

    assert appliance.lamps.lit[-1] == "amber"
    assert appliance.panel.frames[-1][-1] == "Isolation: N/A"
    assert appliance.gate.held is None
    assert appliance.iptables.commands == []


# --- attribution on the routed AP topology (M1, M3, S3) ---------------------


@pytest.mark.parametrize(
    "src,dst,expected",
    [
        (WINDOWS, PI, WINDOWS),             # Windows -> Pi
        (WINDOWS, REMOTE, WINDOWS),         # Windows -> Internet
        (REMOTE, WINDOWS, WINDOWS),         # Internet -> Windows (return traffic)
        (PI, WINDOWS, WINDOWS),             # Pi -> Windows
        (WINDOWS, OTHER_STATION, WINDOWS),  # station -> station: the sender
        (OTHER_STATION, WINDOWS, OTHER_STATION),
        (PI, "192.168.50.255", None),       # subnet broadcast
        (PI, "192.168.50.0", None),         # network address
        (REMOTE, "192.168.50.255", None),
        (PI, REMOTE, None),                 # Pi/self traffic
        (REMOTE, PI, None),
        (WINDOWS, "255.255.255.255", WINDOWS),
    ],
)
def test_attribution_matrix(appliance, src, dst, expected) -> None:
    assert appliance.scope.resolve(src, dst) == expected


def test_only_the_protected_device_ever_becomes_a_device(appliance) -> None:
    worker = appliance.worker()
    appliance.cycles.append(
        [
            _packet(WINDOWS, REMOTE, DNS_LIKE, dport=53),
            _packet(REMOTE, WINDOWS, DNS_LIKE, sport=53),
            _packet(PI, WINDOWS, DNS_LIKE, sport=53),
            _packet(WINDOWS, PI, DNS_LIKE, dport=53),
            _packet(PI, "192.168.50.255", DNS_LIKE),
            _packet(PI, REMOTE, DNS_LIKE),
        ]
    )

    worker.run_cycle()

    assert set(appliance.store.get().assessments_by_ip) == {WINDOWS}


# --- security acceptance -----------------------------------------------------


def test_an_ml_anomaly_alone_cannot_trigger_isolation(appliance) -> None:
    """QRS 5 escalated to a final HIGH by the anomaly detector: displayed as
    HIGH, never isolated."""
    worker = appliance.worker(anomaly_detector=_AlwaysAnomalous())
    appliance.cycles.append([_packet(WINDOWS, PI, DNS_LIKE, dport=53)])

    worker.run_cycle()

    device = appliance.store.get().get_assessment(WINDOWS)
    assert device.risk_assessment.risk_score == 5
    assert device.anomaly_assessment.is_anomaly is True
    assert device.final_category is RiskCategory.HIGH
    assert device.isolation is None
    assert appliance.iptables.commands == []
    assert appliance.gate.held is None


def test_a_final_high_category_alone_does_not_authorize_isolation() -> None:
    assessment = DeviceAssessment(
        device=Device.first_contact(WINDOWS, datetime.now(timezone.utc)),
        risk_assessment=RiskAssessment(6, RiskCategory.MEDIUM, "r", "n"),
        anomaly_assessment=AnomalyAssessment(0.9, True, 0.99),
        final_category=RiskCategory.HIGH,
        assessed_at=datetime.now(timezone.utc),
    )
    assert should_isolate(assessment, 7) is False


@pytest.mark.parametrize("score,eligible", [(6, False), (7, True), (10, True)])
def test_only_raw_qrs_of_seven_or_more_authorizes_isolation(score, eligible) -> None:
    assessment = DeviceAssessment(
        device=Device.first_contact(WINDOWS, datetime.now(timezone.utc)),
        risk_assessment=RiskAssessment(
            score, RiskCategory.HIGH if score >= 7 else RiskCategory.MEDIUM, "r", "n"
        ),
        anomaly_assessment=None,
        final_category=RiskCategory.LOW,  # deliberately inconsistent: must not matter
        assessed_at=datetime.now(timezone.utc),
    )
    assert should_isolate(assessment, 7) is eligible


def test_the_pi_addresses_cannot_be_isolated(appliance) -> None:
    backend = appliance.capture_kwargs["isolation_backend"]

    for address in (PI, PI_MGMT, "127.0.1.1"):
        outcome = backend.isolate(address, 10)
        assert outcome.enforced is False, address

    assert appliance.iptables.commands == []


def test_a_qrs_seven_packet_from_the_pi_never_isolates_the_pi(appliance) -> None:
    """The Pi sending Telnet negotiation to Windows attributes to Windows."""
    worker = appliance.worker()
    appliance.cycles.append([_packet(PI, WINDOWS, TELNET_TRIGGER, sport=23)])

    worker.run_cycle()

    assert PI not in appliance.iptables.isolated_targets()
    assert set(appliance.iptables.isolated_targets()) == {WINDOWS}


def test_a_remote_internet_host_never_becomes_an_isolation_target(appliance) -> None:
    worker = appliance.worker()
    appliance.cycles.append(
        [
            _packet(REMOTE, WINDOWS, TELNET_TRIGGER, sport=23),
            _packet(REMOTE, "192.168.50.255", TELNET_TRIGGER),
            _packet(REMOTE, PI, TELNET_TRIGGER),
        ]
    )

    worker.run_cycle()

    targets = set(appliance.iptables.isolated_targets())
    assert REMOTE not in targets
    assert targets <= {WINDOWS}
    assert REMOTE not in appliance.store.get().assessments_by_ip


@pytest.mark.parametrize("address", ["192.168.50.0", "192.168.50.255", "255.255.255.255"])
def test_network_and_broadcast_addresses_never_become_devices_or_targets(appliance, address) -> None:
    worker = appliance.worker()
    appliance.cycles.append([_packet(PI, address, TELNET_TRIGGER), _packet(REMOTE, address, TELNET_TRIGGER)])

    worker.run_cycle()

    assert address not in appliance.store.get().assessments_by_ip
    assert appliance.iptables.commands == []
    assert appliance.capture_kwargs["isolation_backend"].isolate(address, 10).enforced is False
