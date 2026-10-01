"""run_pi_live.py — CIPHER Linux/Raspberry-Pi live network capture run.

A fifth composition root, alongside main.py (offline, run-and-exit),
run_api.py (API-only dev server), run_demo.py (integrated offline demo)
and run_live_demo.py (host-level WINDOWS live demo). None of those are
modified or replaced by this script.

Why a separate entry point rather than extending run_live_demo.py:
run_live_demo.py is explicitly and documentedly host-level Windows
capture, and it normalizes device identity to the local machine — the
one monitored endpoint on that topology. This script does the opposite,
because it must: on a monitored network path, each distinct source
address is a different device, and that address is the identity a later
Linux enforcement backend would act on. Overloading one entry point with
both identity semantics would leave the Windows demo one wrong flag away
from attributing traffic to the wrong host.

What this does: captures IP-visible frames from ONE explicitly-named
interface, feeds them through the SAME unmodified production pipeline
(fingerprinting, entropy, QRS, optional Isolation Forest, risk fusion,
isolation decision, signed PDF reporting), then prints a summary with
capture counters and per-device results.

SCOPE — read before running:
  * Enforcement is OFF by default. Without `--enforcement iptables`
    this script uses NoOpIsolationBackend exactly like every other entry
    point: a device whose raw QRS reaches the threshold is recorded as
    isolation-requested and never physically isolated. Real enforcement
    is never implicit — it requires that explicit flag (or
    CIPHER_ENFORCEMENT=iptables) and a Linux host.
  * With `--enforcement iptables`, a device whose RAW QRS reaches the
    threshold gets DROP rules in the CIPHER-owned `CIPHER_ISOLATION`
    chain, jumped from `FORWARD`. The eligibility rule is unchanged and
    lives in enforcement/decision.py; an ML category escalation alone
    still cannot isolate anything. CIPHER never flushes a chain, never
    changes a default policy, and never removes a rule it did not add.
    The rule only affects traffic that actually traverses this host: a
    passive monitor interface observes traffic, it does not forward it,
    so on a monitor-only topology the rule is installed and drops
    nothing. No routing, NAT or AP mode is configured by CIPHER.
  * It performs NO WPA/WPA2/WPA3 decryption, NO deauthentication, and NO
    credential capture. A monitor-mode frame is processed only if it
    already exposes a decodable IP layer; a protected frame that does
    not is skipped.
  * Run it only on an interface whose traffic is legitimately available
    to this host: a controlled test network, an authorized mirror/tap, or
    a path this host is explicitly authorized to observe. The interface
    is always named explicitly on the command line — this script
    defaults to none and touches no management interface.
  * Live capture normally requires root or CAP_NET_RAW.

Usage:

    python run_pi_live.py --list-interfaces
    python run_pi_live.py --interface eth0 --timeout 60 --packet-limit 1000
    python run_pi_live.py --interface eth0 --enforcement iptables   # real DROP rules
"""
from __future__ import annotations

import argparse
import logging
import os
import platform
import sys
from dataclasses import replace
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from capture.network_live_source import (
    DEFAULT_PACKET_LIMIT,
    DEFAULT_TIMEOUT_SECONDS,
    NetworkLiveCaptureSource,
    available_interface_names,
)
from config.constants import APP_NAME, APP_VERSION
from config.settings import load_settings
from enforcement import (
    BUILTIN_CHAIN,
    CIPHER_CHAIN,
    IptablesIsolationBackend,
    NoOpIsolationBackend,
)
from enforcement.backends import IsolationBackend
from enforcement.subprocess_runner import SubprocessCommandRunner
from hardware import NoOpStatusDisplay, SSD1306StatusDisplay, StatusDisplay
from ml.loading import load_anomaly_detector
from models.device_assessment import DeviceAssessment
from models.report_metadata import ReportMetadata
from pipeline.runner import run_capture
from signing import load_or_create_keypair
from utils.exceptions import CipherError
from utils.logging_setup import configure_logging

logger = logging.getLogger(__name__)


def _parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="run_pi_live.py",
        description=(
            "CIPHER live network capture on one explicitly-named interface "
            "(Linux/Raspberry Pi). Enforcement is off unless --enforcement "
            "iptables is given explicitly."
        ),
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List the interface names scapy can see on this host, then exit.",
    )
    parser.add_argument(
        "--interface",
        default=None,
        help=(
            "Exact interface name to capture on, e.g. eth0 (see --list-interfaces). "
            "May also be given as the PI_CAPTURE_INTERFACE environment variable. "
            "Required: no interface is ever defaulted."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Stop capturing after this many seconds (default: {DEFAULT_TIMEOUT_SECONDS}).",
    )
    parser.add_argument(
        "--packet-limit",
        type=int,
        default=DEFAULT_PACKET_LIMIT,
        help=f"Stop after this many captured packets (default: {DEFAULT_PACKET_LIMIT}).",
    )
    parser.add_argument(
        "--enforcement",
        choices=("noop", "iptables"),
        default=None,
        help=(
            "Enforcement backend. 'noop' (the default) records isolation decisions "
            "without touching any firewall. 'iptables' installs real DROP rules for "
            "isolated devices in the CIPHER-owned chain; it requires Linux and root "
            "(or CAP_NET_ADMIN) and is never selected implicitly. May also be given "
            "as the CIPHER_ENFORCEMENT environment variable."
        ),
    )
    parser.add_argument(
        "--display",
        choices=("none", "oled"),
        default=None,
        help=(
            "Status display. 'none' (the default) renders nothing. 'oled' drives an "
            "SSD1306 panel over I2C on a Raspberry Pi; it is optional, output-only, "
            "and a display fault never affects capture or enforcement. May also be "
            "given as the CIPHER_DISPLAY environment variable."
        ),
    )
    parser.add_argument(
        "--filter",
        dest="bpf_filter",
        default=None,
        help=(
            "Optional BPF capture filter passed through to the capture backend "
            "(e.g. 'ip'). Omitted by default - filtering decisions are the "
            "operator's, not this script's."
        ),
    )
    return parser.parse_args(argv)


def _print_interface_table() -> None:
    names = available_interface_names()
    print("Interfaces visible to scapy on this host:")
    if not names:
        print("  (none found)")
        return
    for name in names:
        print(f"  {name}")


def _build_isolation_backend(mode: str) -> IsolationBackend:
    """Construct the selected backend. Real enforcement is explicit and
    Linux-only; everything else gets the non-enforcing NoOp backend.

    The platform guard matters: it is the reason a Windows run of this
    script, or a Windows test importing it, cannot execute a firewall
    command even if 'iptables' were somehow passed.
    """
    if mode != "iptables":
        return NoOpIsolationBackend()

    if platform.system() != "Linux":
        raise CipherError(
            "--enforcement iptables requires Linux. This host reports "
            f"{platform.system()!r}; refusing to attempt firewall enforcement. "
            "Use the default (noop) for capture-only testing."
        )

    # The only place in CIPHER that composes an executing command runner.
    # Constructing it here, explicitly, is what makes real enforcement
    # possible at all - no backend reaches it on its own.
    return IptablesIsolationBackend(command_runner=SubprocessCommandRunner())


def _build_status_display(mode: str) -> StatusDisplay:
    """Construct the selected status display.

    The real panel is explicit and Linux-only, for the same reason the
    iptables backend is: a Windows run (or a Windows test that imports this
    module) must not reach for an I2C bus. A display is never enabled
    implicitly, and `NoOpStatusDisplay` is the default.
    """
    if mode != "oled":
        return NoOpStatusDisplay()

    if platform.system() != "Linux":
        logger.warning(
            "--display oled requires Linux; this host reports %r. Continuing with "
            "no status display.",
            platform.system(),
        )
        return NoOpStatusDisplay()

    return SSD1306StatusDisplay()


def _print_disclaimer(
    interface: str, timeout: float, packet_limit: int, enforcement: str
) -> None:
    print("")
    print(f"{APP_NAME} v{APP_VERSION} - live network capture (capture only)")
    print("-" * 62)
    print(f"Interface:     {interface}")
    print(f"Stops after:   {timeout:.0f}s or {packet_limit} packets, whichever is first")
    if enforcement == "iptables":
        print("Enforcement:   IPTABLES - real DROP rules will be installed for")
        print("               devices whose RAW QRS reaches the isolation threshold,")
        print(f"               in the CIPHER-owned {CIPHER_CHAIN} chain ({BUILTIN_CHAIN} only).")
        print("               CIPHER never flushes a chain, never changes a default")
        print("               policy, and never removes a rule it did not add.")
        print("               Effective only for traffic that traverses this host.")
    else:
        print("Enforcement:   NONE - isolation decisions are recorded, never enforced")
    print("Decryption:    NONE - no WPA/WPA2/WPA3 decryption, no deauthentication")
    print("Device identity is each packet's own source IP address, never this host's.")
    print("Run this only on an interface you are authorized to capture on.")
    print("-" * 62)
    print("")


def _print_results(assessments: List[DeviceAssessment], report_count: int, counters) -> None:
    print("")
    print(f"Capture complete: {counters.summary()}")
    print(f"Devices assessed: {len(assessments)}   Reports generated: {report_count}")
    if not assessments:
        print("No IP-visible packets with an analyzable payload were captured.")
        return

    print("")
    print(f"{'Device IP':<18}{'QRS':<6}{'Category':<10}Isolation")
    for assessment in sorted(assessments, key=lambda a: a.device.ip):
        isolation = assessment.isolation
        status = "Not requested" if isolation is None else isolation.status_label
        print(
            f"{assessment.device.ip:<18}"
            f"{assessment.risk_assessment.risk_score:<6}"
            f"{assessment.final_category.value:<10}"
            f"{status}"
        )


def _safe_display(action: str, call, *args) -> None:
    """Call a display method, swallowing anything it raises.

    Every CIPHER display implementation is contractually forbidden from
    raising, so this is defence in depth rather than expected flow: the
    display is an optional output device, and not even a misbehaving one
    may take down a capture run.
    """
    try:
        call(*args)
    except Exception:  # noqa: BLE001 - an output device never fails the run
        logger.warning("Status display %s failed; continuing without it.", action, exc_info=True)


def _show_final_frames(
    display: StatusDisplay,
    assessments: Optional[List[DeviceAssessment]],
    reports: Optional[List[Tuple[Path, ReportMetadata]]],
) -> None:
    """Show each device's final state — now carrying the isolation state
    that is attached at end of capture — then a run summary.

    `isolated_count` counts only assessments the backend itself marked
    `enforced`; nothing here judges whether isolation should have happened.
    Called from a finally block, so an interrupted or failed run leaves the
    panel in a sane state instead of frozen mid-capture.
    """
    if assessments is None:
        display.show_lines(["CIPHER", "Status: STOPPED"])
        return

    for assessment in sorted(assessments, key=lambda a: a.device.ip):
        display.show_assessment(assessment)

    isolated_count = sum(
        1
        for assessment in assessments
        if assessment.isolation is not None and assessment.isolation.enforced
    )
    display.show_summary(len(assessments), len(reports or []), isolated_count)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    if args.list_interfaces:
        _print_interface_table()
        return 0

    interface = args.interface or os.environ.get("PI_CAPTURE_INTERFACE") or None
    if not interface:
        print(
            "No interface specified. Pass --interface <name> (or set "
            "PI_CAPTURE_INTERFACE). Run `python run_pi_live.py --list-interfaces` "
            "to see what this host can capture on.",
            file=sys.stderr,
        )
        return 2

    enforcement_mode = (
        args.enforcement or os.environ.get("CIPHER_ENFORCEMENT") or "noop"
    ).lower()
    if enforcement_mode not in ("noop", "iptables"):
        print(
            f"Unrecognized enforcement mode {enforcement_mode!r}. "
            "Expected 'noop' or 'iptables'.",
            file=sys.stderr,
        )
        return 2

    display_mode = (args.display or os.environ.get("CIPHER_DISPLAY") or "none").lower()
    if display_mode not in ("none", "oled"):
        print(
            f"Unrecognized display mode {display_mode!r}. Expected 'none' or 'oled'.",
            file=sys.stderr,
        )
        return 2

    settings = load_settings()
    configure_logging(settings)
    # So /api/health and any report metadata reflect what actually ran.
    # Nothing else about Settings is altered, and no file is written.
    settings = replace(settings, capture_mode="live", live_interface=interface)

    _print_disclaimer(interface, args.timeout, args.packet_limit, enforcement_mode)

    # Output-only, optional, and never fatal: if the panel cannot be opened
    # the run continues with no display at all.
    display = _build_status_display(display_mode)
    _safe_display("start", display.start)
    _safe_display("ready frame", display.show_ready, interface, enforcement_mode)
    assessments: Optional[List[DeviceAssessment]] = None
    reports: Optional[List[Tuple[Path, ReportMetadata]]] = None

    try:
        isolation_backend = _build_isolation_backend(enforcement_mode)
        capture_source = NetworkLiveCaptureSource(
            interface=interface,
            timeout=args.timeout,
            packet_limit=args.packet_limit,
            bpf_filter=args.bpf_filter,
        )
        anomaly_detector = load_anomaly_detector(settings.model_path)
        public_key, secret_key = load_or_create_keypair(settings.signing_key_path)

        assessments, reports = run_capture(
            capture_source,
            anomaly_detector,
            public_key,
            secret_key,
            isolation_backend,
            risk_isolation_threshold=settings.risk_isolation_threshold,
            # pipeline.runner wraps every observer call in its own
            # try/except, so a display fault here cannot cost a packet.
            assessment_observer=display.show_assessment,
        )
    except CipherError as exc:
        logger.error("Live capture run failed.", exc_info=True)
        print(f"Live capture failed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    finally:
        # Runs on success, failure and interrupt alike, so the panel never
        # keeps showing a stale mid-capture frame.
        _safe_display("final frames", _show_final_frames, display, assessments, reports)
        _safe_display("shutdown", display.close)

    _print_results(assessments, len(reports), capture_source.counters)
    return 0


if __name__ == "__main__":
    sys.exit(main())
