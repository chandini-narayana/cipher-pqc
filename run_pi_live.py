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
  * This is capture only. No firewall rule, no routing, no NAT, no AP
    mode, no GPIO/OLED. Isolation decisions use the existing
    NoOpIsolationBackend, exactly like every other current entry point:
    a device whose raw QRS reaches the threshold is recorded as
    isolation-requested, never physically isolated. Swapping in a real
    enforcement backend is a later, separate phase.
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
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import replace
from typing import List, Optional, Sequence

from capture.network_live_source import (
    DEFAULT_PACKET_LIMIT,
    DEFAULT_TIMEOUT_SECONDS,
    NetworkLiveCaptureSource,
    available_interface_names,
)
from config.constants import APP_NAME, APP_VERSION
from config.settings import load_settings
from enforcement import NoOpIsolationBackend
from ml.loading import load_anomaly_detector
from models.device_assessment import DeviceAssessment
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
            "(Linux/Raspberry Pi). Capture only - no firewall enforcement."
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


def _print_disclaimer(interface: str, timeout: float, packet_limit: int) -> None:
    print("")
    print(f"{APP_NAME} v{APP_VERSION} - live network capture (capture only)")
    print("-" * 62)
    print(f"Interface:     {interface}")
    print(f"Stops after:   {timeout:.0f}s or {packet_limit} packets, whichever is first")
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

    settings = load_settings()
    configure_logging(settings)
    # So /api/health and any report metadata reflect what actually ran.
    # Nothing else about Settings is altered, and no file is written.
    settings = replace(settings, capture_mode="live", live_interface=interface)

    _print_disclaimer(interface, args.timeout, args.packet_limit)

    try:
        capture_source = NetworkLiveCaptureSource(
            interface=interface,
            timeout=args.timeout,
            packet_limit=args.packet_limit,
            bpf_filter=args.bpf_filter,
        )
        anomaly_detector = load_anomaly_detector(settings.model_path)
        public_key, secret_key = load_or_create_keypair(settings.signing_key_path)
        # Capture-only phase: isolation decisions are recorded, never
        # physically enforced. A real Linux backend is swapped in at this
        # exact point in a later phase - pipeline.runner never constructs
        # a backend itself.
        isolation_backend = NoOpIsolationBackend()

        assessments, reports = run_capture(
            capture_source,
            anomaly_detector,
            public_key,
            secret_key,
            isolation_backend,
            risk_isolation_threshold=settings.risk_isolation_threshold,
        )
    except CipherError as exc:
        logger.error("Live capture run failed.", exc_info=True)
        print(f"Live capture failed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130

    _print_results(assessments, len(reports), capture_source.counters)
    return 0


if __name__ == "__main__":
    sys.exit(main())
