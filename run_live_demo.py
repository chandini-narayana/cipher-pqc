"""run_live_demo.py — CIPHER TEMPORARY host-level Windows live-capture demo.

A fourth, separate composition root alongside main.py (offline,
run-and-exit), run_api.py (API-only dev server), and run_demo.py
(integrated offline demo) — none of which are modified or replaced by
this script. Captures live traffic visible to one selected host network
interface, runs it through the SAME unmodified production pipeline
(fingerprinting, entropy, QRS, optional Isolation Forest, risk fusion,
enforcement decision, PDF reporting) that the offline path uses, then
serves the same integrated React UI + REST API used by run_demo.py —
on a separate default port (5010) so it never conflicts with a
concurrently running `Start CIPHER.bat` / run_demo.py on port 5000.

SCOPE — read before running (also printed at startup):
this is HOST-LEVEL WINDOWS LIVE CAPTURE — packets visible to the
selected host network interface, captured non-promiscuously via
scapy/Npcap. It is NOT Raspberry Pi monitor-mode capture, NOT a full
Wi-Fi network tap, NOT promiscuous visibility into other Wi-Fi clients,
and does NOT perform physical firewall enforcement (isolation decisions
use the existing NoOpIsolationBackend, exactly like the offline demo).

This capture is deliberately bounded (default: 30 seconds or 500
packets, whichever comes first) — see capture/host_live_source.py's
LiveCaptureSource. It is a temporary demo entry point, not a long-
running production live-capture service.

Usage:

    python run_live_demo.py --list-interfaces
    python run_live_demo.py --interface "Wi-Fi" --timeout 30 --packet-limit 500

Generate some traffic while it's capturing, e.g. in another terminal:

    curl https://example.com

Do not scan external hosts, generate attacks, or create disruptive
traffic while using this tool — it captures ordinary, benign traffic
only, for demonstration purposes.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from dataclasses import replace
from pathlib import Path

from capture.host_live_source import (
    DEFAULT_PACKET_LIMIT,
    DEFAULT_TIMEOUT_SECONDS,
    LiveCaptureSource,
    list_interfaces,
    resolve_interface,
)
from config.settings import load_settings
from dashboard import build_application_state, create_app
from dashboard.spa import MissingWebBuildError, register_spa, validate_web_build
from enforcement import NoOpIsolationBackend
from ml.loading import load_anomaly_detector
from pipeline.runner import run_capture
from signing import load_or_create_keypair
from utils.exceptions import CipherError
from utils.logging_setup import configure_logging

WEB_DIR = Path(__file__).resolve().parent / "web"
DEFAULT_LIVE_DEMO_PORT = 5010


def _parse_args(argv) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="run_live_demo.py",
        description="CIPHER temporary host-level Windows live-capture demo.",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces (index, name, description, IPv4) and exit.",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Exact network interface name to capture on (see --list-interfaces). "
        "Falls back to the LIVE_CAPTURE_INTERFACE environment variable if not given.",
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
        help=f"Stop capturing after this many packets (default: {DEFAULT_PACKET_LIMIT}).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_LIVE_DEMO_PORT,
        help=f"Port for the dashboard/API (default: {DEFAULT_LIVE_DEMO_PORT}).",
    )
    return parser.parse_args(argv)


def _print_interface_table() -> None:
    interfaces = list_interfaces()
    print("Available network interfaces:")
    print()
    header = f"{'Index':<6}{'Name':<30}{'Description':<45}{'IPv4':<16}"
    print(header)
    print("-" * len(header))
    for info in interfaces:
        print(
            f"{info.index:<6}{info.name:<30}{info.description:<45}{info.ipv4 or '':<16}"
        )


def _print_disclaimer(interface: str, timeout: float, packet_limit: int) -> None:
    print("CIPHER Live Capture Demo")
    print("-" * len("CIPHER Live Capture Demo"))
    print("Mode: Host-level live capture")
    print(f"Interface: {interface}")
    print(f"Timeout: {timeout:g}s")
    print(f"Packet limit: {packet_limit}")
    print("Enforcement: NoOp")
    print()
    print("Note:")
    print("This captures traffic visible to this host interface.")
    print("It is not Raspberry Pi monitor-mode capture.")
    print()


def main(argv=None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    if args.list_interfaces:
        _print_interface_table()
        return 0

    settings = load_settings()
    settings = replace(settings, flask_port=args.port)
    configure_logging(settings)
    logger = logging.getLogger(__name__)

    logger.info("CIPHER live-capture demo starting up.")

    try:
        validate_web_build(WEB_DIR)
    except MissingWebBuildError as exc:
        logger.error("Web application build missing or incomplete.")
        print(str(exc))
        return 1

    interface_name = args.interface or os.environ.get("LIVE_CAPTURE_INTERFACE") or None
    if not interface_name:
        print(
            "No network interface specified. Pass --interface \"<name>\" "
            "(or set LIVE_CAPTURE_INTERFACE), or run "
            "`python run_live_demo.py --list-interfaces` to see available interfaces."
        )
        return 1

    try:
        resolve_interface(interface_name)
    except CipherError as exc:
        logger.error("Interface validation failed: %s", exc)
        print(str(exc))
        return 1

    # So /api/health accurately reports "live" (and the interface used)
    # instead of Settings' own "offline" hard default (config/constants.py) —
    # this only changes what this run's own settings snapshot says about
    # itself, never capture/factory.py's behavior (this script never calls
    # get_capture_source; it constructs LiveCaptureSource directly).
    settings = replace(settings, capture_mode="live", live_interface=interface_name)

    _print_disclaimer(interface_name, args.timeout, args.packet_limit)

    try:
        capture_source = LiveCaptureSource(
            interface=interface_name,
            timeout=args.timeout,
            packet_limit=args.packet_limit,
        )
        anomaly_detector = load_anomaly_detector(settings.model_path)
        public_key, secret_key = load_or_create_keypair(settings.signing_key_path)
        # Same NoOp policy as the offline demo (enforcement/backends.py):
        # isolation decisions are recorded, never physically enforced.
        isolation_backend = NoOpIsolationBackend()

        print("Capturing...")
        assessments, reports = run_capture(
            capture_source,
            anomaly_detector,
            public_key,
            secret_key,
            isolation_backend,
            risk_isolation_threshold=settings.risk_isolation_threshold,
        )
        print("Capture complete.")
    except CipherError as exc:
        logger.error("Live capture run failed; integrated application will not start.", exc_info=True)
        print(f"Live capture failed: {exc}")
        return 1

    packets_captured = capture_source.packets_captured
    print(f"Packets captured: {packets_captured}")
    print(f"Devices assessed: {len(assessments)}")
    print(f"Reports generated: {len(reports)}")

    state = build_application_state(assessments, reports)
    app = create_app(state, settings)
    register_spa(app, WEB_DIR)

    print(f"Dashboard: http://{settings.flask_host}:{settings.flask_port}")
    app.run(host=settings.flask_host, port=settings.flask_port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
