"""REST endpoints: /api/health, /api/devices, /api/devices/<ip>,
/api/devices/<ip>/report, /api/devices/<ip>/report/download.

Every route reads from the already-built ApplicationState
(dashboard/state.py) stored on the Flask app — nothing here recomputes
risk, ML, fusion, or signing, and nothing here constructs a filesystem
path from a request parameter. A device/report lookup is always a
plain dict lookup by IP; an unknown key is a 404, never a filesystem
access attempt (see docs/SDD.md's Phase 12 addendum for the frozen
contract and the path-safety rationale).
"""
from __future__ import annotations

from typing import Tuple

from flask import Blueprint, Response, current_app, jsonify, send_file

from config.constants import APP_NAME, APP_VERSION
from dashboard.serializers import (
    serialize_device_detail,
    serialize_device_summary,
    serialize_report_metadata,
)
from dashboard.state import ApplicationState

bp = Blueprint("api", __name__, url_prefix="/api")


def _state() -> ApplicationState:
    return current_app.config["CIPHER_STATE"]


def _error(status_code: int, error: str, message: str) -> Tuple[Response, int]:
    return jsonify({"error": error, "message": message}), status_code


def _not_found(message: str) -> Tuple[Response, int]:
    return _error(404, "not_found", message)


@bp.route("/health")
def health() -> Response:
    settings = current_app.config["CIPHER_SETTINGS"]
    state = _state()
    return jsonify(
        {
            "status": "ok",
            "app_name": APP_NAME,
            "app_version": APP_VERSION,
            "capture_mode": settings.capture_mode,
            "devices_assessed": state.devices_assessed,
            "reports_generated": state.reports_generated,
        }
    )


@bp.route("/devices")
def list_devices() -> Response:
    state = _state()
    devices = [
        serialize_device_summary(assessment, has_report=state.get_report(assessment.device.ip) is not None)
        for assessment in state.list_assessments()
    ]
    return jsonify({"devices": devices})


@bp.route("/devices/<ip>")
def device_detail(ip: str):
    state = _state()
    assessment = state.get_assessment(ip)
    if assessment is None:
        return _not_found(f"No device found with IP {ip}")

    has_report = state.get_report(ip) is not None
    return jsonify(serialize_device_detail(assessment, has_report))


@bp.route("/devices/<ip>/report")
def device_report(ip: str):
    state = _state()
    if state.get_assessment(ip) is None:
        return _not_found(f"No device found with IP {ip}")

    report = state.get_report(ip)
    if report is None:
        return _not_found(f"No report has been generated for device {ip}")

    _path, metadata = report
    download_url = f"/api/devices/{ip}/report/download"
    return jsonify(serialize_report_metadata(metadata, download_url))


@bp.route("/devices/<ip>/report/download")
def device_report_download(ip: str):
    state = _state()
    if state.get_assessment(ip) is None:
        return _not_found(f"No device found with IP {ip}")

    report = state.get_report(ip)
    if report is None:
        return _not_found(f"No report has been generated for device {ip}")

    path, _metadata = report
    # `path` always comes from ApplicationState, built once from
    # run_capture()'s own trusted output — never from `ip` or any other
    # request input, so no filesystem path is ever derived from the client.
    return send_file(path, mimetype="application/pdf", download_name=path.name)
