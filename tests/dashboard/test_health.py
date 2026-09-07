"""Unit tests for GET /api/health."""
from __future__ import annotations


def test_health_returns_200(client) -> None:
    assert client.get("/api/health").status_code == 200


def test_health_status_and_app_fields(client) -> None:
    data = client.get("/api/health").get_json()
    assert data["status"] == "ok"
    assert data["app_name"] == "CIPHER"
    assert isinstance(data["app_version"], str) and data["app_version"]
    assert data["capture_mode"] == "offline"


def test_health_reports_real_device_and_report_counts(client) -> None:
    data = client.get("/api/health").get_json()
    assert data["devices_assessed"] == 2
    assert data["reports_generated"] == 1
