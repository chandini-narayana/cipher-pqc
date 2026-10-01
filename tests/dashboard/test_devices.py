"""Unit tests for GET /api/devices and GET /api/devices/<ip>."""
from __future__ import annotations

from tests.dashboard.conftest import HIGH_IP, LOW_IP

_SUMMARY_KEYS = {
    "device_ip",
    "first_seen",
    "last_seen",
    "final_category",
    "risk_score",
    "risk_category",
    "anomaly",
    "assessed_at",
    "has_report",
    # Phase 3B: additive isolation state. The assertions below stay
    # exact — this set records the deliberately-extended contract, it
    # does not relax the check.
    "isolation",
}


def _find(devices, ip: str):
    return next(d for d in devices if d["device_ip"] == ip)


# --- list ---


def test_devices_list_returns_all_seeded_devices(client) -> None:
    data = client.get("/api/devices").get_json()
    ips = {d["device_ip"] for d in data["devices"]}
    assert ips == {HIGH_IP, LOW_IP}


def test_devices_list_ordering_is_deterministic(client) -> None:
    first = [d["device_ip"] for d in client.get("/api/devices").get_json()["devices"]]
    second = [d["device_ip"] for d in client.get("/api/devices").get_json()["devices"]]
    assert first == second
    assert first == sorted(first)


def test_device_summary_dto_exact_shape(client) -> None:
    devices = client.get("/api/devices").get_json()["devices"]
    summary = _find(devices, HIGH_IP)
    assert set(summary.keys()) == _SUMMARY_KEYS


def test_anomaly_object_present_when_available(client) -> None:
    devices = client.get("/api/devices").get_json()["devices"]
    summary = _find(devices, HIGH_IP)
    assert summary["anomaly"] == {"is_anomaly": True, "anomaly_score": 0.8, "confidence": 0.9}
    assert summary["has_report"] is True


def test_anomaly_is_null_when_unavailable(client) -> None:
    devices = client.get("/api/devices").get_json()["devices"]
    summary = _find(devices, LOW_IP)
    assert summary["anomaly"] is None
    assert summary["has_report"] is False


# --- detail ---


def test_known_device_detail_returns_200(client) -> None:
    assert client.get(f"/api/devices/{HIGH_IP}").status_code == 200


def test_device_detail_includes_remediation_and_reference(client) -> None:
    data = client.get(f"/api/devices/{HIGH_IP}").get_json()
    assert data["remediation"] == "Upgrade from TLS 1.0 to TLS 1.3."
    assert data["nist_reference"] == "NIST SP 800-52r2"
    assert set(data.keys()) == _SUMMARY_KEYS | {"remediation", "nist_reference"}


def test_unknown_device_detail_returns_structured_404(client) -> None:
    response = client.get("/api/devices/203.0.113.9")
    assert response.status_code == 404
    assert response.get_json() == {
        "error": "not_found",
        "message": "No device found with IP 203.0.113.9",
    }
