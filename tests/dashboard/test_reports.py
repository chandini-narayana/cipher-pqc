"""Unit tests for GET /api/devices/<ip>/report."""
from __future__ import annotations

from tests.dashboard.conftest import HIGH_IP, LOW_IP

_REPORT_KEYS = {
    "report_id",
    "device_ip",
    "generated_at",
    "page_count",
    "report_hash",
    "signature_preview",
    "signing_algorithm",
    "verification_status",
    "download_url",
}


def test_report_metadata_returns_200(client) -> None:
    assert client.get(f"/api/devices/{HIGH_IP}/report").status_code == 200


def test_report_metadata_dto_exact_shape(client) -> None:
    data = client.get(f"/api/devices/{HIGH_IP}/report").get_json()
    assert set(data.keys()) == _REPORT_KEYS


def test_report_metadata_matches_the_real_report(client, seeded_state) -> None:
    _state, _path, metadata = seeded_state
    data = client.get(f"/api/devices/{HIGH_IP}/report").get_json()
    assert data["report_id"] == metadata.report_id
    assert data["report_hash"] == metadata.report_hash
    assert data["signing_algorithm"] == metadata.signing_algorithm
    assert data["verification_status"] == metadata.verification_status
    assert data["download_url"] == f"/api/devices/{HIGH_IP}/report/download"


def test_signature_is_a_preview_not_the_full_signature_hex(client, seeded_state) -> None:
    _state, _path, metadata = seeded_state
    data = client.get(f"/api/devices/{HIGH_IP}/report").get_json()

    assert data["signature_preview"] != metadata.signature_hex
    assert len(data["signature_preview"]) < len(metadata.signature_hex)
    assert metadata.signature_hex.startswith(data["signature_preview"].rstrip("."))


def test_device_with_no_report_returns_structured_404(client) -> None:
    response = client.get(f"/api/devices/{LOW_IP}/report")
    assert response.status_code == 404
    assert response.get_json()["error"] == "not_found"


def test_unknown_device_report_returns_structured_404(client) -> None:
    response = client.get("/api/devices/203.0.113.9/report")
    assert response.status_code == 404
    assert response.get_json()["error"] == "not_found"
