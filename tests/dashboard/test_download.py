"""Unit tests for GET /api/devices/<ip>/report/download — path safety
is the primary concern here: the route must never construct a
filesystem path from the `ip` URL parameter."""
from __future__ import annotations

from tests.dashboard.conftest import HIGH_IP, LOW_IP


def test_known_report_download_is_pdf(client) -> None:
    response = client.get(f"/api/devices/{HIGH_IP}/report/download")
    assert response.status_code == 200
    assert response.content_type == "application/pdf"


def test_downloaded_bytes_match_the_trusted_generated_file(client, seeded_state) -> None:
    _state, path, _metadata = seeded_state
    response = client.get(f"/api/devices/{HIGH_IP}/report/download")
    assert response.data == path.read_bytes()


def test_device_without_report_download_returns_404(client) -> None:
    response = client.get(f"/api/devices/{LOW_IP}/report/download")
    assert response.status_code == 404
    assert response.get_json()["error"] == "not_found"


def test_unknown_device_download_returns_404(client) -> None:
    response = client.get("/api/devices/203.0.113.9/report/download")
    assert response.status_code == 404


def test_traversal_shaped_ip_cannot_expose_arbitrary_file(client) -> None:
    response = client.get("/api/devices/%2e%2e%2f%2e%2e%2fetc%2fpasswd/report/download")
    assert response.status_code == 404


def test_data_keys_directory_can_never_be_downloaded(client) -> None:
    response = client.get(
        "/api/devices/..%2f..%2fdata%2fkeys%2fml_dsa_44_secret.key/report/download"
    )
    assert response.status_code == 404
    # Confirm the response is the standard JSON error, not file content.
    assert response.get_json()["error"] == "not_found"
