"""Unit tests for GET /api/devices/<ip>/report/download — path safety
is the primary concern here: the route must never construct a
filesystem path from the `ip` URL parameter."""
from __future__ import annotations

from config.settings import Settings
from dashboard import build_application_state, create_app
from reports.pdf_generator import generate_report
from tests.dashboard.conftest import HIGH_IP, LOW_IP, _high_assessment


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


def test_download_works_when_report_output_dir_was_relative(tmp_path, monkeypatch, _keypair) -> None:
    """Regression test for a real bug: Flask's send_file() resolves a
    relative filename against the app's root_path, not the process's
    cwd, so a relative report_output_dir used to produce a real 500 on
    download even though the file genuinely existed. Reproduces the
    actual failure mode end to end — a relative output_dir is what's
    passed to generate_report(), never manually resolved to absolute
    here — so the production fix (Path.resolve() inside generate_report)
    is what has to make this pass, not the test itself.

    monkeypatch.chdir(tmp_path) keeps "data/reports" isolated to a
    temp directory instead of touching this checkout's real data/.
    """
    monkeypatch.chdir(tmp_path)
    public_key, secret_key = _keypair
    assessment = _high_assessment()

    path, metadata = generate_report(assessment, secret_key, public_key, output_dir="data/reports")

    assert path.is_absolute()

    state = build_application_state([assessment], [(path, metadata)])
    app = create_app(state, Settings())
    client = app.test_client()

    response = client.get(f"/api/devices/{HIGH_IP}/report/download")

    assert response.status_code == 200
    assert response.content_type == "application/pdf"
    assert response.data == path.read_bytes()
