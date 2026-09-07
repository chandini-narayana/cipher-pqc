"""Unit test for run_api.py's composition — confirms it wires
run_capture()'s results into dashboard.create_app() without ever
starting a real blocking HTTP server (app.run itself is patched out).
"""
from __future__ import annotations

import run_api
from tests.fixtures.generate_fixtures import SAMPLE_PCAP_PATH
from tests.fixtures.generate_fixtures import main as generate_fixtures


def test_run_api_composition_builds_app_from_completed_run(tmp_path, monkeypatch) -> None:
    if not SAMPLE_PCAP_PATH.exists():
        generate_fixtures()

    # Isolate every relative default path (LOG_DIR, DATA_DIR,
    # SIGNING_KEY_PATH, and generate_report's report-output default)
    # inside tmp_path — never touch this checkout's real data/keys/.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PCAP_PATH", str(SAMPLE_PCAP_PATH))

    captured = {}

    class _FakeFlaskApp:
        def run(self, host=None, port=None):
            captured["ran"] = True
            captured["host"] = host
            captured["port"] = port

    def fake_create_app(state, settings):
        captured["state"] = state
        captured["settings"] = settings
        return _FakeFlaskApp()

    monkeypatch.setattr(run_api, "create_app", fake_create_app)

    exit_code = run_api.main()

    assert exit_code == 0
    assert captured["ran"] is True
    assert captured["host"] == captured["settings"].flask_host
    assert captured["port"] == captured["settings"].flask_port
    assert captured["state"].devices_assessed == 3


def test_run_api_mock_mode_does_not_start_a_server(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)  # configure_logging() still runs before the early return
    monkeypatch.setenv("CAPTURE_MODE", "mock")

    def _forbidden(*args, **kwargs):
        raise AssertionError("create_app must not be called for capture_mode=mock")

    monkeypatch.setattr(run_api, "create_app", _forbidden)

    assert run_api.main() == 0
