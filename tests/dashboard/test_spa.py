"""Tests for dashboard.spa — GET /, static asset serving, the SPA
fallback, and /api protection in the integrated application
(docs/SDD.md's Phase 15 addendum).

Uses the real, committed web/ directory throughout (never a fabricated
fixture), so these tests fail immediately if the real production
build's shape ever changes. The one real JS asset filename is
discovered at test time via a glob, never hardcoded, so a frontend
rebuild that changes the content hash never breaks these tests.
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest
from flask import Flask

from config.settings import Settings
from dashboard import create_app
from dashboard.spa import MissingWebBuildError, register_spa, validate_web_build
from tests.dashboard.conftest import HIGH_IP

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WEB_DIR = REPO_ROOT / "web"


def _real_asset_filename() -> str:
    assets = sorted((WEB_DIR / "assets").glob("*.js"))
    assert assets, "expected at least one .js file in web/assets for these tests to be meaningful"
    return assets[0].name


@pytest.fixture()
def spa_app(seeded_state):
    state, _path, _metadata = seeded_state
    app = create_app(state, Settings())
    register_spa(app, WEB_DIR)
    return app


@pytest.fixture()
def spa_client(spa_app):
    return spa_app.test_client()


# --- GET / -------------------------------------------------------------


def test_root_returns_200(spa_client) -> None:
    assert spa_client.get("/").status_code == 200


def test_root_content_type_is_html(spa_client) -> None:
    response = spa_client.get("/")
    assert response.content_type.startswith("text/html")


def test_root_body_matches_real_index_html(spa_client) -> None:
    response = spa_client.get("/")
    assert response.data == (WEB_DIR / "index.html").read_bytes()


# --- static assets -------------------------------------------------------


def test_known_js_asset_is_served(spa_client) -> None:
    filename = _real_asset_filename()
    response = spa_client.get(f"/assets/{filename}")
    assert response.status_code == 200
    assert response.data == (WEB_DIR / "assets" / filename).read_bytes()


def test_favicon_is_served(spa_client) -> None:
    response = spa_client.get("/favicon.svg")
    assert response.status_code == 200
    assert response.data == (WEB_DIR / "favicon.svg").read_bytes()


def test_icons_svg_is_served(spa_client) -> None:
    response = spa_client.get("/icons.svg")
    assert response.status_code == 200
    assert response.data == (WEB_DIR / "icons.svg").read_bytes()


def test_unknown_asset_returns_404(spa_client) -> None:
    assert spa_client.get("/assets/does-not-exist.js").status_code == 404


# --- SPA fallback (BrowserRouter routes) ----------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/dashboard",
        "/monitoring",
        "/network",
        "/devices",
        "/packets",
        "/threats",
        "/quantum",
        "/ai-risk",
        "/incidents",
        "/migration",
        "/reports",
        "/logs",
        "/settings",
        "/about",
    ],
)
def test_spa_route_returns_index_html(spa_client, path: str) -> None:
    response = spa_client.get(path)
    assert response.status_code == 200
    assert response.data == (WEB_DIR / "index.html").read_bytes()


def test_nested_spa_route_returns_index_html(spa_client) -> None:
    """A refresh on a deeper client-side route (e.g. a device detail
    page) must not 404 either."""
    response = spa_client.get("/devices/192.168.1.10")
    assert response.status_code == 200
    assert response.data == (WEB_DIR / "index.html").read_bytes()


# --- /api protection -------------------------------------------------------


def test_api_health_is_unaffected_by_spa_registration(spa_client) -> None:
    response = spa_client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_api_devices_is_unaffected_by_spa_registration(spa_client) -> None:
    response = spa_client.get("/api/devices")
    assert response.status_code == 200
    assert "devices" in response.get_json()


def test_unknown_api_path_returns_json_404_not_index_html(spa_client) -> None:
    response = spa_client.get("/api/does-not-exist")
    assert response.status_code == 404
    assert response.content_type.startswith("application/json")
    assert response.get_json()["error"] == "not_found"


def test_report_download_still_works_with_spa_registered(spa_client, seeded_state) -> None:
    _state, path, _metadata = seeded_state
    response = spa_client.get(f"/api/devices/{HIGH_IP}/report/download")
    assert response.status_code == 200
    assert response.content_type == "application/pdf"
    assert response.data == path.read_bytes()


# --- dependency boundary ---------------------------------------------------


def test_spa_module_does_not_import_forbidden_packages() -> None:
    import dashboard.spa as spa_module

    tree = ast.parse(inspect.getsource(spa_module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    forbidden = {"capture", "fingerprint", "risk", "ml", "fusion", "pipeline", "signing"}
    found = imported & forbidden
    assert not found, f"dashboard.spa imports forbidden package(s): {found}"


# --- missing web build -----------------------------------------------------


def test_validate_web_build_raises_when_index_html_missing(tmp_path) -> None:
    (tmp_path / "assets").mkdir()
    with pytest.raises(MissingWebBuildError, match="index.html"):
        validate_web_build(tmp_path)


def test_validate_web_build_raises_when_assets_dir_missing(tmp_path) -> None:
    (tmp_path / "index.html").write_text("<html></html>")
    with pytest.raises(MissingWebBuildError, match="assets"):
        validate_web_build(tmp_path)


def test_validate_web_build_passes_for_the_real_web_dir() -> None:
    validate_web_build(WEB_DIR)  # must not raise


def test_register_spa_raises_and_registers_no_routes_when_build_missing(tmp_path) -> None:
    app = Flask(__name__)
    rule_count_before = len(list(app.url_map.iter_rules()))

    with pytest.raises(MissingWebBuildError):
        register_spa(app, tmp_path)

    assert len(list(app.url_map.iter_rules())) == rule_count_before
