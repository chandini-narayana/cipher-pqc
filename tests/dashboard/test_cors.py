"""Unit tests for the CORS after_request hook (docs/SDD.md Phase 12
addendum) — never a wildcard, never guessed, only the exact configured
origin."""
from __future__ import annotations


def test_configured_exact_origin_is_returned(app_with_cors) -> None:
    client = app_with_cors.test_client()
    response = client.get("/api/health")
    assert response.headers.get("Access-Control-Allow-Origin") == "http://localhost:3000"


def test_wildcard_is_never_returned(app_with_cors) -> None:
    client = app_with_cors.test_client()
    response = client.get("/api/health")
    assert response.headers.get("Access-Control-Allow-Origin") != "*"


def test_no_configured_origin_means_no_cors_header(client) -> None:
    response = client.get("/api/health")
    assert "Access-Control-Allow-Origin" not in response.headers
