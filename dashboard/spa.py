"""SPA/static-file serving for the integrated CIPHER application.

Adds React production-build serving (GET /, static assets, and a
BrowserRouter-compatible fallback) onto an existing Flask app already
built by dashboard.create_app() — used only by run_demo.py's
single-origin integrated server (see docs/SDD.md's Phase 15 addendum).
run_api.py's API-only Flask app never calls register_spa(), so its
existing behavior is completely unaffected.

The served directory (`web/`, a committed, pre-built React production
bundle — see docs/SDD.md) is a release artifact, not source: this
module contains no React/Vite/Node awareness, only static file
serving. It never imports capture/, fingerprint/, risk/, ml/, fusion/,
pipeline/, or signing/ (enforced by a static-analysis test, same
precedent as the rest of dashboard/).

Route precedence (Flask/Werkzeug matches the most specific rule that
fits a request, regardless of registration order):
- The existing `/api/...` blueprint (registered separately by
  create_app()) is untouched and always matches its own paths first.
- One route serves each real static asset directly from disk
  (`/assets/<file>`, `/favicon.svg`, `/icons.svg`) — never through the
  fallback below.
- A catch-all `/<path:path>` route returns `index.html` for any other
  path, so React Router's BrowserRouter survives a full-page reload on
  a client-side route (e.g. `/devices`) — except a path starting with
  `api/`, which is a genuinely-unknown API route and must 404 like any
  other unmatched API path, never silently serve the SPA shell.
"""
from __future__ import annotations

from pathlib import Path

from flask import Flask, Response, abort, send_from_directory


class MissingWebBuildError(RuntimeError):
    """Raised when `web/` doesn't contain a usable production build."""


def validate_web_build(web_dir: Path) -> None:
    """Raise MissingWebBuildError with an actionable message unless
    `web_dir` contains at least an `index.html` and an `assets/`
    directory — the minimum a real Vite production build always has.

    Deliberately checks before any route is registered or any request
    is served: a missing/incomplete build must fail the whole startup
    immediately, never serve a half-functional app.
    """
    index_html = web_dir / "index.html"
    if not index_html.is_file():
        raise MissingWebBuildError(
            f"CIPHER web application is missing.\nExpected: {index_html}"
        )

    assets_dir = web_dir / "assets"
    if not assets_dir.is_dir():
        raise MissingWebBuildError(
            f"CIPHER web application is incomplete (no assets/ directory).\n"
            f"Expected: {assets_dir}"
        )


def register_spa(app: Flask, web_dir: Path) -> None:
    """Wire GET /, static asset serving, and the BrowserRouter fallback
    onto `app`.

    Raises MissingWebBuildError (propagated, not caught) if `web_dir`
    isn't a real production build — the caller is expected to let this
    abort startup rather than register routes for files that don't
    exist.
    """
    validate_web_build(web_dir)

    @app.route("/")
    def _index() -> Response:
        return send_from_directory(web_dir, "index.html")

    @app.route("/assets/<path:filename>")
    def _assets(filename: str) -> Response:
        return send_from_directory(web_dir / "assets", filename)

    @app.route("/favicon.svg")
    def _favicon() -> Response:
        return send_from_directory(web_dir, "favicon.svg")

    @app.route("/icons.svg")
    def _icons() -> Response:
        return send_from_directory(web_dir, "icons.svg")

    @app.route("/<path:path>")
    def _spa_fallback(path: str) -> Response:
        if path.startswith("api/"):
            # A genuinely-unknown API path (e.g. /api/does-not-exist):
            # let it 404 through the app's existing error handler,
            # never serve the SPA shell for something under /api/.
            abort(404)
        return send_from_directory(web_dir, "index.html")
