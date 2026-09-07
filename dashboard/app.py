"""create_app(state, settings) -> Flask

Flask app factory. Wires the already-implemented REST routes
(dashboard/routes.py) to an already-built ApplicationState
(dashboard/state.py) — this module computes nothing itself and never
imports capture/, fingerprint/, risk/, ml/, fusion/, or signing/
internals.

CORS: if `settings.cors_origin` is configured, every response carries
`Access-Control-Allow-Origin` set to exactly that configured origin —
never a wildcard, and never guessed at. If unconfigured, no
cross-origin header is added at all. No `flask-cors` dependency; this
is a small `after_request` hook (see docs/SDD.md's Phase 12 addendum).
"""
from __future__ import annotations

from flask import Flask, Response, jsonify

from config.settings import Settings
from dashboard.routes import bp
from dashboard.state import ApplicationState


def create_app(state: ApplicationState, settings: Settings) -> Flask:
    """Build the Flask app serving `state` over the frozen REST contract."""
    app = Flask(__name__)
    app.config["CIPHER_STATE"] = state
    app.config["CIPHER_SETTINGS"] = settings

    app.register_blueprint(bp)

    @app.errorhandler(404)
    def _handle_not_found(_error):
        # Covers both our own explicit 404s (unknown device/report) and
        # any URL that doesn't match a route at all (e.g. a malformed or
        # traversal-shaped path) — every 404 is the same standard JSON
        # shape, never Flask's default HTML page or a filesystem detail.
        return jsonify({"error": "not_found", "message": "The requested resource was not found."}), 404

    if settings.cors_origin:
        allowed_origin = settings.cors_origin

        @app.after_request
        def _apply_cors(response: Response) -> Response:
            response.headers["Access-Control-Allow-Origin"] = allowed_origin
            return response

    return app
