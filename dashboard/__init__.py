"""dashboard — Flask app and REST API (Phase 12).

Depends only on already-computed data: `models/` (for type hints) and
`dashboard.state.ApplicationState`, built once by `run_api.py` from
`pipeline.runner.run_capture()`'s results. Never imports `capture/`,
`fingerprint/`, `risk/`, `ml/`, `fusion/`, or `signing/` internals, and
never recomputes an assessment — see docs/SDD.md's Phase 12 addendum
for the frozen REST contract.
"""

from dashboard.app import create_app
from dashboard.state import ApplicationState, build_application_state

__all__ = ["create_app", "ApplicationState", "build_application_state"]
