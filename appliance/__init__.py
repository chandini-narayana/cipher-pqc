"""appliance — the repeated bounded-capture loop for appliance mode.

Appliance mode serves the existing dashboard and REST API while CIPHER
captures, assesses and enforces continuously. This package contributes
exactly one thing: a loop that calls the existing
`pipeline.runner.run_capture()` over a fresh `NetworkLiveCaptureSource`
once per cycle and publishes each cycle's results to a
`dashboard.state_store.ApplicationStateStore`.

It is NOT a second assessment pipeline. It computes no score, runs no
model, applies no fusion rule and makes no isolation decision — all of
that stays inside the untouched `run_capture()` call. Physical isolation
and the OLED/LED updates likewise remain immediate and per-packet inside
that call; the cycle boundary governs only when the dashboard's snapshot
is replaced.

`HardwareOutputGate` (output_gate.py) is the shutdown barrier between the
worker's per-packet hardware writes and releasing that hardware: it disables
further output before anything is closed, then waits out at most one in-flight
write, so a device is never released while the worker could still be writing
to it.

`run_appliance.py` is the composition root that wires this worker to the
capture source, the isolation backend, the hardware output devices and the
Flask app.
"""

from appliance.output_gate import (
    DEFAULT_CLOSE_TIMEOUT_SECONDS,
    HardwareOutputGate,
)
from appliance.worker import (
    DEFAULT_CYCLE_SECONDS,
    MIN_CYCLE_SECONDS,
    ApplianceCaptureWorker,
)

__all__ = [
    "ApplianceCaptureWorker",
    "HardwareOutputGate",
    "DEFAULT_CLOSE_TIMEOUT_SECONDS",
    "DEFAULT_CYCLE_SECONDS",
    "MIN_CYCLE_SECONDS",
]
