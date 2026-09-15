"""enforcement — the Phase 14 high-risk isolation decision and hardware
backend abstraction.

`should_isolate` is the pure, deterministic eligibility check (raw QRS
>= threshold, never the fused final_category — see decision.py).
`IsolationBackend`/`NoOpIsolationBackend`/`IsolationOutcome` are the
hardware-execution boundary: Phase 1 (Windows, hardware-free) only
ever uses `NoOpIsolationBackend`, which records that isolation was
requested without claiming it was physically enforced. A real
Linux/Raspberry-Pi iptables backend is deferred to hardware
integration — see backends.py's module docstring for why.

pipeline.runner.run_capture() calls should_isolate() immediately after
each assess_packet() call and, if eligible, calls the injected
IsolationBackend — never waiting for end-of-capture representative
selection, so the Execution Report's detection-to-isolation latency
target is not undermined by deferring to EOF (see docs/SDD.md's Phase
14 addendum).
"""

from enforcement.backends import IsolationBackend, IsolationOutcome, NoOpIsolationBackend
from enforcement.decision import should_isolate

__all__ = [
    "should_isolate",
    "IsolationBackend",
    "IsolationOutcome",
    "NoOpIsolationBackend",
]
