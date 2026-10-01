"""enforcement — the Phase 14 high-risk isolation decision and hardware
backend abstraction.

`should_isolate` is the pure, deterministic eligibility check (raw QRS
>= threshold, never the fused final_category — see decision.py).
`IsolationBackend`/`NoOpIsolationBackend`/`IsolationOutcome` are the
hardware-execution boundary: Windows (non-enforcing) only ever uses
`NoOpIsolationBackend`, which records that isolation was requested
without claiming it was physically enforced.

`LinuxIsolationBackend` (linux_backend.py) is the location real
Raspberry-Pi enforcement will live. It is fully wired against the same
contract but constructs no firewall command of its own: both the rule
construction (`RuleBuilder`) and the execution (`CommandRunner`, from
command_runner.py) are injected, and both defaults are deliberately
non-functional, so it can never change a firewall until the controlled
enforcement topology is frozen on the Pi. Neither backends.py,
command_runner.py, nor linux_backend.py imports `subprocess` or `os`.

Backend selection stays at the composition root (main.py / run_api.py /
run_demo.py / run_live_demo.py), exactly as today — never via
platform-sniffing inside enforcement/ or pipeline/runner.py.

pipeline.runner.run_capture() calls should_isolate() immediately after
each assess_packet() call and, if eligible, calls the injected
IsolationBackend — never waiting for end-of-capture representative
selection, so the Execution Report's detection-to-isolation latency
target is not undermined by deferring to EOF (see docs/SDD.md's Phase
14 addendum).
"""

from enforcement.backends import (
    NOOP_BACKEND_NAME,
    IsolationBackend,
    IsolationOutcome,
    NoOpIsolationBackend,
)
from enforcement.command_runner import CommandResult, CommandRunner, UnavailableCommandRunner
from enforcement.decision import should_isolate
from enforcement.linux_backend import (
    LINUX_BACKEND_NAME,
    IsolationPolicyNotFrozenError,
    LinuxIsolationBackend,
    RuleBuilder,
    unfrozen_rule_builder,
)

__all__ = [
    "should_isolate",
    "IsolationBackend",
    "IsolationOutcome",
    "NoOpIsolationBackend",
    "NOOP_BACKEND_NAME",
    "CommandResult",
    "CommandRunner",
    "UnavailableCommandRunner",
    "LinuxIsolationBackend",
    "LINUX_BACKEND_NAME",
    "IsolationPolicyNotFrozenError",
    "RuleBuilder",
    "unfrozen_rule_builder",
]
