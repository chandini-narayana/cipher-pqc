"""enforcement — the Phase 14 high-risk isolation decision and hardware
backend abstraction.

`should_isolate` is the pure, deterministic eligibility check (raw QRS
>= threshold, never the fused final_category — see decision.py).
`IsolationBackend`/`NoOpIsolationBackend`/`IsolationOutcome` are the
hardware-execution boundary: Windows (non-enforcing) only ever uses
`NoOpIsolationBackend`, which records that isolation was requested
without claiming it was physically enforced.

`IsolationOutcome.to_status()` projects an enforcement result into
`models.isolation_status.IsolationStatus`, which pipeline/runner.py
attaches to the retained DeviceAssessment per device — that is how
isolation state reaches the REST API, the dashboard and the signed PDF
(see docs/SDD.md's Phase 3B addendum). enforcement/ depends on models/;
models/ never imports enforcement/.

`LinuxIsolationBackend` (linux_backend.py) is the generic Linux seam:
both the rule construction (`RuleBuilder`) and the execution
(`CommandRunner`, from command_runner.py) are injected, and both defaults
are deliberately non-functional. `IptablesIsolationBackend`
(iptables_backend.py) specializes it with CIPHER's frozen iptables
policy: idempotent DROP rules for one IPv4 device inside the
CIPHER-owned chain `CIPHER_ISOLATION`, jumped from `FORWARD` only. It
never flushes a chain, never sets a default policy, and never removes a
rule it did not add. Neither backends.py, command_runner.py,
linux_backend.py nor iptables_backend.py imports `subprocess` or `os`.

Process-spawning capability lives in exactly one module,
`enforcement.subprocess_runner`, and is deliberately NOT re-exported
here: importing `enforcement` cannot make a firewall command possible, so
a composition root must import `SubprocessCommandRunner` explicitly and
hand it to a backend before anything can execute. Every backend's default
runner is the non-executing `UnavailableCommandRunner`.

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
from enforcement.iptables_backend import (
    BUILTIN_CHAIN,
    CIPHER_CHAIN,
    IPTABLES_BACKEND_NAME,
    IptablesIsolationBackend,
    validate_isolation_target,
)
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
    "IptablesIsolationBackend",
    "IPTABLES_BACKEND_NAME",
    "CIPHER_CHAIN",
    "BUILTIN_CHAIN",
    "validate_isolation_target",
    "IsolationPolicyNotFrozenError",
    "RuleBuilder",
    "unfrozen_rule_builder",
]
