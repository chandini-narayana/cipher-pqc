"""Phase 3D tests for enforcement.iptables_backend — real iptables
isolation, exercised entirely through a fake CommandRunner.

No test here runs iptables, needs root, or touches this host's firewall:
every command runner is a recording test double, and the backend's own
default runner (`UnavailableCommandRunner`) cannot spawn a process at all.
The exact argv the backend *would* run is asserted instead, which is a
stronger check than observing a side effect on a real firewall.

iptables exit-code convention used by the fakes below: a `-C`/`-L` check
exits 0 when the rule/chain is present and non-zero when it is not. A
non-zero check is therefore normal flow, not a failure.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Sequence

import pytest

from enforcement.backends import IsolationOutcome, NoOpIsolationBackend
from enforcement.command_runner import CommandResult, CommandRunner, UnavailableCommandRunner
from enforcement.iptables_backend import (
    BUILTIN_CHAIN,
    CIPHER_CHAIN,
    IPTABLES_BACKEND_NAME,
    IptablesIsolationBackend,
    local_ipv4_addresses,
    validate_isolation_target,
)
from enforcement.linux_backend import LinuxIsolationBackend
from models.isolation_status import ENFORCED, FAILED

_DEVICE = "192.168.50.21"
_PI_IP = "192.168.50.1"


class _FakeIptables(CommandRunner):
    """A fake iptables that models presence/absence of chain and rules.

    `present` holds the argv-tails of rules/chains that currently exist;
    `-C`/`-L` checks consult it, and `-N`/`-I`/`-A`/`-D` mutate it. This
    lets a test assert both the exact commands issued and that the
    sequence is genuinely idempotent.
    """

    def __init__(self, chain_exists: bool = False, rules: Sequence[str] = ()) -> None:
        self.commands: List[tuple] = []
        self.chain_exists = chain_exists
        self.rules = set(rules)
        self.jump_installed = False

    def run(self, command: Sequence[str]) -> CommandResult:
        argv = tuple(str(part) for part in command)
        self.commands.append(argv)
        op = argv[2]

        if op == "-L":
            return self._result(argv, 0 if self.chain_exists else 1)
        if op == "-N":
            self.chain_exists = True
            return self._result(argv, 0)
        if op == "-C":
            if argv[3] == BUILTIN_CHAIN:
                return self._result(argv, 0 if self.jump_installed else 1)
            return self._result(argv, 0 if self._rule_key(argv) in self.rules else 1)
        if op == "-I":
            self.jump_installed = True
            return self._result(argv, 0)
        if op == "-A":
            self.rules.add(self._rule_key(argv))
            return self._result(argv, 0)
        if op == "-D":
            self.rules.discard(self._rule_key(argv))
            return self._result(argv, 0)
        return self._result(argv, 1)

    @staticmethod
    def _rule_key(argv) -> str:
        # e.g. ("iptables","-w","-C","CIPHER_ISOLATION","-s","1.2.3.4","-j","DROP")
        return f"{argv[4]} {argv[5]}"

    @staticmethod
    def _result(argv, exit_code: int) -> CommandResult:
        return CommandResult(command=argv, executed=True, exit_code=exit_code)

    def ops(self) -> List[str]:
        """The mutating operations issued, in order — what actually
        changed the firewall."""
        return [c[2] for c in self.commands if c[2] in ("-N", "-I", "-A", "-D")]


class _MissingBinary(CommandRunner):
    def run(self, command: Sequence[str]) -> CommandResult:
        return CommandResult(
            command=tuple(command),
            executed=False,
            exit_code=-1,
            stderr="'iptables' was not found on this system",
        )


class _PermissionDenied(CommandRunner):
    """iptables exists and runs, but refuses: the real-world unprivileged
    case (iptables exits non-zero with a permission message)."""

    def run(self, command: Sequence[str]) -> CommandResult:
        if command[2] in ("-L", "-C"):
            return CommandResult(
                command=tuple(command),
                executed=True,
                exit_code=4,
                stderr="Permission denied (you must be root)",
            )
        return CommandResult(
            command=tuple(command),
            executed=True,
            exit_code=4,
            stderr="Permission denied (you must be root)",
        )


def _backend(runner: CommandRunner, **kwargs) -> IptablesIsolationBackend:
    kwargs.setdefault("local_address_provider", lambda: {_PI_IP})
    return IptablesIsolationBackend(command_runner=runner, **kwargs)


# --- identity and contract ------------------------------------------------


def test_backend_name_is_recorded() -> None:
    assert IptablesIsolationBackend().backend_name == IPTABLES_BACKEND_NAME == "linux-iptables"


def test_is_a_linux_isolation_backend_not_a_parallel_path() -> None:
    assert isinstance(IptablesIsolationBackend(), LinuxIsolationBackend)


def test_declares_itself_enforcement_capable() -> None:
    """So an enforced=False outcome from it reads as Failed, never as a
    deliberately non-enforcing deployment."""
    assert IptablesIsolationBackend().enforcement_capable is True


def test_the_default_runner_cannot_execute_anything() -> None:
    """Constructing the backend with no runner must be inert, so no test
    and no accidental composition can reach a firewall."""
    backend = IptablesIsolationBackend()
    assert isinstance(backend._command_runner, UnavailableCommandRunner)
    outcome = backend.isolate(_DEVICE, 9)
    assert outcome.enforced is False


def test_an_outcome_carries_every_contract_field() -> None:
    outcome = _backend(_FakeIptables()).isolate(_DEVICE, 9)
    assert isinstance(outcome, IsolationOutcome)
    assert outcome.device_ip == _DEVICE
    assert outcome.risk_score == 9
    assert outcome.requested is True
    assert outcome.enforced is True
    assert outcome.backend == IPTABLES_BACKEND_NAME
    assert outcome.reason
    assert outcome.requested_at is not None


def test_a_successful_outcome_maps_to_the_enforced_status_label() -> None:
    """Phase 3B propagation stays intact: the status the API and report
    show is derived from this outcome."""
    status = _backend(_FakeIptables()).isolate(_DEVICE, 9).to_status()
    assert status.enforced is True
    assert status.status_label == ENFORCED


def test_a_failed_outcome_maps_to_the_failed_status_label() -> None:
    status = _backend(_MissingBinary()).isolate(_DEVICE, 9).to_status()
    assert status.enforced is False
    assert status.status_label == FAILED


# --- the iptables strategy ------------------------------------------------


def test_valid_ipv4_isolation_succeeds() -> None:
    assert _backend(_FakeIptables()).isolate(_DEVICE, 9).enforced is True


def test_the_chain_is_created_when_absent() -> None:
    runner = _FakeIptables(chain_exists=False)
    _backend(runner).isolate(_DEVICE, 9)

    assert ("iptables", "-w", "-N", CIPHER_CHAIN) in runner.commands


def test_the_chain_is_not_recreated_when_it_already_exists() -> None:
    runner = _FakeIptables(chain_exists=True)
    _backend(runner).isolate(_DEVICE, 9)

    assert "-N" not in runner.ops()


def test_the_jump_from_the_builtin_chain_is_installed_once() -> None:
    runner = _FakeIptables()
    _backend(runner).isolate(_DEVICE, 9)

    assert ("iptables", "-w", "-I", BUILTIN_CHAIN, "1", "-j", CIPHER_CHAIN) in runner.commands
    assert runner.ops().count("-I") == 1


def test_the_jump_is_checked_before_being_installed() -> None:
    runner = _FakeIptables()
    _backend(runner).isolate(_DEVICE, 9)

    assert ("iptables", "-w", "-C", BUILTIN_CHAIN, "-j", CIPHER_CHAIN) in runner.commands


def test_drop_rules_are_added_for_both_directions_of_the_device() -> None:
    runner = _FakeIptables()
    _backend(runner).isolate(_DEVICE, 9)

    assert ("iptables", "-w", "-A", CIPHER_CHAIN, "-s", _DEVICE, "-j", "DROP") in runner.commands
    assert ("iptables", "-w", "-A", CIPHER_CHAIN, "-d", _DEVICE, "-j", "DROP") in runner.commands


def test_only_the_forward_chain_is_touched() -> None:
    """Narrowest safe behavior: INPUT/OUTPUT are never modified, so this
    cannot lock the host out of its own management network."""
    runner = _FakeIptables()
    _backend(runner).isolate(_DEVICE, 9)

    for command in runner.commands:
        assert "INPUT" not in command
        assert "OUTPUT" not in command


def test_every_command_uses_the_lock_wait_flag() -> None:
    runner = _FakeIptables()
    _backend(runner).isolate(_DEVICE, 9)

    for command in runner.commands:
        assert command[1] == "-w"


def test_the_iptables_binary_is_configurable_without_shell_syntax() -> None:
    runner = _FakeIptables()
    _backend(runner, iptables_binary="/sbin/iptables").isolate(_DEVICE, 9)

    assert all(command[0] == "/sbin/iptables" for command in runner.commands)


def test_the_chain_names_are_configurable() -> None:
    runner = _FakeIptables()
    backend = IptablesIsolationBackend(
        command_runner=runner,
        chain="TEST_CHAIN",
        builtin_chain=BUILTIN_CHAIN,
        local_address_provider=lambda: set(),
    )
    backend.isolate(_DEVICE, 9)

    assert ("iptables", "-w", "-N", "TEST_CHAIN") in runner.commands


# --- idempotency ----------------------------------------------------------


def test_repeated_isolation_adds_no_duplicate_rules() -> None:
    runner = _FakeIptables()
    backend = _backend(runner)

    first = backend.isolate(_DEVICE, 9)
    runner.commands.clear()
    second = backend.isolate(_DEVICE, 9)

    assert first.enforced is True
    assert second.enforced is True
    # Second pass: everything already in place, so nothing mutates.
    assert runner.ops() == []


def test_an_already_isolated_device_still_reports_enforced() -> None:
    runner = _FakeIptables(chain_exists=True, rules=[f"-s {_DEVICE}", f"-d {_DEVICE}"])
    runner.jump_installed = True

    assert _backend(runner).isolate(_DEVICE, 9).enforced is True


def test_a_second_device_reuses_the_existing_chain_and_jump() -> None:
    runner = _FakeIptables()
    backend = _backend(runner)

    backend.isolate(_DEVICE, 9)
    runner.commands.clear()
    backend.isolate("192.168.50.22", 8)

    assert runner.ops() == ["-A", "-A"]  # only the new device's two rules


def test_a_partially_present_rule_set_is_completed_not_duplicated() -> None:
    """Only the -s rule exists (e.g. an interrupted earlier run): the
    missing -d rule is added and the existing one is not re-added."""
    runner = _FakeIptables(chain_exists=True, rules=[f"-s {_DEVICE}"])
    runner.jump_installed = True

    _backend(runner).isolate(_DEVICE, 9)

    adds = [c for c in runner.commands if c[2] == "-A"]
    assert len(adds) == 1
    assert adds[0][4] == "-d"


# --- safety: refused targets ----------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["127.0.0.1", "127.1.2.3"],
)
def test_loopback_is_refused_without_running_anything(target) -> None:
    runner = _FakeIptables()
    outcome = _backend(runner).isolate(target, 9)

    assert outcome.enforced is False
    assert "loopback" in outcome.reason.lower()
    assert runner.commands == []


def test_the_hosts_own_address_is_refused() -> None:
    """Management-access protection: isolating the Pi itself is refused."""
    runner = _FakeIptables()
    outcome = _backend(runner).isolate(_PI_IP, 9)

    assert outcome.enforced is False
    assert "own addresses" in outcome.reason
    assert runner.commands == []


def test_an_unknown_local_address_set_does_not_block_a_normal_target() -> None:
    """If the host's own addresses cannot be determined, that protection is
    simply unavailable — it must not break ordinary enforcement."""
    runner = _FakeIptables()
    backend = IptablesIsolationBackend(
        command_runner=runner, local_address_provider=lambda: set()
    )
    assert backend.isolate(_DEVICE, 9).enforced is True


def test_a_raising_local_address_provider_is_survived() -> None:
    def _boom():
        raise OSError("no network configuration available")

    runner = _FakeIptables()
    backend = IptablesIsolationBackend(command_runner=runner, local_address_provider=_boom)

    assert backend.isolate(_DEVICE, 9).enforced is True


@pytest.mark.parametrize(
    "target",
    ["not-an-ip", "", "192.168.1.999", "192.168.1", "192.168.1.1/24", "1.2.3.4 ; rm -rf /"],
)
def test_an_invalid_ipv4_target_is_refused_without_running_anything(target) -> None:
    """Validation happens before any argv is built, so a hostile string
    never reaches iptables at all."""
    runner = _FakeIptables()
    outcome = _backend(runner).isolate(target, 9)

    assert outcome.enforced is False
    assert runner.commands == []


def test_an_ipv6_target_is_refused_as_out_of_scope() -> None:
    runner = _FakeIptables()
    outcome = _backend(runner).isolate("2001:db8::1", 9)

    assert outcome.enforced is False
    assert "IPv4-only" in outcome.reason
    assert runner.commands == []


@pytest.mark.parametrize("target", ["0.0.0.0", "224.0.0.1", "255.255.255.255"])
def test_unspecified_multicast_and_broadcast_are_refused(target) -> None:
    runner = _FakeIptables()
    assert _backend(runner).isolate(target, 9).enforced is False
    assert runner.commands == []


def test_validate_isolation_target_accepts_an_ordinary_device() -> None:
    assert validate_isolation_target(_DEVICE, {_PI_IP}) is None


# --- safety: what is never done -------------------------------------------


def test_no_flush_policy_change_or_unrelated_deletion_ever_happens() -> None:
    runner = _FakeIptables()
    backend = _backend(runner)
    backend.isolate(_DEVICE, 9)
    backend.restore(_DEVICE)

    for command in runner.commands:
        for forbidden in ("-F", "-X", "-P", "--flush", "--policy"):
            assert forbidden not in command


def test_deletions_only_ever_target_cipher_s_own_chain() -> None:
    runner = _FakeIptables(chain_exists=True, rules=[f"-s {_DEVICE}", f"-d {_DEVICE}"])
    runner.jump_installed = True
    _backend(runner).restore(_DEVICE)

    for command in runner.commands:
        if command[2] == "-D":
            assert command[3] == CIPHER_CHAIN


def test_the_module_uses_no_other_firewall_technology() -> None:
    import inspect

    import enforcement.iptables_backend as module

    source = inspect.getsource(module).lower()
    for forbidden in ("nftables", "firewalld", "ufw", "shell=true", "os.system"):
        assert forbidden not in source


def test_the_module_imports_neither_subprocess_nor_os() -> None:
    """Execution stays behind the injected runner seam — this module can
    construct a command but has no way to spawn one."""
    import ast
    import inspect

    import enforcement.iptables_backend as module

    tree = ast.parse(inspect.getsource(module))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert "subprocess" not in imported
    assert "os" not in imported


def test_commands_are_argument_lists_never_shell_strings() -> None:
    """Every element is a separate argv entry, so no value is ever
    concatenated into something a shell could reinterpret."""
    runner = _FakeIptables()
    _backend(runner).isolate(_DEVICE, 9)

    for command in runner.commands:
        assert isinstance(command, tuple)
        assert len(command) >= 3
        for part in command:
            assert isinstance(part, str)
            assert " " not in part


# --- failure modes --------------------------------------------------------


def test_a_missing_iptables_binary_is_reported_not_claimed() -> None:
    outcome = _backend(_MissingBinary()).isolate(_DEVICE, 9)

    assert outcome.enforced is False
    assert "not found" in outcome.reason
    assert "root" in outcome.reason or "CAP_NET_ADMIN" in outcome.reason


def test_permission_denied_is_reported_clearly() -> None:
    outcome = _backend(_PermissionDenied()).isolate(_DEVICE, 9)

    assert outcome.enforced is False
    assert "Permission denied" in outcome.reason


def test_a_generic_command_failure_is_reported_with_its_detail() -> None:
    class _FailingAdd(_FakeIptables):
        def run(self, command):
            if command[2] == "-A":
                self.commands.append(tuple(command))
                return CommandResult(
                    command=tuple(command),
                    executed=True,
                    exit_code=2,
                    stderr="iptables: Invalid argument",
                )
            return super().run(command)

    outcome = _backend(_FailingAdd()).isolate(_DEVICE, 9)

    assert outcome.enforced is False
    assert "Invalid argument" in outcome.reason
    assert "exit code 2" in outcome.reason


def test_a_failure_with_no_output_still_reports_the_exit_code() -> None:
    class _SilentFailure(CommandRunner):
        def run(self, command):
            if command[2] in ("-L", "-C"):
                return CommandResult(tuple(command), executed=True, exit_code=1)
            return CommandResult(tuple(command), executed=True, exit_code=9)

    outcome = _backend(_SilentFailure()).isolate(_DEVICE, 9)

    assert outcome.enforced is False
    assert "exit code 9" in outcome.reason


def test_a_failure_stops_the_sequence_rather_than_continuing() -> None:
    """A chain that cannot be created must not be followed by rule
    attempts against a chain that does not exist."""

    class _ChainCreationFails(_FakeIptables):
        def run(self, command):
            if command[2] == "-N":
                self.commands.append(tuple(command))
                return CommandResult(
                    tuple(command), executed=True, exit_code=1, stderr="cannot create chain"
                )
            return super().run(command)

    runner = _ChainCreationFails()
    outcome = _backend(runner).isolate(_DEVICE, 9)

    assert outcome.enforced is False
    assert not any(c[2] == "-A" for c in runner.commands)


def test_an_executed_zero_exit_is_required_for_enforcement() -> None:
    """A runner reporting exit 0 while never having executed must not be
    read as success."""

    class _NeverExecuted(CommandRunner):
        def run(self, command):
            return CommandResult(tuple(command), executed=False, exit_code=0)

    assert _backend(_NeverExecuted()).isolate(_DEVICE, 9).enforced is False


# --- restore / unisolate --------------------------------------------------


def _isolated_runner() -> _FakeIptables:
    runner = _FakeIptables(chain_exists=True, rules=[f"-s {_DEVICE}", f"-d {_DEVICE}"])
    runner.jump_installed = True
    return runner


def test_restore_removes_both_of_the_devices_rules() -> None:
    runner = _isolated_runner()
    outcome = _backend(runner).restore(_DEVICE)

    assert outcome.enforced is True
    assert ("iptables", "-w", "-D", CIPHER_CHAIN, "-s", _DEVICE, "-j", "DROP") in runner.commands
    assert ("iptables", "-w", "-D", CIPHER_CHAIN, "-d", _DEVICE, "-j", "DROP") in runner.commands
    assert runner.rules == set()


def test_restore_leaves_the_chain_and_jump_in_place() -> None:
    """Other devices may still be isolated through them — removing shared
    state would silently un-isolate those."""
    runner = _isolated_runner()
    _backend(runner).restore(_DEVICE)

    assert runner.chain_exists is True
    assert runner.jump_installed is True
    assert "-X" not in runner.ops()


def test_restore_is_idempotent() -> None:
    runner = _isolated_runner()
    backend = _backend(runner)

    first = backend.restore(_DEVICE)
    runner.commands.clear()
    second = backend.restore(_DEVICE)

    assert first.enforced is True
    assert second.enforced is True
    assert runner.ops() == []  # nothing left to delete


def test_restoring_a_device_that_was_never_isolated_is_predictable() -> None:
    runner = _FakeIptables(chain_exists=True)
    outcome = _backend(runner).restore(_DEVICE)

    assert outcome.enforced is True
    assert "nothing to remove" in outcome.reason
    assert runner.ops() == []


def test_restore_does_not_touch_another_devices_rules() -> None:
    other = "192.168.50.99"
    runner = _FakeIptables(
        chain_exists=True, rules=[f"-s {_DEVICE}", f"-d {_DEVICE}", f"-s {other}", f"-d {other}"]
    )
    runner.jump_installed = True

    _backend(runner).restore(_DEVICE)

    assert runner.rules == {f"-s {other}", f"-d {other}"}


def test_restore_refuses_an_invalid_target() -> None:
    runner = _FakeIptables()
    outcome = _backend(runner).restore("not-an-ip")

    assert outcome.enforced is False
    assert runner.commands == []


def test_restore_reports_a_deletion_failure() -> None:
    class _DeleteFails(_FakeIptables):
        def run(self, command):
            if command[2] == "-D":
                self.commands.append(tuple(command))
                return CommandResult(
                    tuple(command), executed=True, exit_code=1, stderr="rule does not exist"
                )
            return super().run(command)

    runner = _DeleteFails(chain_exists=True, rules=[f"-s {_DEVICE}", f"-d {_DEVICE}"])
    runner.jump_installed = True
    outcome = _backend(runner).restore(_DEVICE)

    assert outcome.enforced is False
    assert "rule does not exist" in outcome.reason


def test_restore_reports_a_missing_binary() -> None:
    outcome = _backend(_MissingBinary()).restore(_DEVICE)

    assert outcome.enforced is False
    assert "not found" in outcome.reason


def test_restore_carries_the_backend_name() -> None:
    assert _backend(_isolated_runner()).restore(_DEVICE).backend == IPTABLES_BACKEND_NAME


# --- logging --------------------------------------------------------------


def test_enforcement_requested_and_succeeded_are_logged(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="enforcement.iptables_backend"):
        _backend(_FakeIptables()).isolate(_DEVICE, 9)

    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "Enforcement requested" in messages
    assert "Enforcement succeeded" in messages
    assert _DEVICE in messages


def test_enforcement_failure_is_logged_at_error(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="enforcement.iptables_backend"):
        _backend(_MissingBinary()).isolate(_DEVICE, 9)

    assert any(r.levelno >= logging.ERROR for r in caplog.records)


def test_a_refusal_is_logged_as_a_warning(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="enforcement.iptables_backend"):
        _backend(_FakeIptables()).isolate("127.0.0.1", 9)

    assert any("refused" in r.getMessage().lower() for r in caplog.records)


def test_restore_outcomes_are_logged(caplog) -> None:
    with caplog.at_level(logging.INFO, logger="enforcement.iptables_backend"):
        _backend(_isolated_runner()).restore(_DEVICE)

    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "Restore requested" in messages
    assert "Restore succeeded" in messages


# --- the NoOp backend is unaffected ---------------------------------------


def test_the_noop_backend_still_never_enforces() -> None:
    outcome = NoOpIsolationBackend().isolate(_DEVICE, 9)
    assert (outcome.requested, outcome.enforced) == (True, False)
    assert outcome.backend == "noop"
    assert outcome.enforcement_capable is False


def test_the_noop_backend_restore_is_unchanged() -> None:
    assert NoOpIsolationBackend().restore(_DEVICE).enforced is False


# --- the local-address helper --------------------------------------------


def test_local_address_discovery_never_raises() -> None:
    """Best-effort by contract: it may return nothing, but it must not
    fail and take enforcement down with it."""
    assert isinstance(local_ipv4_addresses(), set)
