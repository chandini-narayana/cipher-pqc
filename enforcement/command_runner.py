"""CommandRunner — the injectable, mockable execution seam a real Linux
isolation backend will use to run a firewall command, and the only
Phase-3A implementation of it, `UnavailableCommandRunner`.

This module deliberately does **not** import `subprocess` or `os`, and
nothing in CIPHER currently constructs a runner that can spawn a
process. That is the point: `LinuxIsolationBackend` (see
linux_backend.py) is written against this interface so that, when the
controlled enforcement topology is frozen on the Raspberry Pi, the only
new code needed is one concrete `CommandRunner` that shells out — no
change to `IsolationBackend`, `should_isolate()`, `pipeline/runner.py`,
or any composition root.

Keeping execution behind an interface also means every test can assert
*exactly* which argv a backend would have run, without any real
firewall rule ever being created on the developer's machine.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True, slots=True)
class CommandResult:
    """The outcome of one attempted command execution.

    `executed` distinguishes "the command ran and returned
    `exit_code`" from "no process was ever spawned" — the second is the
    only case that can occur in this phase, and conflating the two is
    exactly the honesty failure `IsolationOutcome.enforced` exists to
    prevent.
    """

    command: tuple[str, ...]
    executed: bool
    exit_code: int
    stdout: str = ""
    stderr: str = ""

    @property
    def succeeded(self) -> bool:
        return self.executed and self.exit_code == 0


class CommandRunner(ABC):
    """Abstract command-execution seam.

    `run()` must never raise for an ordinary failure (command missing,
    non-zero exit, insufficient privilege) — it returns a
    `CommandResult` describing what happened, so the calling backend can
    surface it as a non-enforced `IsolationOutcome` rather than an
    exception escaping into `pipeline/runner.py`.
    """

    @abstractmethod
    def run(self, command: Sequence[str]) -> CommandResult:
        raise NotImplementedError  # pragma: no cover - interface only


class UnavailableCommandRunner(CommandRunner):
    """The only CommandRunner in this phase: it never spawns a process.

    Returns `executed=False` with an explanatory `stderr` for any
    command. This is the safe default for `LinuxIsolationBackend`, so
    that even an accidentally-constructed Linux backend on any platform
    cannot touch a firewall.
    """

    REASON = "Command execution is unavailable: no executing CommandRunner is configured"

    def run(self, command: Sequence[str]) -> CommandResult:
        return CommandResult(
            command=tuple(command),
            executed=False,
            exit_code=-1,
            stderr=self.REASON,
        )
