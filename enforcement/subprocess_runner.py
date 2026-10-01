"""SubprocessCommandRunner — the one CommandRunner in CIPHER that actually
executes a command.

It lives in its own module, apart from `enforcement/command_runner.py`, for
a reason that is enforced by test: that module (and `backends.py`, and
`linux_backend.py`) is statically asserted to import neither `subprocess`
nor `os`. Process-spawning capability therefore exists in exactly one
file, and it reaches a run only when a composition root deliberately
constructs this class. Importing `enforcement` does not make a firewall
command possible; composing this runner does.

Safety properties, all load-bearing:

  * **Never `shell=True`.** Commands are passed as an argument list
    straight to `subprocess.run`, so no value is ever concatenated into a
    shell string and no shell metacharacter in an IP or interface name
    can mean anything. A test asserts `shell` is never passed.
  * **Never raises for an ordinary failure.** A missing binary, a
    permission denial, a timeout, or a non-zero exit all come back as a
    `CommandResult` the caller inspects — so a firewall problem surfaces
    as a non-enforced `IsolationOutcome` instead of an exception
    escaping into `pipeline/runner.py`.
  * **`executed` is honest.** It is True only when a process really ran
    and returned a status. A binary that does not exist reports
    `executed=False`, which `CommandResult.succeeded` can never treat as
    success regardless of the exit code field.
"""
from __future__ import annotations

import logging
import subprocess
from typing import Sequence

from enforcement.command_runner import CommandResult, CommandRunner

logger = logging.getLogger(__name__)

DEFAULT_COMMAND_TIMEOUT_SECONDS = 10.0


class SubprocessCommandRunner(CommandRunner):
    """Runs a command as a plain argument list, with no shell.

    `timeout` bounds each individual command so a wedged firewall utility
    cannot hang the capture run; a timeout is reported as a failed
    command, never as a raised exception.
    """

    def __init__(self, timeout: float = DEFAULT_COMMAND_TIMEOUT_SECONDS) -> None:
        self._timeout = float(timeout)

    def run(self, command: Sequence[str]) -> CommandResult:
        argv = [str(part) for part in command]
        if not argv:
            return CommandResult(
                command=(), executed=False, exit_code=-1, stderr="empty command"
            )

        logger.debug("Running command: %s", argv)
        try:
            completed = subprocess.run(  # noqa: S603 - argv list, never shell=True
                argv,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except FileNotFoundError:
            return CommandResult(
                command=tuple(argv),
                executed=False,
                exit_code=-1,
                stderr=f"{argv[0]!r} was not found on this system",
            )
        except PermissionError as exc:
            return CommandResult(
                command=tuple(argv),
                executed=False,
                exit_code=-1,
                stderr=f"not permitted to execute {argv[0]!r}: {exc}",
            )
        except subprocess.TimeoutExpired:
            return CommandResult(
                command=tuple(argv),
                executed=False,
                exit_code=-1,
                stderr=f"{argv[0]!r} timed out after {self._timeout:g}s",
            )
        except OSError as exc:
            return CommandResult(
                command=tuple(argv),
                executed=False,
                exit_code=-1,
                stderr=f"failed to execute {argv[0]!r}: {exc}",
            )

        return CommandResult(
            command=tuple(argv),
            executed=True,
            exit_code=int(completed.returncode),
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )
