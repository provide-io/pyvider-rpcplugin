#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Launch a real plugin server the way go-plugin's host launches one.

`go-plugin/client.go:637-700` builds the child environment: the magic cookie,
`PLUGIN_MIN_PORT` / `PLUGIN_MAX_PORT`, `PLUGIN_PROTOCOL_VERSIONS`, and (only
under AutoMTLS) `PLUGIN_CLIENT_CERT`. It then reads one pipe-delimited line
from the child's stdout. This harness does the same so the tests can assert on
what the plugin actually puts on the wire, rather than on a helper's return
value.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
import contextlib
import os
from pathlib import Path
import queue
import signal
import subprocess  # nosec B404 - launching the plugin under test is the point
import sys
import threading
import time

MAGIC_COOKIE_KEY = "TEST_PLUGIN_MAGIC_COOKIE"
MAGIC_COOKIE_VALUE = "e2e-cookie"

_REPO_ROOT = Path(__file__).resolve().parents[2]

#: Everything the plugin config layer reads. Cleared so an ambient value in the
#: developer's shell (or a leaked one from another test) cannot steer a run.
_CLEARED_PREFIXES = ("PLUGIN_", "SUPPORTED_", "TF_PLUGIN_")


class PluginProcess:
    """A launched plugin server plus the pipe its handshake arrives on."""

    def __init__(self, proc: subprocess.Popen[str]) -> None:
        self.proc = proc
        self._lines: queue.Queue[str | None] = queue.Queue()
        self._stderr_chunks: list[str] = []
        self._reader = threading.Thread(target=self._pump_stdout, daemon=True)
        self._reader.start()
        # stderr has to be drained continuously, not read at the end: these
        # plugins log a full rich traceback on a startup fault, which is more
        # than a pipe buffer holds, and a child blocked writing to a full pipe
        # never reaches its own sys.exit.
        self._stderr_reader = threading.Thread(target=self._pump_stderr, daemon=True)
        self._stderr_reader.start()

    def _pump_stdout(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._lines.put(line.rstrip("\n"))
        self._lines.put(None)

    def _pump_stderr(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self._stderr_chunks.append(line)

    def _next_line(self, timeout: float) -> str | None:
        """The next non-empty stdout line, or None if the pipe ends first."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty:
                return None
            if line is None:
                return None
            if line.strip():
                return line.strip()

    def read_handshake(self, timeout: float = 30.0) -> str:
        """Return the first non-empty stdout line, as go-plugin's host would."""
        line = self._next_line(timeout)
        if line is None:
            raise AssertionError(f"no handshake within {timeout}s; stderr:\n{self.wait_and_read_stderr()}")
        return line

    def saw_no_handshake(self, timeout: float = 30.0) -> str:
        """Assert the plugin never handshook, returning everything it logged."""
        line = self._next_line(timeout)
        if line is not None:
            raise AssertionError(f"expected no handshake, got: {line}")
        return self.wait_and_read_stderr()

    def wait_and_read_stderr(self, timeout: float = 15.0) -> str:
        """Let the plugin finish, then return everything it logged."""
        with contextlib.suppress(Exception):
            self.proc.wait(timeout=timeout)
        self._stderr_reader.join(timeout=5.0)
        return self.stderr()

    def stderr(self) -> str:
        """Whatever the plugin has written to stderr so far."""
        return "".join(self._stderr_chunks)

    def is_running(self) -> bool:
        return self.proc.poll() is None

    def wait(self, timeout: float = 10.0) -> int:
        return self.proc.wait(timeout=timeout)

    def signal(self, sig: signal.Signals) -> None:
        self.proc.send_signal(sig)

    def kill(self) -> None:
        with contextlib.suppress(Exception):
            self.proc.kill()
        with contextlib.suppress(Exception):
            self.proc.wait(timeout=5)


def host_env(**overrides: str) -> dict[str, str]:
    """The environment go-plugin's host hands a plugin, plus any overrides."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(_CLEARED_PREFIXES)
        # Inherited into the child this would make the server think it is under
        # test and skip its own process-exit path -- exactly what we measure.
        and key != "PYTEST_CURRENT_TEST"
    }
    env["PYTHONPATH"] = os.pathsep.join([str(_REPO_ROOT / "src"), str(_REPO_ROOT)])
    env["PYTHONUNBUFFERED"] = "1"
    env["PLUGIN_MAGIC_COOKIE_KEY"] = MAGIC_COOKIE_KEY
    env["PLUGIN_MAGIC_COOKIE_VALUE"] = MAGIC_COOKIE_VALUE
    env[MAGIC_COOKIE_KEY] = MAGIC_COOKIE_VALUE
    env["PLUGIN_MIN_PORT"] = "10000"
    env["PLUGIN_MAX_PORT"] = "25000"
    env.update(overrides)
    return env


@contextlib.contextmanager
def spawn(
    env: Mapping[str, str] | None = None,
    args: list[str] | None = None,
) -> Iterator[PluginProcess]:
    """Run the e2e plugin server as its own process, cleaning it up after."""
    proc = subprocess.Popen(  # nosec B603 - fixed argv, test-controlled
        [sys.executable, "-m", "tests.goplugin._plugin_main", *(args or [])],
        cwd=str(_REPO_ROOT),
        env=dict(env if env is not None else host_env()),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        # No setsid: go-plugin deliberately leaves the plugin in the host's
        # process group (go-plugin/internal/cmdrunner/cmd_runner.go:72-82 sets
        # no Setpgid), which is why a terminal Ctrl-C reaches it at all.
    )
    plugin = PluginProcess(proc)
    try:
        yield plugin
    finally:
        plugin.kill()
