#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""go-plugin eats SIGINT; SIGTERM still stops the plugin.

`go-plugin/server.go:459-473` spawns a goroutine that receives `os.Interrupt`
forever and only logs "plugin received interrupt signal, ignoring". The plugin
is not put in its own process group (`internal/cmdrunner/cmd_runner.go:72-82`
sets no `Setpgid`), so a terminal Ctrl-C is delivered to the whole foreground
group -- host and plugin alike. The host must be the one to sequence the stop.
"""

from __future__ import annotations

import signal
import sys
import time

import pytest

from tests.goplugin import harness

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="POSIX signal delivery semantics",
)


def test_plugin_ignores_sigint() -> None:
    """A Ctrl-C that reaches the plugin must not take the plugin down."""
    with harness.spawn() as plugin:
        plugin.read_handshake()

        plugin.signal(signal.SIGINT)
        time.sleep(2.0)

        assert plugin.is_running(), (
            f"plugin exited on SIGINT (rc={plugin.proc.returncode}); "
            f"stderr:\n{plugin.stderr()}"
        )


def test_plugin_still_stops_on_sigterm() -> None:
    """SIGTERM keeps its graceful-shutdown meaning."""
    with harness.spawn() as plugin:
        plugin.read_handshake()

        plugin.signal(signal.SIGTERM)

        assert plugin.wait(timeout=15.0) == 0


def test_sigint_ignoring_can_be_switched_off() -> None:
    """`PLUGIN_IGNORE_SIGINT=false` is the equivalent of go-plugin's test mode.

    `go-plugin/server.go:458` guards the interrupt-eating goroutine with
    `if opts.Test == nil` so that `go test` can cancel a plugin. This library
    exposes the same escape hatch as configuration.
    """
    env = harness.host_env(PLUGIN_IGNORE_SIGINT="false")
    with harness.spawn(env=env) as plugin:
        plugin.read_handshake()

        plugin.signal(signal.SIGINT)

        assert plugin.wait(timeout=15.0) == 0
