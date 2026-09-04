#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""A plugin that never came up must not exit 0.

`go-plugin/server.go:232-266` records `exitCode = 1` for a startup fault -- a
missing magic cookie key or value, a cookie that does not match -- and a
deferred `os.Exit` runs it. A plugin that exits 0 without handshaking leaves
Terraform reporting only "plugin exited before we could connect", with nothing
attached about why.
"""

from __future__ import annotations

import sys

import pytest

from tests.goplugin import harness

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the harness serves over a Unix socket",
)


def test_missing_magic_cookie_exits_nonzero() -> None:
    """Running the plugin directly, with no cookie from a host, is a failure."""
    env = harness.host_env()
    del env[harness.MAGIC_COOKIE_KEY]

    with harness.spawn(env=env) as plugin:
        stderr = plugin.saw_no_handshake(timeout=20.0)

        assert plugin.proc.returncode == 1, (
            f"startup failure exited {plugin.proc.returncode}; stderr:\n{stderr}"
        )
        assert "Magic cookie not provided" in stderr, stderr


def test_wrong_magic_cookie_exits_nonzero() -> None:
    """A cookie that does not match is the same class of failure.

    A protocol-version mismatch is deliberately not one of these: go-plugin
    advertises its oldest served version and lets the host object
    (`server.go:145-147`), so the plugin comes up and handshakes normally.
    The general "any startup exception exits 1" contract is covered by
    tests/server/test_server_core_coverage.py.
    """
    env = harness.host_env(**{harness.MAGIC_COOKIE_KEY: "not-the-cookie"})

    with harness.spawn(env=env) as plugin:
        stderr = plugin.saw_no_handshake(timeout=20.0)

        assert plugin.proc.returncode == 1, (
            f"startup failure exited {plugin.proc.returncode}; stderr:\n{stderr}"
        )
        assert "Magic cookie mismatch" in stderr, stderr


def test_a_served_plugin_shut_down_cleanly_exits_zero() -> None:
    """The success path is unchanged: a graceful stop is still exit 0."""
    import signal

    with harness.spawn() as plugin:
        plugin.read_handshake()
        plugin.signal(signal.SIGTERM)

        assert plugin.wait(timeout=15.0) == 0
