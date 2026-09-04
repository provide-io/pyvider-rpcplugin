#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""The advertised protocol version is bounded by what the plugin serves.

`go-plugin/server.go:145-222` intersects the host's `PLUGIN_PROTOCOL_VERSIONS`
with `opts.VersionedPlugins` -- the versions the *server* registered -- and
returns the newest match. It never invents a version out of a static range.
Terraform sends `5,6` (`terraform/internal/plugin6/serve.go` registers the
plugin set it can talk to), so a plugin serving `tfplugin6.Provider` must say
6 and nothing else.
"""

from __future__ import annotations

import signal
import sys

import pytest

from tests.goplugin import harness

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the harness serves over a Unix socket",
)


def _version(handshake: str) -> int:
    return int(handshake.split("|")[1])


def test_version_comes_from_the_service_the_plugin_registered() -> None:
    """With no list from the host, advertise what is actually served."""
    with harness.spawn(args=["--service-name", "tfplugin6.Provider"]) as plugin:
        assert _version(plugin.read_handshake()) == 6


def test_newest_mutually_supported_version_wins() -> None:
    """Terraform offers 5 and 6; a tfplugin6 provider takes 6."""
    env = harness.host_env(PLUGIN_PROTOCOL_VERSIONS="5,6")
    with harness.spawn(env=env, args=["--service-name", "tfplugin6.Provider"]) as plugin:
        assert _version(plugin.read_handshake()) == 6


def test_no_overlap_advertises_the_lowest_served_version() -> None:
    """A host asking only for 5 is told 6, not 5, and rejects it itself.

    `go-plugin/server.go:145-147` is explicit: "In the event that there is no
    suitable version, the last version in the config is returned leaving the
    client to report the incompatibility", and `:216-222` returns the lowest
    registered version to do it. That is the better error: the host names both
    version sets to the user, where a plugin that exited during the handshake
    would surface only "plugin exited before we could connect".
    """
    env = harness.host_env(PLUGIN_PROTOCOL_VERSIONS="5")
    with harness.spawn(env=env, args=["--service-name", "tfplugin6.Provider"]) as plugin:
        handshake = plugin.read_handshake()
        assert _version(handshake) == 6, handshake

        plugin.signal(signal.SIGTERM)
        stderr = plugin.wait_and_read_stderr()

    assert "No mutually supported protocol version" in stderr, stderr
    assert "[5]" in stderr and "[6]" in stderr, stderr


def test_a_tfplugin5_provider_serves_5() -> None:
    """The version tracks the registered service, not a hardcoded preference."""
    env = harness.host_env(PLUGIN_PROTOCOL_VERSIONS="5,6")
    with harness.spawn(env=env, args=["--service-name", "tfplugin5.Provider"]) as plugin:
        assert _version(plugin.read_handshake()) == 5


def test_supported_protocol_versions_still_overrides() -> None:
    """The config escape hatch stays available for tests and odd plugins."""
    env = harness.host_env(
        PLUGIN_PROTOCOL_VERSIONS="4,5",
        SUPPORTED_PROTOCOL_VERSIONS="4,5",
    )
    with harness.spawn(env=env, args=["--service-name", "tfplugin6.Provider"]) as plugin:
        assert _version(plugin.read_handshake()) == 5
