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


def test_a_version_the_plugin_does_not_serve_is_never_advertised() -> None:
    """A host asking only for 5 must not be told 5 by a tfplugin6 provider."""
    env = harness.host_env(PLUGIN_PROTOCOL_VERSIONS="5")
    with harness.spawn(env=env, args=["--service-name", "tfplugin6.Provider"]) as plugin:
        stderr = plugin.saw_no_handshake(timeout=20.0)

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
