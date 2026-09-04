#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""A real go-plugin host launches the plugin, negotiates mTLS, and pings it.

Every other test in this directory drives the plugin from Python, which cannot
reach this class of defect: a Python host generates a certificate its own TLS
stack can present, so the mutual-TLS path always succeeds. go-plugin's host
generates an ECDSA **P-521** client certificate (`go-plugin/mtls.go:21`), and
gRPC's BoringSSL does not offer `ecdsa_secp521r1_sha512` among the signature
schemes in its CertificateRequest. A server that sets
`require_client_auth=True` therefore asks for a certificate the host is unable
to send, and the connection dies as `PEER_DID_NOT_RETURN_A_CERTIFICATE`.

`tests/goplugin/real/main.go` is the host: `plugin.NewClient` with
`AutoMTLS: true`, so the handshake, the certificate generation, the pinning of
the plugin's certificate from the sixth handshake field and the health check
are all go-plugin's own code, not a reimplementation of it.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess  # nosec B404 - launching the Go host under test is the point
import sys

import pytest

from tests.goplugin import harness

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the plugin serves over a Unix socket",
)

_SOURCE = Path(__file__).parent / "real"


@pytest.fixture(scope="session")
def go_host(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the go-plugin host, or skip where Go is unavailable."""
    if shutil.which("go") is None:
        pytest.skip("no Go toolchain; this test needs a real go-plugin host")

    binary = tmp_path_factory.mktemp("gohost") / "host"
    build = subprocess.run(  # nosec B603 B607 - fixed argv, repo-controlled source
        ["go", "build", "-o", str(binary), "."],
        cwd=_SOURCE,
        capture_output=True,
        text=True,
        timeout=600,
    )
    if build.returncode != 0:
        pytest.fail(f"could not build the go-plugin host:\n{build.stderr}")
    return binary


def _run(go_host: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603 - fixed argv
        [str(go_host), sys.executable, "-m", "tests.goplugin._plugin_main"],
        cwd=Path(__file__).resolve().parents[2],
        env=harness.host_env(),
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_the_plugin_answers_a_real_go_plugin_host(go_host: Path) -> None:
    """The whole contract: handshake, AutoMTLS, and a health check that passes.

    A failure here reads `CONNECT FAILED` (handshake or TLS) or `PING FAILED`
    (the health service is registered under the wrong name).
    """
    result = _run(go_host)

    assert result.returncode == 0, (
        f"a real go-plugin host could not drive the plugin\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr[-3000:]}"
    )
    assert "PING OK" in result.stdout


# 🐍🏗️🔚
