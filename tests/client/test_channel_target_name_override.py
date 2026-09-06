"""The TLS target name has to be overridden on every transport, not just unix.

The server's auto-generated certificate carries `DNS:localhost` and no IP SAN.
A unix socket has no hostname to verify against, so the client overrides the
target name to `localhost` and verification succeeds. A TCP endpoint is dialled
by literal address -- `127.0.0.1:<port>` -- which does not match a DNS SAN
either, and without the same override gRPC never completes its TLS handshake:
the channel stays not-ready until the deadline, three retries burn the client's
budget, and the failure surfaces as a HandshakeError for a handshake that had
already succeeded.

Windows is where this bites, because it is the only platform whose default
transport list is TCP-only.

SPDX-FileCopyrightText: Copyright (c) 2025-2026 provide.io llc. All rights reserved.
SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from typing import Any

from pyvider.rpcplugin.client.process import ClientProcessMixin


class _Client(ClientProcessMixin):
    """The mixin under test, with only the attributes it reads."""

    def __init__(self, transport: str, server_cert: str | None) -> None:
        self._transport_name = transport
        self._server_cert = server_cert
        self.logger = _SilentLogger()


class _SilentLogger:
    def debug(self, *args: Any, **kwargs: Any) -> None:
        pass


def _override(transport: str, server_cert: str | None) -> str | None:
    options = dict(_Client(transport, server_cert)._get_channel_options())  # type: ignore[arg-type]
    value = options.get("grpc.ssl_target_name_override")
    return str(value) if value is not None else None


def test_tcp_with_a_server_certificate_overrides_the_target_name() -> None:
    """The regression: a TCP endpoint is dialled by IP and matches no DNS SAN."""
    assert _override("tcp", "CERTDATA") == "localhost"


def test_unix_with_a_server_certificate_still_overrides() -> None:
    assert _override("unix", "CERTDATA") == "localhost"


def test_no_override_without_a_server_certificate() -> None:
    """Nothing is being verified, so there is no name to override."""
    assert _override("tcp", None) is None
    assert _override("unix", None) is None
