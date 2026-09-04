#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""TLS is keyed on PLUGIN_CLIENT_CERT, and when on it is mutual.

`go-plugin/server.go:304-338` builds a TLS config *only* when the host sent
`PLUGIN_CLIENT_CERT`, and when it does it sets `ClientAuth:
RequireAndVerifyClientCert` with `ClientCAs` set to that certificate. With no
client cert the plugin serves plaintext and emits an empty sixth handshake
field, which is what `go-plugin/client.go:920-926` keys off: a sixth field
longer than 50 characters makes the host call `loadServerCert`, which
dereferences `c.config.TLSConfig.RootCAs` (`client.go:950-968`) -- nil for a
host that disabled TLS.
"""

from __future__ import annotations

import base64
import sys

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc
import pytest

from tests.goplugin import harness

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="the harness serves over a Unix socket",
)

_SSL_OPTS = (("grpc.ssl_target_name_override", "localhost"),)


def _client_identity() -> tuple[str, str]:
    """A client keypair, the way go-plugin's host generates one (client.go:670-683)."""
    from provide.foundation.crypto import Certificate

    cert = Certificate.create_self_signed_client_cert(
        common_name="localhost",
        organization_name="goplugin-e2e",
        validity_days=1,
        alt_names=["localhost"],
    )
    return cert.cert_pem, cert.key_pem


def _server_cert_pem(handshake: str) -> bytes:
    """Rebuild a PEM from the handshake's base64 DER, as `loadServerCert` does."""
    raw = handshake.split("|")[5]
    der = base64.b64decode(raw + "=" * (-len(raw) % 4))
    body = base64.b64encode(der).decode()
    lines = [body[i : i + 64] for i in range(0, len(body), 64)]
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n").encode()


def _check(target: str, creds: grpc.ChannelCredentials | None) -> str:
    """Run one health Check, returning "SERVING" or the failure's status code."""
    channel = (
        grpc.secure_channel(target, creds, options=list(_SSL_OPTS))
        if creds is not None
        else grpc.insecure_channel(target)
    )
    with channel:
        stub = health_pb2_grpc.HealthStub(channel)
        try:
            reply = stub.Check(health_pb2.HealthCheckRequest(service=""), timeout=10)
        except grpc.RpcError as exc:
            return exc.code().name
        return health_pb2.HealthCheckResponse.ServingStatus.Name(reply.status)


def test_no_client_cert_means_plaintext_and_an_empty_cert_field() -> None:
    """Without PLUGIN_CLIENT_CERT the plugin must not advertise a certificate.

    A host with `TLSConfig == nil` -- the `TF_DISABLE_PLUGIN_TLS` path the SDK
    test harnesses use -- sees a sixth field over 50 characters, calls
    `loadServerCert`, and nil-pointer panics on `c.config.TLSConfig.RootCAs`.
    """
    with harness.spawn() as plugin:
        handshake = plugin.read_handshake()

        parts = handshake.split("|")
        assert len(parts) == 6, handshake
        assert parts[5] == "", f"advertised a server cert with no client cert: {handshake[:120]}"
        assert _check(f"unix:{parts[3]}", None) == "SERVING"


def test_client_cert_turns_on_tls_and_is_required() -> None:
    """With PLUGIN_CLIENT_CERT the plugin serves TLS and verifies the client."""
    client_pem, client_key = _client_identity()
    env = harness.host_env(PLUGIN_CLIENT_CERT=client_pem)

    with harness.spawn(env=env) as plugin:
        handshake = plugin.read_handshake()

        parts = handshake.split("|")
        assert len(parts[5]) > 50, f"no server cert advertised: {handshake[:120]}"

        target = f"unix:{parts[3]}"
        root = _server_cert_pem(handshake)

        presented = grpc.ssl_channel_credentials(
            root_certificates=root,
            private_key=client_key.encode(),
            certificate_chain=client_pem.encode(),
        )
        assert _check(target, presented) == "SERVING"

        anonymous = grpc.ssl_channel_credentials(root_certificates=root)
        assert _check(target, anonymous) != "SERVING", "server accepted a client with no certificate"


def test_a_client_cert_from_elsewhere_is_rejected() -> None:
    """Only the host's own certificate is a trusted client identity.

    go-plugin makes exactly that certificate the whole `ClientCAs` pool
    (`server.go:308-311`, `server.go:331`).
    """
    client_pem, client_key = _client_identity()
    other_pem, other_key = _client_identity()
    env = harness.host_env(PLUGIN_CLIENT_CERT=client_pem)

    with harness.spawn(env=env) as plugin:
        handshake = plugin.read_handshake()
        parts = handshake.split("|")
        root = _server_cert_pem(handshake)

        impostor = grpc.ssl_channel_credentials(
            root_certificates=root,
            private_key=other_key.encode(),
            certificate_chain=other_pem.encode(),
        )
        assert _check(f"unix:{parts[3]}", impostor) != "SERVING"
