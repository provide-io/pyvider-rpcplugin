#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""TLS is keyed on PLUGIN_CLIENT_CERT; client auth needs PLUGIN_CLIENT_ROOT_CERTS.

`go-plugin/server.go:304-338` builds a TLS config *only* when the host sent
`PLUGIN_CLIENT_CERT`, and when it does it sets `ClientAuth:
RequireAndVerifyClientCert` with `ClientCAs` set to that certificate. With no
client cert the plugin serves plaintext and emits an empty sixth handshake
field, which is what `go-plugin/client.go:920-926` keys off: a sixth field
longer than 50 characters makes the host call `loadServerCert`, which
dereferences `c.config.TLSConfig.RootCAs` (`client.go:950-968`) -- nil for a
host that disabled TLS.

The reverse direction is where a Go plugin and this one part company. go-plugin
requires and verifies the host's certificate; this server cannot, because that
certificate is ECDSA P-521 (`go-plugin/mtls.go:21`) and BoringSSL does not
offer `ecdsa_secp521r1_sha512` in its CertificateRequest -- Go then presents
nothing and the connection dies as `PEER_DID_NOT_RETURN_A_CERTIFICATE`. So the
automatic path is encrypted but does not authenticate the host, and client
verification is available only via an explicitly configured
PLUGIN_CLIENT_ROOT_CERTS. `test_goplugin_real_host.py` holds that line with an
actual go-plugin host.
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


def test_client_cert_turns_on_tls_but_does_not_require_one_back() -> None:
    """PLUGIN_CLIENT_CERT turns TLS on; it cannot turn client auth on.

    Requiring a client certificate here asks go-plugin's host for a P-521
    certificate gRPC will not let it present, so the host connects and is then
    dropped. The anonymous client below stands in for that host: it must be
    served, or a real Terraform cannot reach the plugin at all.
    """
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
        assert _check(target, anonymous) == "SERVING", (
            "client auth was required on the automatic-mTLS path; go-plugin's host "
            "cannot satisfy that and every provider becomes unreachable"
        )


def test_explicit_client_root_certs_do_require_and_verify_a_client() -> None:
    """The one path where client verification works: a CA you configured.

    PLUGIN_CLIENT_ROOT_CERTS is an operator's own bundle, on a curve gRPC will
    accept, so `require_client_auth` can be honoured here. An anonymous client
    and one signed by a different CA must both be refused.
    """
    client_pem, client_key = _client_identity()
    other_pem, other_key = _client_identity()
    env = harness.host_env(
        PLUGIN_CLIENT_CERT=client_pem,
        PLUGIN_CLIENT_ROOT_CERTS=client_pem,
    )

    with harness.spawn(env=env) as plugin:
        handshake = plugin.read_handshake()
        parts = handshake.split("|")
        target = f"unix:{parts[3]}"
        root = _server_cert_pem(handshake)

        presented = grpc.ssl_channel_credentials(
            root_certificates=root,
            private_key=client_key.encode(),
            certificate_chain=client_pem.encode(),
        )
        assert _check(target, presented) == "SERVING"

        anonymous = grpc.ssl_channel_credentials(root_certificates=root)
        assert _check(target, anonymous) != "SERVING", "accepted a client with no certificate"

        impostor = grpc.ssl_channel_credentials(
            root_certificates=root,
            private_key=other_key.encode(),
            certificate_chain=other_pem.encode(),
        )
        assert _check(target, impostor) != "SERVING", "accepted a certificate from another CA"
