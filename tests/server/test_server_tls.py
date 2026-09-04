#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#


from provide.foundation.crypto import Certificate
import pytest

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import SecurityError
from pyvider.rpcplugin.server import RPCPluginServer
import pyvider.rpcplugin.server.network as server_network


@pytest.mark.asyncio
async def test_generate_server_credentials_failure(
    monkeypatch, mock_server_protocol, mock_server_handler
) -> None:
    # Force Certificate creation to raise an exception.

    forced_error_message = "Diagnosing CertificateError message"

    def mock_certificate_init_raises_error(self, *args, **kwargs):
        raise Exception(forced_error_message)

    monkeypatch.setattr(Certificate, "__init__", mock_certificate_init_raises_error)

    monkeypatch.setattr(rpcplugin_config, "plugin_server_cert", "dummy.crt")
    monkeypatch.setattr(rpcplugin_config, "plugin_server_key", "dummy.key")
    monkeypatch.setattr(rpcplugin_config, "plugin_auto_mtls", False)

    server: RPCPluginServer = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
    )

    with pytest.raises(SecurityError, match=r"Failed to load server certificate/key: .*"):
        server._generate_server_credentials()




def _make_dummy_cert(common_name: str = "CN"):
    """Create a mock certificate object for testing."""
    from unittest.mock import MagicMock
    dummy = MagicMock(spec=Certificate)
    dummy.cert_pem = "CERT"
    dummy.key_pem = "KEY"
    dummy.common_name = common_name
    return dummy


HOST_CLIENT_CERT = "-----BEGIN CERTIFICATE-----\nhost\n-----END CERTIFICATE-----"


def test_generate_server_credentials_auto_mtls_does_not_require_a_client_cert(
    monkeypatch, mock_server_protocol, mock_server_handler, mocker
):
    """The host's certificate turns TLS on, and nothing more.

    go-plugin/server.go:329-336 sets ClientAuth: RequireAndVerifyClientCert with
    ClientCAs holding exactly that certificate, and a Go plugin honours it. gRPC
    cannot: the host's certificate is ECDSA P-521 (go-plugin/mtls.go:21) and
    BoringSSL omits ecdsa_secp521r1_sha512 from its CertificateRequest, so the
    host is asked for a certificate it cannot present and the connection is
    dropped. Passing the bundle while require_client_auth is False would be
    inert -- no CertificateRequest is sent -- so neither is passed.
    """
    monkeypatch.setattr(rpcplugin_config, "plugin_server_cert", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_server_key", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_auto_mtls", True)
    monkeypatch.setattr(rpcplugin_config, "plugin_client_root_certs", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_client_cert", HOST_CLIENT_CERT)

    monkeypatch.setattr(
        "pyvider.rpcplugin.server.network.Certificate.create_self_signed_server_cert",
        lambda **_: _make_dummy_cert("serverCN"),
    )

    ssl_mock = mocker.patch("pyvider.rpcplugin.server.network.grpc.ssl_server_credentials")

    server = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler, config=None)

    result = server._generate_server_credentials()

    ssl_mock.assert_called_once()
    _, kwargs = ssl_mock.call_args
    assert kwargs["require_client_auth"] is False, (
        "requiring client auth here makes the plugin unreachable from stock Terraform"
    )
    assert kwargs["root_certificates"] is None
    assert result == ssl_mock.return_value


def test_generate_server_credentials_with_client_root_file(
    monkeypatch, tmp_path, mock_server_protocol, mock_server_handler, mocker
) -> None:
    """An explicit PLUGIN_CLIENT_ROOT_CERTS wins over the host's own cert."""
    monkeypatch.setattr(rpcplugin_config, "plugin_server_cert", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_server_key", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_auto_mtls", True)
    monkeypatch.setattr(rpcplugin_config, "plugin_client_cert", HOST_CLIENT_CERT)

    root_file = tmp_path / "root.pem"
    root_file.write_bytes(b"root-data")
    monkeypatch.setattr(rpcplugin_config, "plugin_client_root_certs", f"file://{root_file}")

    monkeypatch.setattr(
        "pyvider.rpcplugin.server.network.Certificate.create_self_signed_server_cert",
        lambda **_: _make_dummy_cert("serverCN"),
    )

    ssl_mock = mocker.patch("pyvider.rpcplugin.server.network.grpc.ssl_server_credentials")

    server = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler, config=None)
    server._generate_server_credentials()

    _, kwargs = ssl_mock.call_args
    assert kwargs["root_certificates"] == b"root-data"
    assert kwargs["require_client_auth"] is True


def test_generate_server_credentials_plaintext_without_host_cert(
    monkeypatch, mock_server_protocol, mock_server_handler, mocker
) -> None:
    """No PLUGIN_CLIENT_CERT means plaintext, whatever PLUGIN_AUTO_MTLS says.

    go-plugin/server.go:304-306 gates the whole TLS config on the host's
    certificate, so a host that did not ask for TLS is not handed one.
    """
    monkeypatch.setattr(rpcplugin_config, "plugin_server_cert", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_server_key", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_auto_mtls", True)
    monkeypatch.setattr(rpcplugin_config, "plugin_client_root_certs", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_client_cert", None)

    ssl_mock = mocker.patch("pyvider.rpcplugin.server.network.grpc.ssl_server_credentials")

    server = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler, config=None)

    assert server._generate_server_credentials() is None
    assert server._server_cert_obj is None
    ssl_mock.assert_not_called()


def test_generate_server_credentials_auto_mtls_off_declines_host_cert(
    monkeypatch, mock_server_protocol, mock_server_handler, mocker
) -> None:
    """PLUGIN_AUTO_MTLS=false declines automatic mTLS even when asked."""
    monkeypatch.setattr(rpcplugin_config, "plugin_server_cert", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_server_key", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_auto_mtls", False)
    monkeypatch.setattr(rpcplugin_config, "plugin_client_root_certs", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_client_cert", HOST_CLIENT_CERT)

    ssl_mock = mocker.patch("pyvider.rpcplugin.server.network.grpc.ssl_server_credentials")

    server = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler, config=None)

    assert server._generate_server_credentials() is None
    ssl_mock.assert_not_called()

# 🐍🔌📞🔚
