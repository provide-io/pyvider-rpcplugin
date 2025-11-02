# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""TODO: Add module docstring."""

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


def test_generate_server_credentials_auto_mtls_success(monkeypatch, mock_server_protocol, mock_server_handler, mocker):
    monkeypatch.setattr(rpcplugin_config, "plugin_server_cert", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_server_key", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_auto_mtls", True)
    monkeypatch.setattr(rpcplugin_config, "plugin_client_root_certs", None)

    monkeypatch.setattr(
        "pyvider.rpcplugin.client.handshake.Certificate.create_self_signed_client_cert",
        lambda **_: _make_dummy_cert(),
    )
    monkeypatch.setattr(
        "pyvider.rpcplugin.server.network.Certificate.create_self_signed_server_cert",
        lambda **_: _make_dummy_cert("serverCN"),
    )

    ssl_mock = mocker.patch("pyvider.rpcplugin.server.network.grpc.ssl_server_credentials")

    server = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler, config=None)

    result = server._generate_server_credentials()

    ssl_mock.assert_called_once()
    assert result == ssl_mock.return_value


def test_generate_server_credentials_with_client_root_file(
    monkeypatch, tmp_path, mock_server_protocol, mock_server_handler, mocker
) -> None:
    monkeypatch.setattr(rpcplugin_config, "plugin_server_cert", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_server_key", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_auto_mtls", True)

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


def test_generate_server_credentials_info_when_missing_root(
    monkeypatch, mock_server_protocol, mock_server_handler, mocker
) -> None:
    monkeypatch.setattr(rpcplugin_config, "plugin_server_cert", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_server_key", None)
    monkeypatch.setattr(rpcplugin_config, "plugin_auto_mtls", True)
    monkeypatch.setattr(rpcplugin_config, "plugin_client_root_certs", None)

    monkeypatch.setattr(
        "pyvider.rpcplugin.server.network.Certificate.create_self_signed_server_cert",
        lambda **_: _make_dummy_cert("serverCN"),
    )

    server = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler, config=None)

    info_spy = mocker.spy(server_network.logger, "info")
    server._generate_server_credentials()
    info_spy.assert_any_call(
        "auto_mtls is True, but PLUGIN_CLIENT_ROOT_CERTS not provided. Client certs will not be required/verified."
    )

# 🔌📞🔚
