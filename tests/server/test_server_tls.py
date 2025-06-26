# pyvider/rpcplugin/tests/server/test_server_tls.py

import pytest
from unittest import mock

from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import SecurityError

from tests.conftest import (
    mock_server_protocol,
    mock_server_handler,
)

@pytest.mark.asyncio
async def test_generate_server_credentials_failure(
    monkeypatch, mock_server_protocol, mock_server_handler
) -> None:
    # Force Certificate creation to raise an exception.
    from pyvider.rpcplugin.exception import SecurityError

    forced_error_message = "Diagnosing CertificateError message"

    def mock_certificate_init_raises_error(self, *args, **kwargs):
        raise Exception(forced_error_message)

    monkeypatch.setattr(Certificate, "__init__", mock_certificate_init_raises_error)

    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_SERVER_CERT", "dummy.crt")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_SERVER_KEY", "dummy.key")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_AUTO_MTLS", False)

    server: RPCPluginServer = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
    )

    with pytest.raises(SecurityError, match=r"Failed to load server certificate/key: Diagnosing CertificateError message"):
        server._generate_server_credentials()
