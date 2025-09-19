# pyvider/rpcplugin/tests/server/test_server_tls.py

from provide.foundation.crypto import Certificate
import pytest

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import SecurityError
from pyvider.rpcplugin.server import RPCPluginServer


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


# 🐍🔌🧪🪄
