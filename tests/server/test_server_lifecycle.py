import asyncio
import gc
import pytest
from unittest.mock import AsyncMock, MagicMock

# FIX: Import ConfigError from config.py to match the exception's source module
from pyvider.rpcplugin.config import ConfigError
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol as BaseRpcAbcProtocol # Added import
from pyvider.rpcplugin.transport import UnixSocketTransport

from tests.conftest import (
    mock_server_protocol,
    mock_server_handler,
)

def test_attrs_post_init_handshake_config_error(mocker):
    """
    Tests that a synchronous error during __attrs_post_init__ is correctly handled.
    This test uses a manual try/except block for robustness.
    """
    local_mock_protocol = MagicMock()
    local_mock_handler = MagicMock()

    mocker.patch(
        "pyvider.rpcplugin.server.rpcplugin_config.magic_cookie_key",
        side_effect=ValueError("Test rpcplugin_config error"),
    )

    try:
        RPCPluginServer(
            protocol=local_mock_protocol,
            handler=local_mock_handler,
            config=None,
            transport=None,
        )
        pytest.fail("ConfigError was not raised when expected")
    except ConfigError as e:
        # Assert that the caught exception is the one we expect.
        assert "Failed to initialize handshake configuration: Test rpcplugin_config error" in str(e)
    except Exception as e:
        pytest.fail(f"An unexpected exception was raised: {type(e).__name__}: {e}")


@pytest.mark.asyncio
async def test_serve_setup_server_raises_exception(
    mocker,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport,
    )

    mocker.patch.object(server, "_register_signal_handlers")
    mocker.patch.object(server, "_negotiate_handshake", new_callable=AsyncMock)
    mocker.patch.object(server, "_read_client_cert", return_value=None)
    
    mocker.patch.object(
        server,
        "_setup_server",
        new_callable=AsyncMock,
        side_effect=RuntimeError("Setup failed!"),
    )
    mocker.patch.object(server, "stop", new_callable=AsyncMock)

    with pytest.raises(RuntimeError, match="Setup failed!"):
        await server.serve()

    server.stop.assert_called_once()

@pytest.mark.asyncio
async def test_attrs_post_init_empty_protocol_service_name(mocker): # Added mocker
    # Ensure rpcplugin_config is fresh for this test, especially for health_service_enabled
    mocker.patch("pyvider.rpcplugin.server.rpcplugin_config.health_service_enabled", return_value=True)

    mock_protocol_empty_name = MagicMock(spec=BaseRpcAbcProtocol)
    # To correctly simulate an empty service_name that hasattr would find:
    # setattr(mock_protocol_empty_name, 'service_name', "") # This also works
    type(mock_protocol_empty_name).service_name = mocker.PropertyMock(return_value="")

    mock_handler = MagicMock()

    server = RPCPluginServer(protocol=mock_protocol_empty_name, handler=mock_handler)
    # Default main_service_name should be used
    assert server._main_service_name == "pyvider.default.plugin.Service"
    assert server._health_servicer is not None, "Health servicer should be initialized if enabled"
    assert server._health_servicer._service_name == "pyvider.default.plugin.Service"
