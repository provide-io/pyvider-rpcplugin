import asyncio
import gc
import pytest
from unittest.mock import AsyncMock, MagicMock


from pyvider.rpcplugin.config import ConfigError
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.server import RPCPluginServer
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
    mocker, # Only one mocker argument
    rpc_plugin_server_manager, # Use the new fixture
    # mock_server_protocol, mock_server_handler, mock_server_config, mock_server_transport are no longer direct dependencies
    # as rpc_plugin_server_manager will use its own (or defaults).
):
    # Create a server instance using the manager, but don't auto-start it.
    # The manager handles transport and basic protocol/handler setup.
    # We use default transport_type "unix" here, can be parameterized if needed.
    server, _ = await rpc_plugin_server_manager(
        auto_start=False
    )

    # Mock internal methods that precede _setup_server in the serve() call flow, if necessary,
    # or ensure they don't interfere.
    # The original test mocked _register_signal_handlers, _negotiate_handshake, _read_client_cert.
    # The rpc_plugin_server_manager doesn't call these directly when auto_start=False.
    # They are called by server.serve().

    mocker.patch.object(server, "_register_signal_handlers") # Keep this if still relevant before _setup_server
    mocker.patch.object(server, "_negotiate_handshake", new_callable=AsyncMock) # Keep this
    mocker.patch.object(server, "_read_client_cert", return_value=None) # Keep this

    # Mock _setup_server to raise an exception
    mocker.patch.object(
        server,
        "_setup_server",
        new_callable=AsyncMock,
        side_effect=RuntimeError("Setup failed!"),
    )

    # We also need to mock server.stop if we want to assert it was called,
    # or rely on the rpc_plugin_server_manager's cleanup to call it.
    # The original test explicitly mocked and asserted server.stop.
    mocked_stop = mocker.patch.object(server, "stop", new_callable=AsyncMock)

    with pytest.raises(RuntimeError, match="Setup failed!"):
        await server.serve()

    # server.serve() calls stop() in its finally block.
    mocked_stop.assert_called_once()

    # The rpc_plugin_server_manager will also call stop on cleanup,
    # so server.stop might be called twice. This is generally fine if stop() is idempotent.
    # If specific call count for stop (once by serve's finally) is critical,
    # then the manager's cleanup needs to be considered.
    # For this test, asserting it was called by serve() is the primary goal.
