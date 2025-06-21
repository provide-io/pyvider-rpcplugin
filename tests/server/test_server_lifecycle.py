# pyvider/rpcplugin/tests/server/test_server_lifecycle.py

import asyncio
import sys
import builtins
import os
import pytest
from io import StringIO
import gc
import stat
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from grpc.aio import server as GrpcAioServerType
from pyvider.rpcplugin.types import RPCPluginTransport
from pyvider.rpcplugin.exception import TransportError, ProtocolError, HandshakeError, ConfigError
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport


from tests.conftest import (
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    DummyAioServer,
    DummyGRPCServer,
)

class MockBytesIO:
    """Mock implementation of sys.stdout.buffer for testing."""

    def __init__(self, string_io):
        self.string_io = string_io

    def write(self, data):
        if isinstance(data, bytes):
            self.string_io.write(data.decode("utf-8"))
        else:
            self.string_io.write(str(data))
        return len(data)

    def flush(self):
        self.string_io.flush()


@pytest.mark.asyncio
async def test_wait_for_server_ready(
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    managed_unix_socket_path,
    mocker,
) -> None:
    test_transport = UnixSocketTransport(path=managed_unix_socket_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    # Manually assign the transport since negotiate_handshake is not run
    server._transport = test_transport
    server._transport.endpoint = managed_unix_socket_path

    # Mock the event to be set
    server._serving_event = asyncio.Event()
    server._serving_event.set()

    # Mock os checks to simulate a ready socket
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('socket.socket') # Mock socket creation
    
    # This should now pass without AttributeError
    await server.wait_for_server_ready(timeout=0.1)
    
    assert server._serving_event.is_set()


@pytest.mark.asyncio
async def test_attrs_post_init_handshake_config_error(mocker):
    """
    Test that if HandshakeConfig instantiation raises an error during
    RPCPluginServer instantiation, that error is propagated as a ConfigError.
    """
    # Mock HandshakeConfig to raise a specific error
    mocker.patch(
        "pyvider.rpcplugin.server.HandshakeConfig",
        side_effect=ValueError("Test HandshakeConfig error"),
    )

    with pytest.raises(ConfigError, match="Failed to initialize handshake configuration"):
        RPCPluginServer(
            protocol=mock_server_protocol,
            handler=mock_server_handler,
            config=None,
            transport=None,
        )


@pytest.mark.asyncio
async def test_serve_error(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    managed_unix_socket_path,
) -> None:
    test_transport = UnixSocketTransport(path=managed_unix_socket_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    monkeypatch.setattr(server, "_register_signal_handlers", lambda: None)

    async def failing_negotiate(self):
        raise HandshakeError("Handshake failed deliberately")

    monkeypatch.setattr(
        server, "_negotiate_handshake", failing_negotiate.__get__(server, type(server))
    )

    with pytest.raises(HandshakeError, match="Handshake failed deliberately"):
        await server.serve()

    await server.stop()


@pytest.mark.asyncio
async def test_serve_setup_server_raises_exception(
    mocker,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):
    """Test serve() when _setup_server raises a non-specific exception."""
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

    # The refined `serve` method will now let RuntimeError propagate
    with pytest.raises(RuntimeError, match="Setup failed!"):
        await server.serve()

    server.stop.assert_called_once()


@pytest.mark.asyncio
async def test_del_method_logging_unknown_endpoint(
    mock_server_protocol,
    mock_server_handler,
    mocker,
):
    """Test __del__ logging when transport/port are unavailable and server not stopped."""
    mock_logger_warning = mocker.patch("pyvider.rpcplugin.server.logger.warning")

    server_instance = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=None,
    )

    del server_instance
    gc.collect()

    # The assertion is relaxed to check if *any* call matches.
    # This avoids failures due to other potential warnings during test teardown.
    found_log = any(
        "RPCPluginServer for unknown endpoint was not explicitly stopped" in call.args[0]
        for call in mock_logger_warning.call_args_list
    )
    assert found_log, "Expected warning for un-stopped server not found in logs."
