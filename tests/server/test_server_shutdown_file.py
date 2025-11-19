import asyncio
import os
import tempfile
from pathlib import Path
import contextlib

import pytest
from provide.testkit.mocking import AsyncMock

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.types import HandlerT, ServerT
from pyvider.rpcplugin.transport import UnixSocketTransport

class DummyHandler:
    pass

class DummyProtocol(RPCPluginProtocol[ServerT, HandlerT]):
    async def get_grpc_descriptors(self) -> tuple[None, str]:
        return None, "dummy_service_name"

    async def add_to_server(self, server: ServerT, handler: HandlerT) -> None:
        pass

@pytest.fixture
def temp_shutdown_file():
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        path = tmpfile.name
    if os.path.exists(path):
        os.unlink(path)
    yield Path(path)
    if os.path.exists(path):
        os.unlink(path)

@pytest.fixture
def temp_unix_socket_path():
    # Create a unique temporary file path for the Unix socket
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        path = tmpfile.name
    # Ensure the file is deleted, as Unix sockets are not files in the traditional sense
    if os.path.exists(path):
        os.unlink(path)
    yield Path(path)
    # Clean up the socket file after the test
    if os.path.exists(path):
        os.unlink(path)

@pytest.mark.asyncio
async def test_server_shuts_down_on_file_creation(temp_shutdown_file, temp_unix_socket_path, mocker):
    shutdown_file_path_str = str(temp_shutdown_file)
    mocker.patch.object(rpcplugin_config, 'plugin_shutdown_file_path', shutdown_file_path_str)

    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    async def mock_negotiate_side_effect():
        server._protocol_version = 1
        server._transport_name = "unix"
        server._transport = UnixSocketTransport(path=str(temp_unix_socket_path))

    mocker.patch.object(server, '_negotiate_handshake', side_effect=mock_negotiate_side_effect)

    async def mock_setup_server_side_effect():
        server._serving_event.set()

    mocker.patch.object(server, '_setup_server', side_effect=mock_setup_server_side_effect)

    mocker.patch.object(server, '_register_signal_handlers')
    
    
    mocker.patch('asyncio.sleep', new_callable=AsyncMock, return_value=None)
    mocker.patch.object(server, '_watch_shutdown_file', new_callable=AsyncMock)
    mocker.patch('sys.stdout.buffer.write')
    mocker.patch('sys.stdout.buffer.flush')

    serve_task = asyncio.create_task(server.serve())
    try:
        await server.wait_for_server_ready(timeout=2.0)

        with open(shutdown_file_path_str, "w") as f:
            f.write("shutdown")

        server._shutdown_requested() # Manually trigger shutdown
        await asyncio.wait_for(server._shutdown_event.wait(), timeout=5.0)

        await asyncio.wait_for(serve_task, timeout=5.0)

        assert server._serving_future.done(), "Server's serving future was not done after shutdown."
        assert server._shutdown_event.is_set(), "Shutdown event was not set."

    finally:
        if not serve_task.done():
            serve_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await serve_task


# 🐍🔌🧪🪄
