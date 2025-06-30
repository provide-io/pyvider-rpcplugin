import asyncio
import contextlib
import os
import tempfile
from collections.abc import Generator  # Added Any, Generator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock  # Added MagicMock

import pytest

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.transport import UnixSocketTransport

# Use Any for ServerT, HandlerT in mock protocol for simplicity in test file
# from pyvider.rpcplugin.types import HandlerT, ServerT


class DummyHandler:
    pass


class DummyProtocol(RPCPluginProtocol[Any, Any]):  # Using Any for generics
    async def get_grpc_descriptors(self) -> tuple[None, str]:
        return None, "dummy_service_name"

    async def add_to_server(self, server: Any, handler: Any) -> None:
        pass


@pytest.fixture
def temp_shutdown_file() -> Generator[Path]:
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        path_str = tmpfile.name  # Consistently use path_str
    if os.path.exists(path_str):
        os.unlink(path_str)
    yield Path(path_str)
    if os.path.exists(path_str):  # Check path_str for cleanup
        os.unlink(path_str)


@pytest.mark.asyncio
async def test_server_shuts_down_on_file_creation(
    temp_shutdown_file: Path, mocker: MagicMock
) -> None:
    shutdown_file_path_str = str(temp_shutdown_file)

    # Mock rpcplugin_config.get to return the temp_shutdown_file path
    # for the specific key
    original_get = rpcplugin_config.get

    def mock_get_config(key: str, default: Any = None) -> Any:
        if key == "PLUGIN_SHUTDOWN_FILE_PATH":
            return shutdown_file_path_str
        # For other keys, fall back to the original implementation.
        # This ensures other parts of server init get expected values.
        # For this test, we only care about PLUGIN_SHUTDOWN_FILE_PATH.
        return original_get(key, default)

    mocker.patch.object(rpcplugin_config, "get", side_effect=mock_get_config)

    protocol: RPCPluginProtocol[Any, Any] = DummyProtocol()
    handler = DummyHandler()
    server: RPCPluginServer = RPCPluginServer(protocol=protocol, handler=handler)

    async def mock_negotiate_side_effect() -> None:
        server._protocol_version = 1
        server._transport_name = "unix"
        server._transport = UnixSocketTransport(
            path="/tmp/dummy_for_shutdown_test.sock"
        )

    mocker.patch.object(
        server, "_negotiate_handshake", side_effect=mock_negotiate_side_effect
    )

    mocker.patch.object(server, "_register_signal_handlers")
    mocker.patch.object(server, "_setup_server", new_callable=AsyncMock)
    mocker.patch("sys.stdout.buffer.write")
    mocker.patch("sys.stdout.buffer.flush")

    serve_task = asyncio.create_task(server.serve())
    try:
        await asyncio.sleep(0.2)

        assert server._shutdown_watcher_task is not None, (
            "Shutdown watcher task not started"
        )

        with open(shutdown_file_path_str, "w") as f:
            f.write("shutdown")

        await asyncio.wait_for(serve_task, timeout=5.0)

        assert server._serving_future.done(), (
            "Server's serving future was not done after shutdown."
        )

    finally:
        if not serve_task.done():
            serve_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await serve_task
