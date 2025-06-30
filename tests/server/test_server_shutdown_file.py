import asyncio
import contextlib
import os
import tempfile
from collections.abc import Iterator  # Added for type hint
from pathlib import Path
from unittest.mock import AsyncMock  # Ensure patch is imported

import pytest

from pyvider.rpcplugin.protocol.base import RPCPluginProtocol

# from pyvider.rpcplugin.config import rpcplugin_config # No longer mocking global cfg
from pyvider.rpcplugin.server import RPCPluginServer

# from pyvider.telemetry import logger # Not used in this test
from pyvider.rpcplugin.transport.unix import UnixSocketTransport
from pyvider.rpcplugin.types import HandlerT, ServerT

# pylint: disable=protected-access


class DummyHandler:
    pass


class DummyProtocol(RPCPluginProtocol[ServerT, HandlerT]):
    async def get_grpc_descriptors(self) -> tuple[None, str]:
        return None, "dummy_service_name"

    async def add_to_server(self, server: ServerT, handler: HandlerT) -> None:
        pass

    def get_method_type(self, method_name: str) -> str:  # pylint: disable=unused-argument
        return "unary_unary"


@pytest.fixture
def temp_shutdown_file() -> Iterator[Path]:
    # Create a temporary file path for the shutdown signal
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        path_str = tmp_file.name
    path = Path(path_str)
    if path.exists():
        # This should ideally not happen if NamedTemporaryFile(delete=False) means
        # it's unique and then we unlink it.
        # However, being defensive for test environments.
        try:
            path.unlink()
        except OSError:  # pragma: no cover
            # Handle cases where unlinking might fail after creation in edge cases/OS.
            pass

    try:
        yield path
    finally:
        # Robust cleanup
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_server_shuts_down_on_file_creation(
    temp_shutdown_file: Path, mocker: pytest.MonkeyPatch
) -> None:
    shutdown_file_path_str = str(temp_shutdown_file)

    protocol: DummyProtocol = DummyProtocol()
    handler: DummyHandler = DummyHandler()

    server_config_override = {"PLUGIN_SHUTDOWN_FILE_PATH": shutdown_file_path_str}
    server: RPCPluginServer = RPCPluginServer(
        protocol=protocol, handler=handler, config=server_config_override
    )

    dummy_socket_file = f"/tmp/dummy_for_shutdown_test_{os.getpid()}.sock"

    async def mock_negotiate_side_effect() -> None:
        server._protocol_version = 1
        server._transport_name = "unix"
        if server._transport is None:
            server._transport = UnixSocketTransport(path=dummy_socket_file)
        elif isinstance(server._transport, UnixSocketTransport):
            server._transport.path = dummy_socket_file
        else:  # pragma: no cover
            server._transport = UnixSocketTransport(path=dummy_socket_file)

    mocker.patch.object(  # type: ignore[attr-defined]
        server, "_negotiate_handshake", side_effect=mock_negotiate_side_effect
    )
    mocker.patch.object(server, "_register_signal_handlers")  # type: ignore[attr-defined]
    mocker.patch.object(server, "_setup_server", new_callable=AsyncMock)  # type: ignore[attr-defined]
    mocker.patch("sys.stdout.buffer.write")  # type: ignore[attr-defined]
    mocker.patch("sys.stdout.buffer.flush")  # type: ignore[attr-defined]

    serve_task = asyncio.create_task(server.serve())
    try:
        await asyncio.sleep(0.3)

        assert server._shutdown_watcher_task is not None, (
            "Shutdown watcher task not started"
        )
        assert server._shutdown_file_path == shutdown_file_path_str, (
            "Shutdown file path not correctly set on server"
        )

        temp_shutdown_file.touch()
        # Increased sleep time to be greater than the watcher's polling interval (1s)
        # and give more buffer for the task to run.
        await asyncio.sleep(2.2)  # Original was 0.4

        assert server._shutdown_event.is_set(), (
            "Server shutdown event not set after file creation"
        )

        await asyncio.wait_for(serve_task, timeout=2.0)

        assert server._serving_future.done(), (
            "Server's serving future was not done after shutdown."
        )

    except TimeoutError:  # pragma: no cover
        pytest.fail("Server did not shut down within timeout after file creation.")
    finally:
        if not serve_task.done():
            serve_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await serve_task

        if Path(dummy_socket_file).exists():
            with contextlib.suppress(OSError):
                Path(dummy_socket_file).unlink(missing_ok=True)
