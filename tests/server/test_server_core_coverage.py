# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Tests for server/core.py to improve code coverage.

Focuses on testing uncovered paths in RPCPluginServer core functionality."""

import asyncio
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from provide.foundation.crypto import Certificate

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import ConfigError, TransportError
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.types import HandlerT, ServerT


class DummyHandler:
    """Dummy handler for testing."""

    pass


class DummyProtocol(RPCPluginProtocol[ServerT, HandlerT]):
    """Dummy protocol for testing."""

    service_name = "test.Service"

    async def get_grpc_descriptors(self) -> tuple[None, str]:
        return None, self.service_name

    async def add_to_server(self, server: ServerT, handler: HandlerT) -> None:
        pass


@pytest.mark.asyncio
async def test_attrs_post_init_config_error(mocker):
    """Test exception handling in __attrs_post_init__."""
    protocol = DummyProtocol()
    handler = DummyHandler()

    # Mock HandshakeConfig to raise ConfigError
    with patch("pyvider.rpcplugin.server.core.HandshakeConfig") as mock_handshake:
        mock_handshake.side_effect = ConfigError(
            message="Failed to initialize handshake",
            hint="Check your configuration",
        )

        with pytest.raises(ConfigError, match="Failed to initialize handshake"):
            RPCPluginServer(protocol=protocol, handler=handler)


@pytest.mark.asyncio
async def test_attrs_post_init_generic_exception(mocker):
    """Test generic exception handling in __attrs_post_init__."""
    protocol = DummyProtocol()
    handler = DummyHandler()

    # Mock HandshakeConfig to raise a generic exception
    with patch("pyvider.rpcplugin.server.core.HandshakeConfig") as mock_handshake:
        mock_handshake.side_effect = RuntimeError("Unexpected error")

        with pytest.raises(ConfigError, match="Failed to initialize handshake configuration"):
            RPCPluginServer(protocol=protocol, handler=handler)


@pytest.mark.asyncio
async def test_watch_shutdown_file_creates_and_deletes_file(temp_unix_socket_path, mocker):
    """Test _watch_shutdown_file with actual file creation and deletion."""
    # Create a temporary shutdown file path
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        shutdown_file_path = tmpfile.name
    # Remove it so we can test file creation
    if os.path.exists(shutdown_file_path):
        os.unlink(shutdown_file_path)

    try:
        protocol = DummyProtocol()
        handler = DummyHandler()

        # Set shutdown file path
        config = {"PLUGIN_SHUTDOWN_FILE_PATH": shutdown_file_path}
        server = RPCPluginServer(protocol=protocol, handler=handler, config=config)

        # Mock _shutdown_requested to track if it was called
        shutdown_called = asyncio.Event()

        def mock_shutdown():
            shutdown_called.set()
            server._shutdown_event.set()

        mocker.patch.object(server, "_shutdown_requested", side_effect=mock_shutdown)

        # Start the watcher task
        watcher_task = asyncio.create_task(server._watch_shutdown_file())

        # Give it time to start watching
        await asyncio.sleep(0.1)

        # Create the shutdown file
        Path(shutdown_file_path).touch()

        # Wait for shutdown to be triggered
        await asyncio.wait_for(shutdown_called.wait(), timeout=3.0)

        # Cancel the watcher task
        watcher_task.cancel()
        try:
            await watcher_task
        except asyncio.CancelledError:
            pass

        assert shutdown_called.is_set(), "Shutdown should have been called"

    finally:
        # Cleanup
        if os.path.exists(shutdown_file_path):
            os.unlink(shutdown_file_path)


@pytest.mark.asyncio
async def test_watch_shutdown_file_consecutive_os_errors(mocker):
    """Test _watch_shutdown_file with consecutive OS errors."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    config = {"PLUGIN_SHUTDOWN_FILE_PATH": "/nonexistent/path/shutdown.txt"}
    server = RPCPluginServer(protocol=protocol, handler=handler, config=config)

    # Mock Path.exists to raise OSError
    with patch("pyvider.rpcplugin.server.core.Path") as mock_path:
        mock_path.return_value.exists.side_effect = OSError("Permission denied")

        # Start the watcher task
        watcher_task = asyncio.create_task(server._watch_shutdown_file())

        # Wait for it to complete (should exit after 3 consecutive errors)
        await asyncio.wait_for(watcher_task, timeout=5.0)

        # Task should complete without raising


@pytest.mark.asyncio
async def test_watch_shutdown_file_unexpected_exception(mocker):
    """Test _watch_shutdown_file with unexpected exception."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    config = {"PLUGIN_SHUTDOWN_FILE_PATH": "/tmp/test_shutdown.txt"}
    server = RPCPluginServer(protocol=protocol, handler=handler, config=config)

    # Mock Path.exists to raise unexpected exception
    with patch("pyvider.rpcplugin.server.core.Path") as mock_path:
        mock_path.return_value.exists.side_effect = RuntimeError("Unexpected error")

        # Start the watcher task
        watcher_task = asyncio.create_task(server._watch_shutdown_file())

        # Wait for it to complete (should exit on unexpected exception)
        await asyncio.wait_for(watcher_task, timeout=2.0)

        # Task should complete without raising


@pytest.mark.asyncio
async def test_wait_for_server_ready_timeout(mocker):
    """Test wait_for_server_ready with timeout."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    # Don't set the serving event - it will timeout
    with pytest.raises(TimeoutError, match="Server failed to become ready"):
        await server.wait_for_server_ready(timeout=0.1)


@pytest.mark.asyncio
async def test_verify_transport_readiness_no_transport(mocker):
    """Test _verify_transport_readiness with no transport."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    with pytest.raises(TransportError, match="Transport is not configured"):
        await server._verify_transport_readiness()


@pytest.mark.asyncio
async def test_verify_transport_readiness_unix_socket_missing(temp_unix_socket_path, mocker):
    """Test _verify_transport_readiness with missing Unix socket."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    transport = UnixSocketTransport(path=str(temp_unix_socket_path))
    server = RPCPluginServer(protocol=protocol, handler=handler, transport=transport)

    # Ensure socket doesn't exist
    if temp_unix_socket_path.exists():
        temp_unix_socket_path.unlink()

    with pytest.raises(TransportError, match="Unix socket file .* does not exist"):
        await server._verify_transport_readiness()


@pytest.mark.asyncio
async def test_verify_transport_readiness_tcp_no_port(mocker):
    """Test _verify_transport_readiness with TCP but no port."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    transport = TCPSocketTransport(host="127.0.0.1", port=0)
    server = RPCPluginServer(protocol=protocol, handler=handler, transport=transport)

    # Set _port to None to trigger the error
    server._port = None

    with pytest.raises(TransportError, match="TCP port not available"):
        await server._verify_transport_readiness()


@pytest.mark.asyncio
async def test_verify_transport_readiness_tcp_connection_failed(mocker):
    """Test _verify_transport_readiness with TCP connection failure."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    transport = TCPSocketTransport(host="127.0.0.1", port=9999)
    server = RPCPluginServer(protocol=protocol, handler=handler, transport=transport)
    server._port = 9999  # Port that's not listening

    with pytest.raises(TransportError, match="Server readiness check failed"):
        await server._verify_transport_readiness()


@pytest.mark.asyncio
async def test_serve_with_tracer_enabled(mocker):
    """Test serve() with OpenTelemetry tracer enabled."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    # Mock tracer
    mock_tracer = MagicMock()
    mock_span = MagicMock()
    mock_span.__enter__ = MagicMock(return_value=mock_span)
    mock_span.__exit__ = MagicMock(return_value=None)
    mock_tracer.start_as_current_span.return_value = mock_span

    # Mock server implementation methods
    mocker.patch.object(server, "_register_signal_handlers")
    mocker.patch.object(server, "_negotiate_handshake", new_callable=AsyncMock)
    mocker.patch.object(server, "_setup_server", new_callable=AsyncMock)
    mocker.patch.object(server, "_build_and_send_handshake_response", new_callable=AsyncMock)
    mocker.patch.object(server, "stop", new_callable=AsyncMock)

    # Make _serving_future complete immediately
    async def wait_for_serving():
        server._serving_event.set()
        await asyncio.sleep(0.01)
        server._serving_future.set_result(None)

    with patch("pyvider.rpcplugin.server.core._tracer", mock_tracer):
        serve_task = asyncio.create_task(server.serve())
        wait_task = asyncio.create_task(wait_for_serving())

        await asyncio.wait_for(serve_task, timeout=2.0)
        await wait_task

        # Verify tracer was used
        mock_tracer.start_as_current_span.assert_called_once_with("rpc.server.serve")


@pytest.mark.asyncio
async def test_stop_with_shutdown_watcher_task(mocker):
    """Test stop() with active shutdown watcher task."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    # Create a real asyncio task that we can control
    async def dummy_watcher():
        try:
            await asyncio.sleep(100)  # Long sleep
        except asyncio.CancelledError:
            raise

    # Create task and assign it
    server._shutdown_watcher_task = asyncio.create_task(dummy_watcher())

    # Store reference to verify it was cancelled
    task_ref = server._shutdown_watcher_task

    await server.stop()

    # Verify task was cancelled
    assert task_ref.cancelled() or task_ref.done()


@pytest.mark.asyncio
async def test_stop_without_pytest_env(mocker):
    """Test stop() exit behavior without PYTEST_CURRENT_TEST."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    # Remove PYTEST_CURRENT_TEST from environment
    original_value = os.environ.get("PYTEST_CURRENT_TEST")
    if "PYTEST_CURRENT_TEST" in os.environ:
        del os.environ["PYTEST_CURRENT_TEST"]

    try:
        # Mock sys.exit to prevent actual exit
        with patch("sys.exit") as mock_exit:
            await server.stop()
            # Should try to call sys.exit(0)
            mock_exit.assert_called_once_with(0)
    finally:
        # Restore environment
        if original_value is not None:
            os.environ["PYTEST_CURRENT_TEST"] = original_value


@pytest.fixture
def temp_unix_socket_path():
    """Create a temporary Unix socket path."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        path = tmpfile.name
    # Ensure the file is deleted
    if os.path.exists(path):
        os.unlink(path)
    yield Path(path)
    # Clean up after test
    if os.path.exists(path):
        os.unlink(path)

# 🔌📞🔚
