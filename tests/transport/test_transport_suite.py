#
# tests/test_transport_suite.py
#

import asyncio
import os
import socket
import tempfile
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import pytest
import pytest_asyncio

from pyvider.telemetry import logger
from pyvider.rpcplugin.exception import TransportError

from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.types import TransportT

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol import RPCPluginProtocol

from tests.fixtures import *

@asynccontextmanager
async def managed_transport(transport_type: str, **kwargs) -> AsyncGenerator[TransportT, None]:
    """Context manager for transport lifecycle."""
    transport = None
    path = None
    try:
        if transport_type == "unix":
            # Generate unique path
            import uuid
            import time
            path = f"/tmp/pyvider_test_{time.time()}_{uuid.uuid4().hex[:8]}.sock"

            # Ensure clean state
            if os.path.exists(path):
                os.unlink(path)

            transport = UnixSocketTransport(path=path, **kwargs)
        else:
            transport = TCPSocketTransport(host="127.0.0.1", **kwargs)

        yield transport

    finally:
        # Robust cleanup with timeouts
        if transport:
            try:
                await asyncio.wait_for(transport.close(), timeout=2.0)
            except asyncio.TimeoutError:
                logger.error("Timeout during transport close")
            except Exception as e:
                logger.error(f"Error during transport close: {e}")

        # Additional socket file cleanup
        if path and os.path.exists(path):
            try:
                os.chmod(path, 0o770)  # Force permissions
                os.unlink(path)
            except OSError:
                pass

# Core Fixtures
@pytest.fixture
def unused_tcp_port() -> int:
    """Find an unused TCP port."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

@pytest.fixture
def temp_sock_dir():
    """Create a temporary directory for Unix sockets."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir

@pytest_asyncio.fixture(scope="function")
async def transport_factory(request):
    """Factory fixture for creating isolated transport instances."""
    created = []

    async def create(transport_type: str, **kwargs) -> TransportT:
        # Create unique paths for Unix sockets
        if transport_type == "unix":
            import uuid
            socket_path = f"/tmp/pyv_test_{uuid.uuid4().hex[:8]}.sock"
            # Clean any existing file
            if os.path.exists(socket_path):
                try:
                    os.unlink(socket_path)
                except OSError:
                    pass
            transport = UnixSocketTransport(path=socket_path, **kwargs)
        else:
            transport = TCPSocketTransport(**kwargs)

        created.append(transport)
        return transport

    yield create

    # Thorough cleanup
    for transport in created:
        try:
            await transport.close()
            # For Unix sockets, ensure file is gone
            if isinstance(transport, UnixSocketTransport) and hasattr(transport, 'path'):
                if os.path.exists(transport.path):
                    os.unlink(transport.path)
        except Exception as e:
            logger.error(f"Error during transport cleanup: {e}")

@pytest_asyncio.fixture
async def mock_protocol() -> MockProtocol:
    """Create a mock protocol instance."""
    return MockProtocol()

@pytest_asyncio.fixture
async def mock_handler() -> MockHandler:
    """Create a mock handler instance."""
    return MockHandler()

@pytest_asyncio.fixture
async def server_factory(mock_protocol, mock_handler):
    """Factory fixture for creating server instances."""
    servers = []

    async def create(transport: TransportT, **kwargs) -> RPCPluginServer:
        server = RPCPluginServer(
            protocol=mock_protocol, handler=mock_handler, transport=transport, **kwargs
        )
        servers.append(server)
        return server

    yield create

    # Cleanup
    for server in servers:
        try:
            await server.stop()
        except Exception as e:
            logger.error(f"Error stopping server: {e}")

@pytest_asyncio.fixture
async def connected_pair_factory(transport_factory):
    """Factory for creating connected transport pairs."""
    pairs = []

    async def create(transport_type: str) -> tuple[TransportT, TransportT]:
        server_transport = await transport_factory(transport_type)
        client_transport = await transport_factory(transport_type)

        endpoint = await server_transport.listen()
        await client_transport.connect(endpoint)

        pair = (server_transport, client_transport)
        pairs.append(pair)
        return pair

    yield create

    # Cleanup
    for server, client in pairs:
        await client.close()
        await server.close()

################################################################################
# TCP
######
@pytest.mark.asyncio
async def test_tcp_transport_basic(transport_factory) -> None:
    """Test basic TCP transport creation and listening."""
    transport = await transport_factory("tcp")
    endpoint = await transport.listen()

    assert endpoint.startswith("127.0.0.1:")
    assert transport.endpoint == endpoint

    await transport.close()

@pytest.mark.asyncio
async def test_unix_transport_basic(transport_factory) -> None:
    """Test basic Unix transport creation and listening."""
    transport = await transport_factory("unix")
    endpoint = await transport.listen()

    assert os.path.exists(endpoint)
    assert transport.endpoint == endpoint

    await transport.close()
    assert not os.path.exists(endpoint)

@pytest.mark.asyncio
@pytest.mark.parametrize("transport_type", ["tcp", "unix"])
async def test_transport_connection(transport_type, connected_pair_factory) -> None:
    """Test transport connection for both TCP and Unix."""
    server_transport, client_transport = await connected_pair_factory(transport_type)

    # Test data transfer
    test_data = b"Hello, Transport!"
    writer = getattr(client_transport, "_writer", None)
    assert writer is not None

    writer.write(test_data)
    await writer.drain()

    # Cleanup happens via fixture

@pytest.mark.asyncio
@pytest.mark.parametrize("transport_type", ["tcp"])
async def test_server_with_transport(
    transport_type, transport_factory, server_factory, temp_sock_dir
) -> None:
    """Test server creation and basic operation with different transports."""
    transport = await transport_factory(transport_type)
    server = await server_factory(transport)

    # Create future for server task
    server._serving_future = asyncio.Future()
    server._serving_event = asyncio.Event()

    # Start server in background task
    server_task = asyncio.create_task(server.serve())

    try:
        # Wait for server to be ready
        await asyncio.wait_for(server.wait_for_server_ready(), timeout=5.0)
        assert server._serving_event.is_set()

        # Trigger server shutdown
        server._shutdown_requested()
        await server.stop()

        # Verify server task completed
        assert server._serving_future.done()

    finally:
        # Ensure cleanup
        server_task.cancel()
        import contextlib

        with contextlib.suppress(asyncio.CancelledError):
            await server_task

@pytest.mark.asyncio
async def test_unix_socket_error_handling() -> None:
    """Test error handling in Unix socket transport."""
    with tempfile.NamedTemporaryFile() as tf:
        # Create a file with non-socket content
        tf.write(b"this is not a socket")
        tf.flush()

        # Try to use file that exists but isn't a socket
        transport = UnixSocketTransport(path=tf.name)
        with pytest.raises(TransportError, match="Failed to create Unix socket"):
            await transport.listen()

    # Try to connect to nonexistent socket
    nonexistent_path = "/tmp/nonexistent_socket_path_12345.sock"
    if os.path.exists(nonexistent_path):
        os.unlink(nonexistent_path)

    transport = UnixSocketTransport(path=nonexistent_path)
    with pytest.raises(TransportError, match="does not exist"):
        await transport.connect(nonexistent_path)

@pytest.mark.asyncio
async def test_transport_error_handling(transport_factory) -> None:
    """Test transport error handling."""
    transport = await transport_factory("tcp")

    # Try to connect to non-existent endpoint
    with pytest.raises(Exception):
        await transport.connect("127.0.0.1:1")

    await transport.close()

@pytest.mark.asyncio
async def test_unix_socket_lifecycle(socket_monitor) -> None:
    """Test complete Unix socket transport lifecycle."""
    async with managed_transport("unix") as transport:
        monitor = socket_monitor(transport.path)

        # Pre-listen state
        assert not await asyncio.wait_for(monitor.check_state(), timeout=1.0)

        # Listen with timeout
        endpoint = await asyncio.wait_for(transport.listen(), timeout=2.0)

        # Wait with timeout
        assert await asyncio.wait_for(
            monitor.wait_for_active(timeout=1.0),
            timeout=2.0
        ), "Socket failed to become active"

        assert os.path.exists(endpoint), "Socket file missing"
        assert os.stat(endpoint).st_mode & 0o770 == 0o770, "Invalid permissions"

        # Connect
        client = UnixSocketTransport()
        await client.connect(endpoint)

        # Test data transfer
        test_data = b"lifecycle test"
        client._writer.write(test_data)
        await client._writer.drain()

        # Cleanup
        await client.close()
        await transport.close()
        assert await monitor.wait_for_inactive(timeout=1.0), (
            "Socket failed to become inactive"
        )

@pytest.mark.asyncio
async def test_unix_socket_server_integration(socket_monitor) -> None:
    """Test Unix socket transport with server integration."""
    async with managed_transport("unix") as transport:
        monitor = socket_monitor(transport.path)

        # Create and start server
        server = RPCPluginServer(
            protocol=MockProtocol(), handler=MockHandler(), transport=transport
        )

        server._serving_future = asyncio.Future()
        server._serving_event = asyncio.Event()

        # Start server
        server_task = asyncio.create_task(server.serve())

        try:
            # Wait for server ready
            await asyncio.wait_for(server.wait_for_server_ready(), timeout=5.0)

            assert server._serving_event.is_set()
            assert await monitor.check_state()

            # Create client connection
            client = UnixSocketTransport()
            await client.connect(transport.path)

            # Test data transfer
            test_data = b"server test"
            client._writer.write(test_data)
            await client._writer.drain()

            await client.close()

        finally:
            # Cleanup
            server._shutdown_requested()
            await server.stop()
            server_task.cancel()
            import contextlib

            with contextlib.suppress(asyncio.CancelledError):
                await server_task

@pytest.mark.asyncio
async def test_unix_socket_cleanup_handling(socket_monitor) -> None:
    """Test proper cleanup of Unix socket resources."""
    # Create a temporary path for testing
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        path = tf.name

    # Create file with non-socket content
    with open(path, "w") as f:
        f.write("not a socket")

    # Create the monitor
    monitor = socket_monitor(path)

    try:
        # First transport should handle stale file
        transport1 = UnixSocketTransport(path=path)
        await transport1.listen()

        # Verify socket is active
        assert await monitor.check_state(), "Socket should be active after listen"

        # Close first transport
        await transport1.close()

        # Verify socket is inactive
        assert not await monitor.check_state(), "Socket should be inactive after close"
        assert not os.path.exists(path), "Socket file should be removed after close"

        # New transport should work on same path
        transport2 = UnixSocketTransport(path=path)
        await transport2.listen()

        # Verify new socket is active
        assert await monitor.check_state(), "New socket should be active after listen"

        await transport2.close()

        # Final verification
        assert not await monitor.check_state(), "Socket should be inactive after final close"

    finally:
        # Cleanup if anything remains
        if os.path.exists(path):
            os.unlink(path)

### 🐍🏗🧪️
