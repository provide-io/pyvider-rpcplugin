#
# tests/test_transport_suite.py
#

import asyncio
import os
import socket
import stat # Added import
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

from tests.fixtures import * # Assumes SocketStateMonitor, MockProtocol, MockHandler are here

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
            # Use tempfile.gettempdir() for better portability
            path = os.path.join(tempfile.gettempdir(), f"pyvider_test_{time.time()}_{uuid.uuid4().hex[:8]}.sock")

            # Ensure clean state
            if os.path.exists(path):
                 try:
                      os.unlink(path)
                 except OSError:
                      pass # Ignore errors if file is already gone

            transport = UnixSocketTransport(path=path, **kwargs)
        else:
            transport = TCPSocketTransport(host="127.0.0.1", **kwargs)

        yield transport

    finally:
        # Robust cleanup with timeouts
        if transport:
            try:
                await asyncio.wait_for(transport.close(), timeout=3.0) # Increased timeout
            except asyncio.TimeoutError:
                logger.error("Timeout during transport close")
            except Exception as e:
                logger.error(f"Error during transport close: {e}")

        # Additional socket file cleanup (redundant if close works, but safe)
        if path and os.path.exists(path):
            try:
                os.chmod(path, 0o770)  # Force permissions if needed
                os.unlink(path)
            except OSError:
                pass

# Core Fixtures (keep as is)
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
            # Use tempfile.gettempdir() and shorter name
            socket_path = os.path.join(tempfile.gettempdir(), f"pyv_t_{uuid.uuid4().hex[:6]}.sock")
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
            # Ensure close is awaited
            await transport.close()
            # For Unix sockets, ensure file is gone
            if isinstance(transport, UnixSocketTransport) and hasattr(transport, 'path') and transport.path:
                if os.path.exists(transport.path):
                     try:
                          os.unlink(transport.path)
                     except OSError:
                          pass # Ignore cleanup errors
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
        # Ensure the passed transport is valid
        assert transport is not None, "Transport must be provided to server factory"
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
        # Add a small delay to ensure the server socket is ready
        await asyncio.sleep(0.05)
        await client_transport.connect(endpoint)

        pair = (server_transport, client_transport)
        pairs.append(pair)
        return pair

    yield create

    # Cleanup
    for server, client in pairs:
        # Close client first, then server
        try:
            await client.close()
        except Exception: pass # Ignore client close errors during cleanup
        try:
            await server.close()
        except Exception: pass # Ignore server close errors during cleanup

################################################################################
# Tests
######
@pytest.mark.asyncio
async def test_tcp_transport_basic(transport_factory) -> None:
    """Test basic TCP transport creation and listening."""
    transport = await transport_factory("tcp")
    endpoint = await transport.listen()

    assert endpoint.startswith("127.0.0.1:")
    assert transport.endpoint == endpoint
    # Verify port is active
    host, port_str = endpoint.split(":")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    sock.connect((host, int(port_str)))
    sock.close()

    await transport.close()

@pytest.mark.asyncio
async def test_unix_transport_basic(transport_factory) -> None:
    """Test basic Unix transport creation and listening."""
    transport = await transport_factory("unix")
    endpoint = await transport.listen()

    assert os.path.exists(endpoint)
    assert transport.endpoint == endpoint
    # Verify socket is active
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    sock.connect(endpoint)
    sock.close()


    await transport.close()
    # Add delay for OS file cleanup
    await asyncio.sleep(0.1)
    assert not os.path.exists(endpoint)

@pytest.mark.asyncio
@pytest.mark.parametrize("transport_type", ["tcp", "unix"])
async def test_transport_connection(transport_type, connected_pair_factory) -> None:
    """Test transport connection for both TCP and Unix."""
    server_transport, client_transport = await connected_pair_factory(transport_type)

    # Test data transfer (client -> server echo)
    test_data = b"Hello, Transport!"
    writer = getattr(client_transport, "_writer", None)
    reader = getattr(client_transport, "_reader", None)
    assert writer is not None
    assert reader is not None

    writer.write(test_data)
    await writer.drain()

    # Server should echo back (assuming default handle_client)
    response = await reader.read(len(test_data))
    assert response == test_data

    # Cleanup happens via fixture

@pytest.mark.asyncio
@pytest.mark.parametrize("transport_type", ["tcp", "unix"]) # Parametrize test
async def test_server_with_transport(
    transport_type, transport_factory, server_factory, temp_sock_dir # Use temp_sock_dir if needed
) -> None:
    """Test server creation and basic operation with different transports."""
    transport = await transport_factory(transport_type)
    server = await server_factory(transport=transport) # Pass transport explicitly

    # Server needs a future to await on in serve()
    server._serving_future = asyncio.Future()
    # server._serving_event is created by default

    # Start server in background task
    server_task = asyncio.create_task(server.serve())

    try:
        # Wait for server to be ready (Increased timeout)
        await asyncio.wait_for(server.wait_for_server_ready(), timeout=7.0)
        assert server._serving_event.is_set()

        # Simple check: try to connect to the endpoint
        client = await transport_factory(transport_type)
        await client.connect(transport.endpoint)
        await client.close()

        # Trigger server shutdown
        server._shutdown_requested() # This should set the future

        # Wait for server task to complete (Increased timeout)
        await asyncio.wait_for(server_task, timeout=7.0)
        assert server._serving_future.done()

    except asyncio.TimeoutError as e:
         pytest.fail(f"Test timed out: {e}")
    except Exception as e:
         pytest.fail(f"Test failed unexpectedly: {e}")
    finally:
        # Ensure cleanup even on failure
        if not server_task.done():
            server_task.cancel()
            import contextlib
            with contextlib.suppress(asyncio.CancelledError):
                await server_task
        # Explicitly stop server if task failed before shutdown_requested
        if hasattr(server, '_server') and server._server is not None:
            await server.stop()


@pytest.mark.asyncio
async def test_unix_socket_error_handling(transport_factory) -> None: # Use factory
    """Test error handling in Unix socket transport."""
    # Test 1: Connect to non-existent socket
    nonexistent_path = "/tmp/nonexistent_socket_path_123456789.sock"
    if os.path.exists(nonexistent_path):
        os.unlink(nonexistent_path)

    transport_nonexist = await transport_factory("unix")
    # Override path for this specific test case if factory generates one
    transport_nonexist.path = nonexistent_path
    with pytest.raises(TransportError, match="does not exist"):
        await transport_nonexist.connect(nonexistent_path)
    await transport_nonexist.close() # Close after failed connect

    # Test 2: Connect to an existing file that is not a socket
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"this is not a socket")
        tf.flush()
        non_socket_path = tf.name

    transport_nonsocket = await transport_factory("unix")
    try:
        with pytest.raises(TransportError, match="not a socket"):
            await transport_nonsocket.connect(non_socket_path)
    finally:
        await transport_nonsocket.close() # Close after failed connect
        os.unlink(non_socket_path) # Clean up the temp file


@pytest.mark.asyncio
async def test_tcp_transport_error_handling(transport_factory) -> None: # Renamed test
    """Test TCP transport error handling."""
    transport = await transport_factory("tcp")

    # Try to connect to non-existent endpoint (port 1 is usually reserved/unavailable)
    with pytest.raises(TransportError, match="Connection refused|timed out"):
        await transport.connect("127.0.0.1:1")

    await transport.close()

# 🐍🏗🧪️
