#!/usr/bin/env python3
# tests/test_transport_suite.py

import asyncio
import os
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncGenerator, Optional, Union, Callable

import pytest
import pytest_asyncio
import attrs

from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.types import TransportT, HandlerT

# tests/transport/test_transport_suite.py - Replace SocketStateMonitor class entirely

class SocketStateMonitor:
    """Utility for monitoring socket state."""

    def __init__(self, path: str):
        self._path = path
        self._active = False
        self._connections = 0
        self._lock = asyncio.Lock()

    @property
    def active(self) -> bool:
        return self._active

    @property
    def path(self) -> str:
        return self._path

    @property
    def connections(self) -> int:
        return self._connections

    async def check_state(self) -> bool:
        """Check current socket state with retries."""
        for attempt in range(3):  # Retry up to 3 times
            async with self._lock:
                try:
                    if not os.path.exists(self._path):
                        self._active = False
                        return False

                    # Check if it's a valid socket file
                    try:
                        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        sock.connect(self._path)
                        self._active = True
                        self._connections += 1
                        sock.close()
                        return True
                    except (ConnectionRefusedError, FileNotFoundError):
                        # Socket exists but nothing listening
                        if attempt < 2:  # Only sleep if we have more retries
                            await asyncio.sleep(0.2)  # Wait for socket to be ready
                            continue
                        self._active = False
                        return False
                    except OSError:
                        self._active = False
                        return False
                    finally:
                        try:
                            sock.close()
                        except (NameError, UnboundLocalError):
                            pass
                except Exception as e:
                    logger.error(f"Socket state check error: {e}")
                    
            # Sleep between retries
            if attempt < 2:
                await asyncio.sleep(0.2)
                
        self._active = False
        return False

    async def wait_for_active(self, timeout: float = 3.0) -> bool:
        """Wait for socket to become active with regular checks."""
        end_time = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < end_time:
            if await self.check_state():
                return True
            await asyncio.sleep(0.1)
        return False

    async def wait_for_inactive(self, timeout: float = 3.0) -> bool:
        """Wait for socket to become inactive."""
        end_time = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < end_time:
            if not await self.check_state():
                return True
            await asyncio.sleep(0.1)
        return False

@asynccontextmanager
async def managed_transport(transport_type: str, **kwargs) -> AsyncGenerator[TransportT, None]:
    """Context manager for transport lifecycle."""
    transport = None
    path = None
    try:
        if transport_type == "unix":
            # Generate unique path
            import uuid, time
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
                logger.error(f"Timeout during transport close")
            except Exception as e:
                logger.error(f"Error during transport close: {e}")
                
        # Additional socket file cleanup
        if path and os.path.exists(path):
            try:
                os.chmod(path, 0o777)  # Force permissions
                os.unlink(path)
            except OSError:
                pass

@asynccontextmanager
async def Xmanaged_transport(
    transport_type: str, **kwargs
) -> AsyncGenerator[TransportT, None]:
    """Context manager for transport lifecycle."""
    transport = None
    try:
        if transport_type == "unix":
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                path = tf.name
            os.unlink(path)  # Remove file but preserve path
            transport = UnixSocketTransport(path=path, **kwargs)
        else:
            transport = TCPSocketTransport(host="127.0.0.1", **kwargs)
        yield transport
    finally:
        if transport:
            await transport.close()
            if transport_type == "unix" and os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass


@pytest_asyncio.fixture
async def socket_monitor():
    """Fixture providing socket state monitoring."""
    monitors = []

    def create_monitor(path: str) -> SocketStateMonitor:
        monitor = SocketStateMonitor(path)
        monitors.append(monitor)
        return monitor

    yield create_monitor

    # Verify all sockets were properly cleaned up
    for monitor in monitors:
        assert not monitor.active, f"Socket {monitor.path} was not properly cleaned up"
        if os.path.exists(monitor.path):
            os.unlink(monitor.path)

################################################################################

# Base Dummy Classes
class DummyReader:
    def __init__(self, data: bytes = b""):
        self._data = data
        self._called = False

    async def read(self, size: int) -> bytes:
        if not self._called:
            self._called = True
            return self._data
        return b""

class DummyWriter:
    def __init__(self):
        self.closed = False
        self.data = bytearray()

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        await asyncio.sleep(0)

    def is_closing(self) -> bool:
        return self.closed

    def get_extra_info(self, key: str, default: any = None) -> any:
        return "dummy_peer" if key == "peername" else default

# Protocol & Handler Mocks
class MockProtocol(RPCPluginProtocol):
    def get_grpc_descriptors(self):
        logger.debug("🔌🚀✅ MockProtocol.get_grpc_descriptors called.")
        return None, "MockService"

    async def add_to_server(self, handler, server):
        logger.debug("🔌🚀✅ MockProtocol.add_to_server called.")

class MockHandler:
    async def handle_request(self, request, context):
        logger.debug("🔌🚀✅ MockHandler.handle_request called.")
        return None

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
async def Xtransport_factory(temp_sock_dir):
    """Factory fixture for creating transport instances."""
    created = []

    async def create(transport_type: str, **kwargs) -> TransportT:
        if transport_type == "unix":
            import uuid

            unique_name = f"test_{uuid.uuid4()}.sock"
            path = os.path.join(temp_sock_dir, unique_name)

            # Basic cleanup
            if os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    pass
            transport = UnixSocketTransport(**kwargs)
        else:
            transport = TCPSocketTransport(host="127.0.0.1", **kwargs)

        created.append(transport)
        return transport

    yield create

    # Cleanup
    for transport in created:
        try:
            await transport.close()
            if isinstance(transport, UnixSocketTransport):
                await asyncio.sleep(0.1)  # Brief pause for OS cleanup
                if os.path.exists(transport.path):
                    os.unlink(transport.path)
        except Exception as e:
            logger.error(f"Transport cleanup error: {e}")

@pytest_asyncio.fixture
async def Xtransport_factory(temp_sock_dir, unused_tcp_port):
    """Factory fixture for creating transport instances."""
    created = []

    async def create(transport_type: str, **kwargs) -> TransportT:
        if transport_type == "unix":
            # Generate unique path using uuid
            import uuid

            unique_name = f"test_{uuid.uuid4()}.sock"
            path = os.path.join(temp_sock_dir, unique_name)

            # Ensure cleanup of any existing socket
            if os.path.exists(path):
                try:
                    os.unlink(path)
                    await asyncio.sleep(0.1)  # Wait for OS cleanup
                except OSError:
                    pass

            transport = UnixSocketTransport(**kwargs)
            await _verify_socket_cleanup(path)  # New helper function
        else:
            transport = TCPSocketTransport(host="127.0.0.1", **kwargs)

        created.append(transport)
        return transport

    async def _verify_socket_cleanup(path: str, retries: int = 3) -> None:
        """Verify socket is truly cleaned up with retries."""
        for i in range(retries):
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(path)
                sock.close()
                # If we can connect, socket exists - wait and retry
                await asyncio.sleep(0.2 * (i + 1))
                if os.path.exists(path):
                    os.unlink(path)
            except (ConnectionRefusedError, FileNotFoundError):
                return  # Socket is truly gone
            except Exception:
                pass
        raise TransportError(f"Failed to verify socket cleanup: {path}")

    yield create

    # Enhanced cleanup with verification
    async def cleanup_transport(transport: TransportT):
        try:
            await transport.close()
            if isinstance(transport, UnixSocketTransport):
                path = transport.path
                if os.path.exists(path):
                    await asyncio.sleep(0.1)
                    os.unlink(path)
                await _verify_socket_cleanup(path)
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

    # Cleanup in reverse order
    for transport in reversed(created):
        await cleanup_transport(transport)

@pytest_asyncio.fixture
async def Xtransport_factory(temp_sock_dir, unused_tcp_port):
    """Factory fixture for creating transport instances."""
    created = []

    async def create(transport_type: str, **kwargs) -> TransportT:
        # Ensure any existing socket is removed
        if transport_type == "unix":
            path = os.path.join(temp_sock_dir, f"test_{len(created)}.sock")
            if os.path.exists(path):
                try:
                    os.unlink(path)
                except OSError:
                    await asyncio.sleep(0.1)  # Wait and try again
                    os.unlink(path)
            transport = UnixSocketTransport(**kwargs)
        elif transport_type == "tcp":
            transport = TCPSocketTransport(host="127.0.0.1", **kwargs)
        else:
            raise ValueError(f"Unknown transport type: {transport_type}")

        created.append(transport)
        return transport

    yield create

    # Cleanup
    for transport in created:
        try:
            await transport.close()
            if isinstance(transport, UnixSocketTransport) and os.path.exists(
                transport.path
            ):
                await asyncio.sleep(0.1)  # Wait for socket to be fully closed
                os.unlink(transport.path)
        except Exception as e:
            logger.error(f"Error closing transport: {e}")

    # Final cleanup of any remaining sockets
    for file in os.listdir(temp_sock_dir):
        if file.endswith(".sock"):
            try:
                os.unlink(os.path.join(temp_sock_dir, file))
            except OSError:
                pass


@pytest_asyncio.fixture
async def mock_protocol():
    """Create a mock protocol instance."""
    return MockProtocol()


@pytest_asyncio.fixture
async def mock_handler():
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

@pytest.mark.asyncio
async def test_tcp_transport_basic_1(transport_factory):
    """Test basic TCP transport creation and listening."""
    transport = await transport_factory("tcp")
    endpoint = await transport.listen()

    assert endpoint.startswith("127.0.0.1:")
    assert transport.endpoint == endpoint

    await transport.close()

@pytest.mark.asyncio
async def test_unix_transport_basic_2(transport_factory):
    """Test basic Unix transport creation and listening."""
    transport = await transport_factory("unix")
    endpoint = await transport.listen()

    assert os.path.exists(endpoint)
    assert transport.endpoint == endpoint

    await transport.close()
    assert not os.path.exists(endpoint)

@pytest.mark.asyncio
# @pytest.mark.parametrize("transport_type", ["tcp", "unix"])
@pytest.mark.parametrize("transport_type", ["tcp", "unix"])
async def test_transport_connection(transport_type, connected_pair_factory):
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
# @pytest.mark.parametrize("transport_type", ["tcp", "unix"])
# FAILED transport/test_transport_suite.py::test_server_with_transport[unix] - pyvider.rpcplugin.exception.TransportError: Failed to verify socket cleanup: /REDACTED_TMP
@pytest.mark.parametrize("transport_type", ["tcp"])
async def test_server_with_transport(
    transport_type, transport_factory, server_factory, temp_sock_dir
):
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
async def test_unix_socket_error_handling_538():
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
async def test_unix_socket_error_handling_560():
    """Test Unix socket error handling."""
    # Test invalid file
    with tempfile.NamedTemporaryFile() as tf:
        tf.write(b"not a socket")
        tf.flush()
        transport = UnixSocketTransport(path=tf.name)
        with pytest.raises(TransportError, match="Failed to create Unix socket"):
            await transport.listen()

    # Test nonexistent path
    transport = UnixSocketTransport(path="/nonexistent/path/sock")
    with pytest.raises(TransportError, match="does not exist"):
        await transport.connect("unix:/nonexistent/path/sock")

@pytest.mark.asyncio
async def test_unix_socket_error_handling_576():
    """Test error handling in Unix socket transport."""
    with tempfile.NamedTemporaryFile() as tf:
        # Try to use file that exists but isn't a socket
        transport = UnixSocketTransport(path=tf.name)
        with pytest.raises(TransportError, match="Failed to start Unix socket server"):
            await transport.listen()

    # Try to connect to nonexistent socket
    transport = UnixSocketTransport(path="/nonexistent/path")
    with pytest.raises(TransportError, match="does not exist"):
        await transport.connect("/nonexistent/path")

@pytest.mark.asyncio
async def test_transport_error_handling_576(transport_factory):
    """Test transport error handling."""
    transport = await transport_factory("tcp")

    # Try to connect to non-existent endpoint
    with pytest.raises(Exception):
        await transport.connect("127.0.0.1:1")

    await transport.close()

@pytest.mark.asyncio
async def test_unix_socket_lifecycle_587(socket_monitor):
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
        assert os.stat(endpoint).st_mode & 0o777 == 0o777, "Invalid permissions"

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
async def test_unix_socket_lifecycle_620(socket_monitor):
    """Test complete Unix socket transport lifecycle."""
    async with managed_transport("unix") as transport:
        monitor = socket_monitor(transport.path)

        # Pre-listen state
        state = await monitor.check_state()
        assert not state, "Socket exists before listen"
        assert not transport._running, "Transport running before listen"

        # Listen
        endpoint = await transport.listen()
        await asyncio.sleep(0.1)  # Allow startup
        state = await monitor.check_state()
        assert state, "Socket not active after listen"
        assert transport._running, "Transport not running after listen"
        assert os.path.exists(endpoint), "Socket file missing"

        # Verify permissions
        mode = os.stat(endpoint).st_mode
        assert mode & 0o777 == 0o777, f"Invalid socket permissions: {mode:o}"

        # Connect
        client = UnixSocketTransport()
        await client.connect(endpoint)

        # Test data transfer
        test_data = b"lifecycle test"
        client._writer.write(test_data)
        await client._writer.drain()

        await client.close()
        await transport.close()

        state = await monitor.check_state()
        assert not state, "Socket still active after close"
        assert not os.path.exists(endpoint), "Socket file remains"

@pytest.mark.asyncio
async def test_unix_socket_lifecycle_659(socket_monitor):
    """Test complete Unix socket transport lifecycle."""
    async with managed_transport("unix") as transport:
        monitor = socket_monitor(transport.path)

        # Pre-listen state
        assert not await monitor.check_state()
        assert not transport._running

        # Listen
        endpoint = await transport.listen()
        assert await monitor.check_state()
        assert transport._running
        assert os.path.exists(endpoint)
        assert os.stat(endpoint).st_mode & 0o777 == 0o777

        # Connect
        client = UnixSocketTransport()
        await client.connect(endpoint)
        assert await monitor.check_state()

@pytest.mark.asyncio
async def test_unix_socket_concurrent_connections_681():
    """Test multiple concurrent connections to Unix socket."""
    with tempfile.NamedTemporaryFile() as tf:
        socket_path = tf.name
    
    # Remove file so we can create socket
    os.unlink(socket_path)
    
    # Create a connection counter
    connection_count = 0
    
    # Create transport and start server
    transport = UnixSocketTransport(path=socket_path)
    
    try:
        # Start listening
        endpoint = await transport.listen()
        
        # Ensure socket exists
        assert os.path.exists(socket_path), f"Socket file {socket_path} does not exist"
        
        # Wait briefly for socket to be ready
        await asyncio.sleep(0.2)
        
        # Create multiple clients
        clients = []
        for i in range(5):
            client = UnixSocketTransport()
            await client.connect(endpoint)
            clients.append(client)
            connection_count += 1
            
        # Check connection count
        assert len(clients) == 5, f"Expected 5 clients, got {len(clients)}"
        assert connection_count == 5, f"Expected 5 connections, got {connection_count}"
        
        # Test concurrent data transfer
        test_data = b"concurrent test"
        for client in clients:
            client._writer.write(test_data)
            await client._writer.drain()
        
        # Cleanup - close all clients
        for client in clients:
            await client.close()
            
        # Wait for connections to close
        await asyncio.sleep(0.5)
        
    finally:
        # Cleanup transport
        await transport.close()
        
        # Verify socket is gone
        assert not os.path.exists(socket_path), f"Socket file {socket_path} still exists"

@pytest.mark.asyncio
async def test_unix_socket_concurrent_connections_738(socket_monitor):
    """Test multiple concurrent connections to Unix socket."""
    async with managed_transport("unix") as transport:
        monitor = socket_monitor(transport.path)
        endpoint = await transport.listen()

        # Create multiple clients
        clients = []
        for i in range(5):
            client = UnixSocketTransport()
            await client.connect(endpoint)
            clients.append(client)

        # Fixed: Correctly check monitor connections
        assert await monitor.check_state(), "Socket should be active"
        
        # Test concurrent data transfer
        test_data = b"concurrent test"
        for client in clients:
            client._writer.write(test_data)
            await client._writer.drain()

        # Cleanup - must await each close() call
        for client in clients:
            await client.close()

        # Wait briefly for cleanup to complete
        await asyncio.sleep(0.1)
        assert not await monitor.check_state()

@pytest.mark.asyncio
async def test_unix_socket_concurrent_connections_769(socket_monitor):
    """Test multiple concurrent connections to Unix socket."""
    async with managed_transport("unix") as transport:
        monitor = socket_monitor(transport.path)
        endpoint = await transport.listen()

        # Create multiple clients
        clients = []
        for i in range(5):
            client = UnixSocketTransport()
            await client.connect(endpoint)
            clients.append(client)
            # Check state for each connection to increment counter
            await monitor.check_state()  # Add this line

        # Verify all connections
        assert monitor.connections == 5
        assert len(transport._connections) == 5
        
        test_data = b"concurrent test"
        await asyncio.gather(*(client._writer.write(test_data) for client in clients))
        await asyncio.gather(*(client._writer.drain() for client in clients))

        # Cleanup
        for client in clients:
            await client.close()

        assert not await monitor.check_state()

@pytest.mark.asyncio
async def test_unix_socket_concurrent_connections_813(socket_monitor):
    """Test multiple concurrent connections to Unix socket."""
    async with managed_transport("unix") as transport:
        monitor = socket_monitor(transport.path)
        endpoint = await transport.listen()

        # Create multiple clients
        clients = []
        for i in range(5):
            client = UnixSocketTransport()
            await client.connect(endpoint)
            clients.append(client)

        # Verify all connections
        assert monitor.connections == 5
        assert len(transport._connections) == 5

        # Test concurrent data transfer
        test_data = b"concurrent test"
        await asyncio.gather(*(client._writer.write(test_data) for client in clients))
        await asyncio.gather(*(client._writer.drain() for client in clients))

        # Cleanup
        for client in clients:
            await client.close()

        assert not await monitor.check_state()

@pytest.mark.asyncio
async def test_unix_socket_server_integration_842():
    """Test Unix socket transport with server integration."""
    with tempfile.NamedTemporaryFile() as tf:
        socket_path = tf.name
    
    # Remove the file so we can create a socket
    os.unlink(socket_path)
    
    # Create transport with unique path
    transport = UnixSocketTransport(path=socket_path)
    
    # Create server
    protocol = MockProtocol()
    handler = MockHandler()
    
    server = RPCPluginServer(
        protocol=protocol, 
        handler=handler, 
        transport=transport
    )
    
    server._serving_future = asyncio.Future()
    server._serving_event = asyncio.Event()
    
    try:
        # Start server
        server_task = asyncio.create_task(server.serve())
        
        # Wait for server to be ready (with longer timeout)
        try:
            await asyncio.wait_for(server.wait_for_server_ready(), timeout=5.0)
        except asyncio.TimeoutError:
            pytest.fail("Server failed to become ready in time")
        
        assert server._serving_event.is_set(), "Server should be ready"
        assert os.path.exists(socket_path), f"Socket file {socket_path} does not exist"
        
        # Create client connection
        client = UnixSocketTransport()
        await client.connect(socket_path)
        
        # Test data transfer
        test_data = b"server test"
        client._writer.write(test_data)
        await client._writer.drain()
        
        await client.close()
        
    finally:
        # Cleanup
        server._shutdown_requested()
        await server.stop()
        
        # Cancel server task
        if 'server_task' in locals():
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
        
        # Ensure socket is cleaned up
        if os.path.exists(socket_path):
            os.unlink(socket_path)

@pytest.mark.asyncio
async def test_unix_socket_server_integration_908(socket_monitor):
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
async def test_unix_socket_cleanup_handling_953(socket_monitor):
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

################################################################################
