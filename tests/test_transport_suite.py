#
# tests/transport/test_transport_suite.py
#

import asyncio
import io # Added for type hinting and potential use
import os
import socket
import stat # Added for potential permission checks if needed later
import tempfile
from typing import Tuple, AsyncGenerator, Callable, Type # Added Callable, Type

import pytest
import pytest_asyncio

# Assuming pyvider.telemetry exists and logger is configured
from pyvider.telemetry import logger
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.server import RPCPluginServer
# Assuming a base or mock protocol/handler is needed for server init
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
# Import specific transport types
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
# Import base transport type for hinting
from pyvider.rpcplugin.transport.base import RPCPluginTransport as BaseTransportT


# Mock Handler/Protocol for Server Initialization (replace with actual if needed)
class MockHandler:
    pass # Add methods required by your protocol

class MockProtocol(RPCPluginProtocol):
     async def get_grpc_descriptors(self) -> tuple[None, str]:
         return None, "MockService"
     async def add_to_server(self, handler: MockHandler, server: any) -> None:
         pass # No-op for basic testing

# Simple SocketStateMonitor (consider enhancements if needed)
class SocketStateMonitor:
    """Utility for monitoring socket state (basic version)."""
    def __init__(self, path: str) -> None:
        self._path = path
        self._lock = asyncio.Lock()

    @property
    def path(self) -> str:
        return self._path

    async def exists(self) -> bool:
        """Check if the socket file exists."""
        return os.path.exists(self._path)

    async def is_connectable(self) -> bool:
        """Check if the socket is connectable (basic check)."""
        if not await self.exists():
            return False
        async with self._lock:
            sock = None # Ensure sock is defined
            try:
                if self._path.startswith("unix:"): # Check if path is URI for Unix
                     path_to_connect = self._path.split(":", 1)[1]
                else: # Assume raw path
                     path_to_connect = self._path

                # Differentiate based on socket type deduced from path or known type
                # For simplicity, assuming Unix if not obviously TCP format
                if ":" not in path_to_connect or "/" in path_to_connect: # Heuristic for Unix
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.settimeout(0.2)
                    await asyncio.get_event_loop().sock_connect(sock, path_to_connect)
                    return True
                else: # Assume TCP
                     host, port_str = path_to_connect.split(":", 1)
                     port = int(port_str)
                     reader, writer = await asyncio.wait_for(
                         asyncio.open_connection(host, port), timeout=0.5
                     )
                     writer.close()
                     await writer.wait_closed()
                     return True

            except (ConnectionRefusedError, FileNotFoundError, asyncio.TimeoutError, OSError, ValueError):
                return False # Cannot connect or invalid format
            finally:
                if sock:
                    sock.close()

    async def wait_for_active(self, timeout: float = 3.0) -> bool:
        """Wait for socket to become connectable."""
        end_time = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < end_time:
            if await self.is_connectable():
                return True
            await asyncio.sleep(0.1)
        logger.warning(f"Timed out waiting for socket {self._path} to become active.")
        return False

    async def cleanup(self) -> None:
        """Attempt to remove the socket file if it's a Unix socket path."""
        # Only attempt unlink if it looks like a file path
        if os.path.exists(self._path) and "/" in self._path:
            async with self._lock:
                 try:
                     # Check if it's actually a socket before unlinking
                     if stat.S_ISSOCK(os.stat(self._path).st_mode):
                         os.unlink(self._path)
                         logger.info(f"Cleaned up socket file: {self._path}")
                     else:
                          logger.warning(f"Path exists but is not a socket: {self._path}")
                 except FileNotFoundError:
                      pass # Already gone
                 except OSError as e:
                     logger.error(f"Error cleaning up socket {self._path}: {e}")


# Define TransportFactoryType more explicitly
TransportFactoryType = Callable[..., BaseTransportT]

@pytest_asyncio.fixture(params=["tcp", "unix"], scope="function")
async def transport_fixture(request, unused_tcp_port_factory) -> AsyncGenerator[Tuple[str, TransportFactoryType, str | None], None]:
    """
    Parametrized fixture providing transport type, factory, and endpoint.
    Uses function scope and proper cleanup for Unix sockets.
    """
    transport_type = request.param
    endpoint: str | None = None
    factory: TransportFactoryType | None = None
    monitor: SocketStateMonitor | None = None
    temp_dir = tempfile.TemporaryDirectory() # Create a unique temp dir per test run
    socket_path: str | None = None

    try:
        if transport_type == "tcp":
            port = unused_tcp_port_factory()
            host = "127.0.0.1"
            endpoint = f"{host}:{port}"
            # Factory now includes host/port binding
            factory = lambda **kwargs: TCPSocketTransport(host=host, port=port, **kwargs)
            # No specific cleanup needed for TCP beyond closing the instance

        elif transport_type == "unix":
            # Create socket inside the dedicated temp directory
            socket_file = f"test-{os.urandom(4).hex()}.sock"
            socket_path = os.path.join(temp_dir.name, socket_file)
            endpoint = socket_path # Raw path used for Unix
            monitor = SocketStateMonitor(socket_path)
            # Pass the specific path to the factory
            factory = lambda **kwargs: UnixSocketTransport(path=socket_path, **kwargs)

        else:
            raise ValueError(f"Unknown transport type: {transport_type}")

        if factory is None:
             raise RuntimeError("Factory was not created")

        yield transport_type, factory, endpoint

    finally:
        # Cleanup
        if monitor:
            await monitor.cleanup() # Attempt to remove the socket file
        temp_dir.cleanup() # Remove the temporary directory

# --- Fixtures using transport_fixture ---

@pytest_asyncio.fixture(scope="function")
async def server_transport(transport_fixture) -> AsyncGenerator[BaseTransportT, None]:
    """Fixture creates *and yields* a server transport instance using the factory."""
    transport_type, factory, endpoint = transport_fixture
    logger.debug(f"Creating SERVER transport: Type={transport_type}, Endpoint={endpoint}")
    # Create instance using the factory from transport_fixture
    instance = factory()
    yield instance # Provide the created instance to the test
    # Teardown: Close the specific instance
    logger.debug(f"Closing SERVER transport: Type={transport_type}, Endpoint={endpoint}")
    await instance.close()


@pytest_asyncio.fixture(scope="function")
async def client_transport(transport_fixture) -> AsyncGenerator[BaseTransportT, None]:
    """Fixture creates *and yields* a client transport instance using the factory."""
    transport_type, factory, endpoint = transport_fixture
    logger.debug(f"Creating CLIENT transport: Type={transport_type}, Endpoint={endpoint}")
    # Create instance using the factory
    instance = factory()
    yield instance # Provide the created instance to the test
    # Teardown: Close the specific instance
    logger.debug(f"Closing CLIENT transport: Type={transport_type}, Endpoint={endpoint}")
    await instance.close()


@pytest_asyncio.fixture(scope="function")
async def server_protocol() -> MockProtocol:
     """Provides a mock protocol."""
     return MockProtocol()

@pytest_asyncio.fixture(scope="function")
async def server_handler() -> MockHandler:
     """Provides a mock handler."""
     return MockHandler()

@pytest_asyncio.fixture(scope="function")
async def rpc_server(server_transport, server_protocol, server_handler) -> AsyncGenerator[RPCPluginServer, None]:
    """Fixture creates an RPCPluginServer instance."""
    logger.debug("Creating RPCPluginServer instance for test...")
    # Pass the already created server_transport instance
    instance = RPCPluginServer(
         transport=server_transport,
         protocol=server_protocol,
         handler=server_handler
    )
    yield instance
    # Teardown: Ensure server is stopped (stop might handle transport close too)
    logger.debug("Stopping RPCPluginServer instance in fixture teardown...")
    # Check if server was actually started before trying to stop
    if hasattr(instance, '_server') and instance._server is not None:
         await instance.stop()
    elif instance._transport is not None: # If server didn't start, maybe transport still needs closing
         await instance._transport.close()


# --- Test Functions ---

@pytest.mark.asyncio
async def test_server_startup_and_shutdown(rpc_server: RPCPluginServer, transport_fixture):
    """Test server starts listening and shuts down cleanly."""
    transport_type, _, endpoint = transport_fixture
    monitor = SocketStateMonitor(endpoint) # Monitor the specific endpoint

    logger.info(f"Testing server startup: Type={transport_type}, Endpoint={endpoint}")
    server_task = asyncio.create_task(rpc_server.serve())

    # Wait for the server to be ready (listening on socket/port)
    try:
        await rpc_server.wait_for_server_ready(timeout=5.0)
        logger.info("Server reported ready.")
        # Verify the transport endpoint is active
        assert await monitor.wait_for_active(timeout=2.0), "Transport endpoint did not become active"
        logger.info("Transport endpoint confirmed active.")
    except Exception as e:
         server_task.cancel()
         await asyncio.gather(server_task, return_exceptions=True)
         pytest.fail(f"Server readiness check failed: {e}")

    logger.info("Requesting server shutdown...")
    await rpc_server.stop() # Request graceful shutdown

    # Wait for the serve() task to complete
    await asyncio.wait_for(server_task, timeout=5.0)
    logger.info("Server serve task completed.")

    # Verify endpoint is no longer active/exists
    assert not await monitor.is_connectable(), "Transport endpoint still connectable after shutdown"
    # For Unix, also check existence (cleanup might be slightly delayed)
    if transport_type == "unix":
         await asyncio.sleep(0.2) # Short delay for file system ops
         assert not await monitor.exists(), "Unix socket file still exists after shutdown"
    logger.info("Server shutdown confirmed.")


@pytest.mark.asyncio
async def test_connection_refused(transport_fixture):
    """Test connecting fails when no server is listening."""
    transport_type, factory, endpoint = transport_fixture
    monitor = SocketStateMonitor(endpoint)

    # Ensure nothing is listening
    assert not await monitor.is_connectable(), "Endpoint unexpectedly connectable before test"

    logger.info(f"Testing connection refusal: Type={transport_type}, Endpoint={endpoint}")
    client = factory() # Create a client transport instance
    with pytest.raises((TransportError, ConnectionRefusedError, FileNotFoundError, OSError)):
        # Attempt to connect - should fail quickly
        await asyncio.wait_for(client.connect(endpoint), timeout=1.0)

    # Cleanup client transport if connect failed partially (less likely)
    await client.close()
    await monitor.cleanup() # Cleanup socket file if Unix


@pytest.mark.asyncio
async def test_basic_client_server_connect_disconnect(rpc_server, transport_fixture):
    """Test a client connecting to and disconnecting from a running server."""
    transport_type, client_factory, endpoint = transport_fixture
    monitor = SocketStateMonitor(endpoint)

    logger.info(f"Testing connect/disconnect: Type={transport_type}, Endpoint={endpoint}")
    server_task = asyncio.create_task(rpc_server.serve())
    await rpc_server.wait_for_server_ready(timeout=5.0)
    assert await monitor.wait_for_active(timeout=2.0), "Server endpoint did not become active"

    # Create and connect client
    client = client_factory()
    try:
        logger.info("Client connecting...")
        await asyncio.wait_for(client.connect(endpoint), timeout=2.0)
        logger.info("Client connected successfully.")
        # Add a small delay to ensure connection is fully established server-side if needed
        await asyncio.sleep(0.1)
    except Exception as e:
        logger.error(f"Client connection failed: {e}")
        server_task.cancel()
        await rpc_server.stop()
        await asyncio.gather(server_task, return_exceptions=True)
        await client.close() # Attempt cleanup
        await monitor.cleanup()
        pytest.fail(f"Client failed to connect: {e}")

    # Disconnect client
    logger.info("Client disconnecting...")
    await client.close()
    logger.info("Client disconnected.")

    # Shutdown server
    logger.info("Stopping server...")
    await rpc_server.stop()
    await asyncio.wait_for(server_task, timeout=5.0)
    logger.info("Server stopped.")

    # Final checks
    assert not await monitor.is_connectable(), "Endpoint still connectable after test"
    await monitor.cleanup()


# Add more tests:
# - test_concurrent_connections (similar to original but using fixtures)
# - test_data_echo (requires simple echo logic in MockHandler/Protocol)
# - test_transport_error_scenarios (e.g., invalid endpoint format)
