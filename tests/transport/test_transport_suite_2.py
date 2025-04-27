# tests/transport/test_transport_suite_2.py

import asyncio
import os
import socket
import stat # Import stat
import tempfile
from typing import AsyncGenerator, Callable, Type

import pytest
import pytest_asyncio

from pyvider.telemetry import logger
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.transport.base import RPCPluginTransport as BaseTransportT

from tests.fixtures import *

# Define TransportFactoryType
TransportFactoryType = Callable[..., BaseTransportT]

@pytest_asyncio.fixture(params=["tcp", "unix"], scope="function")
async def transport_fixture(request, unused_tcp_port) -> AsyncGenerator[tuple[str, TransportFactoryType, str | None], None]:
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
            port = unused_tcp_port
            host = "127.0.0.1"
            endpoint = f"{host}:{port}"
            # Factory now includes host/port binding
            factory = lambda **kwargs: TCPSocketTransport(host=host, port=port, **kwargs)
            # No specific cleanup needed for TCP beyond closing the instance

        elif transport_type == "unix":
            # Create socket inside the dedicated temp directory with shorter name
            socket_file = f"test-{os.urandom(4).hex()}.sock" # Use shorter random name
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
async def test_server_startup_and_shutdown(rpc_server: RPCPluginServer, transport_fixture, socket_monitor):
    """Test server starts listening and shuts down cleanly."""
    transport_type, _, endpoint = transport_fixture

    # Create a socket monitor appropriate for the transport type
    monitor = None
    if transport_type == "unix":
        monitor = socket_monitor(endpoint)  # Use the fixture correctly here


    logger.info(f"Testing server startup: Type={transport_type}, Endpoint={endpoint}")
    server_task = asyncio.create_task(rpc_server.serve())
    # Add a small delay *before* checking readiness to allow server task to proceed
    await asyncio.sleep(0.1)

    # Wait for the server to be ready (listening on socket/port)
    try:
        # Use increased timeout for readiness check
        await asyncio.wait_for(rpc_server.wait_for_server_ready(), timeout=7.0)
        logger.info("Server reported ready.")

        # Verify the transport endpoint is active
        if transport_type == "unix":
            assert monitor is not None
            assert await monitor.wait_for_active(timeout=2.0), "Transport endpoint did not become active"
            # Add stat check
            assert stat.S_ISSOCK(os.stat(endpoint).st_mode), "Unix path is not a socket"
        else:  # tcp
            # For TCP, try to connect to verify it's active
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host, port_str = endpoint.split(":")
            sock.settimeout(2.0)
            sock.connect((host, int(port_str)))
            sock.close()

        logger.info("Transport endpoint confirmed active.")
    except Exception as e:
         server_task.cancel()
         await asyncio.gather(server_task, return_exceptions=True)
         pytest.fail(f"Server readiness check failed for {transport_type}: {e}")

    logger.info("Requesting server shutdown...")
    await rpc_server.stop() # Request graceful shutdown

    # Wait for the serve() task to complete
    try:
        await asyncio.wait_for(server_task, timeout=5.0)
    except asyncio.TimeoutError:
        pytest.fail("Server task did not complete after stop()")
    logger.info("Server serve task completed.")

    # Verify endpoint is no longer active/exists
    if transport_type == "unix":
        # For Unix, check file existence (cleanup might be slightly delayed)
        await asyncio.sleep(0.1) # Short delay for file system ops
        assert not os.path.exists(endpoint), "Unix socket file still exists after shutdown"
    else:  # tcp
        # For TCP, try to connect - should fail now
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host, port_str = endpoint.split(":")
        sock.settimeout(1.0)
        with pytest.raises((ConnectionRefusedError, OSError)): # OSError for some platforms
            sock.connect((host, int(port_str)))
        sock.close()

    logger.info("Server shutdown confirmed.")


@pytest.mark.asyncio
async def test_connection_refused(transport_fixture):
    """Test connecting fails when no server is listening."""
    transport_type, factory, endpoint = transport_fixture

    # For Unix sockets, verify the file doesn't exist
    if transport_type == "unix":
        if os.path.exists(endpoint):
            try: os.unlink(endpoint)
            except OSError: pass
        assert not os.path.exists(endpoint), "Socket file unexpectedly exists before test"

    # For TCP, verify nothing is listening on the port
    else:  # tcp
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        host, port_str = endpoint.split(":")
        with pytest.raises((ConnectionRefusedError, socket.timeout, OSError)): # Catch timeout too
             sock.connect((host, int(port_str)))
        sock.close()


    logger.info(f"Testing connection refusal: Type={transport_type}, Endpoint={endpoint}")
    client = factory() # Create a client transport instance
    with pytest.raises(TransportError):
        # Attempt to connect - should fail quickly
        await client.connect(endpoint) # Rely on internal timeout

    # Cleanup client transport even if connect failed
    await client.close()


@pytest.mark.asyncio
async def test_basic_client_server_connect_disconnect(rpc_server, transport_fixture):
    """Test a client connecting to and disconnecting from a running server."""
    transport_type, client_factory, endpoint = transport_fixture

    logger.info(f"Testing connect/disconnect: Type={transport_type}, Endpoint={endpoint}")
    server_task = asyncio.create_task(rpc_server.serve())
    # Add delay before checking readiness
    await asyncio.sleep(0.1)

    try:
        # Wait for server to be ready
        await asyncio.wait_for(rpc_server.wait_for_server_ready(), timeout=7.0) # Increased timeout

        # Verify endpoint is active
        if transport_type == "unix":
            assert os.path.exists(endpoint), "Unix socket file does not exist"
            assert stat.S_ISSOCK(os.stat(endpoint).st_mode), "Unix path is not a socket"
            # Verify socket is active with a direct socket connection
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(endpoint)
            sock.close()
        else:  # tcp
            # For TCP, verify with a direct socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host, port_str = endpoint.split(":")
            sock.settimeout(2.0)
            sock.connect((host, int(port_str)))
            sock.close()

        logger.info("Server endpoint is active and connectable")

        # Create and connect client
        client = client_factory()
        try:
            logger.info("Client connecting...")
            await client.connect(endpoint) # Rely on internal timeout
            logger.info("Client connected successfully.")
            # Add a small delay to ensure connection is fully established server-side
            await asyncio.sleep(0.1)
        except Exception as e:
            logger.error(f"Client connection failed: {e}")
            raise

        # Test data transfer
        if hasattr(client, "_writer") and client._writer:
            test_data = b"test data"
            client._writer.write(test_data)
            await client._writer.drain()
            logger.info("Data sent through client")
            # Add verification that server received/echoed if possible
            # This requires accessing server connection state or using mocks

        # Disconnect client
        logger.info("Client disconnecting...")
        await client.close()
        logger.info("Client disconnected.")

    except Exception as e:
        logger.error(f"Test failure: {e}")
        # Ensure server is stopped even on failure
        await rpc_server.stop()
        await asyncio.gather(server_task, return_exceptions=True) # Wait for task to finish/cancel
        raise
    finally:
        # Shutdown server (if not already stopped on error)
        if not server_task.done():
            logger.info("Stopping server...")
            await rpc_server.stop()
            await asyncio.wait_for(server_task, timeout=5.0)
            logger.info("Server stopped.")


@pytest.mark.asyncio
async def test_transport_error_scenarios(transport_fixture):
    """Test various error scenarios with transports."""
    transport_type, factory, endpoint = transport_fixture

    # Test 1: Invalid endpoint format (TCP only)
    if transport_type == "tcp":
        invalid_transport = TCPSocketTransport()
        with pytest.raises(TransportError, match="Invalid TCP endpoint format"):
            await invalid_transport.connect("invalid:endpoint:format")
        await invalid_transport.close()

    # Test 2: Connect timeout / Unroutable
    connect_transport = factory()
    if transport_type == "unix":
        # For Unix, connect to a non-existent file (should raise TransportError quickly)
        non_existent_unix_path = "/tmp/non_existent_socket_for_error_test.sock"
        if os.path.exists(non_existent_unix_path): os.unlink(non_existent_unix_path)
        with pytest.raises(TransportError, match="does not exist"):
             await connect_transport.connect(non_existent_unix_path)
    else:  # tcp
        # For TCP, use an unroutable IP
        with pytest.raises(TransportError, match="timed out|timeout|Network is unreachable|Connection refused"):
            await connect_transport.connect("240.0.0.1:12345") # Rely on internal timeout
    await connect_transport.close()


    # Test 3: Listen on already-in-use endpoint
    # First create and start a transport
    server1 = factory()
    actual_endpoint = await server1.listen() # Get the actual endpoint used

    # Then try to listen on the same endpoint
    server2 = factory() # Create a new instance
    try:
        with pytest.raises(TransportError, match="already in use|Failed to create|Failed to bind"): # Match possible errors
            # Ensure server2 tries to listen on the *same* endpoint server1 is using
            if transport_type == "unix":
                # For Unix, explicitly set the path
                server2.path = actual_endpoint
            else: # tcp
                # For TCP, explicitly set the port
                host, port_str = actual_endpoint.split(":")
                server2.port = int(port_str)
            await server2.listen()
    finally:
        # Clean up
        await server1.close()
        await server2.close() # Close even if listen failed

# 🐍🏗🧪️
