# tests/transport/unix/test_unix_concurrent_connections.py

import asyncio
import os
import tempfile

import pytest

from pyvider.rpcplugin.transport import UnixSocketTransport
from pyvider.telemetry import logger

@pytest.mark.asyncio
async def test_unix_socket_concurrent_connections() -> None:
    """Test multiple concurrent connections to Unix socket with proper tracking."""
    # Create temporary socket path
    temp_dir = tempfile.mkdtemp()
    socket_path = os.path.join(temp_dir, "test.sock")

    # Track created connections
    client_transports = []

    try:
        # Create and start server transport
        server_transport = UnixSocketTransport(path=socket_path)
        endpoint = await server_transport.listen()

        # Connect multiple clients
        num_clients = 5
        for i in range(num_clients):
            client = UnixSocketTransport()
            await client.connect(endpoint)
            client_transports.append(client)
            logger.debug(f"Connected client {i+1}")

        # Verify connection count in server
        # Add a small delay to ensure all connections are tracked
        await asyncio.sleep(0.1)
        assert len(server_transport._connections) == num_clients, \
            f"Expected {num_clients} connections, got {len(server_transport._connections)}"

        # Test data transfer with each client
        test_data = b"concurrent test data"
        for i, client in enumerate(client_transports):
            client._writer.write(test_data)
            await client._writer.drain()
            logger.debug(f"Sent data through client {i+1}")

        # Close clients
        for i, client in enumerate(client_transports):
            await client.close()
            logger.debug(f"Closed client {i+1}")

        # Verify connections are closed
        # Add small delay to ensure connection removal is processed
        await asyncio.sleep(0.2)
        assert len(server_transport._connections) == 0, \
            f"Expected 0 remaining connections, got {len(server_transport._connections)}"

        # Close server
        await server_transport.close()

    finally:
        # Clean up remaining clients if any
        for client in client_transports:
            try:
                await client.close()
            except Exception as e:
                logger.error(f"Error closing client: {e}")

        # Clean up socket file if it exists
        if os.path.exists(socket_path):
            try:
                os.unlink(socket_path)
            except Exception as e:
                logger.error(f"Error removing socket file: {e}")

        # Clean up temp directory
        try:
            os.rmdir(temp_dir)
        except Exception as e:
            logger.error(f"Error removing temp directory: {e}")

@pytest.mark.asyncio
async def test_unix_socket_connection_tracking() -> None:
    """Test that the server correctly tracks connections and disconnections."""
    # Create temporary socket path
    with tempfile.TemporaryDirectory() as temp_dir:
        socket_path = os.path.join(temp_dir, "tracking.sock")

        # Create and start server transport
        server = UnixSocketTransport(path=socket_path)
        endpoint = await server.listen()

        # Verify initial state
        assert len(server._connections) == 0, "Should start with 0 connections"

        # Connect a client
        client = UnixSocketTransport()
        await client.connect(endpoint)

        # Wait briefly for the connection to be registered
        await asyncio.sleep(0.1)

        # Verify connection was tracked
        assert len(server._connections) == 1, "Should have 1 connection after client connects"

        # Close the client
        await client.close()

        # Wait briefly for the disconnection to be processed
        await asyncio.sleep(0.2)

        # Verify connection was removed
        assert len(server._connections) == 0, "Connection should be removed after client disconnect"

        # Close server
        await server.close()

@pytest.mark.asyncio
async def test_unix_socket_multiple_clients_data_transfer() -> None:
    """Test that multiple concurrent clients can send and receive data correctly."""
    # Create temporary socket path
    with tempfile.TemporaryDirectory() as temp_dir:
        socket_path = os.path.join(temp_dir, "transfer.sock")

        # Create and start server transport
        server = UnixSocketTransport(path=socket_path)
        endpoint = await server.listen()

        # Connect multiple clients
        clients = []
        num_clients = 5
        for i in range(num_clients):
            client = UnixSocketTransport()
            await client.connect(endpoint)
            clients.append(client)

        # Wait for connections to be established
        await asyncio.sleep(0.1)

        # Each client sends unique test data
        for i, client in enumerate(clients):
            test_data = f"client-{i}-data".encode()
            client._writer.write(test_data)
            await client._writer.drain()

        # Give the server time to process and handle the data
        await asyncio.sleep(0.2)

        # Close all clients
        for client in clients:
            await client.close()

        # Close the server
        await server.close()

        # Verify the socket file was removed
        assert not os.path.exists(socket_path), "Socket file should be removed after server closes"
