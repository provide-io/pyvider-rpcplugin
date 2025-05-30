# tests/transport/unix/test_transport_unix_handle_client.py

import asyncio
import os
import pytest

from pyvider.telemetry import logger
from pyvider.rpcplugin.transport.unix import UnixSocketTransport

from tests.fixtures import *


@pytest.mark.asyncio
async def test_unix_socket_handle_client_called(managed_unix_socket_path) -> None:
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    endpoint = await transport.listen()
    logger.debug(f"Unix socket server started at {endpoint}")

    try:
        # Simulate a client connection
        reader, writer = await asyncio.open_unix_connection(endpoint)
        writer.write(b"test data")
        await writer.drain()

        # Verify the server handles data correctly
        response = await reader.read(100)
        logger.debug(f"Server echoed response: {response}")
        assert response == b"test data", "Data was not echoed back correctly."

        # Close the client connection
        writer.close()
        await writer.wait_closed()
    finally:
        await transport.close()
        assert not os.path.exists(endpoint), (
            "Socket file was not removed after transport closed."
        )


@pytest.mark.asyncio
async def test_unix_socket_handle_client_direct(managed_unix_socket_path) -> None:
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    endpoint = await transport.listen()

    try:
        # Simulate a direct client connection
        reader, writer = await asyncio.open_unix_connection(endpoint)
        writer.write(b"direct test data")
        await writer.drain()

        # Check that data is echoed back correctly
        response = await reader.read(100)
        assert response == b"direct test data", (
            "Direct data was not echoed back correctly."
        )

        writer.close()
        await writer.wait_closed()
    finally:
        await transport.close()
        assert not os.path.exists(endpoint), (
            "Socket file was not removed after transport closed."
        )


@pytest.mark.asyncio
async def test_unix_socket_handle_client_error(managed_unix_socket_path) -> None:
    """Test error handling during client connection."""
    # Ensure we're using a string path
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    endpoint = await transport.listen()

    try:
        # Simulate client connection
        reader, writer = await asyncio.open_unix_connection(endpoint)

        # Force an error by closing the writer
        writer.close()
        await writer.wait_closed()

        # Allow error handling to complete
        await asyncio.sleep(0)
    finally:
        await transport.close()
        # Add a small delay for cleanup
        await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_handle_client_echo(managed_unix_socket_path) -> None:
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    transport._running = True
    fake_reader = DummyReader(b"echo")
    fake_writer = DummyWriter()
    # Call _handle_client directly.
    await transport._handle_client(fake_reader, fake_writer)
    # Verify that the data was echoed back.
    assert fake_writer.data == b"echo"


################################################################################
