# tests/transport/unix/test_transport_unix_handle_client.py

import asyncio
import os
import pytest
from unittest.mock import AsyncMock, MagicMock # Added

from pyvider.telemetry import logger
from pyvider.rpcplugin.transport.unix import UnixSocketTransport

# Fixtures will be available via tests.fixtures through conftest.py
# from tests.fixtures.transport import managed_unix_socket_path
from tests.fixtures.dummy import DummyReader, DummyWriter  # Re-added specific import


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
        logger.debug(f"Server echoed response: {response!r}")
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
        # Add a longer delay for cleanup
        await asyncio.sleep(0.5)


@pytest.mark.asyncio
async def test_handle_client_echo(managed_unix_socket_path) -> None:
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    transport._running = True
    fake_reader = DummyReader(b"echo")
    fake_writer = DummyWriter()
    # Call _handle_client directly.
    await transport._handle_client(fake_reader, fake_writer)  # type: ignore[arg-type]
    # Verify that the data was echoed back.
    assert fake_writer.data == b"echo"


@pytest.mark.asyncio
async def test_handle_client_cancelled(mocker):
    transport = UnixSocketTransport(path="/tmp/dummy_cancel.sock") # Path doesn't need to exist for this unit test
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = AsyncMock(spec=asyncio.StreamWriter)
    writer.get_extra_info.return_value = "peer_cancelled"
    writer.is_closing.return_value = False # Simulate writer is open

    # Make reader.read() allow the loop to run once, then subsequent calls can be interrupted
    read_call_count = 0
    async def read_side_effect(*args, **kwargs):
        nonlocal read_call_count
        read_call_count += 1
        if read_call_count == 1:
            return b"initial data"
        # For subsequent calls, we'll let the task be cancelled externally
        await asyncio.sleep(0.1) # Give a chance for cancellation
        return b"should not be reached if cancelled"

    reader.read = read_side_effect

    # Mock the lock as it's used in _handle_client
    mocker.patch.object(transport, '_lock', AsyncMock(spec=asyncio.Lock))
    transport._running = True # To allow the while loop in _handle_client to run

    handle_client_task = asyncio.create_task(transport._handle_client(reader, writer))

    await asyncio.sleep(0.01) # Ensure the task starts and enters the loop

    handle_client_task.cancel() # Cancel the task externally

    try:
        await asyncio.wait_for(handle_client_task, timeout=0.5)
    except asyncio.TimeoutError:
        pytest.fail("_handle_client task did not complete after cancellation.")

    assert handle_client_task.done()
    assert handle_client_task.exception() is None # Should not have an unhandled exception

    # Assertions to ensure cleanup was attempted
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()
    # Check if the connection was removed from the pool (if it was added)
    # This requires checking transport._connections, which might need another mock or inspection.
    # For now, focus on cancellation handling and cleanup calls.

################################################################################
