# tests/transport/tcp/test_transport_tcp_handle_client.py


# test_tcp_handle_client_called REMOVED - Incompatible with new listen()
# test_tcp_handle_client_direct REMOVED - Incompatible with new listen()

import asyncio
from unittest.mock import AsyncMock

import pytest

from pyvider.rpcplugin.transport.tcp import TCPSocketTransport


@pytest.mark.asyncio
async def test_handle_client_echoes_data():
    """Test that _handle_client correctly echoes received data."""
    transport = TCPSocketTransport()
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = AsyncMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False  # Ensure close can be called

    # Configure reader.read to return specific data then empty bytes to end loop
    test_data = b"hello world"

    async def read_side_effect_func(*args, **kwargs):
        if not hasattr(read_side_effect_func, "call_count"):
            read_side_effect_func.call_count = 0

        read_side_effect_func.call_count += 1
        if read_side_effect_func.call_count == 1:
            return test_data
        else:
            return b""  # Subsequent calls, including the one that breaks the loop, return empty bytes

    reader.read.side_effect = read_side_effect_func
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)  # for logging

    await transport._handle_client(reader, writer)

    # Check that read was called at least twice (once for data, once for EOF)
    assert reader.read.call_count >= 2
    reader.read.assert_any_call(100)  # Check if it was called with 100 at least once
    writer.write.assert_called_once_with(test_data)
    writer.drain.assert_called_once()
    writer.close.assert_called_once()
    writer.wait_closed.assert_called_once()


@pytest.mark.asyncio
async def test_handle_client_graceful_disconnect():
    """Test _handle_client with an immediate client disconnect."""
    transport = TCPSocketTransport()
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = AsyncMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False  # Ensure close can be called

    reader.read.return_value = b""  # Simulate immediate disconnect
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)

    await transport._handle_client(reader, writer)

    reader.read.assert_called_once_with(100)
    writer.write.assert_not_called()  # No data to echo
    writer.close.assert_called_once()
    writer.wait_closed.assert_called_once()


@pytest.mark.asyncio
async def test_handle_client_incomplete_read_error():
    """Test _handle_client when reader.read raises IncompleteReadError."""
    transport = TCPSocketTransport()
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = AsyncMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False  # Ensure close can be called

    reader.read.side_effect = asyncio.IncompleteReadError(
        partial=b"partial", expected=100
    )
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)

    await transport._handle_client(reader, writer)

    writer.close.assert_called_once()
    writer.wait_closed.assert_called_once()


@pytest.mark.asyncio
async def test_handle_client_writer_oserror_on_echo():
    """Test _handle_client when writer.write raises OSError."""
    transport = TCPSocketTransport()
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = AsyncMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False  # Ensure close can be called

    test_data = b"data to echo"
    reader.read.side_effect = [test_data, b""]  # Send data, then disconnect
    writer.write.side_effect = OSError("Simulated write error")
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)

    await transport._handle_client(reader, writer)

    # Ensure close is still attempted despite the error
    writer.close.assert_called_once()
    writer.wait_closed.assert_called_once()


@pytest.mark.asyncio
async def test_handle_client_error_on_close():
    """Test _handle_client when writer.close() or wait_closed() raises an error."""
    transport = TCPSocketTransport()
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = AsyncMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False  # Ensure close can be called

    reader.read.return_value = b""  # Immediate disconnect
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)
    writer.wait_closed.side_effect = RuntimeError("Error during wait_closed")

    await transport._handle_client(reader, writer)  # Should catch and log the error

    writer.close.assert_called_once()  # Close is still called
    writer.wait_closed.assert_called_once()  # wait_closed is called and raises error


@pytest.mark.asyncio
async def test_handle_client_reader_generic_exception():
    """Test _handle_client when reader.read() raises a generic Exception."""
    transport = TCPSocketTransport()
    reader = AsyncMock(spec=asyncio.StreamReader)
    writer = AsyncMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False

    reader.read.side_effect = RuntimeError("Simulated generic read error")
    writer.get_extra_info.return_value = ("127.0.0.1", 12345)

    await transport._handle_client(reader, writer)

    # Ensure cleanup is still attempted
    writer.close.assert_called_once()
    writer.wait_closed.assert_called_once()


### 🐍🏗🧪️
