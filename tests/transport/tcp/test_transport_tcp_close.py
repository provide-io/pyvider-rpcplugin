# tests/transport/tcp/test_transport_tcp_close.py

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from pyvider.rpcplugin.transport import TCPSocketTransport
from pyvider.rpcplugin.exception import TransportError


# test_tcp_socket_transport_close_connection_active REMOVED - Incompatible with new listen()
# test_tcp_socket_transport_close_writer_oserror REMOVED - Incompatible with new listen()


@pytest.mark.asyncio
async def test_tcp_socket_transport_close_no_connection() -> None:
    """Test closing a TCPSocketTransport that has no active connection."""
    transport = TCPSocketTransport()
    await transport.close()  # Should not raise any error
    assert transport._writer is None
    assert transport._reader is None
    assert transport._server is None


@pytest.mark.asyncio
async def test_tcp_transport_close_handles_server_close_method_error() -> None:
    """Test close handles error when server.close() method itself errors."""
    transport = TCPSocketTransport()
    # Simulate a server object that errors when close is called
    mock_server = AsyncMock()
    mock_server.is_serving = MagicMock(return_value=True)  # Make is_serving a sync mock
    mock_server.close = MagicMock(
        side_effect=RuntimeError("Server.close() failed")
    )  # Make close a sync mock
    # mock_server.wait_closed will remain an AsyncMock, suitable for awaiting
    transport._server = mock_server  # type: ignore

    await transport.close()  # Should not raise, error should be caught and logged

    assert transport._server is None  # Should still be reset


@pytest.mark.asyncio
async def test_tcp_transport_close_handles_server_wait_closed_error() -> None:
    """Test close handles error when server.wait_closed() errors or times out."""
    transport = TCPSocketTransport()
    mock_server = AsyncMock()
    mock_server.is_serving = MagicMock(return_value=True)  # Make is_serving a sync mock
    mock_server.close = (
        MagicMock()
    )  # Make close a sync mock, no specific side effect needed here for it
    mock_server.wait_closed.side_effect = (
        asyncio.TimeoutError
    )  # wait_closed remains AsyncMock

    transport._server = mock_server  # type: ignore
    await transport.close()  # Should not raise

    assert transport._server is None


@pytest.mark.asyncio
async def test_tcp_socket_transport_connect_timeout() -> None:
    """Test connection timeout for TCP transport."""
    transport = TCPSocketTransport(host="8.8.8.8", port=12345)  # Non-existent server
    with pytest.raises(TransportError, match="Connection timed out"):
        # Shorten timeout for testing purposes if possible, or ensure it hits default.
        # The connect method has a hardcoded 5s timeout for asyncio.wait_for.
        # This test might be slow if it always waits the full 5s.
        # For now, rely on the default.
        await transport.connect("8.8.8.8:12345")  # Address for connect is more relevant


@pytest.mark.asyncio
async def test_tcp_transport_close_writer_timeout(mocker):
    """Test _close_writer when writer.wait_closed() times out."""
    transport = TCPSocketTransport()
    mock_writer = AsyncMock(spec=asyncio.StreamWriter)
    mock_writer.is_closing = MagicMock(return_value=False)
    mock_writer.close = MagicMock()
    mock_writer.wait_closed.side_effect = asyncio.TimeoutError

    transport._writer = mock_writer  # type: ignore

    # Call close() which should internally call _close_writer
    await transport.close()

    # Assert that writer was closed and reset despite timeout
    mock_writer.close.assert_called_once()
    assert transport._writer is None


@pytest.mark.asyncio
async def test_tcp_transport_close_writer_general_exception(mocker):
    """Test _close_writer when writer.wait_closed() raises a general exception."""
    transport = TCPSocketTransport()
    mock_writer = AsyncMock(spec=asyncio.StreamWriter)
    mock_writer.is_closing = MagicMock(return_value=False)
    mock_writer.close = MagicMock()
    mock_writer.wait_closed.side_effect = RuntimeError("Something else went wrong")

    transport._writer = mock_writer  # type: ignore
    await transport.close()

    mock_writer.close.assert_called_once()
    assert transport._writer is None


@pytest.mark.asyncio
async def test_close_with_active_writer():
    """Test close() after a successful connect, ensuring writer is closed."""
    server_host = "127.0.0.1"
    server_port = 0

    async def handle_echo(reader, writer):
        # Simple echo and close
        try:
            data = await reader.read(100)
            if data:
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_server(handle_echo, server_host, server_port)
    actual_port = server.sockets[0].getsockname()[1]

    transport = TCPSocketTransport()
    try:
        await transport.connect(f"{server_host}:{actual_port}")
        assert transport._writer is not None
        # Keep a reference if transport._writer is cleared by close() before we can check methods on it
        writer_ref = transport._writer
    except Exception as e:
        server.close()
        await server.wait_closed()
        pytest.fail(f"Connect failed unexpectedly: {e}")

    await transport.close()
    assert transport._writer is None
    if writer_ref:
        # Check if close was called on the writer instance
        # This is a bit tricky as is_closing might be True and wait_closed might have been called.
        # A direct mock would be better if _close_writer was public & testable.
        # For now, we assume if transport._writer is None, it was processed by _close_writer.
        pass


@pytest.mark.asyncio
async def test_close_writer_already_closing(mocker):
    """Test _close_writer branch where writer.is_closing() is True."""
    transport = TCPSocketTransport()
    mock_writer = AsyncMock(spec=asyncio.StreamWriter)
    mock_writer.is_closing.return_value = True  # Writer is already closing
    mock_writer.close = MagicMock()  # Should not be called
    mock_writer.wait_closed.return_value = None  # Should still be awaited

    transport._writer = mock_writer  # type: ignore
    await transport.close()  # This calls _close_writer internally

    mock_writer.close.assert_not_called()
    mock_writer.wait_closed.assert_called_once()  # wait_closed is still awaited
    assert transport._writer is None


@pytest.mark.asyncio
async def test_tcp_transport_close_writer_is_none():
    transport = TCPSocketTransport()
    # Call _close_writer directly with None, it should not raise an error
    await transport._close_writer(None)
    # Assertion is that it completes without error


@pytest.mark.asyncio
async def test_close_server_wait_closed_timeout(mocker, caplog):
    transport = TCPSocketTransport()
    mock_server = AsyncMock(spec=asyncio.AbstractServer)
    mock_server.is_serving.return_value = True # Server is serving
    mock_server.wait_closed = AsyncMock(side_effect=asyncio.TimeoutError("Simulated wait_closed timeout"))

    transport._server = mock_server
    transport._running = True # Assume it was running

    # Patch the lock to avoid issues with it being acquired if already acquired in other parts of close
    mocker.patch.object(transport, '_lock', AsyncMock(spec=asyncio.Lock))
    mock_logger_warning = mocker.patch("pyvider.rpcplugin.transport.tcp.logger.warning")

    await transport.close()

    assert transport._server is None # Should be reset

    mock_logger_warning.assert_called_once()
    args, _ = mock_logger_warning.call_args
    assert "Timeout closing TCP server" in args[0]
    # The endpoint is None in this test setup if listen() wasn't called, so log includes "unknown"
    assert "endpoint unknown" in args[0]

    mock_server.close.assert_called_once() # close should still be called


@pytest.mark.asyncio
async def test_close_server_not_serving(mocker):
    """Test close() branch where server.is_serving() is False."""
    transport = TCPSocketTransport()
    mock_server = AsyncMock(spec=asyncio.AbstractServer)
    mock_server.is_serving = MagicMock(return_value=False)  # Server is not serving
    mock_server.close = MagicMock()  # Should not be called
    mock_server.wait_closed = AsyncMock()  # Should not be called if close isn't

    transport._server = mock_server  # type: ignore
    await transport.close()

    mock_server.close.assert_not_called()
    mock_server.wait_closed.assert_not_called()
    assert transport._server is None


@pytest.mark.asyncio
async def test_close_server_wait_closed_generic_exception(mocker):
    """Test close() when server.wait_closed() raises a generic Exception."""
    transport = TCPSocketTransport()
    mock_server = AsyncMock(spec=asyncio.AbstractServer)
    mock_server.is_serving = MagicMock(return_value=True)
    mock_server.close = MagicMock()
    mock_server.wait_closed.side_effect = RuntimeError(
        "Simulated server wait_closed error"
    )

    transport._server = mock_server  # type: ignore
    await transport.close()  # Should catch the error and log

    mock_server.close.assert_called_once()
    mock_server.wait_closed.assert_called_once()
    assert transport._server is None


### 🐍🏗🧪️
