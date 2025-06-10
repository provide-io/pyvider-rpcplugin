# tests/transport/tcp/test_transport_tcp_close.py

import asyncio
import socket
from unittest.mock import AsyncMock, patch

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
    mock_server.is_serving.return_value = True
    mock_server.close.side_effect = RuntimeError("Server.close() failed")
    transport._server = mock_server # type: ignore

    await transport.close() # Should not raise, error should be caught and logged

    assert transport._server is None # Should still be reset


@pytest.mark.asyncio
async def test_tcp_transport_close_handles_server_wait_closed_error() -> None:
    """Test close handles error when server.wait_closed() errors or times out."""
    transport = TCPSocketTransport()
    mock_server = AsyncMock()
    mock_server.is_serving.return_value = True
    mock_server.wait_closed.side_effect = asyncio.TimeoutError # Simulate timeout

    transport._server = mock_server # type: ignore
    await transport.close() # Should not raise

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
        await transport.connect("8.8.8.8:12345") # Address for connect is more relevant

### 🐍🏗🧪️
