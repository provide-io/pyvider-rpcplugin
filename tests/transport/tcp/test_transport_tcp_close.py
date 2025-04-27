#
# tests/transport/tcp/test_transport_tcp_close.py
#

import asyncio
from unittest.mock import AsyncMock

import pytest
import socket # Added import

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import TCPSocketTransport

from tests.fixtures import *


@pytest.mark.asyncio
async def test_tcp_socket_transport_close_connection_active(mock_server_transport_tcp) -> None:
    # This test seems incomplete - it creates a transport but doesn't use the fixture?
    # Assuming it meant to test closing while a server is listening.
    transport = TCPSocketTransport()
    endpoint = None
    try:
        endpoint = await asyncio.wait_for(transport.listen(), timeout=5)
        # Add a simple check that listening worked
        host, port_str = endpoint.split(":")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        sock.connect((host, int(port_str)))
        sock.close()
    except Exception as e:
        pytest.fail(f"Setup failed: {e}")
    finally:
        await transport.close()


@pytest.mark.asyncio
async def test_tcp_socket_transport_close_no_connection() -> None:
    """
    Test that TCPSocketTransport.close works when no connection is active.
    """
    transport = TCPSocketTransport(host="127.0.0.1")
    await transport.listen()
    await transport.close()

    # Check if the server is no longer serving
    if transport._server:
        assert not transport._server.is_serving()


@pytest.mark.asyncio
async def test_tcp_socket_transport_close_writer_oserror() -> None:
    """
    Test that TCPSocketTransport.close properly handles errors during writer close.
    """
    transport = TCPSocketTransport(host="127.0.0.1")
    await transport.listen()

    client_transport = TCPSocketTransport()
    await client_transport.connect(transport.endpoint)

    # Create a mock writer that raises an error on close
    mock_writer = AsyncMock()
    # Simulate error only on wait_closed, as close itself might not raise
    mock_writer.close.return_value = None
    mock_writer.wait_closed.side_effect = Exception("Mocked wait_closed error")

    # Replace the client's writer with our mock
    client_transport._writer = mock_writer

    # This should catch the error and log it without propagating
    await client_transport.close()

    # Now close the server transport
    await transport.close()


@pytest.mark.asyncio
async def test_tcp_socket_transport_server_error() -> None:
    """
    Test that TCPSocketTransport.close properly handles errors when closing the server.
    """
    transport = TCPSocketTransport(host="127.0.0.1")
    await transport.listen()

    # Create a mock server that raises an error on close
    mock_server = AsyncMock()
    mock_server.close.side_effect = Exception("Mocked server close error")
    mock_server.wait_closed.side_effect = Exception("Mocked server wait_closed error")

    # Replace the transport's server with our mock
    transport._server = mock_server

    # Should handle the error without propagating
    await transport.close()


@pytest.mark.asyncio
async def test_tcp_socket_transport_connect_timeout() -> None:
    """Test that TCPSocketTransport.connect handles connection timeouts properly."""
    # Use an unroutable IP address to force a timeout
    transport = TCPSocketTransport()

    # TCPSocketTransport.connect catches asyncio.TimeoutError and raises TransportError
    with pytest.raises(TransportError, match="timed out|Connection timed out|refused"):
        # Let connect handle its internal timeout (default 5s)
        # Don't use asyncio.wait_for here as it masks the internal error handling
        await transport.connect("240.0.0.1:12345") # Unroutable IP

    # Ensure close still works even after failed connect attempt
    await transport.close()

################################################################################
# _|_|_  _ _|_' _   _ ||   |` _ ||  _
#  | | |(_| |  _\  (_|||  ~|~(_)||<_\
#
