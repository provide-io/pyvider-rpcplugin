# pyvider/rpcplugin/tests/transport/tcp/test_transport_tcp_listen.py

import asyncio
import socket
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import TCPSocketTransport

from tests.fixtures import *


@pytest.mark.asyncio
async def test_tcp_socket_transport_listen_and_connect_2():
    transport = TCPSocketTransport()
    endpoint = await transport.listen()
    # do your checks, e.g. open a connection

@pytest.mark.asyncio
async def test_tcp_socket_transport_listen_and_connect_1():
    transport = TCPSocketTransport()

    # Start the TCP server
    endpoint = await transport.listen()
    host, port = endpoint.split(":")

    # Assert that the endpoint is correctly set
    assert transport.endpoint == endpoint
    assert transport._server is not None

    # Simulate a client connection
    reader, writer = await asyncio.open_connection(host, int(port))
    test_message = b"test message"
    writer.write(test_message)
    await writer.drain()

    # Read the echoed message
    response = await reader.read(100)
    assert response == test_message  # Verify echo functionality

    # Close the client connection
    writer.close()
    await writer.wait_closed()

    await transport.close()

    # Verify the server is no longer running
    assert transport._server is None or not transport._server.is_serving()

@pytest.mark.asyncio
async def test_tcp_socket_transport_listen_port_in_use_2(unused_tcp_port):
    transport = TCPSocketTransport(host="127.0.0.1")
    with socket.socket() as s:
        s.bind(("127.0.0.1", unused_tcp_port))
        with pytest.raises(TransportError, match="Port already in use"):
            await transport.listen()

@pytest.mark.asyncio
async def test_tcp_socket_transport_listen_port_in_use_1(unused_tcp_port):
    """
    Test that TCPSocketTransport.listen raises TransportError when the port is in use.
    """
    transport = TCPSocketTransport(host="127.0.0.1")
    endpoint = await transport.listen()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", unused_tcp_port))
        with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start_server:
            mock_start_server.side_effect = OSError("Port already in use")
            with pytest.raises(TransportError) as excinfo:
                await transport.listen()

            assert "Port already in use" in str(excinfo.value)

################################################################################
# _|_|_  _ _|_' _   _ ||   |` _ ||  _
#  | | |(_| |  _\  (_|||  ~|~(_)||<_\
#
