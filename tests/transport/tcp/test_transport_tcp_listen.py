#
# pyvider/rpcplugin/tests/transport/tcp/test_transport_tcp_listen.py
#

import asyncio
import socket
import errno # Added import

import pytest

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import TCPSocketTransport

from tests.fixtures import *

@pytest.mark.asyncio
async def test_tcp_socket_transport_listen_and_connect(unused_tcp_port) -> None: # Added fixture
    # Use the fixture to ensure the port is free initially
    transport = TCPSocketTransport(port=unused_tcp_port)

    # Start the TCP server
    endpoint = await transport.listen()
    host, port_str = endpoint.split(":")
    port = int(port_str)
    assert port == unused_tcp_port # Verify the correct port was used

    # Assert that the endpoint is correctly set
    assert transport.endpoint == endpoint
    assert transport._server is not None

    # Simulate a client connection
    reader, writer = await asyncio.open_connection(host, port)
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
async def test_tcp_socket_transport_listen_port_in_use(unused_tcp_port) -> None:
    """
    Test that TCPSocketTransport.listen raises TransportError when the port is in use
    by another process/socket.
    """
    # First, bind the port using a standard socket to simulate it being in use
    blocker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        blocker_socket.bind(("127.0.0.1", unused_tcp_port))
        blocker_socket.listen(1)

        # Now, try to create and listen with our transport on the same port
        transport = TCPSocketTransport(host="127.0.0.1", port=unused_tcp_port)

        with pytest.raises(TransportError) as excinfo:
            await transport.listen()

        # Check that the error is due to the port being in use (EADDRINUSE)
        assert "Failed to bind TCP server" in str(excinfo.value)
        # Check the underlying OSError details if possible (errno might vary slightly by OS)
        assert isinstance(excinfo.value.__cause__, OSError)
        # Common errnos for "Address already in use"
        assert excinfo.value.__cause__.errno in (errno.EADDRINUSE, 98, 48) # Linux, macOS, Windows WSAEADDRINUSE is 10048 but Python maps it

    finally:
        blocker_socket.close()
        # Ensure the transport is closed if listen failed partially (though unlikely here)
        if hasattr(transport, '_server') and transport._server is not None:
             await transport.close()


### 🐍🏗🧪️