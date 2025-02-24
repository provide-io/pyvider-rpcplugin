
# pyvider/rpcplugin/tests/transport/tcp/test_transport_tcp_connect.py

import asyncio
import socket
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import TCPSocketTransport

from tests.fixtures import *

@pytest.mark.asyncio
async def test_tcp_socket_transport_connect_unreachable_address():
    unreachable = "192.0.2.254:80"
    transport = TCPSocketTransport(host=unreachable)

    with pytest.raises(TransportError):
        await asyncio.wait_for(transport.listen(), timeout=3.0)

@pytest.mark.asyncio
async def test_tcp_socket_transport_connect_invalid_endpoint():
    transport = TCPSocketTransport()
    with pytest.raises(TransportError):
        await asyncio.wait_for(transport.connect("127.0.0.1:65530"), timeout=5.0)

@pytest.mark.asyncio
async def test_tcp_socket_transport_connect_invalid_endpoint():
    """
    Test connecting to an invalid endpoint with TCPSocketTransport.
    """
    transport = TCPSocketTransport()
    endpoint = await transport.listen()

    # Use a valid format but an unlikely to be used port
    with pytest.raises(TransportError):
        # Include a timeout to prevent indefinite hanging
        await asyncio.wait_for(transport.connect("127.0.0.1:65530"), timeout=6.0)

@pytest.mark.asyncio
async def test_tcp_socket_transport_default_host():
    """
    Test that TCPSocketTransport uses the default host when none is provided.
    """
    transport = TCPSocketTransport()
    assert transport.host == "127.0.0.1"

################################################################################
# _|_|_  _ _|_' _   _ ||   |` _ ||  _
#  | | |(_| |  _\  (_|||  ~|~(_)||<_\
#
