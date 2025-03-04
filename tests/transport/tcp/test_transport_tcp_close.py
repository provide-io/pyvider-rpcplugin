# pyvider/rpcplugin/tests/transport/tcp/test_transport_tcp_close.py

import asyncio
from unittest.mock import AsyncMock

import pytest

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import TCPSocketTransport

from tests.fixtures import *


@pytest.mark.asyncio
async def test_tcp_socket_transport_close_connection_active(mock_server_transport_tcp) -> None:
    transport = TCPSocketTransport()

    try:
        await asyncio.wait_for(transport.listen(), timeout=5)
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
    transport = TCPSocketTransport(host="127.0.0.1")
    await transport.listen()

    client_transport = TCPSocketTransport()
    await client_transport.connect(transport.endpoint)

    mock_writer = AsyncMock()
    mock_writer.close.side_effect = TransportError("Mocked close error")
    client_transport._writer = mock_writer

    with pytest.raises(TransportError, match="Mocked close error"):
        await client_transport.close()

    await transport.close()


################################################################################
# _|_|_  _ _|_' _   _ ||   |` _ ||  _
#  | | |(_| |  _\  (_|||  ~|~(_)||<_\
#
