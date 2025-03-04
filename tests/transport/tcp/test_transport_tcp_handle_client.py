# pyvider/rpcplugin/tests/transport/tcp/test_transport_tcp_handle_client.py

import asyncio

import pytest

from pyvider.rpcplugin.transport import TCPSocketTransport

from tests.fixtures import *


@pytest.mark.asyncio
async def test_tcp_handle_client_called() -> None:
    transport = TCPSocketTransport(host="127.0.0.1")
    endpoint = await transport.listen()

    try:
        reader, writer = await asyncio.open_connection(*endpoint.split(":"))
        writer.write(b"test data")
        await writer.drain()
        response = await reader.read(100)
        assert response == b"test data", "Data was not echoed back by _handle_client"
        writer.close()
        await writer.wait_closed()
    finally:
        await transport.close()


@pytest.mark.asyncio
async def test_tcp_handle_client_direct() -> None:
    transport = TCPSocketTransport(host="127.0.0.1")
    endpoint = await transport.listen()

    host, port = endpoint.split(":")

    # Simulate a client connection
    try:
        reader, writer = await asyncio.open_connection(host, int(port))
        writer.write(b"test data")
        await writer.drain()

        # Read back echoed data
        response = await reader.read(100)
        assert response == b"test data", "Data was not echoed back by _handle_client"

        writer.close()
        await writer.wait_closed()
    finally:
        await transport.close()


################################################################################
# _|_|_  _ _|_' _   _ ||   |` _ ||  _
#  | | |(_| |  _\  (_|||  ~|~(_)||<_\
#
