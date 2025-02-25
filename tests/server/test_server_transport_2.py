# test_server_transport.py

import pytest
import asyncio
import os
from unittest.mock import AsyncMock, patch

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport


@pytest.mark.asyncio
async def test_setup_server_unix_success(
    unique_socket_path, mock_server_protocol, mock_server_handler
):
    sock_path = unique_socket_path

    transport = UnixSocketTransport(path=sock_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol, handler=mock_server_handler, transport=transport
    )

    try:
        await transport.listen()
        await server._setup_server(None)  # Test insecure mode first
        assert server._server is not None
        assert os.path.exists(sock_path)
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_setup_server_unix_no_socket(
    tmp_path, mock_server_protocol, mock_server_handler
):
    sock_path = str(tmp_path / "nosock.sock")
    transport = UnixSocketTransport(path=sock_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol, handler=mock_server_handler, transport=transport
    )

    with pytest.raises(TransportError):
        await server._setup_server(None)

