# pyvider/rpcplugin/tests/server/test_server_transport.py

import asyncio
import os
import stat
import sys
import tempfile
import pytest
from io import StringIO
from unittest.mock import AsyncMock, patch

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.exception import TransportError, HandshakeError, CertificateError
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport
from pyvider.rpcplugin.config import rpcplugin_config

from tests.conftest import (
    mock_server_transport,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    DummyAioServer,
    DummyGRPCServer,
)

from tests.fixtures import *


@pytest.mark.asyncio
async def test_setup_server_unix_success(
    tmp_path,
    mock_server_preotocol,
    mock_server_handler,
    mock_server_config,
):
    sock_path = str(tmp_path / "test.sock")
    # TODO: Figure out sock_path length.

    if len(sock_path) > 104:  # Unix socket path length limit
        sock_path = "/tmp/test.sock"
    transport = UnixSocketTransport(path=sock_path)

    # dummy_server = DummyGRPCServer()
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    try:
        if isinstance(transport, UnixSocketTransport):
            await transport.listen()
        await server._setup_server("client_cert")

        expected = f"unix:{sock_path}"
        assert any(expected in port for port in server.ports)
    finally:
        await transport.close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)


@pytest.mark.asyncio
async def test_setup_server_unix_no_socket(
    tmp_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
):
    sock_path = str(tmp_path / "nosock.sock")
    transport = UnixSocketTransport(path=sock_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    with pytest.raises(TransportError, match="Failed to start"):
        await transport.listen()
        await server._setup_server("client_cert")


@pytest.mark.asyncio
async def test_setup_server_unix_bad_permissions(
    tmp_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
):
    sock_path = str(tmp_path / "badperm.sock")
    transport = UnixSocketTransport(path=sock_path)

    with open(sock_path, "w") as f:
        f.write("")
    os.chmod(sock_path, 0o100)

    try:
        server = RPCPluginServer(
            protocol=mock_server_protocol,
            handler=mock_server_handler,
            config=mock_server_config,
            transport=transport,
        )

        await transport.listen()
        with pytest.raises(TransportError, match="has incorrect permissions"):
            await server._setup_server("client_cert")
    finally:
        if os.path.exists(sock_path):
            os.chmod(sock_path, 0o700)
            os.unlink(sock_path)


@pytest.mark.asyncio
async def test_setup_server_exception(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):

    transport = mock_server_transport

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    # with pytest.raises(Exception, match="Server creation failed"):
    with pytest.raises(Exception, match="Failed to "):
        await transport.listen()
        await server._setup_server("client_cert")
        await transport.close()


@pytest.mark.asyncio
async def test_setup_server_tcp_success(
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
):

    transport_name, transport, endpoint = TCPSocketTransport()

    # monkeypatch.setattr(rpcplugin_config, "get",
    #     lambda key, default=None: "tcp:127.0.0.1:0" if key=="PLUGIN_SERVER_ENDPOINT" else default)

    # TODO: man this stuff fails really poorly if any if this stuff is missing.
    dummy_server = DummyGRPCServer()
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    server._server = dummy_server

    await transport.listen()
    #await server._setup_server("client_cert")

    await transport.close()

    # TODO: actually check this shit.

    #assert any(
    #    "127.0.0.1" in port and not port.startswith("unix:")
    #    for port in server.ports
    #)


@pytest.mark.asyncio
async def test_setup_server_unix_success(
    tmp_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
):
    transport = UnixSocketTransport()

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    await transport.listen()
    await server.serve()
#    await server._setup_server("client_cert")

    expected = f"unix:{endpoint}"
    #assert any(expected in port for port in dummy_server.ports)
    await transport.close()


################################################################################
# _|_|_  _ _|_' _   _ ||   |` _ ||  _
#  | | |(_| |  _\  (_|||  ~|~(_)||<_\
#
