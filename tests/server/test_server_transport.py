# tests/server/test_server_transport.py

import os
import platform
import pytest
import asyncio
from unittest import mock

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.exception import TransportError, SecurityError
from pyvider.rpcplugin.transport import UnixSocketTransport

from tests.fixtures.dummy import DummyGRPCServer

@pytest.mark.asyncio
async def test_setup_server_unix_success_secure(
    managed_unix_socket_path,
    client_cert,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mocker,
) -> None:
    sock_path = managed_unix_socket_path
    test_transport = UnixSocketTransport(path=sock_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    server._transport = test_transport
    server._transport_name = "unix"
    server._port = None

    mocker.patch.object(server, '_generate_server_credentials', return_value="mock_secure_creds")
    mock_grpc_server = mocker.AsyncMock()
    mocker.patch('pyvider.rpcplugin.server.GRPCServer', return_value=mock_grpc_server)

    try:
        # _setup_server calls listen(), so we don't call it beforehand.
        await server._setup_server(client_cert.cert)
        
        assert server._server is not None
        mock_grpc_server.add_secure_port.assert_called_once_with(f"unix:{sock_path}", "mock_secure_creds")
        mock_grpc_server.start.assert_called_once()
    finally:
        await server.stop()


@pytest.mark.asyncio
async def test_setup_server_exception_3(
    managed_unix_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    sock_path = managed_unix_socket_path
    transport = UnixSocketTransport(path=sock_path)
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    
    server._transport = transport
    server._transport_name = "unix"
    
    dummy_server = DummyGRPCServer()
    server._server = dummy_server

    def mock_add_secure_port(*args, **kwargs):
        raise RuntimeError("Failed to bind to socket")

    with mock.patch.object(dummy_server, "add_secure_port", mock_add_secure_port):
        with pytest.raises(TransportError, match=r"gRPC server failed to start: Failed to bind to socket"):
            await server._setup_server("client_cert")


@pytest.mark.asyncio
@pytest.mark.skipif(platform.system() == "Linux", reason="This test is for non-Linux platforms")
async def test_setup_server_unix_no_socket_2_macos(
    managed_unix_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mocker,
) -> None:
    nonexistent_path = os.path.join(
        os.path.dirname(managed_unix_socket_path), "nosock.sock"
    )
    transport = UnixSocketTransport(path=nonexistent_path)
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    
    server._transport = transport
    server._transport_name = "unix"

    dummy_server = DummyGRPCServer()
    server._server = dummy_server
    
    macos_error = "Failed to create Unix socket: No such file or directory"

    def mock_add_socket_port(*args, **kwargs):
        raise TransportError(macos_error)

    # Add this mock to ensure the secure path is taken
    mocker.patch.object(server, '_generate_server_credentials', return_value="mock_creds")

    with mock.patch.object(dummy_server, "add_secure_port", mock_add_socket_port):
        with pytest.raises(TransportError, match=macos_error):
            await server._setup_server("client_cert")
