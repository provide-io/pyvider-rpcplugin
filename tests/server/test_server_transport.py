# tests/server/test_server_transport.py

import os
import platform
import pytest
import asyncio
from unittest import mock

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.exception import TransportError, SecurityError
from pyvider.rpcplugin.transport import UnixSocketTransport
from pyvider.rpcplugin.config import rpcplugin_config

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
    """
    Tests that _setup_server correctly configures a secure port when mTLS is enabled.
    """
    sock_path = managed_unix_socket_path
    test_transport = UnixSocketTransport(path=sock_path)

    mocker.patch.object(rpcplugin_config, 'auto_mtls_enabled', return_value=True)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    # Call _negotiate_handshake to correctly set internal state like _transport
    mocker.patch('pyvider.rpcplugin.server.validate_magic_cookie')
    mocker.patch('pyvider.rpcplugin.server.negotiate_protocol_version', return_value=1)
    await server._negotiate_handshake()


    mocker.patch.object(server, '_generate_server_credentials', return_value="mock_secure_creds")
    
    mock_grpc_server_instance = mocker.MagicMock()
    mock_grpc_server_instance.start = mocker.AsyncMock()
    mock_grpc_server_instance.stop = mocker.AsyncMock()
    
    mocker.patch('pyvider.rpcplugin.server.GRPCServer', return_value=mock_grpc_server_instance)

    try:
        await server._setup_server(client_cert.cert)
        
        assert server._server is not None
        mock_grpc_server_instance.add_secure_port.assert_called_once_with(f"unix:{sock_path}", "mock_secure_creds")
        mock_grpc_server_instance.start.assert_called_once()
    finally:
        await server.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raised_exception, expected_match",
    [
        (RuntimeError("Failed to bind to socket"), r"gRPC server failed to start: Failed to bind to socket"),
        (TransportError("Failed to create Unix socket: No such file or directory"), r"Failed to create Unix socket: No such file or directory")
    ],
    ids=["runtime_error_on_bind", "transport_error_on_create"]
)
async def test_setup_server_add_port_failure(
    raised_exception,
    expected_match,
    managed_unix_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mocker, # Removed mock_server_config as it was causing issues
) -> None:
    """
    Consolidated and parameterized test for failures during server port binding.
    """
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None, # Use default config
        transport=transport,
    )

    # FIX: Ensure the condition to take the secure path is met by mocking auto_mtls_enabled.
    mocker.patch.object(rpcplugin_config, 'auto_mtls_enabled', return_value=True)

    # Call _negotiate_handshake to correctly set internal state like _transport.
    mocker.patch('pyvider.rpcplugin.server.validate_magic_cookie')
    mocker.patch('pyvider.rpcplugin.server.negotiate_protocol_version', return_value=1)
    await server._negotiate_handshake()

    dummy_server = DummyGRPCServer()
    mocker.patch('pyvider.rpcplugin.server.GRPCServer', return_value=dummy_server)
    
    mocker.patch.object(server, '_generate_server_credentials', return_value="mock_creds")

    with mock.patch.object(dummy_server, "add_secure_port", side_effect=raised_exception):
        with pytest.raises(TransportError, match=expected_match):
            await server._setup_server("client_cert")
