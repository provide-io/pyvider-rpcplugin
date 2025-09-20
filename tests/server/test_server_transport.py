# tests/server/test_server_transport.py

from provide.testkit.mocking import patch
import pytest

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.server import RPCPluginServer
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
    """
    Tests that _setup_server correctly configures a secure port when mTLS is enabled.
    """
    sock_path = managed_unix_socket_path
    test_transport = UnixSocketTransport(path=sock_path)

    mocker.patch.object(rpcplugin_config, "plugin_auto_mtls", True)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    # Call _negotiate_handshake to correctly set internal state like _transport
    mocker.patch("pyvider.rpcplugin.server.network.validate_magic_cookie")
    mocker.patch("pyvider.rpcplugin.server.network.negotiate_protocol_version", return_value=1)
    await server._negotiate_handshake()

    mock_creds = mocker.MagicMock()
    mock_creds._credentials = mocker.MagicMock()
    mocker.patch.object(server, "_generate_server_credentials", return_value=mock_creds)

    mock_grpc_server_instance = mocker.MagicMock()
    mock_grpc_server_instance.start = mocker.AsyncMock()
    mock_grpc_server_instance.stop = mocker.AsyncMock()

    mocker.patch("pyvider.rpcplugin.server.network.GRPCServer", return_value=mock_grpc_server_instance)

    try:
        await server._setup_server()

        assert server._server is not None
        mock_grpc_server_instance.add_secure_port.assert_called_once_with(f"unix:{sock_path}", mock_creds)
        mock_grpc_server_instance.start.assert_called_once()
    finally:
        await server.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raised_exception, expected_match",
    [
        (RuntimeError("Failed to bind to socket"), r"gRPC server failed to start: Failed to bind to socket"),
        (
            TransportError("Failed to create Unix socket: No such file or directory"),
            r"Failed to create Unix socket: No such file or directory",
        ),
    ],
    ids=["runtime_error_on_bind", "transport_error_on_create"],
)
async def test_setup_server_add_port_failure(
    raised_exception,
    expected_match,
    managed_unix_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mocker,  # Removed mock_server_config as it was causing issues
) -> None:
    """
    Consolidated and parameterized test for failures during server port binding.
    """
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,  # Use default config
        transport=transport,
    )

    mocker.patch.object(rpcplugin_config, "plugin_auto_mtls", True)

    # Call _negotiate_handshake to correctly set internal state like _transport.
    mocker.patch("pyvider.rpcplugin.server.network.validate_magic_cookie")
    mocker.patch("pyvider.rpcplugin.server.network.negotiate_protocol_version", return_value=1)
    await server._negotiate_handshake()

    dummy_server = DummyGRPCServer()
    mocker.patch("pyvider.rpcplugin.server.network.GRPCServer", return_value=dummy_server)

    mock_creds = mocker.MagicMock()
    mock_creds._credentials = mocker.MagicMock()
    mocker.patch.object(server, "_generate_server_credentials", return_value=mock_creds)

    with patch.object(dummy_server, "add_secure_port", side_effect=raised_exception):
        with pytest.raises(TransportError, match=expected_match):
            await server._setup_server()


# 🐍🔌🧪🪄
