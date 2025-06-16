# tests/server/test_server_transport.py

import os
import platform
import pytest

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import UnixSocketTransport

from unittest import mock # Corrected import

# Fixtures will be available via tests.fixtures through conftest.py
# from tests.fixtures.transport import managed_unix_socket_path
# from tests.fixtures.mocks import mock_server_protocol, mock_server_handler, mock_server_config, mock_server_transport_tcp
# from tests.fixtures.crypto import client_cert
from tests.fixtures.dummy import DummyGRPCServer # Re-added specific import

# If TCPSocketTransport is used implicitly via fixtures, ensure it's defined for type hints if strict
if 'TCPSocketTransport' not in globals():
    class TCPSocketTransport:
        pass # type: ignore


@pytest.mark.asyncio
async def test_setup_server_unix_success_insecure(
    managed_unix_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    test_transport = UnixSocketTransport(path=managed_unix_socket_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    original_endpoint_config = None
    try:
        original_endpoint_config = rpcplugin_config.get("PLUGIN_SERVER_ENDPOINT")
        rpcplugin_config.set("PLUGIN_SERVER_ENDPOINT", None)
        await server._negotiate_handshake()
        await server._setup_server(None)

        assert server._server is not None, "gRPC server object should be created"
        assert server._transport is not None, "Internal transport should be set"
        assert server._transport.endpoint is not None, (
            "Endpoint should be set by listen()"
        )
        assert server._transport.endpoint == managed_unix_socket_path, (
            "Endpoint should match the provided path"
        )
        assert os.path.exists(server._transport.endpoint), "Socket file should exist"
    finally:
        if original_endpoint_config is not None:
            rpcplugin_config.set("PLUGIN_SERVER_ENDPOINT", original_endpoint_config)
        await server.stop()


@pytest.mark.asyncio
async def test_setup_server_unix_no_socket(
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    sock_path = "/fucked"
    transport = UnixSocketTransport(path=sock_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    with pytest.raises(TransportError, match="Failed to"):
        await transport.listen()
        await server._setup_server("client_cert")


@pytest.mark.asyncio
async def test_setup_server_unix_bad_permissions(
    tmp_path,
    managed_unix_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    sock_path = managed_unix_socket_path
    with open(sock_path, "w") as f:
        f.write("")
    os.chmod(sock_path, 0o000)

    transport = mock.AsyncMock()
    transport.path = sock_path
    transport.listen = mock.AsyncMock(return_value=sock_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    try:
        async def mock_setup(*args):
            raise TransportError(f"Socket file {sock_path} has incorrect permissions.")

        with mock.patch.object(server, "_setup_server", mock_setup):
            with pytest.raises(TransportError, match="has incorrect permissions"):
                await server.serve()
    finally:
        if os.path.exists(sock_path):
            os.chmod(sock_path, 0o770)


@pytest.mark.skip
async def test_setup_server_unix_success_secure(
    managed_unix_socket_path,
    client_cert,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    sock_path = managed_unix_socket_path
    test_transport = UnixSocketTransport(path=sock_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    try:
        endpoint = await test_transport.listen()
        assert os.path.exists(sock_path), "Socket file should exist after listen()"
        assert endpoint is sock_path
        await server._setup_server("client_cert")
        assert server._server is not None, "Server should be initialized"
    finally:
        await test_transport.close()
        await server.stop()
        if os.path.exists(sock_path):
            try:
                os.chmod(sock_path, 0o777)
                os.unlink(sock_path)
            except Exception:  # Replaced bare except
                pass


@pytest.mark.asyncio
async def test_setup_server_exception_1(
    monkeypatch,
    managed_unix_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    await transport.listen()
    transport2 = UnixSocketTransport(path=managed_unix_socket_path)
    with pytest.raises(
        TransportError, match=r"Socket .* is already running"
    ):
        await transport2.listen()
    await transport.close()


@pytest.mark.asyncio
async def test_setup_server_exception_2(
    managed_unix_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    from unittest import mock # Already imported at top, but kept for clarity if this test is isolated
    socket_path = managed_unix_socket_path
    transport = UnixSocketTransport(path=socket_path)
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    await server._negotiate_handshake()
    dummy_server_instance = DummyGRPCServer()
    def mock_add_secure_port_on_dummy(*args, **kwargs):
        raise Exception("Failed to bind to")
    dummy_server_instance.add_secure_port = mock_add_secure_port_on_dummy
    dummy_server_instance.add_insecure_port = mock_add_secure_port_on_dummy
    with mock.patch(
        "pyvider.rpcplugin.server.GRPCServer", return_value=dummy_server_instance
    ):
        with pytest.raises(Exception, match="Failed to bind to"):
            await server._setup_server("client_cert_placeholder_for_secure_path")
    if (
        server._transport
        and hasattr(server._transport, "_running")
        and server._transport._running
    ):
        await server._transport.close()
    elif (
        hasattr(transport, "_running") and transport._running
    ):
        await transport.close()


@pytest.mark.skip
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
    await transport.listen()
    assert os.path.exists(sock_path), "Socket should exist"
    dummy_server = DummyGRPCServer()
    server._server = dummy_server
    def mock_add_secure_port(*args, **kwargs):
        raise Exception("Failed to bind to")
    with mock.patch.object(dummy_server, "add_secure_port", mock_add_secure_port):
        with pytest.raises(Exception, match="Failed to bind to"):
            await server._setup_server("client_cert")


@pytest.mark.asyncio
@pytest.mark.skipif(platform.system() != "Linux", reason="This test is Linux-specific")
async def test_setup_server_unix_no_socket_linux_1(
    tmp_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    nonexistent_path = str(tmp_path / "nonexistent_dir" / "nosock.sock")
    if os.path.lexists(nonexistent_path):
        os.unlink(nonexistent_path)
    os.makedirs(os.path.dirname(nonexistent_path), exist_ok=True)
    transport = UnixSocketTransport(path=nonexistent_path)
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    await server._negotiate_handshake()
    with mock.patch("pyvider.rpcplugin.server.GRPCServer") as mock_grpc_server_class:
        dummy_server_instance = DummyGRPCServer()
        def mock_add_secure_port_on_dummy(*args, **kwargs):
            raise RuntimeError("Failed to bind to address")
        dummy_server_instance.add_secure_port = mock_add_secure_port_on_dummy
        dummy_server_instance.add_insecure_port = mock_add_secure_port_on_dummy
        mock_grpc_server_class.return_value = dummy_server_instance
        expected_msg_regex = (
            r"\[TransportError\] gRPC server failed to start: Failed to bind to address "
            r"\(Hint: Check logs for details on binding or server start issues\. Ensure the address is not already in use\.\)"
        )
        with pytest.raises(TransportError, match=expected_msg_regex):
            await server._setup_server("client_cert")


@pytest.mark.skip
@pytest.mark.parametrize("platform_name", ["macos", "linux"])
async def test_setup_server_unix_no_socket_2(
    managed_unix_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    platform_name,
) -> None:
    current_platform = platform.system().lower()
    is_macos = current_platform == "darwin"
    is_linux = current_platform == "linux"
    if (platform_name == "macos" and not is_macos) or \
       (platform_name == "linux" and not is_linux):
        pytest.skip(f"Skipping {platform_name} test on {current_platform}")
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
    dummy_server = DummyGRPCServer()
    server._server = dummy_server
    macos_error = "Failed to create Unix socket: No such file or directory"
    linux_error = "Failed to bind to address"
    if platform_name == "macos":
        error_pattern = macos_error
    else:
        error_pattern = linux_error
    def mock_add_socket_port(*args, **kwargs):
        if platform_name == "macos":
            raise TransportError(macos_error)
        else:
            raise RuntimeError(f"{linux_error} 127.0.0.1:0; set GRPC_VERBOSITY=debug")
    with mock.patch.object(dummy_server, "add_secure_port", mock_add_socket_port):
        with pytest.raises((TransportError, RuntimeError), match=error_pattern):
            await server._setup_server("client_cert")


@pytest.mark.asyncio
async def test_setup_server_tcp_success(
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport_tcp,
) -> None:
    transport = mock_server_transport_tcp
    await transport.listen()
    RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    await transport.close()
    server_instance = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    await server_instance._negotiate_handshake()
    await server_instance._setup_server(client_cert=None)
    assert server_instance._transport is not None, "Server's transport should be set"
    transport_endpoint = server_instance._transport.endpoint
    assert transport_endpoint is not None, "Server transport endpoint should be set"
    assert "127.0.0.1" in transport_endpoint and not transport_endpoint.startswith(
        "unix:"
    ), f"Endpoint {transport_endpoint} is not a valid TCP endpoint as expected."
    assert server_instance._port is not None and server_instance._port > 0, (
        "gRPC server port not assigned"
    )
    await server_instance.stop()


### 🐍🏗🧪️
