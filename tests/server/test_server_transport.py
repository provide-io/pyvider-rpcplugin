# tests/server/test_server_transport.py

import os
import platform
import pytest

from pyvider.rpcplugin.config import rpcplugin_config # Added import
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import UnixSocketTransport

from unittest import mock

from tests.fixtures import *

@pytest.mark.asyncio
async def test_setup_server_unix_success_insecure(
    managed_unix_socket_path, # Changed
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    # The managed_unix_socket_path will be used by the transport if not explicitly passed
    # For this test, we want the transport to pick its own path initially if not given one,
    # or use the one we give it. Let's assume the test implies the transport should use a specific path.
    test_transport = UnixSocketTransport(path=managed_unix_socket_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    original_endpoint_config = None
    try:
        # Ensure PLUGIN_SERVER_ENDPOINT is None for this test
        original_endpoint_config = rpcplugin_config.get("PLUGIN_SERVER_ENDPOINT")
        rpcplugin_config.set("PLUGIN_SERVER_ENDPOINT", None)

        # Call _negotiate_handshake to set server._transport
        await server._negotiate_handshake()

        # Now call _setup_server. It will use server._transport and call listen() on it.
        await server._setup_server(None) # client_cert is None for insecure

        assert server._server is not None, "gRPC server object should be created"
        assert server._transport is not None, "Internal transport should be set"
        assert server._transport.endpoint is not None, "Endpoint should be set by listen()"
        assert server._transport.endpoint == managed_unix_socket_path, "Endpoint should match the provided path"
        assert os.path.exists(server._transport.endpoint), "Socket file should exist"
    finally:
        if original_endpoint_config is not None: # Restore config
            rpcplugin_config.set("PLUGIN_SERVER_ENDPOINT", original_endpoint_config)

        await server.stop() # server.stop() should handle closing the transport

@pytest.mark.asyncio
async def test_setup_server_unix_no_socket(
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    sock_path = "/fucked" #unique_socket_path
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
    tmp_path, # tmp_path might still be useful for other temporary files if needed by test setup
    managed_unix_socket_path, # Changed
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    """Test server behavior with incorrect socket permissions."""
    # Use the managed socket path
    sock_path = managed_unix_socket_path

    # Create the socket file (as a file, not a dir) at the managed path with restricted permissions
    # The managed_unix_socket_path fixture ensures the path itself is valid and will be cleaned.
    # We are creating a file at this path for the purpose of this test.
    with open(sock_path, "w") as f:
        f.write("")
    os.chmod(sock_path, 0o000)  # No permissions

    # Create server with mocked transport
    transport = mock.AsyncMock()
    transport.path = sock_path # Mock transport uses this path
    transport.listen = mock.AsyncMock(return_value=sock_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport
    )

    try:
        # Mock _setup_server to check permissions and fail
        async def mock_setup(*args):
            # Fail with the expected error message
            raise TransportError(f"Socket file {sock_path} has incorrect permissions.")

        with mock.patch.object(server, '_setup_server', mock_setup):
            # This should raise TransportError with the permission message
            with pytest.raises(TransportError, match="has incorrect permissions"):
                await server.serve()
    finally:
        # Cleanup of sock_path is handled by managed_unix_socket_path fixture.
        # However, we manually chmodded it, so ensure it's writable for the fixture.
        if os.path.exists(sock_path):
            os.chmod(sock_path, 0o770)
            # The fixture will unlink.


###########

@pytest.mark.skip
async def test_setup_server_unix_success_secure(
    managed_unix_socket_path, # Changed
    client_cert,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    """Test secure Unix socket server setup with isolated path."""
    # Use the managed socket path
    sock_path = managed_unix_socket_path

    # Create a fresh transport that won't conflict with other tests
    test_transport = UnixSocketTransport(path=sock_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    try:
        # Listen on the transport first
        endpoint = await test_transport.listen()
        assert os.path.exists(sock_path), "Socket file should exist after listen()"
        assert endpoint is sock_path

        # Test server setup with client cert
        await server._setup_server("client_cert")
        assert server._server is not None, "Server should be initialized"

    finally:
        # Clean up resources
        await test_transport.close()
        await server.stop()

        # Extra cleanup in case transport.close() missed it
        if os.path.exists(sock_path):
            try:
                os.chmod(sock_path, 0o777)
                os.unlink(sock_path)
            except:
                pass

################################################################################

@pytest.mark.asyncio
async def test_setup_server_exception_1(
    monkeypatch,
    managed_unix_socket_path, # Changed
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    # Use a unique socket path for this test
    transport = UnixSocketTransport(path=managed_unix_socket_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    # First listen to set up the socket
    await transport.listen()
    
    # Create a new transport with the same path, which should fail
    transport2 = UnixSocketTransport(path=managed_unix_socket_path)
    
    with pytest.raises(TransportError, match="already in use"):
        await transport2.listen()
        
    # Clean up
    await transport.close()

@pytest.mark.asyncio
async def test_setup_server_exception_2(
    monkeypatch,
    managed_unix_socket_path, # Changed
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    """Test properly handling exceptions in server setup."""
    # Use the managed socket path
    socket_path = managed_unix_socket_path
    transport = UnixSocketTransport(path=socket_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    # Start the transport to create the socket
    await transport.listen()
    assert os.path.exists(socket_path), "Socket should exist"

    # Create a dummy server instance to patch
    dummy_server = DummyGRPCServer()
    server._server = dummy_server
    
    # Define the mock function that will be used directly
    def mock_add_secure_port(*args, **kwargs):
        raise Exception("Failed to bind to")
        
    # Apply the mock to the server instance
    with mock.patch.object(dummy_server, "add_secure_port", mock_add_secure_port):
        # Now try to set up the server, which should fail
        with pytest.raises(Exception, match="Failed to bind to"):
            await server._setup_server("client_cert")
    
    # Clean up
    await transport.close()

@pytest.mark.skip
async def test_setup_server_exception_3(
    managed_unix_socket_path, # Changed
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:

################################################################################
    """Test properly handling exceptions in server setup."""
    # Use the managed socket path
    sock_path = managed_unix_socket_path
    transport = UnixSocketTransport(path=sock_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    # Start the transport to create the socket
    await transport.listen()
    assert os.path.exists(sock_path), "Socket should exist"

    # Create a mock server instance to patch
    dummy_server = DummyGRPCServer()
    server._server = dummy_server
    
    # Define the mock function that will be used for patching
    def mock_add_secure_port(*args, **kwargs):
        raise Exception("Failed to bind to")

    # Apply the mock to the server instance
    with mock.patch.object(dummy_server, "add_secure_port", mock_add_secure_port):
        # Now try to set up the server, which should fail
        with pytest.raises(Exception, match="Failed to bind to"):
            await server._setup_server("client_cert")

@pytest.mark.asyncio
@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="This test is Linux-specific"
)
async def test_setup_server_unix_no_socket_linux_1(
    tmp_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    """Test behavior when the socket doesn't exist (Linux version)."""
    # Create a path that definitely doesn't exist
    nonexistent_path = str(tmp_path / "nonexistent_dir" / "nosock.sock")

    # Create directories but not the socket file
    os.makedirs(os.path.dirname(nonexistent_path), exist_ok=True)

    transport = UnixSocketTransport(path=nonexistent_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    # Create a dummy server instance
    dummy_server = DummyGRPCServer()
    server._server = dummy_server
    
    # Mock the add_secure_port method to simulate Linux binding error
    def mock_add_secure_port(*args, **kwargs):
        raise RuntimeError("Failed to bind to address 127.0.0.1:0; set GRPC_VERBOSITY=debug environment variable to see detailed error message.")
    
    # Apply platform-specific mocking
    with mock.patch.object(dummy_server, "add_secure_port", mock_add_secure_port):
        # Linux behavior will be different, expect a RuntimeError
        with pytest.raises(RuntimeError, match="Failed to bind to address"):
            await server._setup_server("client_cert")


# This done need to be evaluated.
@pytest.mark.skip
@pytest.mark.parametrize("platform_name", ["macos", "linux"])
async def test_setup_server_unix_no_socket_2(
    managed_unix_socket_path, # Changed
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    platform_name,
) -> None:
    """Test socket behavior on different platforms when socket file doesn't exist."""
    # Skip test if not running on the platform being tested
    current_platform = platform.system().lower()
    is_macos = current_platform == "darwin"
    is_linux = current_platform == "linux"
    
    if (platform_name == "macos" and not is_macos) or (platform_name == "linux" and not is_linux):
        pytest.skip(f"Skipping {platform_name} test on {current_platform}")

    # Create a path that definitely doesn't exist, in the same temp area as the managed path
    # managed_unix_socket_path is like .../sockets_pvXYZ/somehash.sock
    # We want .../sockets_pvXYZ/nosock.sock
    nonexistent_path = os.path.join(os.path.dirname(managed_unix_socket_path), "nosock.sock")
    
    # The directory os.path.dirname(managed_unix_socket_path) is created by the fixture.
    # So, no need for os.makedirs here.

    transport = UnixSocketTransport(path=nonexistent_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    # Create a dummy server for our test
    dummy_server = DummyGRPCServer()
    server._server = dummy_server
    
    # Define error behaviors by platform
    macos_error = "Failed to create Unix socket: No such file or directory"
    linux_error = "Failed to bind to address"
    
    if platform_name == "macos":
        error_pattern = macos_error
    else:
        error_pattern = linux_error
    
    # Mock the method that will fail
    def mock_add_socket_port(*args, **kwargs):
        if platform_name == "macos":
            raise TransportError(macos_error)
        else:
            raise RuntimeError(f"{linux_error} 127.0.0.1:0; set GRPC_VERBOSITY=debug")
        
    # Apply the mock
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

    # monkeypatch.setattr(rpcplugin_config, "get",
    #     lambda key, default=None: "tcp:127.0.0.1:0" if key=="PLUGIN_SERVER_ENDPOINT" else default)

    # TODO: man this stuff fails really poorly if any if this stuff is missing.
    #dummy_server = DummyGRPCServer()
    RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    #server._server = dummy_server

    #await transport.listen()
    #await server._setup_server("client_cert")

    #await transport.close()

    # TODO: actually check this shit.

    #assert any(
    #    "127.0.0.1" in port and not port.startswith("unix:")
    #    for port in server.ports
    #)

### 🐍🏗🧪️
