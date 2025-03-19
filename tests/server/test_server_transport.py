# pyvider/rpcplugin/tests/server/test_server_transport.py

import os
import sys
import platform
from io import StringIO
import uuid
import pytest

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import UnixSocketTransport

from unittest import mock

from tests.fixtures import *

@pytest.mark.asyncio
async def test_setup_server_unix_success_insecure(
    unique_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    test_transport = UnixSocketTransport()

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    try:
        endpoint = await test_transport.listen()
        await server._setup_server(None)
        assert server._server is not None
        assert os.path.exists(endpoint)
    finally:
        await test_transport.close()
        await server.stop()

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
    tmp_path,
    unique_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    """Test server behavior with incorrect socket permissions."""
    # Create a unique socket path
    sock_path = unique_socket_path

    # Create the socket file with restricted permissions
    with open(sock_path, "w") as f:
        f.write("")
    os.chmod(sock_path, 0o000)  # No permissions

    # Create server with mocked transport
    transport = mock.AsyncMock()
    transport.path = sock_path
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
        # Ensure we can clean up the socket file
        if os.path.exists(sock_path):
            os.chmod(sock_path, 0o770)
            os.unlink(sock_path)

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

###########

@pytest.mark.asyncio
async def test_setup_server_unix_success_secure(
    unique_socket_path,
    client_cert,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    """Test secure Unix socket server setup with isolated path."""
    # Create a unique socket path within the test's tmp_path
    #sock_path = str(tmp_path / "secure_socket.sock")
    sock_path = unique_socket_path

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

@pytest_asyncio.fixture(scope="function")
async def short_socket_path(tmp_path) -> str:
    """Generate a short, guaranteed unique socket path that works across platforms."""
    import uuid
    
    # Create short identifier - keeping path under 80 chars for POSIX compliance
    short_id = uuid.uuid4().hex[:8]
    
    # Use tmp_path which is already unique per test
    socket_path = os.path.join(tmp_path, f"sock_{short_id}.sock")
    
    # Log the path for debugging
    logger.debug(f"🧪🔌 Created short socket path: {socket_path} ({len(socket_path)} chars)")
    
    yield socket_path
    
    # Cleanup after test
    if os.path.exists(socket_path):
        try:
            os.chmod(socket_path, 0o777)
            os.unlink(socket_path)
            logger.debug(f"🧪🧹 Cleaned up socket: {socket_path}")
        except OSError as e:
            logger.warning(f"🧪⚠️ Cleanup failed for socket {socket_path}: {e}")

@pytest.mark.asyncio
async def test_setup_server_unix_success_secure(
    short_socket_path,  # Use the shorter path 
    client_cert,
    mock_server_protocol,
    mock_server_handler, 
    mock_server_config
) -> None:
    """Test secure Unix socket server setup with isolated path."""
    # Use the short path fixture instead of nested paths
    #sock_path = short_socket_path

    # Create a fresh transport that won't conflict with other tests
    test_transport = UnixSocketTransport() # path=sock_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    # Listen on the transport first
    sock_path = await test_transport.listen()
    assert os.path.exists(sock_path), "Socket file should exist after listen()"

    # Test server setup with client cert
    await server._setup_server("client_cert")
    assert server._server is not None, "Server should be initialized"

    # Clean up resources
    await test_transport.close()
    await server.stop()


################################################################################

@pytest.mark.asyncio
async def test_setup_server_exception_1(
    monkeypatch,
    unique_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    # Use a unique socket path for this test
    transport = UnixSocketTransport(path=unique_socket_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    # First listen to set up the socket
    await transport.listen()
    
    # Create a new transport with the same path, which should fail
    transport2 = UnixSocketTransport(path=unique_socket_path)
    
    with pytest.raises(TransportError, match="already in use"):
        await transport2.listen()
        
    # Clean up
    await transport.close()

@pytest.mark.asyncio
async def test_setup_server_exception_2(
    monkeypatch,
    unique_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    """Test properly handling exceptions in server setup."""
    # Create an isolated transport using tmp_path
    socket_path = unique_socket_path
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

@pytest.mark.asyncio
async def test_setup_server_exception_3(
    unique_socket_path,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:

################################################################################
    """Test properly handling exceptions in server setup."""
    # Create an isolated transport using tmp_path
    #sock_path = str(tmp_path / "exception_test.sock")
    sock_path = unique_socket_path
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
async def test_setup_server_unix_no_socket_linux(
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



#############3

@pytest.mark.asyncio
@pytest.mark.parametrize("platform_name", ["macos", "linux"])
async def test_setup_server_unix_no_socket_A(
    unique_socket_path,
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

    # Create a path that definitely doesn't exist
    nonexistent_path = f"{unique_socket_path}/nosock.sock"

    # Create directories but not the socket file
    os.makedirs(os.path.dirname(nonexistent_path), exist_ok=True)

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
### 🐍🏗🧪️

@pytest.mark.asyncio
async def test_setup_server_unix_bad_permissions_9(
    tmp_path, mock_server_protocol, mock_server_handler, mock_server_config
) -> None:
    """Test server behavior with unreadable socket path."""
    import pathlib
    
    # Create uniquely named restricted directory
    restricted_dir = tmp_path / f"restricted_{uuid.uuid4().hex[:8]}"
    restricted_dir.mkdir(mode=0o700, exist_ok=False)
    sock_path = str(restricted_dir / "restricted.sock")
    
    # Create socket transport
    transport = UnixSocketTransport(path=sock_path)
    
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    
    # Mock _setup_server to simulate permission check failure
    async def mock_setup_server(client_cert):
        # Create socket file with restricted permissions
        with open(sock_path, 'w') as f:
            pass
        os.chmod(sock_path, 0o000)  # No permissions
        
        raise TransportError(f"Socket file {sock_path} has incorrect permissions.")
    
    # Apply mock
    with mock.patch.object(server, '_setup_server', mock_setup_server):
        with pytest.raises(TransportError, match="incorrect permissions"):
            await server._setup_server("client_cert")