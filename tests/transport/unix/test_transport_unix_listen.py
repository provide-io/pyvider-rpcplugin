# tests/transport/unix/test_transport_unix_listen.py

import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, patch

import pytest


from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import UnixSocketTransport

# Fixtures will be available via tests.fixtures through conftest.py
# from tests.fixtures.transport import managed_unix_socket_path


@pytest.mark.asyncio
async def test_unix_socket_listen_and_connect(managed_unix_socket_path) -> None:
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    # Validate the transport instance
    assert isinstance(transport, UnixSocketTransport), (
        f"Expected UnixSocketTransport, got {type(transport)}"
    )

    # Listen on the unique socket
    endpoint = await transport.listen()
    assert endpoint == managed_unix_socket_path, (
        f"Expected {managed_unix_socket_path}, got {endpoint}"
    )

    # Client transport setup and connect
    client_transport = UnixSocketTransport(path=endpoint)
    await client_transport.connect(endpoint)
    await client_transport.close()

    # Cleanup
    await transport.close()
    assert not os.path.exists(endpoint), (
        "Socket file was not removed after transport closed."
    )


@pytest.mark.asyncio
async def test_unix_socket_listen_path_creation_failure() -> None:
    """Test that UnixSocketTransport.listen raises TransportError when the socket path cannot be created."""
    # Create a temporary directory with no permissions to create sockets
    temp_dir = tempfile.mkdtemp()
    try:
        # Make temp dir inaccessible
        os.chmod(temp_dir, 0o000)

        # Try to create a socket in the inaccessible directory
        transport = UnixSocketTransport(path=os.path.join(temp_dir, "socket.sock"))
        with pytest.raises(TransportError, match="Failed to create Unix socket"):
            await transport.listen()
    finally:
        # Restore permissions for cleanup
        os.chmod(temp_dir, 0o700)
        os.rmdir(temp_dir)


@pytest.mark.asyncio
async def test_unix_socket_listen_socket_in_use(managed_unix_socket_path) -> None:
    """Test Unix socket transport handling of a socket already in use."""
    # Ensure the path is a string
    socket_path = str(managed_unix_socket_path)

    transport1 = UnixSocketTransport(path=socket_path)
    await transport1.listen()

    try:
        transport2 = UnixSocketTransport(path=socket_path)
        with pytest.raises(TransportError) as excinfo:
            await transport2.listen()

        assert "is already running" in str(
            excinfo.value
        )  # Updated to check for new message
    finally:
        await transport1.close()
        # Add a small delay to ensure cleanup
        await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_unix_listen_socket_in_use(monkeypatch) -> None:
    # Simulate _check_socket_in_use returning True.
    transport = UnixSocketTransport(path="/tmp/test.sock")
    monkeypatch.setattr(transport, "_check_socket_in_use", AsyncMock(return_value=True))
    with pytest.raises(
        TransportError, match=r"Socket .* is already running"
    ):  # Updated match pattern
        await transport.listen()


@pytest.mark.asyncio
async def test_unix_socket_listen_unlink_file_not_found(
    managed_unix_socket_path,
) -> None:
    transport = UnixSocketTransport(path=managed_unix_socket_path)

    try:
        # Mock `os.unlink` to raise FileNotFoundError
        with patch("os.unlink", side_effect=FileNotFoundError):
            endpoint = await transport.listen()
            assert endpoint == managed_unix_socket_path, (
                "Socket should be initialized despite missing file."
            )
    finally:
        await transport.close()
        # Allow event loop to clean up a bit longer
        await asyncio.sleep(0.1)


@pytest.mark.asyncio
async def test_unix_listen_success(monkeypatch, tmp_path) -> None:
    # Test that listen() cleans up a stale file and creates a server.
    sock_path = str(tmp_path / "test.sock")
    transport = UnixSocketTransport(path=sock_path)
    # Patch _check_socket_in_use to return False.
    monkeypatch.setattr(
        transport, "_check_socket_in_use", AsyncMock(return_value=False)
    )
    # Create a stale file.
    with open(sock_path, "w") as f:
        f.write("stale")
    # Patch asyncio.start_unix_server to return a dummy server.
    dummy_server = AsyncMock()
    dummy_server.wait_closed = AsyncMock()
    monkeypatch.setattr(
        asyncio, "start_unix_server", AsyncMock(return_value=dummy_server)
    )
    # Patch os.chmod to do nothing.
    monkeypatch.setattr(os, "chmod", lambda path, mode: None)
    endpoint = await transport.listen()
    assert endpoint == sock_path


@pytest.mark.asyncio
async def test_unix_listen_stale_file_error(monkeypatch, tmp_path) -> None:
    import errno

    # Simulate error when removing a stale file.
    sock_path = str(tmp_path / "stale.sock")
    transport = UnixSocketTransport(path=sock_path)
    monkeypatch.setattr(
        transport, "_check_socket_in_use", AsyncMock(return_value=False)
    )
    # Create a stale file.
    with open(sock_path, "w") as f:
        f.write("stale")

    # Patch os.unlink to raise an error.
    def fake_unlink(path):
        raise OSError(errno.EACCES, "Access denied")

    monkeypatch.setattr(os, "unlink", fake_unlink)
    with pytest.raises(TransportError, match="Failed to remove"):
        await transport.listen()


@pytest.mark.asyncio
async def test_unix_listen_chmod_error(mocker, managed_unix_socket_path):
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    mocker.patch("os.makedirs", return_value=None)
    mocker.patch("os.unlink", return_value=None)
    # Ensure start_unix_server is mocked to return a valid server object
    mock_server_instance = AsyncMock(spec=asyncio.AbstractServer)
    mocker.patch("asyncio.start_unix_server", return_value=mock_server_instance)

    mock_chmod = mocker.patch("os.chmod", side_effect=OSError("chmod failed"))

    # The current code logs a warning and proceeds.
    # We'll check that listen still "succeeds" in setting up the endpoint.
    endpoint = await transport.listen()
    assert endpoint == managed_unix_socket_path
    mock_chmod.assert_called_once() # Verify chmod was attempted

    # Ensure the server object was stored
    assert transport._server == mock_server_instance
    await transport.close()

@pytest.mark.asyncio
async def test_unix_listen_start_server_error(mocker, managed_unix_socket_path):
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    mocker.patch("os.makedirs", return_value=None)
    mocker.patch("os.unlink", return_value=None) # Assume unlink works if file exists
    mocker.patch("os.chmod", return_value=None) # Assume chmod works
    mocker.patch("asyncio.start_unix_server", side_effect=OSError("start_unix_server failed"))

    with pytest.raises(TransportError, match="Failed to create Unix socket: start_unix_server failed"):
        await transport.listen()

    # Ensure transport is cleaned up or in a state where close can be called safely
    # Since listen failed, _server might not be set, endpoint might not be set.
    # close() should be resilient.
    await transport.close()


@pytest.mark.asyncio
async def test_unix_listen_path_no_directory(mocker):
    socket_name = "socket_in_cwd.sock" # A path without directory separators
    transport = UnixSocketTransport(path=socket_name)

    # Ensure that os.path.dirname(socket_name) would be empty
    assert not os.path.dirname(socket_name)

    mock_makedirs = mocker.patch("os.makedirs")
    # Mock other fs operations that might occur
    mocker.patch("os.path.exists", return_value=False) # Assume socket does not exist initially
    mocker.patch("os.unlink", return_value=None)
    mocker.patch("os.chmod", return_value=None)

    mock_server_instance = AsyncMock(spec=asyncio.AbstractServer)
    mocker.patch("asyncio.start_unix_server", return_value=mock_server_instance)

    endpoint = await transport.listen()
    assert endpoint == socket_name
    mock_makedirs.assert_not_called() # Key assertion: makedirs not called for empty dir_path

    # Cleanup - ensure the socket file created in CWD (if any) is removed
    if os.path.exists(socket_name):
        try:
            os.unlink(socket_name)
        except OSError:
             pass # Ignore if it's already gone or other issues during cleanup
    await transport.close()

### 🐍🏗🧪️
