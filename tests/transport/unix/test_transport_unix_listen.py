# tests/transport/unix/test_transport_unix_listen.py

import asyncio
import os
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio


from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import UnixSocketTransport

from tests.fixtures import *

@pytest.mark.asyncio
async def test_unix_socket_listen_and_connect(unique_socket_path):
    transport = UnixSocketTransport(path=unique_socket_path)
    # Validate the transport instance
    assert isinstance(transport, UnixSocketTransport), (
        f"Expected UnixSocketTransport, got {type(transport)}"
    )

    # Listen on the unique socket
    endpoint = await transport.listen()
    assert endpoint == unique_socket_path, (
        f"Expected {unique_socket_path}, got {endpoint}"
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
async def test_unix_socket_listen_path_creation_failure():
    """Test that UnixSocketTransport.listen raises TransportError when the socket path cannot be created."""
    transport = UnixSocketTransport(path="/root/unauthorized/socket.sock")

    with pytest.raises(TransportError) as excinfo:
        await transport.listen()

    assert "Failed to create Unix socket" in str(excinfo.value)

@pytest.mark.asyncio
async def test_unix_socket_listen_socket_in_use(unique_socket_path):

    """Test Unix socket transport handling of a socket already in use."""
    # Ensure the path is a string
    socket_path = str(unique_socket_path)

    transport1 = UnixSocketTransport(path=socket_path)
    await transport1.listen()

    try:
        transport2 = UnixSocketTransport(path=socket_path)
        with pytest.raises(TransportError) as excinfo:
            await transport2.listen()

        assert "already in use" in str(excinfo.value)
    finally:
        await transport1.close()
        # Add a small delay to ensure cleanup
        await asyncio.sleep(0.1)

@pytest.mark.asyncio
async def test_unix_listen_socket_in_use(monkeypatch):
    # Simulate _check_socket_in_use returning True.
    transport = UnixSocketTransport(path="/tmp/test.sock")
    monkeypatch.setattr(transport, "_check_socket_in_use", AsyncMock(return_value=True))
    with pytest.raises(TransportError, match="already in use"):
        await transport.listen()

@pytest.mark.asyncio
async def test_unix_socket_listen_unlink_file_not_found(unique_socket_path):
    transport = UnixSocketTransport(path=unique_socket_path)

    try:
        # Mock `os.unlink` to raise FileNotFoundError
        with patch("os.unlink", side_effect=FileNotFoundError):
            endpoint = await transport.listen()
            assert endpoint == unique_socket_path, (
                "Socket should be initialized despite missing file."
            )
    finally:
        await transport.close()
        # Allow event loop to clean up
        await asyncio.sleep(0)

@pytest.mark.asyncio
async def test_unix_listen_success(monkeypatch, tmp_path):
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
async def test_unix_listen_stale_file_error(monkeypatch, tmp_path):
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

### 🐍🏗🧪️
