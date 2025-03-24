# tests/transport/unix/test_transport_unix_listen.py

import asyncio
import os
from unittest.mock import AsyncMock, patch
import tempfile

import pytest


from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import UnixSocketTransport

from tests.fixtures import *

@pytest.mark.asyncio
async def test_unix_socket_listen_and_connect(unique_socket_path) -> None:
    transport = UnixSocketTransport(path=unique_socket_path)
    # Validate the transport instance
    assert isinstance(transport, UnixSocketTransport), (
        f"Expected UnixSocketTransport, got {type(transport)}"
    )
    assert transport.path == unique_socket_path
    await transport.listen()
    client_transport = UnixSocketTransport(path=unique_socket_path)
    await client_transport.connect()
    assert client_transport._reader is not None
    assert client_transport._writer is not None
    await client_transport.close()
    await transport.close()
    assert not os.path.exists(unique_socket_path)


@pytest.mark.asyncio
async def test_unix_socket_listen_path_creation_failure() -> None:
    """Test handling of OSError during socket path creation."""
    with patch("os.makedirs", side_effect=OSError("Permission denied")):
        with pytest.raises(TransportError) as excinfo:
            transport = UnixSocketTransport(path="/root/test_socket")
            await transport.listen()
        assert "Failed to create socket directory" in str(excinfo.value)


@pytest.mark.asyncio
async def test_unix_socket_listen_bind_failure(unique_socket_path) -> None:
    """Test handling of OSError during socket binding."""
    # Create a dummy file at the socket path to cause a bind error
    with open(unique_socket_path, "w") as f:
        f.write("This is a dummy file")

    transport = UnixSocketTransport(path=unique_socket_path)
    with pytest.raises(TransportError) as excinfo:
        await transport.listen()
    assert "Failed to bind to socket" in str(excinfo.value)
    os.remove(unique_socket_path)
