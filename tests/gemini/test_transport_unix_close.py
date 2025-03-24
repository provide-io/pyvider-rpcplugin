# tests/transport/unix/test_transport_unix_close.py

import os
import pytest
from unittest.mock import patch
import tempfile

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport.unix import UnixSocketTransport

from tests.fixtures import *


@pytest.mark.asyncio
async def test_unix_socket_transport_close_no_path(unix_transport) -> None:
    """
    Test that UnixSocketTransport.close works when no path exists.
    """
    # Call close without a path
    await unix_transport.close()
    assert unix_transport._reader is None
    assert unix_transport._writer is None


@pytest.mark.asyncio
async def test_unix_socket_transport_close_unlink_success(unique_socket_path) -> None:
    """
    Test that UnixSocketTransport.close unlinks the socket path if it exists.
    """
    transport = UnixSocketTransport(path=unique_socket_path)
    # Create a dummy socket file
    with open(unique_socket_path, "w") as f:
        f.write("dummy")
    assert os.path.exists(unique_socket_path)
    await transport.close()
    assert not os.path.exists(unique_socket_path)
    assert transport._reader is None
    assert transport._writer is None


@pytest.mark.asyncio
async def test_unix_close_unlink_error(unique_socket_path) -> None:
    """Test handling of OSError during unlink."""
    transport = UnixSocketTransport(path=unique_socket_path)
    # Create a dummy socket file
    with open(unique_socket_path, "w") as f:
        f.write("dummy")
    assert os.path.exists(unique_socket_path)
    with patch("os.unlink", side_effect=OSError("Permission denied")):
        with pytest.raises(TransportError) as excinfo:
            await transport.close()
        assert "Failed to remove socket file" in str(excinfo.value)
    assert os.path.exists(unique_socket_path) # Ensure file is not deleted if unlink fails
    assert transport._reader is None
    assert transport._writer is None


@pytest.mark.asyncio
async def test_unix_socket_close_connection_active(unique_socket_path) -> None:
    """Test closing the transport when a connection is active."""
    transport = UnixSocketTransport(path=unique_socket_path)
    await transport.listen()
    client_transport = UnixSocketTransport(path=unique_socket_path)
    await client_transport.connect()
    assert transport._server is not None
    await transport.close()
    assert not os.path.exists(unique_socket_path)
    assert transport._reader is None
    assert transport._writer is None
    await client_transport.close()


@pytest.mark.asyncio
async def test_close_writer_exception(unique_socket_path):
    """Test handling of exception during writer close."""
    transport = UnixSocketTransport(path=unique_socket_path)
    await transport.listen()
    client_transport = UnixSocketTransport(path=unique_socket_path)
    await client_transport.connect()
    assert client_transport._writer is not None
    with patch.object(client_transport._writer, 'close', side_effect=Exception("Close error")):
        await client_transport.close()
    assert client_transport._reader is None
    assert client_transport._writer is None
    await transport.close()
