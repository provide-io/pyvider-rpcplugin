#!/usr/bin/env python3
# tests/transport/unix/test_unix_error_handling.py

import asyncio
import os
import tempfile
from unittest.mock import patch, AsyncMock, MagicMock

import pytest

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import UnixSocketTransport


@pytest.mark.asyncio
async def test_unix_socket_error_handling() -> None:
    """Test comprehensive error handling in Unix socket transport."""

    # Test 1: Connect to nonexistent socket
    nonexistent_path = "/tmp/nonexistent_socket_path_12345.sock"
    if os.path.exists(nonexistent_path):
        os.unlink(nonexistent_path)

    transport = UnixSocketTransport()
    with pytest.raises(TransportError, match="does not exist"):
        await transport.connect(nonexistent_path)

    # Test 2: Attempt to create socket in inaccessible location
    with tempfile.NamedTemporaryFile() as tf:
        # Create a regular file instead of a socket
        tf.write(b"this is not a socket")
        tf.flush()

        # Try to connect to an existing non-socket file
        transport = UnixSocketTransport()
        with pytest.raises(TransportError, match="not a socket"):
            await transport.connect(tf.name)

    # Test 3: Test socket removal error
    with tempfile.TemporaryDirectory() as tmpdir:
        socket_path = os.path.join(tmpdir, "socket.sock")

        # Set up the transport
        transport = UnixSocketTransport(path=socket_path)
        await transport.listen()

        # Patch os.unlink to raise an error during close()
        with (
            patch("os.unlink", side_effect=PermissionError("Mocked permission error")),
            patch("os.path.exists", return_value=True),
        ):
            with pytest.raises(TransportError, match="Failed to remove socket file"):
                await transport.close()

    # Test 4: Test server startup error
    with tempfile.TemporaryDirectory() as tmpdir:
        socket_path = os.path.join(tmpdir, "socket_error.sock")

        transport = UnixSocketTransport(path=socket_path)

        # Patch asyncio.start_unix_server to raise an error
        with patch(
            "asyncio.start_unix_server",
            side_effect=OSError("Mocked server startup error"),
        ):
            with pytest.raises(TransportError, match="Failed to create Unix socket"):
                await transport.listen()


@pytest.mark.asyncio
async def test_unix_socket_close_error_handling() -> None:
    """Test error handling during close operations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        socket_path = os.path.join(tmpdir, "close_error.sock")

        # Create the transport and start listening
        transport = UnixSocketTransport(path=socket_path)
        await transport.listen()

        # Create a mock writer with an error on close
        # Use MagicMock with spec for asyncio.StreamWriter to ensure close is sync by default
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.close.side_effect = Exception("Mocked writer close error")
        # mock_writer.is_closing.return_value = True # Or False, depending on desired state
        # wait_closed needs to be an AsyncMock if it's called and awaited
        mock_writer.wait_closed = AsyncMock()

        # Assign it to the transport
        transport._writer = mock_writer

        # Close should handle the writer error without propagating
        await transport.close()

        # Socket file should still be removed
        assert not os.path.exists(socket_path)


@pytest.mark.asyncio
async def test_unix_socket_path_normalization() -> None:
    """Test path normalization for Unix sockets."""
    test_cases = [
        ("unix:/path/to/socket.sock", "/path/to/socket.sock"),
        ("unix:///path/to/socket.sock", "/path/to/socket.sock"),
        ("//path/to/socket.sock", "/path/to/socket.sock"),
        ("/path/to/socket.sock", "/path/to/socket.sock"),
        ("relative/path/socket.sock", "relative/path/socket.sock"),
    ]

    for input_path, expected_path in test_cases:
        transport = UnixSocketTransport(path=input_path)
        assert transport.path == expected_path, (
            f"Path normalization failed: expected {expected_path}, got {transport.path}"
        )


@pytest.mark.asyncio
async def test_unix_socket_connect_timeout() -> None:
    """Test connect timeout handling."""
    with tempfile.TemporaryDirectory() as tmpdir:
        socket_path = os.path.join(tmpdir, "timeout.sock")

        # Create the socket file but don't start a server
        with open(socket_path, "w") as f:
            f.write("dummy")

        # Set valid socket permissions
        os.chmod(socket_path, 0o777)

        transport = UnixSocketTransport()

        # Mock open_unix_connection to raise a timeout
        with patch(
            "asyncio.open_unix_connection",
            side_effect=asyncio.TimeoutError("Connection timed out"),
        ):
            with pytest.raises(TransportError, match="timed out|timeout"):
                await transport.connect(socket_path)


# 🐍🏗🧪️
