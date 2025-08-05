# tests/transport/test_transport_unix.py

import asyncio
import os
import errno
import stat
import socket # Ensured socket is imported

import pytest
from unittest.mock import MagicMock, AsyncMock # Ensured AsyncMock is imported for other tests if needed

from pyvider.telemetry import logger
from pyvider.rpcplugin.transport import UnixSocketTransport

# Fixtures will be available via tests.fixtures through conftest.py
# from tests.fixtures.transport import unix_transport, managed_unix_socket_path

################################################################################


@pytest.mark.asyncio
async def test_unix_transport_server_initialization(unix_transport) -> None:
    print(f"DEBUG: unix_transport type: {type(unix_transport)}")

    # Ensure _server attribute exists and is initialized
    assert hasattr(unix_transport, "_server"), (
        "UnixSocketTransport instance is missing '_server' attribute"
    )
    assert unix_transport._server is not None, "_server is not initialized"
    print(f"DEBUG: _server attribute initialized: {unix_transport._server}")


@pytest.mark.asyncio
async def test_unix_socket_connection_metrics(managed_unix_socket_path) -> None:
    """Test connection metrics during data transfer."""
    socket_path = str(managed_unix_socket_path)
    transport = UnixSocketTransport(path=socket_path)

    try:
        # Start the server
        await transport.listen()
        logger.debug(f"Server listening on {socket_path}")

        # Connect client
        reader, writer = await asyncio.open_unix_connection(socket_path)
        logger.debug("Client connected")

        # Send test data
        test_data = b"test data"
        writer.write(test_data)
        await writer.drain()
        logger.debug(f"Sent data: {test_data!r}")

        # Wait a bit to allow for data processing
        await asyncio.sleep(0.1)

        # Read response
        response = await asyncio.wait_for(reader.read(len(test_data)), timeout=1.0)
        logger.debug(f"Received response: {response!r}")

        # Verify the response
        assert response == test_data, f"Expected {test_data!r}, got {response!r}"

        # Clean up client connection
        writer.close()
        await writer.wait_closed()

    except Exception as e:
        logger.error(f"Test failed with error: {e}")
        raise

    finally:
        # Clean up the transport
        await transport.close()
        await asyncio.sleep(0.1)  # Allow time for cleanup

        assert not os.path.exists(socket_path), "Socket file wasn't cleaned up"


################################################################################
# _|_|_  _ _|_' _   _ ||   |` _ ||  _
#  | | |(_| |  _\  (_|||  ~|~(_)||<_\
#


def test_unix_transport_init_with_relative_path(mocker):
    """Test UnixSocketTransport initialization with a relative path."""
    # normalize_unix_path currently doesn't make paths absolute if they are relative
    # It mainly handles "unix:" prefixes and leading slashes.
    # This test will verify that normalize_unix_path is called.

    relative_path = "relative_socket_name.sock"
    # If normalize_unix_path were to make it absolute, expected_path would be os.path.abspath(relative_path)
    # But as it is, it should remain relative after prefix normalization (if any).
    expected_normalized_path = relative_path  # Assuming no "unix:" prefix to strip

    mock_normalize = mocker.patch(
        "pyvider.rpcplugin.transport.unix.normalize_unix_path",
        return_value=expected_normalized_path,
    )

    transport = UnixSocketTransport(path=relative_path)

    mock_normalize.assert_called_once_with(relative_path)
    assert transport.path == expected_normalized_path
    # To truly test lines 116-117 if they existed as os.path.abspath:
    # We would need to mock os.path.abspath and check its call if normalize_unix_path didn't return an absolute path.
    # However, those lines are not in the current __attrs_post_init__.



@pytest.mark.asyncio
async def test_check_socket_in_use_stat_oserror(mocker, managed_unix_socket_path): # caplog removed
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    # Ensure file exists for the first check
    with open(managed_unix_socket_path, 'w') as f: f.write('')

    mocker.patch("os.path.exists", return_value=True) # Ensure this is true for the test
    mock_os_stat = mocker.patch("os.stat", side_effect=OSError("stat failed")) # Keep the mock to ensure it's called
    mock_logger_warning = mocker.patch("pyvider.rpcplugin.transport.unix.logger.warning")

    # Expect it to assume available (False) and log a warning
    assert not await transport._check_socket_in_use() # Function under test

    mock_os_stat.assert_called_once_with(managed_unix_socket_path) # Verify os.stat was called
    mock_logger_warning.assert_called_once()
    args, _ = mock_logger_warning.call_args
    assert f"Could not stat {managed_unix_socket_path}" in args[0]
    assert "stat failed" in args[0] # Exception string is part of the formatted message
    assert "Assuming available" in args[0]
    os.unlink(managed_unix_socket_path) # Clean up the file

@pytest.mark.asyncio
async def test_check_socket_in_use_sock_close_exception(mocker, managed_unix_socket_path, caplog):
    transport = UnixSocketTransport(path=managed_unix_socket_path)

    mock_socket_instance = MagicMock(spec=socket.socket)
    # Simulate connect succeeding, so close is attempted on this socket instance
    mock_socket_instance.connect = MagicMock()
    mock_socket_instance.close = MagicMock(side_effect=Exception("Failed to close test socket"))
    # settimeout is called on the socket
    mock_socket_instance.settimeout = MagicMock()

    mocker.patch("socket.socket", return_value=mock_socket_instance)

    # Ensure os.path.exists and stat checks pass to reach the socket operations
    mocker.patch("os.path.exists", return_value=True)
    mock_stat_result = MagicMock()
    mock_stat_result.st_mode = stat.S_IFSOCK # Simulate it's a socket
    mocker.patch("os.stat", return_value=mock_stat_result)

    # This should return True because connect succeeded.
    # The error during sock.close() is logged as a warning but doesn't change the outcome of _check_socket_in_use
    mock_logger_warning = mocker.patch("pyvider.rpcplugin.transport.unix.logger.warning")
    assert await transport._check_socket_in_use()

    mock_logger_warning.assert_called_once()
    args, _ = mock_logger_warning.call_args
    assert "Error closing temporary socket" in args[0]
    assert "Failed to close test socket" in args[0] # This is the exception message

@pytest.mark.asyncio
async def test_check_socket_in_use_connect_other_oserror(mocker, managed_unix_socket_path, caplog):
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    mock_socket_instance = MagicMock(spec=socket.socket)
    # Simulate an OSError that isn't ConnectionRefused or FileNotFound
    mock_socket_instance.connect = MagicMock(side_effect=OSError(errno.EACCES, "Permission denied"))
    mock_socket_instance.close = MagicMock()
    mock_socket_instance.settimeout = MagicMock()

    mocker.patch("socket.socket", return_value=mock_socket_instance)
    mocker.patch("os.path.exists", return_value=True)
    mock_stat_result = MagicMock()
    mock_stat_result.st_mode = stat.S_IFSOCK
    mocker.patch("os.stat", return_value=mock_stat_result)

    # Should assume available (False) and log a warning
    mock_logger_warning = mocker.patch("pyvider.rpcplugin.transport.unix.logger.warning")
    assert not await transport._check_socket_in_use()

    mock_logger_warning.assert_called_once()
    args, _ = mock_logger_warning.call_args
    assert "OSError while connecting" in args[0]
    assert "Permission denied" in args[0] # This is part of the exception string in the log
    assert "Assuming available" in args[0]

@pytest.mark.asyncio
async def test_check_socket_in_use_path_is_not_socket(mocker, managed_unix_socket_path):
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    # Create a regular file at the socket path
    with open(managed_unix_socket_path, 'w') as f:
        f.write('this is not a socket')

    mocker.patch("os.path.exists", return_value=True)
    mock_stat_result = MagicMock()
    mock_stat_result.st_mode = stat.S_IFREG # Simulate a regular file
    mocker.patch("os.stat", return_value=mock_stat_result)

    # _check_socket_in_use should return False (socket is available) if path is not a socket
    assert not await transport._check_socket_in_use()

    # Clean up the created file
    os.unlink(managed_unix_socket_path)

@pytest.mark.asyncio
@pytest.mark.parametrize("error_to_raise", [ConnectionRefusedError, FileNotFoundError])
async def test_check_socket_in_use_connect_specific_errors(mocker, managed_unix_socket_path, error_to_raise):
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    mock_socket_instance = MagicMock(spec=socket.socket)
    mock_socket_instance.connect = MagicMock(side_effect=error_to_raise)
    mock_socket_instance.close = MagicMock() # Ensure close is mockable
    mock_socket_instance.settimeout = MagicMock() # Ensure settimeout is mockable

    mocker.patch("socket.socket", return_value=mock_socket_instance)
    mocker.patch("os.path.exists", return_value=True) # Assume path exists
    mock_stat_result = MagicMock()
    mock_stat_result.st_mode = stat.S_IFSOCK # Assume it's a socket file
    mocker.patch("os.stat", return_value=mock_stat_result)

    # _check_socket_in_use should return False (socket is available) for these errors
    assert not await transport._check_socket_in_use()

# Tests for normalize_unix_path
def test_normalize_unix_path_double_slash():
    from pyvider.rpcplugin.transport.unix import normalize_unix_path # Local import for clarity
    assert normalize_unix_path("//foo/bar") == "/foo/bar"
    assert normalize_unix_path("///foo/bar") == "/foo/bar"
    assert normalize_unix_path("//") == "/"
    assert normalize_unix_path("///") == "/"


def test_normalize_unix_path_single_slash():
    from pyvider.rpcplugin.transport.unix import normalize_unix_path
    assert normalize_unix_path("/foo/bar") == "/foo/bar"
    assert normalize_unix_path("/") == "/"

def test_normalize_unix_path_no_leading_slash():
    from pyvider.rpcplugin.transport.unix import normalize_unix_path
    assert normalize_unix_path("foo/bar") == "foo/bar"
    assert normalize_unix_path("foo") == "foo"

def test_normalize_unix_path_with_prefix():
    from pyvider.rpcplugin.transport.unix import normalize_unix_path
    assert normalize_unix_path("unix:///foo/bar") == "/foo/bar"
    assert normalize_unix_path("unix://foo/bar") == "/foo/bar"
    assert normalize_unix_path("unix:/foo/bar") == "/foo/bar"
    assert normalize_unix_path("unix:foo/bar") == "foo/bar"
    assert normalize_unix_path("unix:") == ""
    assert normalize_unix_path("unix://") == "/" # Added test case
    assert normalize_unix_path("unix:/") == "/"   # Added test case




### 🐍🏗🧪️
