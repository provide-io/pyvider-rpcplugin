# tests/transport/test_transport_unix.py

import asyncio
import os

import pytest

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
        logger.debug(f"Sent data: {test_data}")

        # Wait a bit to allow for data processing
        await asyncio.sleep(0.1)

        # Read response
        response = await asyncio.wait_for(reader.read(len(test_data)), timeout=1.0)
        logger.debug(f"Received response: {response}")

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


### 🐍🏗🧪️
