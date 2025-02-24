
# tests/transport/test_transport_unix.py

import asyncio
import os
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio

from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport import UnixSocketTransport

from tests.fixtures import *

################################################################################

@pytest.mark.asyncio
async def test_unix_transport_server_initialization(unix_transport):
    print(f"DEBUG: unix_transport type: {type(unix_transport)}")

    # Ensure _server attribute exists and is initialized
    assert hasattr(unix_transport, "_server"), "UnixSocketTransport instance is missing '_server' attribute"
    assert unix_transport._server is not None, "_server is not initialized"
    print(f"DEBUG: _server attribute initialized: {unix_transport._server}")

@pytest.mark.asyncio
async def test_unix_socket_connection_metrics(unique_socket_path):
    """Test connection metrics during data transfer."""
    socket_path = str(unique_socket_path)
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
