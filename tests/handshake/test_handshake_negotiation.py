# pyvider/rpcplugin/tests/handshake/test_handshake_negotiate.py

from unittest.mock import AsyncMock

import pytest

from pyvider.rpcplugin.exception import ProtocolError, TransportError
from pyvider.rpcplugin.handshake import (
    negotiate_protocol_version,
    negotiate_transport,
)
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport

from tests.fixtures import *


# Test for Protocol Version Negotiation
@pytest.mark.asyncio
async def test_negotiate_protocol_version_valid():
    """Test successful protocol version negotiation."""
    SUPPORTED_PROTOCOL_VERSIONS = [1, 2, 3, 4, 5, 6, 7]
    server_versions = [1, 2, 3, 4, 5, 6, 7]  # Server supports these versions
    negotiated_version = negotiate_protocol_version(server_versions)
    assert negotiated_version in SUPPORTED_PROTOCOL_VERSIONS
    assert negotiated_version == max(
        v for v in server_versions if v in SUPPORTED_PROTOCOL_VERSIONS
    )


@pytest.mark.asyncio
async def test_negotiate_protocol_version_no_common_version():
    """Test protocol version negotiation when no common version exists."""
    server_versions = [99, 100]  # Versions not supported by the client
    with pytest.raises(
        ProtocolError, match="No mutually supported protocol version found"
    ):
        negotiate_protocol_version(server_versions)


@pytest.mark.asyncio
async def test_negotiate_protocol_version_empty_list():
    """Test protocol version negotiation when the server provides no versions."""
    server_versions = []  # Server provides no versions
    with pytest.raises(
        ProtocolError, match="No mutually supported protocol version found"
    ):
        negotiate_protocol_version(server_versions)


@pytest.mark.asyncio
async def test_negotiate_transport_valid_tcp():
    """Test successful TCP transport negotiation."""
    transport_name, transport = await negotiate_transport(["tcp"])
    assert transport_name == "tcp"
    assert isinstance(transport, TCPSocketTransport)


@pytest.mark.asyncio
async def test_negotiate_transport_valid_unix():
    """Test successful Unix transport negotiation."""
    transport_name, transport = await negotiate_transport(["unix"])
    assert transport_name == "unix"
    assert isinstance(transport, UnixSocketTransport)


@pytest.mark.asyncio
async def test_negotiate_transport_no_common_transport():
    """Test transport negotiation when no common transport exists."""
    with pytest.raises(TransportError, match="Unsupported transports"):
        await negotiate_transport(["invalid_transport"])


@pytest.mark.asyncio
async def test_negotiate_transport_empty_list():
    """Test transport negotiation when no transports are provided."""
    with pytest.raises(TransportError, match="No transport options provided"):
        await negotiate_transport([])


@pytest.mark.asyncio
async def test_negotiate_transport_prefers_tcp():
    """Test that TCP is preferred when multiple transports are available."""
    transport_name, transport = await negotiate_transport(["unix", "tcp"])
    assert transport_name == "tcp"
    assert isinstance(transport, TCPSocketTransport)
