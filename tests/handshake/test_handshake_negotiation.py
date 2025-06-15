# pyvider/rpcplugin/tests/handshake/test_handshake_negotiate.py


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
async def test_negotiate_protocol_version_valid() -> None:
    """Test successful protocol version negotiation."""
    SUPPORTED_PROTOCOL_VERSIONS = [1, 2, 3, 4, 5, 6, 7]
    server_versions = [1, 2, 3, 4, 5, 6, 7]  # Server supports these versions
    negotiated_version = negotiate_protocol_version(server_versions)
    assert negotiated_version in SUPPORTED_PROTOCOL_VERSIONS
    assert negotiated_version == max(
        v for v in server_versions if v in SUPPORTED_PROTOCOL_VERSIONS
    )


@pytest.mark.asyncio
async def test_negotiate_protocol_version_no_common_version() -> None:
    """Test protocol version negotiation when no common version exists."""
    server_versions = [99, 100]  # Versions not supported by the client
    with pytest.raises(
        ProtocolError, match=r"\[ProtocolError\] No mutually supported protocol version.*Hint:.*"
    ):
        negotiate_protocol_version(server_versions)


@pytest.mark.asyncio
async def test_negotiate_protocol_version_empty_list() -> None:
    """Test protocol version negotiation when the server provides no versions."""
    server_versions = []  # Server provides no versions
    with pytest.raises(
        ProtocolError, match=r"\[ProtocolError\] No mutually supported protocol version.*Hint:.*"
    ):
        negotiate_protocol_version(server_versions)


@pytest.mark.asyncio
async def test_negotiate_transport_valid_tcp() -> None:
    """Test successful TCP transport negotiation."""
    transport_name, transport = await negotiate_transport(["tcp"])
    assert transport_name == "tcp"
    assert isinstance(transport, TCPSocketTransport)


@pytest.mark.asyncio
async def test_negotiate_transport_valid_unix() -> None:
    """Test successful Unix transport negotiation."""
    transport_name, transport = await negotiate_transport(["unix"])
    assert transport_name == "unix"
    assert isinstance(transport, UnixSocketTransport)


@pytest.mark.asyncio
async def test_negotiate_transport_no_common_transport() -> None:
    """Test transport negotiation when no common transport exists."""
    with pytest.raises(TransportError, match=r"\[TransportError\] No compatible transport found.*Hint:.*"):
        await negotiate_transport(["invalid_transport"])


@pytest.mark.asyncio
async def test_negotiate_transport_empty_list() -> None:
    """Test transport negotiation when no transports are provided."""
    with pytest.raises(TransportError, match=r"\[TransportError\] No transport options were provided.*Hint:.*"):
        await negotiate_transport([])


@pytest.mark.asyncio
async def test_negotiate_transport_prefers_unix() -> None:
    """Test that TCP is preferred when multiple transports are available."""
    transport_name, transport = await negotiate_transport(["tcp", "unix"])
    assert transport_name == "unix"
    assert isinstance(transport, UnixSocketTransport)
