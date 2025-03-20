
# tests/handshake/test_handshake_network.py

import os
import socket
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import HandshakeError, TransportError
from pyvider.rpcplugin.handshake import (
    negotiate_transport,
    validate_transport,
)
from pyvider.rpcplugin.transport import (
    TCPSocketTransport,
    UnixSocketTransport,
)


@pytest.mark.asyncio
async def test_negotiate_transport_no_options():
    """Test transport negotiation with no options."""
    with pytest.raises(TransportError, match="No transport options provided"):
        await negotiate_transport([])


@pytest.mark.asyncio
async def test_negotiate_transport_tcp():
    """Test transport negotiation with TCP only."""
    transport_name, transport = await negotiate_transport(["tcp"])
    assert transport_name == "tcp"
    assert isinstance(transport, TCPSocketTransport)


@pytest.mark.asyncio
async def test_negotiate_transport_unix():
    """Test transport negotiation with Unix only."""
    transport_name, transport = await negotiate_transport(["unix"])
    assert transport_name == "unix"
    assert isinstance(transport, UnixSocketTransport)
    
    # Verify the transport has expected attributes
    assert hasattr(transport, "path")
    assert transport.path is not None
    
    # Verify port attribute
    if hasattr(transport, "_port"):
        assert transport._port is None or isinstance(transport._port, int)
    
    # Clean up (just in case)
    await transport.close()


@pytest.mark.asyncio
async def test_negotiate_transport_multiple_options():
    """Test transport negotiation with multiple options."""
    # Unix should be preferred over TCP
    transport_name, transport = await negotiate_transport(["tcp", "unix"])
    assert transport_name == "unix"
    assert isinstance(transport, UnixSocketTransport)
    
    # Clean up
    await transport.close()


@pytest.mark.asyncio
async def test_negotiate_transport_invalid_options():
    """Test transport negotiation with invalid options."""
    with pytest.raises(TransportError, match="Unsupported transports"):
        await negotiate_transport(["invalid"])


@pytest.mark.asyncio
async def test_negotiate_transport_exception_handling():
    """Test exception handling in transport negotiation."""
    # Mock the transport initialization to raise an exception
    with patch('pyvider.rpcplugin.transport.UnixSocketTransport', side_effect=Exception("Transport creation failed")):
        with pytest.raises(TransportError, match="Error negotiating transport"):
            await negotiate_transport(["unix"])

        # Test with multiple options
        with pytest.raises(TransportError, match="Error negotiating transport"):
            await negotiate_transport(["unix", "tcp"])


def test_pem_rebuilding():
    """Test certificate PEM rebuilding."""
    # We'll test the function directly rather than through a class instance
    from pyvider.rpcplugin.handshake import _rebuild_x509_pem
    
    # Test with already formatted PEM
    existing_pem = "-----BEGIN CERTIFICATE-----\nABCDEF\n-----END CERTIFICATE-----\n"
    result = _rebuild_x509_pem(existing_pem)
    assert result == existing_pem
    
    # Test with base64 data only
    base64_only = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = _rebuild_x509_pem(base64_only)
    assert "-----BEGIN CERTIFICATE-----" in result
    assert "-----END CERTIFICATE-----" in result
    assert base64_only in result
