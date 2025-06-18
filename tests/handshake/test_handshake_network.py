# tests/handshake/test_handshake_network.py

from unittest.mock import patch

import pytest

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.handshake import (
    negotiate_transport,
)
from pyvider.rpcplugin.transport import (
    TCPSocketTransport,
    UnixSocketTransport,
)


@pytest.mark.asyncio
async def test_negotiate_transport_no_options():
    """Test transport negotiation with no options."""
    with pytest.raises(
        TransportError,
        match=r"\[TransportError\] No transport options were provided.*Hint:.*",
    ):
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
    with pytest.raises(
        TransportError,
        match=r"\[TransportError\] No compatible transport found.*Hint:.*",
    ):
        await negotiate_transport(["invalid"])


@pytest.mark.asyncio
async def test_negotiate_transport_exception_handling():
    """Test exception handling in transport negotiation."""
    # Mock the transport initialization to raise an exception
    with patch(
        "pyvider.rpcplugin.transport.UnixSocketTransport",
        side_effect=Exception("Transport creation failed"),
    ):
        with pytest.raises(
            TransportError,
            match=r"\[TransportError\] An unexpected error occurred during transport negotiation: Transport creation failed.*Hint:.*",
        ):
            await negotiate_transport(["unix"])

        # Test with multiple options
        with pytest.raises(
            TransportError,
            match=r"\[TransportError\] An unexpected error occurred during transport negotiation: Transport creation failed.*Hint:.*",
        ):
            await negotiate_transport(["unix", "tcp"])


@pytest.mark.asyncio
async def test_negotiate_transport_tempfile_exception(mocker):
    """Test that an exception during tempfile.gettempdir is handled."""
    mocker.patch("tempfile.gettempdir", side_effect=OSError("Disk full"))
    mock_logger_error = mocker.patch("pyvider.rpcplugin.handshake.logger.error")

    with pytest.raises(
        TransportError,
        match=r"\[TransportError\] An unexpected error occurred during transport negotiation: Disk full.*Hint:.*",
    ):
        await negotiate_transport(["unix"])

    mock_logger_error.assert_called_once()
    args, kwargs = mock_logger_error.call_args
    assert "Error during transport negotiation" in args[0]
    assert "Disk full" in kwargs.get("extra", {}).get("error", "")


### 🐍🏗🧪️
