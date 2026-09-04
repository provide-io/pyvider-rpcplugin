#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#


import pytest

from pyvider.rpcplugin.exception import ProtocolError, TransportError
from pyvider.rpcplugin.handshake import (
    negotiate_protocol_version,
    negotiate_transport,
)
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.transport.base import RPCPluginTransport # Added import


# Test for Protocol Version Negotiation
@pytest.mark.asyncio
async def test_negotiate_protocol_version_valid() -> None:
    """The newest version both ends can speak wins."""
    host_offered: list[int] = [1, 2, 3, 4, 5, 6, 7]
    negotiated_version = negotiate_protocol_version(host_offered, server_versions=[5, 6])
    assert negotiated_version == 6


@pytest.mark.asyncio
async def test_negotiate_protocol_version_defaults_to_configured_versions() -> None:
    """With no served set given, the SUPPORTED_PROTOCOL_VERSIONS config applies."""
    negotiated_version = negotiate_protocol_version([1, 2, 3, 4, 5, 6, 7])
    assert negotiated_version == 7


@pytest.mark.asyncio
async def test_negotiate_protocol_version_no_common_version() -> None:
    """No overlap serves the lowest version, leaving the host to object.

    go-plugin/server.go:145-147 says so in as many words -- "the last version
    in the config is returned leaving the client to report the
    incompatibility" -- and :216-222 does it.
    """
    assert negotiate_protocol_version([99, 100], server_versions=[6, 7]) == 6


@pytest.mark.asyncio
async def test_negotiate_protocol_version_empty_host_list_serves_oldest() -> None:
    """A host that offered no list gets the oldest version the plugin serves.

    go-plugin/server.go:216-222 returns the lowest registered version as the
    fallback, deliberately, "to serve the oldest version of our plugins to a
    legacy client that did not send a PLUGIN_PROTOCOL_VERSIONS list".
    """
    assert negotiate_protocol_version([], server_versions=[5, 6]) == 5


@pytest.mark.asyncio
async def test_negotiate_protocol_version_no_served_versions() -> None:
    """A plugin that serves nothing cannot negotiate at all."""
    with pytest.raises(ProtocolError, match=r"declares no protocol versions"):
        negotiate_protocol_version([6], server_versions=[])


@pytest.mark.asyncio
async def test_negotiate_transport_valid_tcp() -> None:
    """Test successful TCP transport negotiation."""
    transport_name, transport_instance = await negotiate_transport(["tcp"])
    transport: RPCPluginTransport = transport_instance # Type annotation
    assert transport_name == "tcp"
    assert isinstance(transport, TCPSocketTransport)


@pytest.mark.asyncio
async def test_negotiate_transport_valid_unix() -> None:
    """Test successful Unix transport negotiation."""
    transport_name, transport_instance = await negotiate_transport(["unix"])
    transport: RPCPluginTransport = transport_instance # Type annotation
    assert transport_name == "unix"
    assert isinstance(transport, UnixSocketTransport)


from provide.testkit.mocking import patch # Added for the new tests
import tempfile # Added for the new tests

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
    mock_logger_error = mocker.patch("pyvider.rpcplugin.handshake.negotiation.logger.error")

    with pytest.raises(
        TransportError,
        match=r"\[TransportError\] An unexpected error occurred during transport negotiation: Disk full.*Hint:.*",
    ):
        await negotiate_transport(["unix"])

    mock_logger_error.assert_called_once()
    args, kwargs = mock_logger_error.call_args
    assert "Error during transport negotiation" in args[0]
    assert "Disk full" in kwargs.get("extra", {}).get("error", "")


@pytest.mark.asyncio
async def test_negotiate_transport_no_common_transport() -> None:
    """Test transport negotiation when no common transport exists."""
    with pytest.raises(
        TransportError,
        match=r"\[TransportError\] No compatible transport found.*Hint:.*",
    ):
        await negotiate_transport(["invalid_transport"])


@pytest.mark.asyncio
async def test_negotiate_transport_empty_list() -> None:
    """Test transport negotiation when no transports are provided."""
    with pytest.raises(
        TransportError,
        match=r"\[TransportError\] No transport options were provided.*Hint:.*",
    ):
        await negotiate_transport([])


@pytest.mark.asyncio
async def test_negotiate_transport_prefers_unix() -> None:
    """Test that TCP is preferred when multiple transports are available."""
    transport_name, transport_instance = await negotiate_transport(["tcp", "unix"])
    transport: RPCPluginTransport = transport_instance # Type annotation
    assert transport_name == "unix"
    assert isinstance(transport, UnixSocketTransport)

# 🐍🔌📞🔚
