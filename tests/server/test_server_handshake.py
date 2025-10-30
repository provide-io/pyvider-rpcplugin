#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
import pytest
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.config import rpcplugin_config

@pytest.mark.asyncio
async def test_server_handshake_invalid_cookie(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_transport,
) -> None:
    monkeypatch.setattr(rpcplugin_config, "plugin_magic_cookie_key", "PLUGIN_MAGIC_COOKIE")
    monkeypatch.setattr(rpcplugin_config, "plugin_magic_cookie_value", "valid_cookie")
    # Simulate client setting the environment variable with the invalid cookie
    monkeypatch.setenv("PLUGIN_MAGIC_COOKIE", "invalid_cookie")
    monkeypatch.setattr(rpcplugin_config, "plugin_protocol_versions", [1])
    monkeypatch.setattr(rpcplugin_config, "plugin_server_transports", ["tcp", "unix"])

    server: RPCPluginServer = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=mock_server_transport,
    )

    with pytest.raises(
        HandshakeError,
        match=r"Expected: 'valid_cookie', Received: 'invalid_cookie'",
    ):
        await server._negotiate_handshake()

@pytest.mark.asyncio
@pytest.mark.parametrize("transport_type", ["tcp", "unix"])
async def test_negotiate_handshake_via_negotiation(
    transport_type, monkeypatch, mock_server_protocol, mock_server_handler
) -> None:
    """Tests that negotiation correctly selects a transport from config."""
    monkeypatch.setattr(rpcplugin_config, "plugin_server_transports", [transport_type])
    monkeypatch.setattr(rpcplugin_config, "plugin_magic_cookie_key", "key")
    monkeypatch.setattr(rpcplugin_config, "plugin_magic_cookie_value", "value")
    # Simulate client setting the environment variable with the correct cookie
    monkeypatch.setenv("key", "value")
    monkeypatch.setattr(rpcplugin_config, "plugin_protocol_versions", [1])

    server: RPCPluginServer = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=None,
    )

    await server._negotiate_handshake()

    assert server._transport_name == transport_type
    if transport_type == "tcp":
        assert isinstance(server._transport, TCPSocketTransport)
    else:
        assert isinstance(server._transport, UnixSocketTransport)

# 📞🔌🔚
