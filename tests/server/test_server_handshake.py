# pyvider/rpcplugin/tests/server/test_server_handshake.py

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
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_VALUE", "valid_cookie")
    # Simulate client setting the environment variable with the invalid cookie
    monkeypatch.setenv("PLUGIN_MAGIC_COOKIE", "invalid_cookie")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_PROTOCOL_VERSIONS", [1])
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_SERVER_TRANSPORTS", ["tcp", "unix"])

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
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_SERVER_TRANSPORTS", [transport_type])
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_KEY", "key")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_MAGIC_COOKIE_VALUE", "value")
    # Simulate client setting the environment variable with the correct cookie
    monkeypatch.setenv("key", "value")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_PROTOCOL_VERSIONS", [1])

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
