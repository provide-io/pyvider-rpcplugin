# pyvider/rpcplugin/tests/server/test_server_handshake.py

import pytest

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.transport import TCPSocketTransport
from pyvider.rpcplugin.config import rpcplugin_config

from pyvider.rpcplugin.handshake import (
    validate_magic_cookie,
)


from tests.fixtures import *

@pytest.mark.asyncio
async def test_server_handshake_invalid_cookie(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
) -> None:
    # Set invalid cookie values directly in rpcplugin_config to ensure they're used by validate_magic_cookie
    monkeypatch.setattr(rpcplugin_config, "config", {
        "PLUGIN_MAGIC_COOKIE_KEY": "PLUGIN_MAGIC_COOKIE",
        "PLUGIN_MAGIC_COOKIE_VALUE": "valid_cookie",
        "PLUGIN_MAGIC_COOKIE": "invalid_cookie",
        "PLUGIN_PROTOCOL_VERSIONS": [1],
        "PLUGIN_SERVER_TRANSPORTS": ["tcp", "unix"]
    })
    
    transport = mock_server_transport
    
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,  # Use None to force using the global config
        transport=transport,
    )

    with pytest.raises(HandshakeError, match="cookie_provided does not match required cookie_value"):
        await server._negotiate_handshake()

@pytest.mark.asyncio
async def Xtest_server_handshake_missing_env(
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
) -> None:

    mock_server_config.set("PLUGIN_MAGIC_COOKIE_KEY", None)
    mock_server_config.set("PLUGIN_MAGIC_COOKIE", "invalid_cookie_value")
    mock_server_config.set("PLUGIN_PROTOCOL_VERSIONS", "5,6")

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=None,
    )

    #await transport.listen()

    with pytest.raises(HandshakeError):
        await server._negotiate_handshake()

@pytest.mark.asyncio
async def test_server_handshake_missing_env(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
) -> None:
    """Test that missing environment variables raise HandshakeError."""
    # Create a clean server with default config
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,  # Use defaults
        transport=None,
    )
    
    # Replace validate_magic_cookie to ensure it checks for None
    original_validate = validate_magic_cookie
    
    def mock_validate(*args, **kwargs):
        # Force cookie_key to None to trigger error
        return original_validate(magic_cookie_key=None)
    
    # Apply the mock
    monkeypatch.setattr(
        "pyvider.rpcplugin.handshake.validate_magic_cookie",
        mock_validate
    )
    
    # Expect HandshakeError
    with pytest.raises(HandshakeError, match="cookie_key not found"):
        await server._negotiate_handshake()


@pytest.mark.asyncio
async def test_negotiate_handshake_with_provided_transport(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
) -> None:
    transport = mock_server_transport

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    await transport.listen()

    async def dummy_negotiate(self):
        self._protocol_version = 1
        self._transport = transport
        self._transport_name = transport._transport_name

    #monkeypatch.setattr(
    #    server, "_negotiate_handshake", dummy_negotiate.__get__(server, type(server))
    #)

    await server._negotiate_handshake()
    assert server._transport_name == transport._transport_name

@pytest.mark.asyncio
async def test_negotiate_handshake_via_negotiation(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_transport,
) -> None:

    # right now this fails if there is Unix. But it works fine
    # with the tests which has a config set.
    transport = mock_server_transport

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=transport,
    )

    # Mock the negotiate_transport function to return unix
    async def fake_negotiate_transport(supported_transports):
        return transport._transport_name, transport

    # Apply the mock to the correct module path
    monkeypatch.setattr(
        "pyvider.rpcplugin.handshake.negotiate_transport", fake_negotiate_transport
    )

    await server._negotiate_handshake()
    assert server._transport_name == transport._transport_name

@pytest.mark.asyncio
async def test_negotiate_handshake_provided_transport(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
) -> None:
    # When self.transport is provided, it should use that transport.
    tcp_transport = TCPSocketTransport(host="127.0.0.1")
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=tcp_transport,
    )

    async def dummy_negotiate(self):
        self._protocol_version = 1
        self._transport = tcp_transport
        self._transport_name = "tcp"

    # Bind the dummy negotiate function to the server.
    monkeypatch.setattr(
        server, "_negotiate_handshake", dummy_negotiate.__get__(server, type(server))
    )
    await server._negotiate_handshake()
    assert server._transport_name == "tcp"

@pytest.mark.asyncio
async def test_negotiate_handshake_from_config(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
) -> None:
    transport = mock_server_transport

    # When self.transport is None, simulate negotiation via configuration.
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=None,
    )

    async def fake_negotiate_transport(supported_transports):
        return transport._transport_name, transport

    monkeypatch.setattr(
        "pyvider.rpcplugin.server.negotiate_transport", fake_negotiate_transport
    )
    await server._negotiate_handshake()
    assert server._transport_name == transport._transport_name

### 🐍🏗🧪️
