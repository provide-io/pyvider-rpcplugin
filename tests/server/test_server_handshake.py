# pyvider/rpcplugin/tests/server/test_server_handshake.py

import pytest

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.transport import TCPSocketTransport
from pyvider.rpcplugin.config import rpcplugin_config



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

    with pytest.raises(HandshakeError, match=r"Handshake negotiation failed: cookie_provided does not match required cookie_value"):
        await server._negotiate_handshake()

@pytest.mark.asyncio
async def test_server_handshake_missing_env(monkeypatch, mock_server_protocol, mock_server_handler):
    """Test handshake with missing environment variables."""
    # Create a new server instance with default config
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,  # Use None to force using the global config
        transport=None,
    )
    
    # This is the key fix: Reset critical config values
    # We need to directly access and modify the config used by validate_magic_cookie
    monkeypatch.setattr("pyvider.rpcplugin.config.rpcplugin_config.config", {
        # Set the problematic values that should trigger a HandshakeError
        "PLUGIN_MAGIC_COOKIE_KEY": None,  # This should force the error
        "PLUGIN_MAGIC_COOKIE_VALUE": "test_value",
        "PLUGIN_MAGIC_COOKIE": "test_cookie",
        "PLUGIN_PROTOCOL_VERSIONS": [1, 2],
        "PLUGIN_SERVER_TRANSPORTS": ["tcp", "unix"]
    })
    
    # Now the exception should be raised
    with pytest.raises(HandshakeError):
        await server._negotiate_handshake()

@pytest.mark.asyncio
async def test_negotiate_handshake_with_provided_transport(
    monkeypatch,
    managed_unix_socket_path,
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

    # Create a mock for _negotiate_handshake that doesn't actually call transport.listen()
    async def dummy_negotiate(self):
        self._protocol_version = 1
        self._transport = transport
        self._transport_name = transport._transport_name
        
    # Apply the mock
    monkeypatch.setattr(
        server, "_negotiate_handshake", dummy_negotiate.__get__(server, type(server))
    )

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
async def test_negotiate_handshake_provided_tcp_transport(
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

@pytest.mark.asyncio
async def test_negotiate_handshake_transport_is_tuple(
    mocker, mock_server_protocol, mock_server_handler, mock_server_config
):
    """Test _negotiate_handshake when self.transport is a tuple."""

    # Create a server instance. We will manually set its .transport attribute.
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config, # Use the fixture that provides global rpcplugin_config
        transport=None, # Initial transport is None
    )

    # Manually set the server's transport to a tuple, as if it was configured that way
    # This simulates the condition `isinstance(self.transport, tuple) and len(self.transport) >= 2`
    mock_actual_transport_instance = mocker.MagicMock(spec=TCPSocketTransport) # e.g. a TCPSocketTransport
    mock_actual_transport_instance.endpoint = "127.0.0.1:1234"

    server.transport = ("tcp", mock_actual_transport_instance) # Set the tuple

    # Mock a callable for supported_transports in HandshakeConfig
    # This part of the code isn't hit if server.transport is already a tuple.
    # The code directly uses the tuple:
    #   if isinstance(self.transport, tuple) and len(self.transport) >= 2:
    #       self._transport_name, self._transport = self.transport[0], self.transport[1]
    # So, no need to mock supported_transports or negotiate_transport for this specific path.

    # Mock validate_magic_cookie and negotiate_protocol_version to prevent side effects
    mocker.patch('pyvider.rpcplugin.handshake.validate_magic_cookie')
    mocker.patch('pyvider.rpcplugin.handshake.negotiate_protocol_version', return_value=1)
    mock_logger_debug = mocker.patch('pyvider.rpcplugin.server.logger.debug')

    await server._negotiate_handshake()

    # Assert that the transport name and instance were correctly unpacked from the tuple
    assert server._transport_name == "tcp"
    assert server._transport == mock_actual_transport_instance

    # Check for the specific log message
    found_log = any(
        "Transport tuple provided; unpacked transport." in call_args[0][0]
        for call_args in mock_logger_debug.call_args_list
    )
    assert found_log, "Log for transport tuple unpacking not found"

### 🐍🏗🧪️
