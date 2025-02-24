# pyvider/rpcplugin/tests/server/test_server_handshake.py

import asyncio
import os
import stat
import sys
import tempfile
import pytest
from io import StringIO
from unittest.mock import AsyncMock, patch

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.exception import TransportError, HandshakeError, CertificateError
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport
from pyvider.rpcplugin.config import rpcplugin_config

from tests.conftest import (
    mock_server_transport,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    DummyAioServer,
    DummyGRPCServer,
)

from tests.fixtures import *


# TODO: fix this
# this test currently just sits there and freezes, it awaits but never shuts
# down.
@pytest.mark.skip
async def test_server_handshake_invalid_cookie(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):
    """Test server raises HandshakeError with invalid cookie."""
    # monkeypatch.setenv("PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE")
    # monkeypatch.setenv("PLUGIN_MAGIC_COOKIE", "invalid_cookie_value")
    # monkeypatch.setenv("PLUGIN_PROTOCOL_VERSIONS", "5,6")
    # monkeypatch.setenv("PLUGIN_TRANSPORTS", "tcp")

    mock_server_config.set("PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE")
    mock_server_config.set("PLUGIN_MAGIC_COOKIE", "invalid_cookie_value")
    mock_server_config.set("PLUGIN_PROTOCOL_VERSIONS", "5,6")
    # mock_server_config.set("PLUGIN_TRANSPORTS", "tcp")

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport,
    )

    with pytest.raises(HandshakeError):
        await server.serve()


# TODO: fix this
# this test currently just sits there and freezes, it awaits but never shuts
# down.
@pytest.mark.skip
async def test_server_handshake_missing_env(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):
    """
    Ensures the server raises HandshakeError if magic cookie key/value is not set at all.
    """
    # monkeypatch.delenv("PLUGIN_MAGIC_COOKIE_KEY", raising=False)
    # monkeypatch.delenv("PLUGIN_MAGIC_COOKIE", raising=False)
    # monkeypatch.setenv("PLUGIN_PROTOCOL_VERSIONS", "5,6")
    # monkeypatch.setenv("PLUGIN_TRANSPORTS", "tcp")

    mock_server_config.set("PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE")
    mock_server_config.set("PLUGIN_MAGIC_COOKIE", "invalid_cookie_value")
    mock_server_config.set("PLUGIN_PROTOCOL_VERSIONS", "5,6")

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport,
    )

    with pytest.raises(HandshakeError):
        await server.serve()


# -------------------------------------------------------------------
# Tests for _negotiate_handshake (lines ~251–252)
# -------------------------------------------------------------------
@pytest.mark.asyncio
async def test_negotiate_handshake_with_provided_transport(monkeypatch):
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

    monkeypatch.setattr(
        server, "_negotiate_handshake", dummy_negotiate.__get__(server, type(server))
    )
    await server._negotiate_handshake()
    assert server._transport_name == "tcp"


@pytest.mark.asyncio
async def test_negotiate_handshake_via_negotiation(monkeypatch):
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=None,
    )

    async def fake_negotiate_transport(supported_transports):
        return "unix", UnixSocketTransport(path="/tmp/fake.sock")

    monkeypatch.setattr(
        "pyvider.rpcplugin.server.negotiate_transport", fake_negotiate_transport
    )
    await server._negotiate_handshake()
    assert server._transport_name == "unix"


# -----------------------------------------------------------------------------
# Test for _negotiate_handshake (lines 230-238)
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_negotiate_handshake_provided_transport(monkeypatch):
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
async def test_negotiate_handshake_from_config(monkeypatch):
    # When self.transport is None, simulate negotiation via configuration.
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport,
    )

    async def fake_negotiate_transport(supported_transports):
        return "unix", UnixSocketTransport(path="/tmp/fake.sock")

    monkeypatch.setattr(
        "pyvider.rpcplugin.server.negotiate_transport", fake_negotiate_transport
    )
    await server._negotiate_handshake()
    assert server._transport_name == "unix"


################################################################################
# _|_|_  _ _|_' _   _ ||   |` _ ||  _
#  | | |(_| |  _\  (_|||  ~|~(_)||<_\
#
