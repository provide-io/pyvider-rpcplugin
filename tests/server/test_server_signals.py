# pyvider/rpcplugin/tests/server/test_server_signals.py

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


@pytest.mark.asyncio
# @pytest.mark.skip
async def test_server_signal_handling(mock_server_transport, mock_server_protocol):
    transport = mock_server_transport

    server = RPCPluginServer(
        protocol=mock_server_protocol,  # Use fixture correctly
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    server._exit_on_stop = False

    def trigger_shutdown():
        server._shutdown_requested()

    loop = asyncio.get_event_loop()
    loop.call_later(0.1, trigger_shutdown)

    await server.serve()
    assert server._serving_future.done()


# -------------------------------------------------------------------
# Tests for _register_signal_handlers (lines ~319–320 and 325–326)
# -------------------------------------------------------------------
@pytest.mark.asyncio
async def test_register_signal_handlers_success(monkeypatch):
    loop = asyncio.new_event_loop()
    monkeypatch.setattr(asyncio, "get_event_loop", lambda: loop)

    def fake_add_signal_handler(sig, handler):
        return

    monkeypatch.setattr(loop, "add_signal_handler", fake_add_signal_handler)
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=None,
    )

    server._register_signal_handlers()


@pytest.mark.asyncio
async def test_register_signal_handlers_not_supported(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    caplog
):
    """Test behavior when signal handlers are not supported."""
    loop = asyncio.new_event_loop()

    def mock_add_signal_handler(*args):
        raise NotImplementedError("Signal handler not supported")

    monkeypatch.setattr(loop, "add_signal_handler", mock_add_signal_handler)
    monkeypatch.setattr(asyncio, "get_event_loop", lambda: loop)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=None,
    )

    import logging
    with caplog.at_level(logging.WARNING):
        server._register_signal_handlers()

    assert "Signal handler not supported" in caplog.text

# -------------------------------------------------------------------
# Test for _shutdown_requested
# -------------------------------------------------------------------
def test_shutdown_requested():
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=None,
    )

    fut = asyncio.Future()
    server._serving_future = fut
    server._shutdown_requested()
    assert fut.done()


################################################################################
# _|_|_  _ _|_' _   _ ||   |` _ ||  _
#  | | |(_| |  _\  (_|||  ~|~(_)||<_\
#
