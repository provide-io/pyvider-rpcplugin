# pyvider/rpcplugin/tests/server/test_server_lifecycle.py

import asyncio
import os
import stat
import sys
import tempfile
import pytest
from io import StringIO
import gc
from typing import Any
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
    MockProtocol,
)

from tests.fixtures import *


@pytest.mark.asyncio
async def test_serve_success(
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):
    """Test server lifecycle with extra coverage."""
    transport_name, transport, endpoint = mock_server_transport

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    server._exit_on_stop = False  # Prevent sys.exit in test

    async def mock_handshake():
        pass

    server._negotiate_handshake = mock_handshake

    def trigger_shutdown():
        server._shutdown_requested()

    loop = asyncio.get_event_loop()
    loop.call_later(0.1, trigger_shutdown)

    await server.serve()
    assert server._serving_future.done()


@pytest.mark.asyncio
# FAILED x_test_server_lifecycle.py::test_server_serve_runtime_error[tcp] - Failed: DID NOT RAISE <class 'RuntimeError'>
# FAILED x_test_server_lifecycle.py::test_server_serve_runtime_error[unix] - pyvider.rpcplugin.exception.TransportError: Socket /var/folders/k6/jdp9qg890l553n47r3khszmc8t5ps6/T/tmpwt4uhtn3 is already in use
async def test_server_serve_runtime_error(
    monkeypatch,
    mock_server_handler,
    mock_server_protocol,
    mock_server_config,
    mock_server_transport,
):
    transport = mock_server_transport()
    #transport = mock_server_transport ### hmm.
    endpoint = await transport.listen()

    class ProtocolWithError(RPCPluginProtocol):
        async def add_to_server(self, handler, server):
            raise RuntimeError("Protocol service registration")

    # when this is set to mock_server_protocol it segfaults stuff.
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport, # if you pass the mock_server_transport in here directly
                             # it throws up. this needs to be excepted.
    )

    with pytest.raises(RuntimeError, match="Protocol service registration"):
        await server.serve()
        #await transport.close()


@pytest.mark.asyncio
async def test_serve_success(
    monkeypatch,
    mock_server_handler,
    mock_server_protocol,
    mock_server_config,
    mock_server_transport,
    ):

    transport_name, transport, endpoint = mock_server_transport

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    fut = asyncio.Future()
    fut.set_result(None)
    server._serving_future = fut
    server._serving_event = asyncio.Event()

    async def dummy_negotiate(self):
        self._protocol_version = 1
        self._transport_name = "tcp"

    monkeypatch.setattr(
        server, "_negotiate_handshake", dummy_negotiate.__get__(server, type(server))
    )

    async def dummy_setup(client_cert):
        return

    monkeypatch.setattr(server, "_setup_server", dummy_setup)

    async def dummy_build_handshake(*args, **kwargs):
        return "handshake_response"

    monkeypatch.setattr(
        "pyvider.rpcplugin.server.build_handshake_response", dummy_build_handshake
    )
    monkeypatch.setattr(server, "_register_signal_handlers", lambda: None)
    fake_stdout = StringIO()
    monkeypatch.setattr(sys, "stdout", fake_stdout)
    await server.serve()
    output = fake_stdout.getvalue().strip()
    assert output == "handshake_response"


@pytest.mark.asyncio
async def test_serve_error(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):
    transport_name, transport, endpoint = mock_server_transport

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    monkeypatch.setattr(server, "_register_signal_handlers", lambda: None)

    async def failing_negotiate(self):
        raise Exception("Handshake failed")

    monkeypatch.setattr(
        server, "_negotiate_handshake", failing_negotiate.__get__(server, type(server))
    )
    with pytest.raises(Exception, match="Handshake failed"):
        await server.serve()


@pytest.mark.asyncio
async def test_wait_for_server_ready(
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):
    transport_name, transport, endpoint = mock_server_transport

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    server._serving_event = asyncio.Event()

    async def set_event():
        await asyncio.sleep(0.1)
        server._serving_event.set()

    asyncio.create_task(set_event())
    await server.wait_for_server_ready()
    assert server._serving_event.is_set()


@pytest.mark.asyncio
async def Xtest_stop_success(monkeypatch):
    # Create dummy _server and _transport with working async close methods.
    dummy_server = DummyGRPCServer()

    async def dummy_stop(grace):
        pass

    dummy_server.stop = dummy_stop
    dummy_transport = AsyncMock()
    dummy_transport.close = AsyncMock()
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=None,
    )
    server._server = dummy_server
    server._transport = dummy_transport
    # Create a serving future that is not done.
    fut = asyncio.Future()
    server._serving_future = fut
    await server.stop()
    dummy_transport.close.assert_called_once()
    # Ensure _shutdown_requested was called so that serving future is done.
    assert fut.done()


@pytest.mark.asyncio
async def test_stop_handles_exceptions(
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):
    # Test that exceptions during _server.stop() and _transport.close() are caught.
    dummy_server = DummyGRPCServer()

    transport_name, transport, endpoint = mock_server_transport

    async def failing_stop(grace):
        raise Exception("Server stop failed")

    dummy_server.stop = failing_stop
    dummy_transport = AsyncMock()
    dummy_transport.close = AsyncMock(side_effect=Exception("Transport close failed"))
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    server._server = dummy_server
    server._transport = dummy_transport
    fut = asyncio.Future()
    fut.set_result(None)
    server._serving_future = fut
    # Calling stop() should log errors but eventually complete.
    await server.stop()
    # Even though exceptions occurred, _shutdown_requested() should have been called.
    assert server._serving_future.done()


# -----------------------------------------------------------------------------
# (Optional) Test for graceful shutdown cleanup in serve()
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_serve_success(
    monkeypatch,
    client_cert,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):

    transport_name, transport, endpoint = mock_server_transport

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )

    fut = asyncio.Future()
    fut.set_result(None)
    server._serving_future = fut
    server._serving_event = asyncio.Event()

    async def dummy_negotiate(self):
        self._protocol_version = 1
        self._transport_name = "tcp"

    monkeypatch.setattr(
        server, "_negotiate_handshake", dummy_negotiate.__get__(server, type(server))
    )

    async def dummy_setup(client_cert):
        return

    monkeypatch.setattr(server, "_setup_server", dummy_setup)

    async def dummy_build_handshake(*args, **kwargs):
        return "handshake_response"

    monkeypatch.setattr(
        "pyvider.rpcplugin.server.build_handshake_response", dummy_build_handshake
    )
    monkeypatch.setattr(server, "_register_signal_handlers", lambda: None)
    fake_stdout = StringIO()
    monkeyatch_stdout = monkeypatch.setattr(sys, "stdout", fake_stdout)
    await server.serve()
    output = fake_stdout.getvalue().strip()
    assert output == "handshake_response"


# this test currently just sits there and freezes, it awaits but never shuts
# down.
@pytest.mark.asyncio
async def test_server_stop_clean_destructor():
    """
    Create an RPCPluginServer with a dummy gRPC server, then call stop() and delete the server.
    This test covers the cleanup paths that trigger __del__ in the underlying gRPC server.
    """
    # Create the server with a dummy protocol.
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport,
    )
    # Inject a dummy gRPC server instance.
    server._server = DummyAioServer()
    # Set a dummy serving future (simulate that the server is running).
    fut = asyncio.Future()
    fut.set_result(None)
    server._serving_future = fut
    # Call stop() to shut down the server and transport.
    await server.stop()
    # Delete the server instance and force garbage collection.
    del server
    gc.collect()
    # If no exception is raised, then cleanup passed.


# this is segfaulting when run with "tests" but not individual directories.
# huh
@pytest.mark.asyncio
async def test_serve_and_stop_no_unawaited_warning(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):
    """
    Test that calling serve() and then stop() does not leave unawaited coroutines,
    even if the event loop is later closed.
    """
    transport_name, transport, endpoint = mock_server_transport

    # Create a server instance with a dummy protocol.
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )


    async def dummy_negotiate(self):
        self._protocol_version = 1
        self._transport = mock_server_transport_tcp
        self._transport_name = transport_name

    # Prepare dummy implementations for required methods.
    # Set _negotiate_handshake to simply set a protocol version.
    monkeypatch.setattr(
        server, "_negotiate_handshake", dummy_negotiate.__get__(server, type(server))
    )
    await server._negotiate_handshake()
    assert server._transport_name == transport_name

    async def dummy_setup(_):
        pass

    monkeypatch.setattr(server, "_setup_server", dummy_setup)
    # Patch build_handshake_response to return a fixed string.
    monkeypatch.setattr(
        "pyvider.rpcplugin.server.build_handshake_response",
        lambda plugin_version,
        transport_name,
        transport,
        server_cert=None,
        port=None: asyncio.sleep(0) or "dummy_handshake",
    )

    # Patch _register_signal_handlers to do nothing.
    monkeypatch.setattr(server, "_register_signal_handlers", lambda: None)

    endpoint = await transport.listen()

    # Create a task for serve(); then, after a short delay, call stop().
    serve_task = asyncio.create_task(server.serve())
    # Wait briefly to allow serve() to start.
    await asyncio.sleep(0.1)
    await server.stop()
    # Cancel serve() task if still running.
    serve_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await serve_task
    # Delete the server and force gc to trigger __del__.
    del server
    gc.collect()
    # If no warnings/errors are raised, then cleanup is successful.


################################################################################
# _|_|_  _ _|_' _   _ ||   |` _ ||  _
#  | | |(_| |  _\  (_|||  ~|~(_)||<_\
#
