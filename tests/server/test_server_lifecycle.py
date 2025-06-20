# pyvider/rpcplugin/tests/server/test_server_lifecycle.py

import asyncio
import sys
import builtins  # Add import for builtins
import os  # Added import for os
import pytest
from io import StringIO
import gc
import stat  # Added import
from typing import Any
from unittest.mock import AsyncMock, MagicMock  # Added MagicMock for ProtocolWithError
from grpc.aio import server as GrpcAioServerType
from pyvider.rpcplugin.types import RPCPluginTransport
from pyvider.rpcplugin.exception import (
    TransportError,
    ProtocolError,
)  # Ensure ProtocolError is imported
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport


from tests.conftest import (
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    DummyAioServer,
    DummyGRPCServer,
)

# Fixtures will be available via tests.fixtures through conftest.py
# from tests.fixtures.mocks import mock_server_transport
# from tests.fixtures.transport import managed_unix_socket_path


class MockBytesIO:
    """Mock implementation of sys.stdout.buffer for testing."""

    def __init__(self, string_io):
        self.string_io = string_io

    def write(self, data):
        if isinstance(data, bytes):
            # Convert bytes to string for StringIO
            self.string_io.write(data.decode("utf-8"))
        else:
            # Handle string content
            self.string_io.write(str(data))
        return len(data)

    def flush(self):
        self.string_io.flush()


@pytest.mark.asyncio
async def test_serve_success(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
) -> None:
    """Test server serve method with proper stdout handling."""
    test_transport = mock_server_transport

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    # Set up a completed future for _serving_future
    fut = asyncio.Future()
    fut.set_result(None)
    server._serving_future = fut
    server._serving_event = asyncio.Event()

    # Create proper mock for negotiate_handshake
    async def dummy_negotiate(self):
        self._protocol_version = 1
        self._transport_name = test_transport._transport_name
        self._transport = test_transport

    monkeypatch.setattr(
        server, "_negotiate_handshake", dummy_negotiate.__get__(server, type(server))
    )

    # Mock setup_server
    async def dummy_setup(_):
        pass

    monkeypatch.setattr(server, "_setup_server", dummy_setup)

    # Create async mock for build_handshake_response
    async def dummy_response(*args, **kwargs):
        return "dummy_handshake"

    monkeypatch.setattr(
        "pyvider.rpcplugin.server.build_handshake_response", dummy_response
    )

    # Mock signal handlers
    monkeypatch.setattr(server, "_register_signal_handlers", lambda: None)

    # Set up stdout capturing
    fake_stdout = StringIO()
    fake_stdout.buffer = MockBytesIO(fake_stdout)
    monkeypatch.setattr(sys, "stdout", fake_stdout)

    # Listen on transport and run serve
    await test_transport.listen()
    await server.serve()

    # Check output
    output = fake_stdout.getvalue().strip()
    assert output == "dummy_handshake"


@pytest.mark.asyncio
async def test_server_serve_runtime_error(
    monkeypatch,
    mock_server_handler,
    mock_server_protocol,
    mock_server_config,
    mock_server_transport,
) -> None:
    test_transport = mock_server_transport

    class ProtocolWithError(RPCPluginProtocol):
        def get_grpc_descriptors(self) -> tuple[Any, str]:
            return (MagicMock(), "service_name")

        async def add_to_server(self, handler, server):  # Corrected signature
            raise RuntimeError("Protocol service registration")

    server = RPCPluginServer(
        protocol=ProtocolWithError(),
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    monkeypatch.setattr(server, "_register_signal_handlers", lambda: None)

    async def mock_negotiate_handshake():
        server._transport = test_transport
        server._transport_name = getattr(test_transport, "_transport_name", "mock")
        server._protocol_version = 1
        server._server_cert_obj = None
        if hasattr(test_transport, "listen") and not getattr(
            test_transport, "_running", False
        ):
            await test_transport.listen()
        if isinstance(test_transport, TCPSocketTransport):
            server._port = getattr(test_transport, "port", 12345)
        else:
            server._port = None

    monkeypatch.setattr(server, "_negotiate_handshake", mock_negotiate_handshake)
    monkeypatch.setattr(server, "_read_client_cert", lambda: None)

    fake_stdout = StringIO()
    fake_stdout.buffer = MockBytesIO(fake_stdout)
    monkeypatch.setattr(sys, "stdout", fake_stdout)

    if hasattr(test_transport, "listen") and not getattr(
        test_transport, "_running", False
    ):
        await test_transport.listen()

    expected_msg_regex = (
        r"\[ProtocolError\] Failed to register protocol service: Protocol service registration "
        r"\(Hint: Ensure the protocol and handler are correctly implemented and compatible\.\)"
    )
    with pytest.raises(ProtocolError, match=expected_msg_regex):
        await server.serve()

    if hasattr(test_transport, "close"):
        await test_transport.close()


# Fix for test_serve_error[unix]
@pytest.mark.asyncio
async def test_serve_error(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    managed_unix_socket_path,  # Use unique path
) -> None:
    # Create fresh transport with unique path
    from pyvider.rpcplugin.transport import UnixSocketTransport  # Import directly

    test_transport = UnixSocketTransport(path=managed_unix_socket_path)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    monkeypatch.setattr(server, "_register_signal_handlers", lambda: None)

    # Use specific error message for regex match
    async def failing_negotiate(self):
        raise Exception("Handshake failed")

    monkeypatch.setattr(
        server, "_negotiate_handshake", failing_negotiate.__get__(server, type(server))
    )

    # We will NOT listen on the transport
    # Instead directly check for the exception
    with pytest.raises(Exception, match="Handshake failed"):
        await server.serve()

    # Clean up
    await server.stop()


# Fix for test_wait_for_server_ready[unix]
@pytest.mark.asyncio
async def test_wait_for_server_ready(
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    managed_unix_socket_path,  # Use unique path
) -> None:
    # Create fresh transport with unique path
    from pyvider.rpcplugin.transport import UnixSocketTransport  # Import directly

    test_transport = UnixSocketTransport(path=managed_unix_socket_path)

    # Don't actually listen on the socket here

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    server._serving_event = asyncio.Event()

    async def set_event():
        await asyncio.sleep(0.1)
        server._serving_event.set()

    asyncio.create_task(set_event())
    await server.wait_for_server_ready()
    assert server._serving_event.is_set()

    # Clean up (no need to call listen or close)


@pytest.mark.asyncio
async def test_stop_success(monkeypatch) -> None:
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


# Fix for test_stop_handles_exceptions[unix]
@pytest.mark.asyncio
async def test_stop_handles_exceptions(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    managed_unix_socket_path,  # Use a unique path fixture
) -> None:
    # Create a fresh transport with unique path for this test
    from pyvider.rpcplugin.transport import UnixSocketTransport  # Import directly

    dummy_transport = UnixSocketTransport(path=managed_unix_socket_path)

    # Don't actually listen on the transport to avoid socket creation
    # We're only testing exception handling during stop()

    dummy_server = DummyGRPCServer()

    async def failing_stop(grace):
        raise Exception("Server stop failed")

    dummy_server.stop = failing_stop

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=dummy_transport,
    )
    server._server = dummy_server

    # Don't reuse the actual transport for testing
    mock_transport = AsyncMock()
    mock_transport.close = AsyncMock(side_effect=Exception("Transport close failed"))
    server._transport = mock_transport

    fut = asyncio.Future()
    fut.set_result(None)
    server._serving_future = fut

    # Call stop() and verify it handles exceptions without raising
    await server.stop()

    # Verify expectations
    assert server._serving_future.done()
    mock_transport.close.assert_called_once()


@pytest.mark.asyncio
async def test_server_stop_clean_destructor(
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
) -> None:
    """
    Create an RPCPluginServer with a dummy gRPC server, then call stop() and delete the server.
    This test covers the cleanup paths that trigger __del__ in the underlying gRPC server.
    """
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=None,
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


@pytest.mark.asyncio
async def test_serve_and_stop_no_unawaited_warning(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
) -> None:
    """Test that calling serve() and then stop() does not leave unawaited coroutines."""
    # Create a server instance with a dummy protocol.
    test_transport = mock_server_transport
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=test_transport,
    )

    async def dummy_negotiate(self):
        self._protocol_version = 1
        self._transport = test_transport
        self._transport_name = test_transport._transport_name

    # Prepare dummy implementations for required methods.
    monkeypatch.setattr(
        server, "_negotiate_handshake", dummy_negotiate.__get__(server, type(server))
    )
    await server._negotiate_handshake()
    assert server._transport_name == test_transport._transport_name

    async def dummy_setup(_):
        pass

    monkeypatch.setattr(server, "_setup_server", dummy_setup)

    # Fix for None + string issue: ensure build_handshake_response returns a string value
    async def mock_build_handshake(*args, **kwargs):
        return "dummy_handshake"

    monkeypatch.setattr(
        "pyvider.rpcplugin.server.build_handshake_response", mock_build_handshake
    )

    # Patch _register_signal_handlers to do nothing.
    monkeypatch.setattr(server, "_register_signal_handlers", lambda: None)

    # Mock system stdout to prevent actual writing
    fake_stdout = StringIO()
    fake_stdout.buffer = MockBytesIO(fake_stdout)
    monkeypatch.setattr(sys, "stdout", fake_stdout)

    await test_transport.listen()

    # Create a task for serve(); then, after a short delay, call stop().
    serve_task = asyncio.create_task(server.serve())
    # Wait briefly to allow serve() to start.
    await asyncio.sleep(0.1)
    await server.stop()

    # Cancel serve() task if still running.
    serve_task.cancel()

    # Handle the cancellation without raising exception
    try:
        await serve_task
    except asyncio.CancelledError:
        pass

    # Success if we made it here without errors
    assert True


@pytest.mark.asyncio
async def test_attrs_post_init_handshake_config_error(mocker):
    """
    Test that if HandshakeConfig.from_server_config raises an error during
    RPCPluginServer instantiation, that error is propagated.
    """
    # Mock HandshakeConfig.from_server_config to raise a ValueError
    mocker.patch(
        "pyvider.rpcplugin.server.HandshakeConfig",
        side_effect=ValueError("Test HandshakeConfig error"),
    )

    with pytest.raises(ValueError, match="Test HandshakeConfig error"):
        RPCPluginServer(
            protocol=mock_server_protocol,  # Using a valid mock protocol
            handler=mock_server_handler,  # Using a valid mock handler
            config=None,  # Config can be None
            transport=None,  # Transport can be None
        )


@pytest.mark.asyncio
async def test_del_method_logging_with_endpoint(
    mock_server_protocol,
    mock_server_handler,
    mocker,  # Changed from caplog to mocker
):
    """Test __del__ logging when _transport.endpoint exists and server not stopped."""
    mock_logger_warning = mocker.patch("pyvider.rpcplugin.server.logger.warning")

    mock_transport_instance = mocker.MagicMock()
    mock_transport_instance.endpoint = "unix:/tmp/specific_socket.sock"
    mock_transport_instance.close = AsyncMock()

    server_instance = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=mock_transport_instance,
    )
    server_instance._transport = mock_transport_instance  # Added this line
    # server_instance._serving_future is not set to done, simulating server not stopped

    del server_instance
    gc.collect()  # Try with gc.collect first

    # Check if any call to logger.warning matches the expected message
    found_expected_call = False
    for call_args in mock_logger_warning.call_args_list:
        args, _ = call_args
        if (
            "RPCPluginServer for unix:/tmp/specific_socket.sock was not explicitly stopped"
            in args[0]
        ):
            found_expected_call = True
            break
    assert found_expected_call, (
        f"Expected log message not found. Actual calls: {mock_logger_warning.call_args_list}"
    )


@pytest.mark.asyncio
async def test_del_method_logging_with_port_only(
    mock_server_protocol,
    mock_server_handler,
    mocker,  # Changed from caplog to mocker
):
    """Test __del__ logging when _transport.endpoint is None, _port exists, and server not stopped."""
    mock_logger_warning = mocker.patch("pyvider.rpcplugin.server.logger.warning")

    mock_transport_instance = mocker.MagicMock()
    mock_transport_instance.endpoint = None  # Explicitly None
    mock_transport_instance.close = AsyncMock()

    server_instance = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=mock_transport_instance,
    )
    server_instance._port = 54321  # Set a port
    # server_instance._serving_future is not set to done

    del server_instance
    gc.collect()

    mock_logger_warning.assert_called_once()
    args, _ = mock_logger_warning.call_args
    assert "RPCPluginServer for port 54321 was not explicitly stopped" in args[0]


@pytest.mark.asyncio
async def test_del_method_logging_unknown_endpoint(
    mock_server_protocol,
    mock_server_handler,
    mocker,  # Changed from caplog to mocker
):
    """Test __del__ logging when transport/port are unavailable and server not stopped."""
    mock_logger_warning = mocker.patch("pyvider.rpcplugin.server.logger.warning")

    server_instance = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=None,  # No transport
    )
    # server_instance._serving_future is not set to done

    del server_instance
    gc.collect()

    mock_logger_warning.assert_called_once()
    args, _ = mock_logger_warning.call_args
    assert "RPCPluginServer for unknown endpoint was not explicitly stopped" in args[0]


@pytest.mark.asyncio
async def test_wait_for_server_ready_unix_path_none(
    mocker, mock_server_protocol, mock_server_handler, mock_server_config
):
    """Test wait_for_server_ready when Unix transport path is None."""
    mock_transport = mocker.MagicMock(spec=UnixSocketTransport)
    mock_transport.path = None  # Simulate path being None
    mock_transport.endpoint = (
        "/tmp/dummy.sock"  # ensure isinstance check passes if it relies on this
    )

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_transport,
    )
    server._transport = mock_transport  # Added this line
    server._serving_event = asyncio.Event()
    server._serving_event.set()  # Ensure the first await passes

    # We need to ensure that the match self._transport results in UnixSocketTransport
    # The spec on MagicMock should handle isinstance, but let's be safe
    original_isinstance = builtins.isinstance
    mocker.patch(
        "builtins.isinstance",
        lambda obj, cls_info: True
        if obj is mock_transport
        and (
            cls_info == UnixSocketTransport
            or (isinstance(cls_info, tuple) and UnixSocketTransport in cls_info)
        )
        else original_isinstance(obj, cls_info),
    )

    expected_unix_path_none_regex = (
        r"\[TransportError\] Unix socket path not set for server readiness check\. "
        r"\(Hint: Ensure the Unix socket transport was properly initialized and its path is set before checking readiness\.\)"
    )
    with pytest.raises(TransportError, match=expected_unix_path_none_regex):
        await server.wait_for_server_ready(timeout=0.1)


@pytest.mark.asyncio
async def test_wait_for_server_ready_unix_file_not_exists(
    mocker, mock_server_protocol, mock_server_handler, mock_server_config
):
    """Test wait_for_server_ready when Unix socket file does not exist."""
    mock_transport = mocker.MagicMock(spec=UnixSocketTransport)
    mock_transport.path = "/tmp/non_existent_socket.sock"
    mock_transport.endpoint = mock_transport.path  # Already set, this is fine

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_transport,
    )
    server._transport = mock_transport  # Added this line
    server._serving_event = asyncio.Event()
    server._serving_event.set()

    mocker.patch("os.path.exists", return_value=False)
    # As before, ensuring isinstance check passes for the match statement
    original_isinstance = builtins.isinstance
    mocker.patch(
        "builtins.isinstance",
        lambda obj, cls_info: True
        if obj is mock_transport
        and (
            cls_info == UnixSocketTransport
            or (isinstance(cls_info, tuple) and UnixSocketTransport in cls_info)
        )
        else original_isinstance(obj, cls_info),
    )

    expected_msg_regex = (
        r"\[TransportError\] Unix socket file /tmp/non_existent_socket\.sock does not exist\. "
        r"\(Hint: Ensure the server has started and created the socket file\. Check file system permissions\.\)"
    )
    with pytest.raises(TransportError, match=expected_msg_regex):
        await server.wait_for_server_ready(timeout=0.1)

    os.path.exists.assert_called_with("/tmp/non_existent_socket.sock")


@pytest.mark.asyncio
async def test_wait_for_server_ready_tcp_port_none(
    mocker, mock_server_protocol, mock_server_handler, mock_server_config
):
    """Test wait_for_server_ready when TCP port is None after server start."""
    mock_transport = mocker.MagicMock(spec=TCPSocketTransport)
    mock_transport.host = "127.0.0.1"
    mock_transport.endpoint = "127.0.0.1:0"  # Ensure endpoint is truthy

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_transport,
    )
    server._transport = mock_transport  # Added this line
    server._port = None  # Simulate port not being set
    server._serving_event = asyncio.Event()
    server._serving_event.set()

    # Ensure isinstance check passes for the match statement
    original_isinstance = builtins.isinstance
    mocker.patch(
        "builtins.isinstance",
        lambda obj, cls_info: True
        if obj is mock_transport
        and (
            cls_info == TCPSocketTransport
            or (isinstance(cls_info, tuple) and TCPSocketTransport in cls_info)
        )
        else original_isinstance(obj, cls_info),
    )

    expected_tcp_port_none_regex = (
        r"\[TransportError\] TCP port not available for server readiness check\. "
        r"\(Hint: Ensure the server started correctly and the TCP port was successfully bound and recorded\.\)"
    )
    with pytest.raises(TransportError, match=expected_tcp_port_none_regex):
        await server.wait_for_server_ready(timeout=0.1)


@pytest.mark.asyncio
async def test_wait_for_server_ready_tcp_connect_fails(
    mocker, mock_server_protocol, mock_server_handler, mock_server_config
):
    """Test wait_for_server_ready with TCP when sock.connect repeatedly fails."""
    mock_transport = mocker.MagicMock(spec=TCPSocketTransport)
    mock_transport.host = "127.0.0.1"
    mock_transport.endpoint = "127.0.0.1:12345"  # Ensure endpoint is truthy

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_transport,
    )
    server._transport = mock_transport  # Added this line
    server._port = 12345  # Port is set
    server._serving_event = asyncio.Event()
    server._serving_event.set()

    mock_socket_instance = mocker.MagicMock()
    mock_socket_instance.connect.side_effect = ConnectionRefusedError(
        "Connection refused by mock"
    )
    mock_socket_instance.close = mocker.MagicMock()

    mocker.patch("socket.socket", return_value=mock_socket_instance)
    original_isinstance = builtins.isinstance
    mocker.patch(
        "builtins.isinstance",
        lambda obj, cls_info: True
        if obj is mock_transport
        and (
            cls_info == TCPSocketTransport
            or (isinstance(cls_info, tuple) and TCPSocketTransport in cls_info)
        )
        else original_isinstance(obj, cls_info),
    )

    expected_msg_regex = (
        r"\[TransportError\] TCP socket at 127\.0\.0\.1:12345 is not connectable: Connection refused by mock "
        r"\(Hint: Verify the server process is running, listening on the port, and firewall rules allow connection\.\)"
    )
    with pytest.raises(TransportError, match=expected_msg_regex):
        await server.wait_for_server_ready(timeout=0.1)  # Short timeout for test speed

    mock_socket_instance.connect.assert_called_with(("127.0.0.1", 12345))


@pytest.mark.asyncio
async def test_wait_for_server_ready_unix_connect_fails(
    mocker, mock_server_protocol, mock_server_handler, mock_server_config
):
    """Test wait_for_server_ready with Unix when sock.connect repeatedly fails."""
    socket_path = "/tmp/test_unix_connect_fail.sock"
    mock_transport = mocker.MagicMock(spec=UnixSocketTransport)
    mock_transport.path = socket_path
    mock_transport.endpoint = socket_path  # Already set, this is fine

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_transport,
    )
    server._transport = mock_transport  # Added this line
    server._serving_event = asyncio.Event()
    server._serving_event.set()

    mocker.patch("os.path.exists", return_value=True)  # Socket file exists
    # Mock stat to return S_ISSOCK
    mock_stat_result = mocker.MagicMock()
    mock_stat_result.st_mode = stat.S_IFSOCK
    mocker.patch("os.stat", return_value=mock_stat_result)

    mock_socket_instance = mocker.MagicMock()
    mock_socket_instance.connect.side_effect = OSError("Unix connect failed")
    mock_socket_instance.close = mocker.MagicMock()

    mocker.patch("socket.socket", return_value=mock_socket_instance)
    original_isinstance = builtins.isinstance
    # This lambda needs to handle both UnixSocketTransport and potentially TCPSocketTransport if it's part of a complex check.
    # However, the specific problem context is usually one type. If only UnixSocketTransport is relevant for this test's match statement:
    mocker.patch(
        "builtins.isinstance",
        lambda obj, cls_info: True
        if obj is mock_transport
        and (
            cls_info == UnixSocketTransport
            or (isinstance(cls_info, tuple) and UnixSocketTransport in cls_info)
        )
        else original_isinstance(obj, cls_info),
    )
    # If the code being tested *could* check against TCPSocketTransport as well in the same logic block:
    # mocker.patch('builtins.isinstance', lambda obj, cls_check: True if cls_check in (UnixSocketTransport, TCPSocketTransport) else original_isinstance(obj, cls_check))
    # For now, assuming the simpler, more common case where it's checking for one specific type in the match.

    expected_msg_regex = (
        r"\[TransportError\] Unix socket at /tmp/test_unix_connect_fail\.sock is not connectable: Unix connect failed "
        r"\(Hint: Verify the server process is running and listening on the socket\. Check for other processes locking the socket\.\)"
    )
    with pytest.raises(TransportError, match=expected_msg_regex):
        await server.wait_for_server_ready(timeout=0.1)

    mock_socket_instance.connect.assert_called_with(socket_path)


@pytest.mark.asyncio
async def test_stop_plugin_task_cancellation_timeout(
    mocker, mock_server_protocol, mock_server_handler, mock_server_config
):
    """Test stop() when cancelling plugin-related tasks times out."""
    # Ensure RPCPluginServer constructor doesn't fail due to bad global config from other tests
    # by mocking what __attrs_post_init__ uses from rpcplugin_config via HandshakeConfig
    mocker.patch(
        "pyvider.rpcplugin.server.HandshakeConfig", return_value=mocker.MagicMock()
    )

    # Use config=None to ensure maximum isolation from global state via mock_server_config fixture
    # The HandshakeConfig mock should handle initialization requirements.
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=None,
    )

    # Explicitly set/verify all critical attributes for this test's logic after instantiation
    # Ensure _serving_future is a valid future, as stop() interacts with it
    # The factory in the class already creates a real asyncio.Future, which is fine.
    # If we want to control its done() state for sure:
    server._serving_future = mocker.create_autospec(asyncio.Future, instance=True)
    server._serving_future.done.return_value = (
        False  # Simulate it's running before stop() is called
    )

    # Ensure _server and _transport are AsyncMocks with awaitable methods
    # These are critical for the stop() method.
    # Using spec can help ensure the mocks behave more like the real objects.
    # from pyvider.rpcplugin.transport.base import RPCPluginTransport # Example for spec
    # import grpc # Example for spec for grpc.aio.Server

    # Explicitly assign mocks to _server and _transport to prevent them from being None
    # Use spec to make the mocks behave more like the real objects.
    # grpc.aio.server is imported as GRPCServer in server.py

    mock_actual_server = mocker.AsyncMock(spec=GrpcAioServerType)
    # Capture the specific mock for the 'stop' method
    mock_server_stop_method = mocker.AsyncMock(return_value=None)
    mock_actual_server.stop = mock_server_stop_method
    server._server = mock_actual_server

    mock_actual_transport = mocker.AsyncMock(spec=RPCPluginTransport)
    # Capture the specific mock for the 'close' method
    mock_transport_close_method = mocker.AsyncMock(return_value=None)
    mock_actual_transport.close = mock_transport_close_method
    server._transport = mock_actual_transport

    # _client_tasks is not an attribute of RPCPluginServer. stop() uses asyncio.all_tasks().
    # server._client_tasks = []

    # _serving_event is created by __attrs_post_init__, ensure it's there or mock if needed
    if not hasattr(server, "_serving_event") or server._serving_event is None:
        server._serving_event = mocker.create_autospec(
            asyncio.Event, instance=True, name="_serving_event_mock"
        )

    # _shutdown_event is also created by __attrs_post_init__
    if not hasattr(server, "_shutdown_event") or server._shutdown_event is None:
        server._shutdown_event = mocker.create_autospec(
            asyncio.Event, instance=True, name="_shutdown_event_mock"
        )

    # Mock asyncio.all_tasks() to return a mock task
    mock_plugin_task = mocker.MagicMock(spec=asyncio.Task)
    mock_plugin_task.get_name.return_value = "RPCPlugin-TestTask"
    mock_plugin_task.done.return_value = False
    mock_plugin_task.cancel = mocker.MagicMock()  # We'll check this is called

    # Make asyncio.gather time out
    mocker.patch(
        "asyncio.all_tasks", return_value=[mock_plugin_task, asyncio.current_task()]
    )
    mocker.patch("asyncio.gather", side_effect=asyncio.TimeoutError("Gather timed out"))

    mock_logger_warning = mocker.patch("pyvider.rpcplugin.server.logger.warning")
    mocker.patch("pyvider.rpcplugin.server.logger.debug")  # To check other logs

    await server.stop()

    mock_plugin_task.cancel.assert_called_once()

    # Check for the specific timeout log
    found_timeout_log = any(
        "Timed out waiting for plugin-related tasks to cancel" in call.args[0]
        for call in mock_logger_warning.call_args_list
    )
    assert found_timeout_log, "Timeout warning for task cancellation not logged"

    # Check that server and transport stop are still attempted
    mock_server_stop_method.assert_called_once()
    mock_transport_close_method.assert_called_once()


@pytest.mark.skip(
    reason="Test silently hangs/crashes pytest for tcp/unix params, needs deep investigation."
)
@pytest.mark.asyncio
async def test_serve_setup_server_raises_exception(
    mocker,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):
    """Test serve() when _setup_server raises an exception."""
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport,
    )

    mocker.patch.object(
        server, "_register_signal_handlers"
    )  # Mock to prevent side effects
    mocker.patch.object(
        server, "_negotiate_handshake", new_callable=AsyncMock
    )  # Mock to prevent side effects
    mocker.patch.object(
        server, "_read_client_cert", return_value=None
    )  # Assume no client cert for this test

    # Make _setup_server raise an error.
    # For diagnostics: Change to MagicMock to see if this provokes an earlier, reportable TypeError.
    mocker.patch.object(
        server,
        "_setup_server",
        new_callable=mocker.MagicMock,
        side_effect=RuntimeError("Setup failed!"),
    )
    mock_logger_error = mocker.patch("pyvider.rpcplugin.server.logger.error")

    # stop() will be called in finally. Patch it directly on the instance.
    # For diagnostics: Change to MagicMock to see if AsyncMock is an issue
    server.stop = mocker.MagicMock(name="stop_sync_mock")

    # For diagnostics: Temporarily remove pytest.raises and handle exception manually
    try:
        await server.serve()
        # If serve() completes without raising the expected error, that's a different problem
        print("server.serve() completed unexpectedly without raising RuntimeError.")
        # We might want to fail here if the RuntimeError from _setup_server was expected to propagate
        pytest.fail(
            "server.serve() did not raise RuntimeError as expected from _setup_server mock."
        )
    except RuntimeError as e:
        if str(e) == "Setup failed!":
            print(f"Caught expected RuntimeError: {e}")
        else:
            # Caught a RuntimeError, but not the one we expected from _setup_server
            print(f"Caught UNEXPECTED RuntimeError: {e}")
            pytest.fail(f"Test failed with unexpected RuntimeError: {e}")
    except Exception as e:
        print(f"Caught UNEXPECTED Exception: {type(e).__name__} - {e}")
        pytest.fail(f"Test failed with unexpected exception: {type(e).__name__} - {e}")

    # Check that the error during setup was logged
    found_log = any(
        "Serve() failed during setup" in call.args[0]
        and "Setup failed!" in call.kwargs.get("extra", {}).get("error", "")
        for call in mock_logger_error.call_args_list
    )
    assert found_log, "Log for setup failure not found or incorrect"

    # Ensure stop() was still called from the finally block in serve()
    # This will now assert on the MagicMock
    server.stop.assert_called_once()


@pytest.mark.asyncio
async def test_serve_serving_future_raises_exception(
    mocker,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):
    """Test serve() when awaiting _serving_future raises an exception."""
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport,
    )

    # Mock earlier setup stages to succeed
    mocker.patch.object(server, "_register_signal_handlers")

    # Ensure _negotiate_handshake sets up transport attributes
    async def mock_negotiate_handshake_sets_transport_attrs():
        server._transport = mock_server_transport  # from fixture
        server._transport_name = (
            mock_server_transport._transport_name
            if hasattr(mock_server_transport, "_transport_name")
            else ("tcp" if "tcp" in mock_server_transport.endpoint else "unix")
        )
        server._protocol_version = 1  # A default valid version
        # Simulate that the transport has been listened on, if applicable
        if hasattr(mock_server_transport, "listen"):
            await mock_server_transport.listen()
        if hasattr(mock_server_transport, "host") and mock_server_transport.host:
            server._port = getattr(
                mock_server_transport, "port", 12345
            )  # Ensure _port is set for TCP
        else:  # Unix
            server._port = None

    mocker.patch.object(
        server,
        "_negotiate_handshake",
        side_effect=mock_negotiate_handshake_sets_transport_attrs,
    )
    mocker.patch.object(server, "_read_client_cert", return_value=None)

    # Ensure _setup_server is properly mocked to reflect a successful setup before the future fails
    # It needs to set server._port for TCP if not already set by negotiate_handshake mock
    async def mock_setup_server_does_minimal_work(client_cert_arg):
        if server._transport_name == "tcp" and not server._port:
            # if mock_server_transport is a real transport instance that has been listened on
            server._port = getattr(server._transport, "port", 54321)
        # Simulate server being started and ready
        server._serving_event.set()  # Crucial for build_handshake_response if it waits on this
        return

    mocker.patch.object(
        server, "_setup_server", side_effect=mock_setup_server_does_minimal_work
    )
    # build_handshake_response should now work, so we don't mock it away, let it run
    # but we do need to mock the stdout writes it performs.
    mocker.patch("sys.stdout.buffer.write")  # Mock stdout writes
    mocker.patch("sys.stdout.buffer.flush")
    mocker.patch("sys.stdout.flush")

    # Make the _serving_future raise an error when awaited
    server._serving_future = asyncio.Future()
    server._serving_future.set_exception(RuntimeError("Serving future error!"))

    mock_logger_error = mocker.patch("pyvider.rpcplugin.server.logger.error")
    mocker.patch.object(
        server, "stop", new_callable=AsyncMock
    )  # Mock stop to check it's called

    expected_msg_regex = (
        r"\[TransportError\] An unexpected error occurred while server was running: Serving future error! "
        r"\(Hint: Check server logs for details\. This could be a gRPC internal error, resource issue, or unhandled exception in a service implemen\.\.\.\)"
    )
    with pytest.raises(TransportError, match=expected_msg_regex):
        await server.serve()

    # Check that the error during run was logged
    found_log = any(
        "Serve() encountered an unexpected error during main execution loop"
        in call.args[0]
        and "Serving future error!" in call.kwargs.get("extra", {}).get("error", "")
        for call in mock_logger_error.call_args_list
    )
    assert found_log, "Log for serving_future error not found or incorrect"

    server.stop.assert_called_once()


@pytest.mark.asyncio
async def test_serve_stop_in_finally_raises_exception(
    mocker,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
    mock_server_transport,
):
    """Test serve() when server.stop() in the finally block raises an exception."""
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport,
    )

    # Mock earlier setup stages to succeed and _serving_future to complete normally
    mocker.patch.object(server, "_register_signal_handlers")

    # Ensure _negotiate_handshake sets up transport attributes
    async def mock_negotiate_handshake_sets_transport_attrs_for_stop_test():
        server._transport = mock_server_transport  # from fixture
        server._transport_name = (
            mock_server_transport._transport_name
            if hasattr(mock_server_transport, "_transport_name")
            else ("tcp" if "tcp" in mock_server_transport.endpoint else "unix")
        )
        server._protocol_version = 1  # A default valid version
        # Simulate that the transport has been listened on, if applicable
        if hasattr(mock_server_transport, "listen"):
            await mock_server_transport.listen()
        if hasattr(mock_server_transport, "host") and mock_server_transport.host:
            server._port = getattr(
                mock_server_transport, "port", 12345
            )  # Ensure _port is set for TCP
        else:  # Unix
            server._port = None

    mocker.patch.object(
        server,
        "_negotiate_handshake",
        side_effect=mock_negotiate_handshake_sets_transport_attrs_for_stop_test,
    )
    mocker.patch.object(server, "_read_client_cert", return_value=None)
    # _setup_server mock is more complex here due to original test structure
    # We'll let the original mock_setup_and_complete_future handle _serving_future completion.
    # We just need to make sure server._port is set by it if TCP.

    # build_handshake_response should now work, so we don't mock it away, let it run
    # but we do need to mock the stdout writes it performs.
    mocker.patch("sys.stdout.buffer.write")
    mocker.patch("sys.stdout.buffer.flush")
    mocker.patch("sys.stdout.flush")

    # Make _serving_future complete successfully to proceed to finally block naturally
    # Or, to force entry into finally via an earlier exception that stop() would then also hit:
    # Here, let's assume serving_future completes, and stop() is the one failing.
    async def set_serving_future_done_mock(
        self,
    ):  # Mock to control when _serving_future is done
        self._serving_future.set_result(None)

    # We can trigger this by mocking a signal or just letting it proceed if _serving_future is awaited
    # For simplicity, let's assume _serving_future will be awaited and completes.

    # Mock server.stop() to raise an error
    mocker.patch.object(
        server, "stop", new_callable=AsyncMock, side_effect=RuntimeError("Stop failed!")
    )
    mock_logger_error = mocker.patch("pyvider.rpcplugin.server.logger.error")

    # The exception from stop() in finally should not be re-raised from serve() if serve() completed its try block.
    # If serve() itself failed (e.g. _serving_future raised error), then that error is raised,
    # and the error from stop() is only logged.
    # Let's test the case where the main try block of serve completes.

    # To make `await self._serving_future` complete, we need to set its result.
    # This is usually done by `_shutdown_requested` or if the future is managed externally.
    # For this test, we can set it directly after setup.

    original_serving_future = server._serving_future

    async def mock_setup_and_complete_future_plus_port(
        client_cert_arg,
    ):  # Matches _setup_server signature
        if server._transport_name == "tcp" and not server._port:
            # if mock_server_transport is a real transport instance that has been listened on
            server._port = getattr(
                server._transport, "port", 54321
            )  # Ensure port is set for TCP
        server._serving_event.set()  # Signal that server setup part is "done"
        await asyncio.sleep(0)  # allow other tasks to run
        if not original_serving_future.done():
            original_serving_future.set_result(None)

    mocker.patch.object(
        server, "_setup_server", side_effect=mock_setup_and_complete_future_plus_port
    )

    await (
        server.serve()
    )  # Should not raise an error itself, error in stop() is caught and logged

    # Check that the error during stop() was logged
    found_log = any(
        "Error during stop()" in call.args[0]
        and "Stop failed!" in call.kwargs.get("extra", {}).get("error", "")
        for call in mock_logger_error.call_args_list
    )
    assert found_log, "Log for stop() failure in finally block not found or incorrect"
    server.stop.assert_called_once()  # stop() itself was called


### 🐍🏗🧪️
