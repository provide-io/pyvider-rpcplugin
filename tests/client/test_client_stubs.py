#
# SPDX-FileCopyrightText: Copyright (c) provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""TODO: Add module docstring."""

import pytest
import asyncio
import grpc
from provide.testkit.mocking import (
    patch,
    MagicMock,
    AsyncMock,
    ANY,
)

from pyvider.rpcplugin.exception import (
    ProtocolError,
    TransportError,
)  # Added TransportError

# Attempt to import StdioData and Empty, but don't fail if not found during this subtask
from typing import Any # Added for StdioData typing
try:
    from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData as ImportedStdioData
    StdioData: Any | None = ImportedStdioData # Allow StdioData to be None or the class type
except ImportError:
    StdioData = None

try:
    from google.protobuf import empty_pb2
except ImportError:
    empty_pb2 = None  # type: ignore[assignment] # Will omit argument assertion if not found


@pytest.mark.asyncio
async def test_init_stubs(client_instance):
    """Test initialization of gRPC stubs."""
    # Setup
    client_instance.grpc_channel = MagicMock()

    # Mock all stub classes
    with (
        patch("pyvider.rpcplugin.client.process.GRPCStdioStub") as mock_stdio_stub_class,
        patch("pyvider.rpcplugin.client.process.GRPCBrokerStub") as mock_broker_stub_class,
        patch(
            "pyvider.rpcplugin.client.process.GRPCControllerStub"
        ) as mock_controller_stub_class,
    ):
        mock_stdio_stub = MagicMock()
        mock_broker_stub = MagicMock()
        mock_controller_stub = MagicMock()

        mock_stdio_stub_class.return_value = mock_stdio_stub
        mock_broker_stub_class.return_value = mock_broker_stub
        mock_controller_stub_class.return_value = mock_controller_stub

        # Initialize stubs
        client_instance._init_stubs()

        # Verify stubs were initialized with the channel
        mock_stdio_stub_class.assert_called_once_with(client_instance.grpc_channel)
        mock_broker_stub_class.assert_called_once_with(client_instance.grpc_channel)
        mock_controller_stub_class.assert_called_once_with(client_instance.grpc_channel)

        # Verify stubs were assigned
        assert client_instance._stdio_stub == mock_stdio_stub
        assert client_instance._broker_stub == mock_broker_stub
        assert client_instance._controller_stub == mock_controller_stub


@pytest.mark.asyncio
async def test_init_stubs_no_channel(client_instance):
    """Test _init_stubs with no channel available."""
    client_instance.grpc_channel = None

    with pytest.raises(
        ProtocolError,
        match="Cannot initialize gRPC stubs; gRPC channel is not available.",
    ):
        client_instance._init_stubs()


@pytest.mark.asyncio
async def test_read_stdio_logs(client_instance):
    """Test reading logs from stdio stub."""
    # Setup
    mock_stdio_stub_instance = AsyncMock()  # Use AsyncMock for the stub
    client_instance._stdio_stub = mock_stdio_stub_instance

    # Prepare mock data to be yielded by the async generator
    mock_chunk_stdout = MagicMock()
    # Use StdioData.STDOUT if available, otherwise fallback to integer
    mock_chunk_stdout.channel = StdioData.STDOUT if StdioData else 1
    mock_chunk_stdout.data = b"stdout log message"

    mock_chunk_stderr = MagicMock()
    # Use StdioData.STDERR if available, otherwise fallback to integer
    mock_chunk_stderr.channel = StdioData.STDERR if StdioData else 2
    mock_chunk_stderr.data = b"stderr log message"

    mock_stream_data = [mock_chunk_stdout, mock_chunk_stderr]

    # Define an async generator function
    async def mock_async_generator(*args, **kwargs):
        for item in mock_stream_data:
            yield item
        # The original method's loop will terminate when this generator is exhausted.

    # Set the StreamStdio method of the mock stub to return the generator
    # Explicitly make StreamStdio a MagicMock, not an AsyncMock, because the gRPC stub method
    # itself is synchronous and returns an async_generator.
    mock_stdio_stub_instance.StreamStdio = MagicMock(
        return_value=mock_async_generator()
    )

    # Call the method under test
    await client_instance._read_stdio_logs()

    # Verify that StreamStdio was called
    mock_stdio_stub_instance.StreamStdio.assert_called_once()
    if empty_pb2:  # Only assert with argument if Empty was successfully imported
        mock_stdio_stub_instance.StreamStdio.assert_called_once_with(empty_pb2.Empty())


@pytest.mark.asyncio
async def test_read_stdio_logs_no_stub(client_instance):
    """Test _read_stdio_logs with no stub available."""
    client_instance._stdio_stub = None

    # Should return without error
    await client_instance._read_stdio_logs()


@pytest.mark.asyncio
async def test_open_broker_subchannel(client_instance):
    """Test opening a broker subchannel."""
    # Setup
    mock_broker_stub_instance = AsyncMock()
    client_instance._broker_stub = mock_broker_stub_instance

    # Mock the StartStream call object (the bidirectional stream)
    mock_stream = AsyncMock()

    # Set up the stream methods
    mock_stream.write = AsyncMock()
    mock_stream.done_writing = AsyncMock()

    # Mock the response for read()
    response_message = MagicMock()
    response_message.service_id = 123
    response_message.knock.ack = True
    response_message.knock.error = ""
    mock_stream.read = AsyncMock(return_value=response_message)

    # Configure StartStream to return the mock stream
    mock_broker_stub_instance.StartStream = MagicMock(return_value=mock_stream)

    # Open subchannel
    await client_instance.open_broker_subchannel(123, "127.0.0.1:8001")

    # Verify the stream methods were called
    mock_broker_stub_instance.StartStream.assert_called_once()
    mock_stream.write.assert_called_once()
    mock_stream.read.assert_called_once()
    mock_stream.done_writing.assert_called_once()


@pytest.mark.asyncio
async def test_shutdown_plugin(client_instance):
    """Test shutting down the plugin via controller stub."""
    # Setup
    mock_controller_stub = MagicMock()
    client_instance._controller_stub = mock_controller_stub

    # Mock Shutdown
    mock_controller_stub.Shutdown = AsyncMock()

    # Shutdown plugin
    await client_instance.shutdown_plugin()

    # Verify controller stub was used
    mock_controller_stub.Shutdown.assert_called_once_with(ANY)


@pytest.mark.asyncio
async def test_open_broker_subchannel_no_stub(client_instance):  # Removed capsys
    """Test open_broker_subchannel when _broker_stub is None."""
    client_instance._broker_stub = None  # Ensure stub is None

    from io import StringIO

    with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
        # Should log a warning and return without error
        await client_instance.open_broker_subchannel(123, "127.0.0.1:8001")
        mock_stderr.getvalue()

    assert client_instance._broker_task is None  # No task should be created


@pytest.mark.asyncio
async def test_read_stdio_logs_stream_exception(client_instance, mocker):
    """Test _read_stdio_logs when the stdio stream raises an exception."""
    mock_stdio_stub_instance = AsyncMock()
    client_instance._stdio_stub = mock_stdio_stub_instance

    # Define an async generator function that raises an error
    async def mock_stream_generator_with_error(*args, **kwargs):
        yield MagicMock(channel=1, data=b"some initial log")
        await asyncio.sleep(0.001)  # Ensure it's a generator
        # Create a proper mock RpcError that derives from Exception and has code() method
        class MockRpcError(Exception):
            def code(self):
                return grpc.StatusCode.INTERNAL

        raise MockRpcError("Simulated RPC error in stream")

    mock_stdio_stub_instance.StreamStdio = MagicMock(
        return_value=mock_stream_generator_with_error()
    )

    # The method should catch the exception and log it, then exit gracefully.
    await client_instance._read_stdio_logs()

    # Verify the stream was called and the method completed without raising
    mock_stdio_stub_instance.StreamStdio.assert_called_once()


@pytest.mark.asyncio
async def test_open_broker_subchannel_knock_ack_false(client_instance, mocker):
    """Test open_broker_subchannel when server replies with knock.ack = False."""
    mock_broker_stub_instance = AsyncMock()
    client_instance._broker_stub = mock_broker_stub_instance

    # Mock the StartStream call object (the bidirectional stream)
    mock_stream = AsyncMock()

    # Set up the stream methods
    mock_stream.write = AsyncMock()
    mock_stream.done_writing = AsyncMock()

    # Mock the response for read() with ack = False
    response_message = MagicMock()
    response_message.service_id = 456
    response_message.knock.ack = False
    response_message.knock.error = "Failed to establish subchannel"
    mock_stream.read = AsyncMock(return_value=response_message)

    # Configure StartStream to return the mock stream
    mock_broker_stub_instance.StartStream = MagicMock(return_value=mock_stream)

    await client_instance.open_broker_subchannel(456, "127.0.0.1:8002")

    # Verify the stream methods were called
    mock_broker_stub_instance.StartStream.assert_called_once()
    mock_stream.write.assert_called_once()
    mock_stream.read.assert_called_once()
    mock_stream.done_writing.assert_called_once()

    # The method completed without raising, even though ack was False


@pytest.mark.asyncio
async def test_shutdown_plugin_rpc_error(client_instance, mocker):
    """Test shutdown_plugin when the RPC call to controller.Shutdown fails."""
    mock_controller_stub = AsyncMock()
    client_instance._controller_stub = mock_controller_stub

    # Create a proper mock RpcError with code() method
    original_rpc_error = MagicMock()
    original_rpc_error.code = MagicMock(return_value=grpc.StatusCode.INTERNAL)
    # Configure the Shutdown method of the AsyncMock instance
    mock_controller_stub.Shutdown = AsyncMock(side_effect=original_rpc_error)

    mock_logger_error = mocker.patch("pyvider.rpcplugin.client.core.logger.error")

    # The shutdown_plugin method catches grpc.RpcError and logs it, then continues normally
    # It doesn't raise TransportError - it just logs a debug message
    await client_instance.shutdown_plugin()

    # Assertions about logging and mock calls
    mock_controller_stub.Shutdown.assert_called_once()  # Verify Shutdown was called
    # The RpcError is logged as debug, not error, so no logger.error call expected
    mock_logger_error.assert_not_called()

# 🐍🔌📞🔚
