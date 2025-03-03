# tests/protocol/test_service_advanced.py

import asyncio
import signal
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from pyvider.rpcplugin.protocol.service import (
    BrokerError,
    SubchannelConnection,
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService,
    register_protocol_service,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from google.protobuf.empty_pb2 import Empty


@pytest.fixture
def stdio_service_with_error():
    """Fixture providing a GRPCStdioService that raises errors on queue operations."""
    service = GRPCStdioService()

    # Mock the message queue to raise exceptions
    service._message_queue = MagicMock()
    service._message_queue.put = AsyncMock(side_effect=Exception("Queue error"))
    service._message_queue.get = AsyncMock(side_effect=Exception("Queue get error"))

    return service


@pytest.mark.asyncio
async def test_stdio_error_handling_in_put_line(stdio_service_with_error):
    """Test that put_line gracefully handles exceptions."""
    # This should not raise an exception even though queue.put will fail
    await stdio_service_with_error.put_line(b"test data")

    # Verify put was called
    stdio_service_with_error._message_queue.put.assert_called_once()


@pytest.mark.asyncio
async def test_stdio_stream_error_handling():
    """Test that StreamStdio handles errors in the queue."""
    service = GRPCStdioService()

    # Mock context
    context = MagicMock()
    context.add_done_callback = MagicMock()

    # Create a mock queue that raises an exception after one successful get
    queue = asyncio.Queue()
    await queue.put(StdioData(channel=StdioData.STDOUT, data=b"test data"))

    original_get = queue.get
    get_called = False

    async def mock_get():
        nonlocal get_called
        if not get_called:
            get_called = True
            return await original_get()
        raise Exception("Queue error")

    queue.get = mock_get
    service._message_queue = queue

    # Start streaming
    results = []
    async for item in service.StreamStdio(Empty(), context):
        results.append(item)
        # Force shutdown after first item to avoid infinite loop
        service.shutdown()

    # Should have one item before error occurred
    assert len(results) == 1
    assert results[0].data == b"test data"


@pytest.mark.asyncio
async def test_stdio_stream_cancellation_handling():
    """Test handling of cancellation during StreamStdio."""
    service = GRPCStdioService()

    # Mock context
    context = MagicMock()

    # Capture the callback
    callback = None
    def add_done_callback(cb):
        nonlocal callback
        callback = cb
    context.add_done_callback.side_effect = add_done_callback

    # Start the stream in a task
    stream_task = asyncio.create_task(collect_stream(service.StreamStdio(Empty(), context)))

    # Wait a bit for the stream to start
    await asyncio.sleep(0.1)

    # Add some data
    await service.put_line(b"test data")

    # Trigger the callback to simulate cancellation
    if callback:
        callback()

    # Wait for the task to complete
    await asyncio.wait_for(stream_task, timeout=1.0)


async def collect_stream(stream):
    """Helper to collect stream items."""
    items = []
    try:
        async for item in stream:
            items.append(item)
    except asyncio.CancelledError:
        pass
    return items


@pytest.mark.asyncio
async def test_broker_service_exception_handling():
    """Test that StartStream properly handles exceptions."""
    service = GRPCBrokerService()

    # Create a subchannel that raises an exception
    mock_subchannel = MagicMock(spec=SubchannelConnection)
    mock_subchannel.open = AsyncMock(side_effect=BrokerError("Failed to open subchannel"))

    # Add the subchannel to the service
    service._subchannels = {}

    # Create a request that will try to use this subchannel
    knock_info = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error="")
    )

    # Mock the subchannel creation to return our problematic subchannel
    original_subchannel = SubchannelConnection

    class MockSubchannelConnection:
        def __init__(self, conn_id, address):
            self.conn_id = conn_id
            self.address = address
            self.is_open = False

        async def open(self):
            raise BrokerError("Failed to open subchannel")

        async def close(self):
            pass

    # Patch SubchannelConnection
    with patch('pyvider.rpcplugin.protocol.service.SubchannelConnection', MockSubchannelConnection):
        # Create request iterator
        request_iterator = MockRequestIterator([knock_info])

        # Collect responses
        responses = []
        context = MagicMock()
        async for response in service.StartStream(request_iterator, context):
            responses.append(response)

        # Check for error response
        assert len(responses) == 1
        assert responses[0].knock.ack == False
        assert "Failed to open subchannel" in responses[0].knock.error or "Broker error" in responses[0].knock.error


class MockRequestIterator:
    """Mock request iterator for broker stream."""
    def __init__(self, requests):
        self.requests = requests
        self.index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.index < len(self.requests):
            request = self.requests[self.index]
            self.index += 1
            return request
        raise StopAsyncIteration


@pytest.mark.asyncio
async def test_controller_delayed_shutdown_signal_handlers():
    """Test _delayed_shutdown with various signal handler implementations."""
    stdio_service = GRPCStdioService()
    shutdown_event = asyncio.Event()
    controller = GRPCControllerService(shutdown_event, stdio_service)

    # 1. Test Unix-style signal handling
    with patch('asyncio.sleep', new_callable=AsyncMock), \
         patch('os.kill') as mock_kill, \
         patch('os.getpid', return_value=12345):

        await controller._delayed_shutdown()
        mock_kill.assert_called_once_with(12345, signal.SIGTERM)

    # 2. Test Windows-style sys.exit fallback (no os.kill)
    with patch('asyncio.sleep', new_callable=AsyncMock), \
         patch('os.kill', side_effect=AttributeError("'module' object has no attribute 'kill'")), \
         patch('sys.exit') as mock_exit:

        await controller._delayed_shutdown()
        mock_exit.assert_called_once_with(0)


@pytest.mark.asyncio
async def test_register_protocol_service_with_mocks():
    """Test registering all services with detailed verification."""
    # Mock the services and their add_*_to_server functions
    with patch('pyvider.rpcplugin.protocol.service.GRPCStdioService') as mock_stdio_cls, \
         patch('pyvider.rpcplugin.protocol.service.GRPCBrokerService') as mock_broker_cls, \
         patch('pyvider.rpcplugin.protocol.service.GRPCControllerService') as mock_controller_cls, \
         patch('pyvider.rpcplugin.protocol.service.add_GRPCStdioServicer_to_server') as mock_add_stdio, \
         patch('pyvider.rpcplugin.protocol.service.add_GRPCBrokerServicer_to_server') as mock_add_broker, \
         patch('pyvider.rpcplugin.protocol.service.add_GRPCControllerServicer_to_server') as mock_add_controller:

        # Setup the mocks
        mock_stdio = MagicMock()
        mock_broker = MagicMock()
        mock_controller = MagicMock()

        mock_stdio_cls.return_value = mock_stdio
        mock_broker_cls.return_value = mock_broker
        mock_controller_cls.return_value = mock_controller

        # Mock server
        mock_server = MagicMock()

        # Mock shutdown event
        mock_shutdown_event = MagicMock(spec=asyncio.Event)

        # Call register_protocol_service
        register_protocol_service(mock_server, mock_shutdown_event)

        # Verify service instantiation
        mock_stdio_cls.assert_called_once()
        mock_broker_cls.assert_called_once()
        mock_controller_cls.assert_called_once_with(mock_shutdown_event, mock_stdio)

        # Verify services were added to server
        mock_add_stdio.assert_called_once_with(mock_stdio, mock_server)
        mock_add_broker.assert_called_once_with(mock_broker, mock_server)
        mock_add_controller.assert_called_once_with(mock_controller, mock_server)

### 🐍🏗🧪️
