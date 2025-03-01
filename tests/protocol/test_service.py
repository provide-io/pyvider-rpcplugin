
# tests/protocol/test_service.py

import asyncio
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import grpc

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
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from google.protobuf.empty_pb2 import Empty

@pytest.fixture
def subchannel():
    """Fixture providing a SubchannelConnection instance."""
    return SubchannelConnection(conn_id=1, address="localhost:12345")

@pytest.mark.asyncio
async def test_subchannel_open(subchannel):
    """Test opening a subchannel connection."""
    assert not subchannel.is_open
    await subchannel.open()
    assert subchannel.is_open

@pytest.mark.asyncio
async def test_subchannel_close(subchannel):
    """Test closing a subchannel connection."""
    await subchannel.open()
    assert subchannel.is_open
    await subchannel.close()
    assert not subchannel.is_open

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

@pytest.fixture
def broker_service():
    """Fixture providing a GRPCBrokerService instance."""
    return GRPCBrokerService()

@pytest.fixture
def mock_context():
    """Mock gRPC context for broker."""
    context = MagicMock()
    context.add_done_callback = MagicMock()
    return context

@pytest.mark.asyncio
async def test_broker_start_stream_open_subchannel(broker_service, mock_context):
    """Test StartStream with a knock request."""
    # Create a request with knock=True
    knock_info = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error="")
    )
    
    # Create request iterator with single knock request
    request_iterator = MockRequestIterator([knock_info])
    
    # Collect responses
    responses = []
    async for response in broker_service.StartStream(request_iterator, mock_context):
        responses.append(response)
    
    # Verify response
    assert len(responses) == 1
    assert responses[0].service_id == 1
    assert responses[0].knock.ack == True
    assert responses[0].knock.error == ""
    
    # Verify subchannel was created
    assert 1 in broker_service._subchannels
    assert broker_service._subchannels[1].is_open

@pytest.mark.asyncio
async def test_broker_start_stream_close_subchannel(broker_service, mock_context):
    """Test StartStream with closing an existing subchannel."""
    # First create a subchannel
    subchan = SubchannelConnection(1, "localhost:12345")
    await subchan.open()
    broker_service._subchannels[1] = subchan
    
    # Create a request to close it (knock=False)
    close_info = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=False, ack=False, error="")
    )
    
    # Create request iterator with single close request
    request_iterator = MockRequestIterator([close_info])
    
    # Collect responses
    responses = []
    async for response in broker_service.StartStream(request_iterator, mock_context):
        responses.append(response)
    
    # Verify response
    assert len(responses) == 1
    assert responses[0].service_id == 1
    assert responses[0].knock.ack == True
    
    # Verify subchannel was removed
    assert 1 not in broker_service._subchannels

@pytest.mark.asyncio
async def test_broker_start_stream_exception(broker_service, mock_context):
    """Test StartStream with an exception during processing."""
    # Create a request that will cause an exception
    with patch.object(broker_service, '_subchannels', side_effect=Exception("Test exception")):
        knock_info = ConnInfo(
            service_id=1,
            network="tcp",
            address="localhost:12345",
            knock=ConnInfo.Knock(knock=True, ack=False, error="")
        )
        
        # Create request iterator with request that will cause exception
        request_iterator = MockRequestIterator([knock_info])
        
        # Collect responses
        responses = []
        async for response in broker_service.StartStream(request_iterator, mock_context):
            responses.append(response)
        
        # Verify error response
        assert len(responses) == 1
        assert responses[0].service_id == 0
        assert responses[0].knock.ack == False
        assert "error" in responses[0].knock.error

@pytest.fixture
def stdio_service():
    """Fixture providing a GRPCStdioService instance."""
    return GRPCStdioService()

@pytest.mark.asyncio
async def test_stdio_put_line(stdio_service):
    """Test putting a line into the stdio queue."""
    # Put a line into the queue
    test_data = b"test line"
    await stdio_service.put_line(test_data)
    
    # Verify it was put in the queue
    assert stdio_service._message_queue.qsize() == 1
    
    # Get the item from the queue and verify it
    item = await stdio_service._message_queue.get()
    assert item.channel == StdioData.STDOUT
    assert item.data == test_data

@pytest.mark.asyncio
async def test_stdio_put_line_stderr(stdio_service):
    """Test putting a stderr line into the stdio queue."""
    # Put a stderr line into the queue
    test_data = b"error line"
    await stdio_service.put_line(test_data, is_stderr=True)
    
    # Verify it was put in the queue with correct channel
    item = await stdio_service._message_queue.get()
    assert item.channel == StdioData.STDERR
    assert item.data == test_data

@pytest.mark.asyncio
async def test_stdio_put_line_error(stdio_service):
    """Test error handling in put_line."""
    # Patch the queue.put to raise an exception
    with patch.object(stdio_service._message_queue, 'put', side_effect=Exception("Queue error")):
        # This should not propagate the exception
        await stdio_service.put_line(b"test data")
        # Test passes if no exception was raised

@pytest.mark.asyncio
async def test_stdio_stream_stdio(stdio_service, mock_context):
    """Test StreamStdio method."""
    # Add data to the queue before starting stream
    test_data = b"test output"
    await stdio_service.put_line(test_data)
    
    # Create empty request
    request = Empty()
    
    # Start streaming in a task
    stream_task = asyncio.create_task(
        collect_stream_data(stdio_service.StreamStdio(request, mock_context))
    )
    
    # Allow some time for the stream to process
    await asyncio.sleep(0.1)
    
    # Add more data
    await stdio_service.put_line(b"more data")
    
    # Set shutdown flag to end the stream
    stdio_service.shutdown()
    
    # Wait for the stream to complete
    results = await stream_task
    
    # Verify results
    assert len(results) >= 1
    assert results[0].data == test_data

async def collect_stream_data(stream):
    """Helper to collect data from an async stream."""
    results = []
    async for item in stream:
        results.append(item)
    return results

@pytest.mark.skip
async def test_stdio_stream_timeout(stdio_service, mock_context):
    """Test StreamStdio with a timeout."""
    # Replace wait_for with a function that always times out
    async def timeout_wait_for(*args, **kwargs):
        raise asyncio.TimeoutError()
    
    with patch('asyncio.wait_for', timeout_wait_for):
        # Start streaming
        stream_task = asyncio.create_task(
            collect_stream_data(stdio_service.StreamStdio(Empty(), mock_context))
        )
        
        # Allow some time for the stream to process timeouts
        await asyncio.sleep(0.3)
        
        # End the stream
        stdio_service.shutdown()
        
        # Wait for the stream to complete
        results = await stream_task
        
        # Should have empty results due to timeouts
        assert len(results) == 0

@pytest.mark.asyncio
async def test_stdio_stream_cancellation(stdio_service, mock_context):
    """Test StreamStdio cancellation."""
    # Mock context.add_done_callback to trigger cancellation
    done_callback = None
    def add_callback(callback):
        nonlocal done_callback
        done_callback = callback
    mock_context.add_done_callback.side_effect = add_callback
    
    # Start streaming in a task
    stream_task = asyncio.create_task(
        collect_with_cancel(stdio_service.StreamStdio(Empty(), mock_context))
    )
    
    # Allow some time for the stream to start
    await asyncio.sleep(0.1)
    
    # Trigger the done callback to simulate cancellation
    if done_callback:
        done_callback()
    
    # Wait for the stream to complete
    try:
        await stream_task
    except asyncio.CancelledError:
        pass  # Expected

async def collect_with_cancel(stream):
    """Helper that will be cancelled."""
    results = []
    try:
        async for item in stream:
            results.append(item)
    except asyncio.CancelledError:
        # Re-raise to propagate to the test
        raise
    return results

@pytest.fixture
def shutdown_event():
    """Fixture providing an asyncio Event for shutdown testing."""
    return asyncio.Event()

@pytest.fixture
def controller_service(shutdown_event, stdio_service):
    """Fixture providing a GRPCControllerService instance."""
    return GRPCControllerService(shutdown_event, stdio_service)

@pytest.mark.asyncio
async def test_controller_shutdown(controller_service, mock_context, shutdown_event):
    """Test the Shutdown method."""
    # Patch the _delayed_shutdown method to prevent actual process termination
    with patch.object(controller_service, '_delayed_shutdown', new_callable=AsyncMock):
        # Call Shutdown
        response = await controller_service.Shutdown(ControllerEmpty(), mock_context)
        
        # Verify shutdown event was set
        assert shutdown_event.is_set()
        
        # Verify stdio service was shutdown
        assert controller_service._stdio_service._shutdown == True
        
        # Verify _delayed_shutdown was called
        controller_service._delayed_shutdown.assert_called_once()
        
        # Verify response is an Empty
        assert isinstance(response, ControllerEmpty)

@pytest.mark.asyncio
async def test_controller_delayed_shutdown(controller_service):
    """Test the _delayed_shutdown method."""
    # Patch sleep to avoid actually waiting
    with patch('asyncio.sleep', new_callable=AsyncMock):
        # Patch os.kill to avoid termination
        with patch('os.kill'):
            with patch('os.getpid', return_value=12345):
                await controller_service._delayed_shutdown()
                # If we get here without error, the test passes

@pytest.mark.asyncio
async def test_controller_delayed_shutdown_fallback(controller_service):
    """Test the _delayed_shutdown fallback path."""
    # Patch sleep to avoid actually waiting
    with patch('asyncio.sleep', new_callable=AsyncMock):
        # Patch hasattr to force the fallback path
        original_hasattr = hasattr
        def mock_hasattr(obj, name):
            if name == 'kill' and obj == os:
                return False
            return original_hasattr(obj, name)
        
        with patch('builtins.hasattr', mock_hasattr):
            # Patch sys.exit to avoid actual exit
            with patch('sys.exit'):
                await controller_service._delayed_shutdown()
                # If we get here without error, the test passes
