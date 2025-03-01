
# tests/protocol/test_service_improvements.py

import asyncio
import pytest
import pytest_asyncio
import os
import signal
import sys
from unittest.mock import AsyncMock, MagicMock, patch

from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService,
    register_protocol_service,
    SubchannelConnection,
)
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from google.protobuf.empty_pb2 import Empty


@pytest.mark.asyncio
async def test_stdio_put_line_exception_handling():
    """Test error handling in stdio put_line method (line 123-128)."""
    stdio_service = GRPCStdioService()

    # Mock _message_queue.put to raise an exception
    original_put = stdio_service._message_queue.put

    async def mock_put(*args, **kwargs):
        raise Exception("Mock queue error")

    stdio_service._message_queue.put = mock_put

    try:
        # This should not raise an exception
        await stdio_service.put_line(b"test data")
        # If we get here, the exception was handled correctly
        assert True
    finally:
        # Restore original method
        stdio_service._message_queue.put = original_put


@pytest.mark.asyncio
async def test_broker_service_start_stream_error_handling():
    """Test broker StartStream exception handling (line 95)."""
    broker_service = GRPCBrokerService()

    # Create a request that will trigger the error branch
    knock_request = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error="")
    )

    # Create a mock iterator that yields the request
    class MockRequestIterator:
        def __init__(self):
            self.yielded = False

        def __aiter__(self):
            return self

        async def __anext__(self):
            if not self.yielded:
                self.yielded = True
                return knock_request
            raise StopAsyncIteration

    # Mock context
    context = MagicMock()

    # Patch the broker's _subchannels to raise an exception when accessed
    with patch.object(broker_service, '_subchannels',
                     side_effect=Exception("Mock exception in _subchannels")):
        # Collect responses
        responses = []
        async for response in broker_service.StartStream(MockRequestIterator(), context):
            responses.append(response)

        # Should have one error response
        assert len(responses) == 1
        assert responses[0].knock.ack == False
        assert "error" in responses[0].knock.error


@pytest.mark.asyncio
async def test_controller_delayed_shutdown_unix():
    """Test controller _delayed_shutdown on Unix systems (line 211-216)."""
    stdio_service = GRPCStdioService()
    shutdown_event = asyncio.Event()
    controller = GRPCControllerService(shutdown_event, stdio_service)

    # Patch os.kill to prevent actual process termination
    with patch('asyncio.sleep', return_value=None), \
         patch('os.kill') as mock_kill, \
         patch('os.getpid', return_value=12345):

        # Call _delayed_shutdown
        await controller._delayed_shutdown()

        # Verify os.kill was called
        mock_kill.assert_called_once_with(12345, signal.SIGTERM)


@pytest.mark.asyncio
async def test_controller_delayed_shutdown_windows():
    """Test controller _delayed_shutdown on Windows (line 211-216)."""
    stdio_service = GRPCStdioService()
    shutdown_event = asyncio.Event()
    controller = GRPCControllerService(shutdown_event, stdio_service)

    # Patch to simulate Windows environment (no os.kill)
    with patch('asyncio.sleep', return_value=None), \
         patch('os.kill', side_effect=AttributeError("'module' object has no attribute 'kill'")), \
         patch('sys.exit') as mock_exit:

        # Call _delayed_shutdown
        await controller._delayed_shutdown()

        # Verify sys.exit was called
        mock_exit.assert_called_once_with(0)

### 🐍🏗🧪️

class MockIterator:
    """Mock async iterator for broker StartStream testing."""
    def __init__(self, items=None, exception=None):
        self.items = items or []
        self.exception = exception
        self.index = 0
    
    def __aiter__(self):
        return self
    
    async def __anext__(self):
        if self.exception:
            raise self.exception
        
        if self.index < len(self.items):
            item = self.items[self.index]
            self.index += 1
            return item
        raise StopAsyncIteration

@pytest.mark.asyncio
async def test_broker_start_stream_exception_line95():
    """Direct test for service.py line 95 - exception in StartStream."""
    broker_service = GRPCBrokerService()
    
    # Create a request that raises an exception when processed
    knock_request = ConnInfo(
        service_id=1,
        network="tcp", 
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error="")
    )
    
    # Create an iterator that yields that request
    request_iterator = MockIterator([knock_request])
    
    # Mock context
    context = MagicMock()
    
    # Patch broker service to raise exception when processing request
    with patch.object(broker_service, '_subchannels', 
                     new_callable=MagicMock,
                     side_effect=Exception("Test exception at line 95")):
        
        # Process the stream
        responses = []
        async for response in broker_service.StartStream(request_iterator, context):
            responses.append(response)
        
        # Verify response
        assert len(responses) == 1
        assert responses[0].knock.ack is False
        assert "Test exception at line 95" in responses[0].knock.error

@pytest.mark.asyncio
async def test_stdio_put_line_exception_line123():
    """Direct test for service.py lines 123-128 - exception in put_line."""
    stdio_service = GRPCStdioService()
    
    # Patch message_queue.put to raise exception
    original_put = stdio_service._message_queue.put
    
    async def failing_put(*args, **kwargs):
        raise Exception("Test exception at line 123-128")
    
    stdio_service._message_queue.put = failing_put
    
    # Call put_line which should catch the exception
    try:
        await stdio_service.put_line(b"test data")
        # If we get here, exception was properly handled
        assert True
    finally:
        # Restore original method
        stdio_service._message_queue.put = original_put

@pytest.mark.asyncio
async def test_controller_delayed_shutdown_unix_path():
    """Direct test for service.py lines 212-216 - unix path in _delayed_shutdown."""
    stdio_service = GRPCStdioService()
    shutdown_event = asyncio.Event()
    controller_service = GRPCControllerService(shutdown_event, stdio_service)
    
    # Patch sleep to avoid delay
    with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
        # Patch os.kill and os.getpid to prevent actual termination
        with patch('os.kill') as mock_kill, \
             patch('os.getpid', return_value=12345):
            
            # Call _delayed_shutdown - Unix path
            await controller_service._delayed_shutdown()
            
            # Verify sleep was called
            mock_sleep.assert_called_once()
            
            # Verify kill was called with right signal
            mock_kill.assert_called_once_with(12345, signal.SIGTERM)

@pytest.mark.asyncio
async def test_controller_delayed_shutdown_windows_path():
    """Direct test for service.py lines 212-216 - Windows path in _delayed_shutdown."""
    stdio_service = GRPCStdioService()
    shutdown_event = asyncio.Event()
    controller_service = GRPCControllerService(shutdown_event, stdio_service)
    
    # Patch sleep to avoid delay
    with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
        # Patch os.kill to simulate missing on Windows and sys.exit to prevent actual exit
        with patch('os.kill', side_effect=AttributeError("'module' object has no attribute 'kill'")), \
             patch('sys.exit') as mock_exit:
            
            # Call _delayed_shutdown - Windows fallback path
            await controller_service._delayed_shutdown()
            
            # Verify sleep was called
            mock_sleep.assert_called_once()
            
            # Verify sys.exit was called
            mock_exit.assert_called_once_with(0)