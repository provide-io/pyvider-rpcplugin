
# tests/protocol/test_service_edge_cases.py

import asyncio
import pytest
from unittest.mock import MagicMock, patch

from pyvider.rpcplugin.protocol.service import (
    GRPCStdioService,
    GRPCBrokerService,
    SubchannelConnection,
    BrokerError,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from google.protobuf.empty_pb2 import Empty


# Definition for MockRequestIterator, needed by test_broker_exception_handling_line95
class MockRequestIterator:
    def __init__(self, requests) -> None:
        self.requests = requests
        self.index = 0

    def __aiter__(self) -> "MockRequestIterator":
        return self

    async def __anext__(self):
        if self.index < len(self.requests):
            request = self.requests[self.index]
            self.index += 1
            return request
        raise StopAsyncIteration


@pytest.mark.asyncio
async def test_broker_service_subchannel_open_failure() -> None:
    """Test broker service handling of subchannel open failure."""
    service = GRPCBrokerService()

    # Create a subchannel class that raises an exception on open
    class FailingSubchannel(SubchannelConnection):
        async def open(self):
            raise BrokerError("Failed to open subchannel")

    # Patch SubchannelConnection to return our failing version
    with patch('pyvider.rpcplugin.protocol.service.SubchannelConnection',
               return_value=FailingSubchannel(1, "localhost:12345")):

        # Create a knock request
        knock_request = ConnInfo(
            service_id=1,
            network="tcp",
            address="localhost:12345",
            knock=ConnInfo.Knock(knock=True, ack=False, error="")
        )

        # Mock iterator
        class MockIterator:
            def __init__(self, request):
                self.request = request
                self.yielded = False

            def __aiter__(self):
                return self

            async def __anext__(self):
                if not self.yielded:
                    self.yielded = True
                    return self.request
                raise StopAsyncIteration

        # Test the service
        context = MagicMock()
        responses = []
        async for response in service.StartStream(MockIterator(knock_request), context):
            responses.append(response)

        # Verify we got an error response
        assert len(responses) == 1
        assert not responses[0].knock.ack
        assert "Failed to open subchannel" in responses[0].knock.error

@pytest.mark.asyncio
async def test_stdio_service_timeouts() -> None:
    """Test StdioService handling of queue timeouts."""
    service = GRPCStdioService()
    context = MagicMock()

    # Mock queue.get to timeout then return a value then timeout again
    get_calls = 0

    async def mock_get():
        nonlocal get_calls
        get_calls += 1
        if get_calls == 1:
            # First call: timeout
            raise asyncio.TimeoutError()
        elif get_calls == 2:
            # Second call: return item
            return StdioData(channel=StdioData.STDOUT, data=b"test data")
        else:
            # Remaining calls: timeout
            raise asyncio.TimeoutError()

    # Patch the queue.get method
    service._message_queue.get = mock_get

    # We need a way to break out of the infinite loop in StreamStdio
    # Set up context.done() to return True after a few iterations
    done_event = asyncio.Event()

    def add_callback(callback):
        # Wait a bit then set done and call callback
        async def delayed_done():
            await asyncio.sleep(0.5)
            done_event.set()
            callback()
        asyncio.create_task(delayed_done())

    context.add_done_callback = add_callback
    context.done = lambda: done_event.is_set()

    # Create a short timeout for wait_for
    with patch('asyncio.wait_for', side_effect=lambda coro, timeout: coro):
        results = []
        async for item in service.StreamStdio(Empty(), context):
            results.append(item)
            if len(results) >= 1:
                break

        # Should have one item despite the timeouts
        assert len(results) == 1
        assert results[0].data == b"test data"

@pytest.mark.asyncio
async def test_stdio_service_backpressure() -> None:
    """Test StdioService handling of queue backpressure."""
    service = GRPCStdioService()

    # Fill the queue with some items
    for i in range(10):
        await service.put_line(f"test line {i}".encode())

    # Verify the queue has items
    assert service._message_queue.qsize() > 0

    # Consume some items
    items = []
    for _ in range(5):
        item = await service._message_queue.get()
        items.append(item)

    # Verify we consumed the expected items
    assert len(items) == 5
    for i, item in enumerate(items):
        assert item.data == f"test line {i}".encode()

from unittest.mock import AsyncMock # Ensure this is imported

@pytest.mark.asyncio
async def test_broker_exception_handling_line95() -> None:
    """Test exception handling in broker.StartStream when subchannel.open() fails."""
    broker = GRPCBrokerService()

    request = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error="")
    )
    
    # MockRequestIterator should already be defined in this file from a previous fix
    iterator = MockRequestIterator([request]) 
    context = MagicMock()

    # Patch SubchannelConnection.open for all instances created within this context
    # Make it an AsyncMock because it's an async method.
    with patch('pyvider.rpcplugin.protocol.service.SubchannelConnection.open', new_callable=AsyncMock) as mock_subchannel_open:
        mock_subchannel_open.side_effect = Exception("Test exception from open")

        responses = []
        async for response in broker.StartStream(iterator, context):
            responses.append(response)

    assert len(responses) == 1, "Should receive one error response"
    assert responses[0].knock.ack is False, "Acknowledgement should be False on error"
    assert "error" in responses[0].knock.error, "Error message should be present"
    # Check for part of the specific exception message
    assert "Test exception from open" in responses[0].knock.error, "Specific error message not found"

### 🐍🏗🧪️
