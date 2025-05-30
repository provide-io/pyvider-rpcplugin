# tests/protocol/test_service_edge_cases.py
#
# Copyright (C) 2024 - All Rights Reserved
#
# This file is part of the PyVider RPCPlugin project.
#
# Any unauthorized use, reproduction, or distribution of this software
# is strictly prohibited without the express written permission of the copyright holder.
#

import asyncio
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

from pyvider.rpcplugin.protocol.service import (
    GRPCStdioService,
    GRPCBrokerService,
    SubchannelConnection,
    BrokerError,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from google.protobuf.empty_pb2 import Empty
from pyvider.telemetry import logger # Added for potential future use, good practice


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
    # This needs to be a class, not an instance for the patch to work as intended
    class FailingSubchannel(SubchannelConnection):
        # Make sure constructor matches base or is not needed if only `open` is called
        def __init__(self, service_id, address): # Add constructor
            super().__init__(service_id, address) # Call super

        async def open(self): # This is the method we care about
            logger.debug("FailingSubchannel.open called, raising BrokerError")
            raise BrokerError("Failed to open subchannel")

    # Patch SubchannelConnection to return our failing version
    # We need to patch the class itself, or where it's instantiated.
    # If SubchannelConnection is instantiated inside StartStream, this patch is tricky.
    # Let's assume it's instantiated with service_id and address.
    # A better approach might be to patch 'SubchannelConnection' and make its .open an AsyncMock
    
    # Simpler: Patch the 'open' method of instances of SubchannelConnection
    # For this specific test, we want any attempt to open a subchannel to fail.
    with patch('pyvider.rpcplugin.protocol.service.SubchannelConnection.open', new_callable=AsyncMock) as mock_open:
        mock_open.side_effect = BrokerError("Failed to open subchannel")

        knock_request = ConnInfo(
            service_id=1,
            network="tcp",
            address="localhost:12345", # This address will be passed to SubchannelConnection
            knock=ConnInfo.Knock(knock=True, ack=False, error="")
        )

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

        context = MagicMock()
        responses = []
        # The service will try to create a SubchannelConnection and call open() on it.
        async for response in service.StartStream(MockIterator(knock_request), context):
            responses.append(response)

        assert len(responses) == 1
        assert not responses[0].knock.ack
        assert "Failed to open subchannel" in responses[0].knock.error
        mock_open.assert_called_once() # Verify that open was indeed called


async def mock_wait_for_actually_awaits(coro, timeout):
    """
    Mock for asyncio.wait_for that actually awaits the coroutine.
    This simulates the behavior of asyncio.wait_for when it doesn't time out,
    which is useful when the test's goal is to bypass the timeout logic
    and test the coroutine's behavior directly.
    """
    logger.debug(f"mock_wait_for_actually_awaits called with coro: {coro}, timeout: {timeout}")
    return await coro


@pytest.mark.asyncio
async def test_stdio_service_timeouts() -> None:
    """Test StdioService handling of queue timeouts."""
    service = GRPCStdioService()
    context = MagicMock()

    get_calls = 0

    async def mock_get():
        nonlocal get_calls
        get_calls += 1
        logger.debug(f"mock_get called, call count: {get_calls}")
        if get_calls == 1:
            logger.debug("mock_get: raising asyncio.TimeoutError (call 1)")
            raise asyncio.TimeoutError()
        elif get_calls == 2:
            item = StdioData(channel=StdioData.STDOUT, data=b"test data")
            logger.debug(f"mock_get: returning item '{item}' (call 2)")
            return item
        else:
            logger.debug("mock_get: raising asyncio.TimeoutError (call > 2)")
            # To ensure the test can eventually terminate if logic changes,
            # we might want to stop raising TimeoutError after a few calls
            # or rely on the context.done() mechanism.
            # For this test, the original logic implies it expects to break after one item.
            raise asyncio.TimeoutError()

    service._message_queue.get = mock_get # Patching the instance's method

    done_event = asyncio.Event()

    def add_callback(callback):
        logger.debug("add_done_callback: scheduling done_event.set() and callback")
        async def delayed_done():
            await asyncio.sleep(0.1) # Reduced sleep, should be enough for a few queue reads
            logger.debug("delayed_done: setting done_event and calling callback")
            done_event.set()
            if callable(callback): # Ensure callback is callable
                 callback()
            else:
                logger.warning("add_done_callback: provided callback is not callable.")

        asyncio.create_task(delayed_done())

    context.add_done_callback = add_callback
    # Ensure context.done is a callable that returns the state of done_event
    context.done = lambda: done_event.is_set()
    context.is_active = lambda: not done_event.is_set() # Common check in gRPC

    # Use the new mock for asyncio.wait_for
    with patch('asyncio.wait_for', new=mock_wait_for_actually_awaits):
        results = []
        try:
            async for item in service.StreamStdio(Empty(), context):
                logger.debug(f"StreamStdio received item: {item}")
                results.append(item)
                if len(results) >= 1: # Test expects to break after one item
                    logger.debug("StreamStdio: received 1 item, breaking loop.")
                    break
        except Exception as e:
            logger.error(f"Error during StreamStdio iteration: {e}")
            raise

        logger.debug(f"StreamStdio loop finished. Results: {results}")
        assert len(results) == 1
        assert results[0].data == b"test data"
        # Verify that get was called at least twice (timeout, then data)
        assert get_calls >= 2, f"Expected at least 2 calls to queue.get, got {get_calls}"


@pytest.mark.asyncio
async def test_stdio_service_backpressure() -> None:
    """Test StdioService handling of queue backpressure."""
    service = GRPCStdioService()

    # Fill the queue with some items
    for i in range(10):
        await service.put_line(f"test line {i}".encode())

    # Verify the queue has items
    assert service._message_queue.qsize() == 10 # Exact check

    # Consume some items
    items = []
    for _ in range(5):
        item = await service._message_queue.get() # Directly get from queue for this test
        items.append(item)

    # Verify we consumed the expected items
    assert len(items) == 5
    for i, item in enumerate(items):
        assert item.data == f"test line {i}".encode()
    
    assert service._message_queue.qsize() == 5 # Check remaining size


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
    
    iterator = MockRequestIterator([request]) 
    context = MagicMock()

    with patch('pyvider.rpcplugin.protocol.service.SubchannelConnection.open', new_callable=AsyncMock) as mock_subchannel_open:
        mock_subchannel_open.side_effect = Exception("Test exception from open")

        responses = []
        async for response in broker.StartStream(iterator, context):
            responses.append(response)

    assert len(responses) == 1, "Should receive one error response"
    assert responses[0].knock.ack is False, "Acknowledgement should be False on error"
    assert "error" in responses[0].knock.error, "Error message should be present"
    assert "Test exception from open" in responses[0].knock.error, "Specific error message not found"
    mock_subchannel_open.assert_called_once()

# 🐍🏗️🔌
