
# tests/protocol/test_service_critical.py

import asyncio
import signal
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo

class MockRequestIterator:
    """Simple async iterator for testing."""
    def __init__(self, items):
        self.items = items
        self.index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.index < len(self.items):
            item = self.items[self.index]
            self.index += 1
            return item
        raise StopAsyncIteration

@pytest.mark.asyncio
async def test_broker_exception_handling_line95():
    """Test exception handling in broker.StartStream (line 95)."""
    broker = GRPCBrokerService()

    # Mock _subchannels to raise an exception
    with patch.object(broker, '_subchannels',
                      side_effect=Exception("Test exception")):

        # Create request that triggers exception path
        request = ConnInfo(
            service_id=1,
            network="tcp",
            address="localhost:12345",
            knock=ConnInfo.Knock(knock=True, ack=False, error="")
        )

        # Create iterator and context
        iterator = MockRequestIterator([request])
        context = MagicMock()

        # Process stream
        responses = []
        async for response in broker.StartStream(iterator, context):
            responses.append(response)

        # Verify error response
        assert len(responses) == 1
        assert responses[0].knock.ack is False
        assert "error" in responses[0].knock.error

@pytest.mark.asyncio
async def test_stdio_put_line_exception_line123():
    """Test exception handling in stdio.put_line (lines 123-128)."""
    stdio = GRPCStdioService()

    # Replace queue.put with one that raises exception
    original_put = stdio._message_queue.put

    async def failing_put(*args, **kwargs):
        raise Exception("Test queue error")

    stdio._message_queue.put = failing_put

    try:
        # This should not propagate the exception
        await stdio.put_line(b"test data")
        # If we get here, exception was handled properly
        assert True
    finally:
        # Restore original method
        stdio._message_queue.put = original_put

@pytest.mark.asyncio
async def test_controller_delayed_shutdown_unix_line212():
    """Test Unix path in controller._delayed_shutdown (lines 212-216)."""
    stdio = GRPCStdioService()
    event = asyncio.Event()
    controller = GRPCControllerService(event, stdio)

    # Patch to prevent actual system calls
    with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep, \
         patch('os.kill') as mock_kill, \
         patch('os.getpid', return_value=12345):

        # Execute the method
        await controller._delayed_shutdown()

        # Verify correct calls
        mock_sleep.assert_called_once()
        mock_kill.assert_called_once_with(12345, signal.SIGTERM)

@pytest.mark.asyncio
async def test_controller_delayed_shutdown_windows_line212():
    """Test Windows path in controller._delayed_shutdown (lines 212-216)."""
    stdio = GRPCStdioService()
    event = asyncio.Event()
    controller = GRPCControllerService(event, stdio)

    # Patch to simulate Windows (no os.kill) and prevent actual exit
    with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep, \
         patch('os.kill', side_effect=AttributeError), \
         patch('sys.exit') as mock_exit:

        # Execute the method
        await controller._delayed_shutdown()

        # Verify correct calls
        mock_sleep.assert_called_once()
        mock_exit.assert_called_once_with(0)