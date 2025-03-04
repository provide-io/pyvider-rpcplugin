
# tests/protocol/test_service_direct.py

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

class MockIterator:
    """Mock async iterator for broker StartStream testing."""
    def __init__(self, items=None, exception=None) -> None:
        self.items = items or []
        self.exception = exception
        self.index = 0

    def __aiter__(self) -> "MockIterator":
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
async def test_broker_start_stream_exception_line95() -> None:
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
async def test_controller_delayed_shutdown_unix_path() -> None:
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
async def test_controller_delayed_shutdown_windows_path() -> None:
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

### 🐍🏗🧪️
