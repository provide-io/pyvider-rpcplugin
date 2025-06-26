# tests/protocol/test_service_critical.py

import asyncio
import signal
import pytest
from unittest.mock import AsyncMock, patch

from pyvider.rpcplugin.protocol.service import GRPCStdioService, GRPCControllerService


class MockRequestIterator:
    """Simple async iterator for testing."""

    def __init__(self, items) -> None:
        self.items = items
        self.index = 0

    def __aiter__(self) -> "MockRequestIterator":
        return self

    async def __anext__(self):
        if self.index < len(self.items):
            item = self.items[self.index]
            self.index += 1
            return item
        raise StopAsyncIteration


@pytest.mark.asyncio
async def test_stdio_put_line_exception_line123() -> None:
    """Test exception handling in stdio.put_line (lines 123-128)."""
    stdio = GRPCStdioService()

    # Replace queue.put with one that raises exception
    original_put = stdio._message_queue.put

    async def failing_put(*args, **kwargs):
        raise Exception("Test queue error")

    stdio._message_queue.put = failing_put # type: ignore[method-assign]

    try:
        # This should not propagate the exception
        await stdio.put_line(b"test data")
        # If we get here, exception was handled properly
        assert True
    finally:
        # Restore original method
        stdio._message_queue.put = original_put # type: ignore[method-assign]


@pytest.mark.asyncio
async def test_controller_delayed_shutdown_unix_line212() -> None:
    """Test Unix path in controller._delayed_shutdown (lines 212-216)."""
    stdio = GRPCStdioService()
    event = asyncio.Event()
    controller = GRPCControllerService(event, stdio)

    # Patch to prevent actual system calls
    with (
        patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        patch("os.kill") as mock_kill,
        patch("os.getpid", return_value=12345),
    ):
        # Execute the method
        await controller._delayed_shutdown()

        # Verify correct calls
        mock_sleep.assert_called_once()
        mock_kill.assert_called_once_with(12345, signal.SIGTERM)


@pytest.mark.asyncio
async def test_controller_delayed_shutdown_windows_line212() -> None:
    """Test Windows path in controller._delayed_shutdown (lines 212-216)."""
    stdio = GRPCStdioService()
    event = asyncio.Event()
    controller = GRPCControllerService(event, stdio)

    # Patch to simulate Windows (no os.kill) and prevent actual exit
    with (
        patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep,
        patch("os.kill", side_effect=AttributeError),
        patch("sys.exit") as mock_exit,
    ):
        # Execute the method
        await controller._delayed_shutdown()

        # Verify correct calls
        mock_sleep.assert_called_once()
        mock_exit.assert_called_once_with(0)


### 🐍🏗🧪️
