# tests/fixtures/dummy.py

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock  # Ensure AsyncMock is imported


class DummyReader:
    def __init__(self, data: bytes = b"") -> None:
        self._data = data
        self._called = False

    async def read(self, size: int) -> bytes:
        if not self._called:
            self._called = True
            return self._data
        return b""


class DummyWriter:
    def __init__(self) -> None:
        self.closed = False
        self.data = bytearray()

    def write(self, data: bytes) -> None:
        self.data.extend(data)

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        await asyncio.sleep(0)

    def is_closing(self) -> bool:
        return self.closed

    def get_extra_info(self, key, default=None) -> str:
        if key == "peername":
            return "dummy_peer"
        return default


# -------------------------------------------------------------------
# Dummy protocol and GRPC server implementations for testing.
# -------------------------------------------------------------------
class DummyGRPCServer:
    """A dummy replacement for grpc.aio.Server."""

    def __init__(self) -> None:
        # from unittest.mock import MagicMock, AsyncMock # Already imported at top
        self.ports: list[str] = []
        self.add_generic_rpc_handlers = MagicMock()
        self.add_registered_method_handlers = MagicMock()  # Added this
        self.start = AsyncMock()  # Added this
        self.stop = AsyncMock()  # Added this
        self.wait_for_termination = AsyncMock()  # Added this

    def add_secure_port(self, address, creds) -> int:
        self.ports.append(address)
        return 12345

    def add_insecure_port(self, address) -> int:
        self.ports.append(address)
        return 12345

    # These were previously simple async defs, converted to AsyncMocks in __init__
    # async def start(self) -> None:
    #     pass
    # async def stop(self, grace) -> None:
    #     pass
    # async def wait_closed(self) -> None:
    #     pass


# A dummy asynchronous GRPC server to simulate grpc.aio.Server behavior.
class DummyAioServer:
    async def start(self) -> None:
        pass

    async def stop(self, grace) -> None:
        # Simulate asynchronous shutdown delay.
        await asyncio.sleep(0.01)

    async def wait_closed(self) -> None:
        await asyncio.sleep(0.01)

    def __del__(self) -> None:
        # In __del__, try to get the event loop;
        # if it is closed, simply pass to avoid raising an exception.
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            pass


# Fixtures for DummyReader and DummyWriter.
# -------------------------------------------------------------------
@pytest.fixture
def dummy_writer() -> DummyWriter:
    return DummyWriter()


@pytest.fixture
def dummy_reader() -> DummyReader:
    # Default dummy reader returns "test data".
    return DummyReader(b"test data")


### 🐍🏗🧪️
