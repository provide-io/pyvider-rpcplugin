# tests/fixtures/dummy.py

import asyncio
from typing import Any # Added Any
from unittest.mock import AsyncMock, MagicMock

import pytest


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

    def get_extra_info(self, key: str, default: Any = None) -> Any: # Fixed annotations
        if key == "peername":
            return "dummy_peer"
        return default


# -------------------------------------------------------------------
# Dummy protocol and GRPC server implementations for testing.
# -------------------------------------------------------------------
class DummyGRPCServer:
    """A dummy replacement for grpc.aio.Server."""

    def __init__(self) -> None:
        self.ports: list[str] = []
        self.add_generic_rpc_handlers = MagicMock()
        self.add_registered_method_handlers = MagicMock()
        self.start = AsyncMock()
        self.stop = AsyncMock()
        self.wait_for_termination = AsyncMock()

    def add_secure_port(self, address: str, creds: Any) -> int: # Fixed annotations
        self.ports.append(address)
        return 12345

    def add_insecure_port(self, address: str) -> int: # Fixed annotations
        self.ports.append(address)
        return 12345

    # These were previously simple async defs, converted to AsyncMocks in __init__
    # async def start(self) -> None:
    #     pass
    # async def stop(self, grace) -> None:
    #     pass
    # async def wait_closed(self) -> None:
    #     pass


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
