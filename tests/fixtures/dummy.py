
# tests/fixtures/dummy.py

import pytest

import asyncio
import os

from pyvider.rpcplugin.logger import logger

class DummyReader:
    def __init__(self, data: bytes = b""):
        self._data = data
        self._called = False
    async def read(self, size: int):
        if not self._called:
            self._called = True
            return self._data
        return b""

class DummyWriter:
    def __init__(self):
        self.closed = False
        self.data = bytearray()
    def write(self, data: bytes):
        self.data.extend(data)
    async def drain(self):
        await asyncio.sleep(0)
    def close(self):
        self.closed = True
    async def wait_closed(self):
        await asyncio.sleep(0)
    def is_closing(self):
        return self.closed
    def get_extra_info(self, key, default=None):
        if key == "peername":
            return "dummy_peer"
        return default

# -------------------------------------------------------------------
# Dummy protocol and GRPC server implementations for testing.
# -------------------------------------------------------------------
class DummyGRPCServer:
    """A dummy replacement for grpc.aio.Server."""
    def __init__(self):
        self.ports = []
    def add_secure_port(self, address, creds):
        self.ports.append(address)
        return 12345
    def add_insecure_port(self, address):
        self.ports.append(address)
        return 12345
    async def start(self):
        pass
    async def stop(self, grace):
        pass
    async def wait_closed(self):
        pass

# A dummy asynchronous GRPC server to simulate grpc.aio.Server behavior.
class DummyAioServer:
    async def start(self):
        pass
    async def stop(self, grace):
        # Simulate asynchronous shutdown delay.
        await asyncio.sleep(0.01)
    async def wait_closed(self):
        await asyncio.sleep(0.01)
    def __del__(self):
        # In __del__, try to get the event loop;
        # if it is closed, simply pass to avoid raising an exception.
        try:
            asyncio.get_event_loop()
        except RuntimeError:
            pass
