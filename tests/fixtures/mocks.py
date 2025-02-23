
# tests/fixtures/mocks.py

import asyncio
import os
import socket
import sys

from typing import TypeVar

import tempfile
import time

from contextlib import suppress

import pytest
import pytest_asyncio

from cryptography.hazmat.primitives import serialization

from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer

from pyvider.rpcplugin.transport import (
    RPCPluginTransport,
    TCPSocketTransport,
    UnixSocketTransport,
)

from pyvider.rpcplugin.types import TransportT, ConfigT, HandlerT

from ..fixtures import *

class MockProtocol(RPCPluginProtocol):
    def get_grpc_descriptors(self):
        # Mock descriptors for testing
        logger.debug("🔌🚀✅ MockProtocol.get_grpc_descriptors called.")
        return None, None, "MockService"

    async def add_to_server(self, handler, server):
        # Mock add_to_server for testing
        logger.debug("🔌🚀✅ MockProtocol.add_to_server called.")
        pass

    def get_method_type(self, method_name: str):
        logger.debug("🔌🚀✅ MockProtocol.get_method_type called.")
        return "unary_unary"  # Mock implementation

class MockHandler:
    """Mock handler for testing the RPCPluginServer."""
    async def GetRequest(self, request, context):
        logger.debug("🔌🚀✅ MockHandler.GetRequest called.")
        return None

    async def GetResponse(self, request, context):
        logger.debug("🔌🚀✅ MockHandler.GetResponse called.")
        return None

    async def PutRequest(self, request, context):
        logger.debug("🔌🚀✅ MockHandler.PutRequest called.")
        return None

    async def Empty(self, request, context):
        logger.debug("🔌🚀✅ MockHandler.Empty called.")
        return None

class MockServicer:
    pass

@pytest_asyncio.fixture(scope="function", params=["tcp", "unix"])
async def mock_server_transport(request, unused_tcp_port: int) -> TransportT:
    transport_name = request.param

    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        socket_path = tmp.name

    logger.debug(f"🧪🔌🐛 mock_server_transport called for transport: {transport_name}")
    logger.debug(f"🧪🔌🐛 socket_path: {socket_path}, unused_tcp_port: {unused_tcp_port}")

    match transport_name:
        case "tcp":
            transport = TCPSocketTransport(host="127.0.0.1")
        case "unix":
            transport = UnixSocketTransport(path=socket_path)
        case _:
            raise ValueError(f"Unknown transport: {transport_name}")

    return transport


@pytest_asyncio.fixture
async def mock_server_transport_tcp(unused_tcp_port: int) -> TransportT:
    try:
        transport = TCPSocketTransport(host="127.0.0.1")
    except Exception as e:
        raise ValueError(f"Could not open a TCP Socket Transport: {transport}")

    return transport

@pytest_asyncio.fixture
async def mock_server_transport_unix() -> TransportT:

    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        socket_path = tmp.name
    try:
        transport = UnixSocketTransport(path=socket_path)

    except Exception as e:
        raise ValueError(f"Could not open a Unix : {transport}")

    return transport


#@pytest_asyncio.fixture(scope="module", autouse=True)
@pytest.fixture(scope="function")
def mock_server_handler() -> HandlerT:
    """Fixture to provide a mock hadler instance."""
    return MockHandler()


@pytest_asyncio.fixture(scope="function")
async def mock_server_protocol():
    """Fixture to provide a mock protocol class."""
    proto = MockProtocol()
    return proto

@pytest.fixture(scope="function")
def mock_server_config():
    """Provides actual RPCPluginConfig instance for testing."""
    from pyvider.rpcplugin.config import RPCPluginConfig

    # Create a fresh instance for each test
    config = RPCPluginConfig()

    # Set default test values
    config.set("PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE")
    config.set("PLUGIN_MAGIC_COOKIE_VALUE", "hello")
    config.set("PLUGIN_MAGIC_COOKIE", "hello")
    config.set("PLUGIN_PROTOCOL_VERSIONS", [1,2,3,4,5,6,7])
    config.set("PLUGIN_SERVER_TRANSPORTS", ["tcp", "unix"])

    return config

@pytest_asyncio.fixture
async def server_with_mocks(mock_server_protocol, mock_server_handler, mock_server_config, mock_server_transport):
    """Fixture to provide a server instance with mocks."""
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport,
    )
    try:
        yield server
    finally:
        with suppress(Exception):
            await server.stop()

