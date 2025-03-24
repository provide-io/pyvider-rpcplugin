# tests/protocol/test_protocol_integration.py
import asyncio
import pytest
import pytest_asyncio

from unittest.mock import patch

import grpc
from google.protobuf.empty_pb2 import Empty
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty

from pyvider.rpcplugin.protocol.service import (
    GRPCStdioService,
    register_protocol_service,
)
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub



@pytest_asyncio.fixture
async def server(unused_tcp_port):
    """Fixture to create a gRPC server for testing."""
    grpc_server = grpc.aio.server()
    stdio_service = GRPCStdioService()
    register_protocol_service(grpc_server, stdio_service)
    listen_addr = f"[::]:{unused_tcp_port}"
    grpc_server.add_insecure_port(listen_addr)
    await grpc_server.start()
    yield listen_addr
    await grpc_server.stop(grace=None)


@pytest_asyncio.fixture
async def client(server):
    """Fixture to create a gRPC client for testing."""
    async with grpc.aio.insecure_channel(server) as channel:
        yield GRPCStdioStub(channel)


@pytest.mark.asyncio
async def test_stdio_integration(client):
    """Test basic stdio integration."""
    response_future = await client.PutLine(
        grpc.aio.stream(iter([Empty(), Empty()]))
    )
    assert response_future is not None
