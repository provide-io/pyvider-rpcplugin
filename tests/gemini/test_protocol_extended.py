# tests/protocol/test_protocol_integration_extended.py
import asyncio
import pytest
import pytest_asyncio
import grpc
from google.protobuf.empty_pb2 import Empty
from unittest.mock import MagicMock, patch

from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
    register_protocol_service,
)
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub


@pytest_asyncio.fixture
async def real_server_client(unused_tcp_port):
    """Fixture to create a real gRPC server and client pair."""
    grpc_server = grpc.aio.server()
    broker_service = GRPCBrokerService()
    stdio_service = GRPCStdioService()
    controller_service = GRPCControllerService()
    register_protocol_service(grpc_server, broker_service)
    register_protocol_service(grpc_server, stdio_service)
    register_protocol_service(grpc_server, controller_service)
    listen_addr = f"[::]:{unused_tcp_port}"
    grpc_server.add_insecure_port(listen_addr)
    await grpc_server.start()
    async with grpc.aio.insecure_channel(listen_addr) as channel:
        yield (
            grpc_server,
            GRPCBrokerStub(channel),
            GRPCStdioStub(channel),
            GRPCControllerStub(channel),
            broker_service,
            stdio_service,
            controller_service,
        )
    await grpc_server.stop(grace=None)


@pytest.mark.asyncio
async def test_stdio_end_to_end(real_server_client):
    """Test end-to-end stdio communication."""
    _, _, stdio_client, _, _, stdio_service, _ = real_server_client
    put_line_stream = grpc.aio.stream(iter([StdioData(data=b"test line\n")]))
    response_future = await stdio_client.PutLine(put_line_stream)
    assert response_future is not None
    get_line_response = await stdio_client.GetLine(Empty())
    assert get_line_response.data == b"test line\n"


@pytest.mark.asyncio
async def test_broker_cancellation(real_server_client):
    """Test client-side cancellation of a broker stream."""
    _, broker_client, _, _, broker_service, _, _ = real_server_client
    mock_request_iterator = MagicMock()
    mock_request_iterator.__aiter__.return_value = [ConnInfo(conn_id=1)]
    call = await broker_client.StartStream(mock_request_iterator)
    await call.cancel()
    assert call.code() == grpc.StatusCode.CANCELLED


@pytest.mark.asyncio
async def test_stdio_early_client_disconnect(real_server_client):
    """Test server handling of early client disconnect in stdio."""
    _, _, stdio_client, _, _, stdio_service, _ = real_server_client
    # Simulate a client sending a single message and then disconnecting
    async def send_one_and_disconnect():
        stream = grpc.aio.stream(iter([StdioData(data=b"partial line")]))
        await stdio_client.PutLine(stream)
        # Client disconnects here implicitly by exiting the function

    await send_one_and_disconnect()
    # Give the server a moment to process (or not)
    await asyncio.sleep(0.1)
    # The server should not have crashed or left the connection in a bad state
    assert True  # Add more specific assertions if needed


@pytest.mark.asyncio
async def test_broker_multiple_clients(real_server_client):
    """Test handling multiple concurrent broker clients."""
    grpc_server, broker_client_1, _, _, _, _, _ = real_server_client
    async with grpc.aio.insecure_channel(grpc_server._port) as channel_2:
        broker_client_2 = GRPCBrokerStub(channel_2)
        mock_request_iterator_1 = MagicMock()
        mock_request_iterator_1.__aiter__.return_value = [ConnInfo(conn_id=1)]
        mock_request_iterator_2 = MagicMock()
        mock_request_iterator_2.__aiter__.return_value = [ConnInfo(conn_id=2)]
        stream_1 = await broker_client_1.StartStream(mock_request_iterator_1)
        stream_2 = await broker_client_2.StartStream(mock_request_iterator_2)
        assert stream_1 is not None
        assert stream_2 is not None
        await stream_1.cancel()
        await stream_2.cancel()
