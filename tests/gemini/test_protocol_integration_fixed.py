# tests/protocol/test_protocol_integration_fixed.py
import asyncio
import pytest
import pytest_asyncio
import grpc
from google.protobuf.empty_pb2 import Empty

from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService,
    register_protocol_service,
)
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub


class MockRequestIterator:
    """Mock async iterator for broker StartStream testing."""
    def __init__(self, requests):
        self._requests = asyncio.Queue()
        for req in requests:
            self._requests.put_nowait(req)
        self._cancelled = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._cancelled and self._requests.empty():
            raise StopAsyncIteration
        try:
            return await self._requests.get()
        except asyncio.CancelledError:
            raise StopAsyncIteration

    async def cancel(self):
        self._cancelled = True

    def put(self, request):
        self._requests.put_nowait(request)


class MockIteratorException:
    """Mock iterator that raises an exception."""
    def __aiter__(self):
        raise Exception("Mock iterator exception")


class ServiceContainer:
    """Container to hold service instances for test access."""
    def __init__(self) -> None:
        self.broker_service = GRPCBrokerService()
        self.stdio_service = GRPCStdioService()
        self.controller_service = GRPCControllerService()


@pytest_asyncio.fixture
async def fixed_server_client(unused_tcp_port):
    """Fixture to create a gRPC server and client pair with fixed services."""
    grpc_server = grpc.aio.server()
    services = ServiceContainer()
    register_protocol_service(grpc_server, services.broker_service)
    register_protocol_service(grpc_server, services.stdio_service)
    register_protocol_service(grpc_server, services.controller_service)
    listen_addr = f"[::]:{unused_tcp_port}"
    grpc_server.add_insecure_port(listen_addr)
    await grpc_server.start()
    async with grpc.aio.insecure_channel(listen_addr) as channel:
        yield (
            grpc_server,
            GRPCBrokerStub(channel),
            GRPCStdioStub(channel),
            services.broker_service,
            services.stdio_service,
        )
    await grpc_server.stop(grace=None)


@pytest.mark.asyncio
async def test_stdio_integration_fixed(fixed_server_client):
    """Test basic stdio integration with fixed services."""
    _, _, stdio_client, _, stdio_service = fixed_server_client
    put_line_stream = grpc.aio.stream(iter([Empty()]))
    response_future = await stdio_client.PutLine(put_line_stream)
    assert response_future is not None
    stdio_service._message_queue.put_nowait(StdioData(data=b"test line\n"))
    get_line_response = await stdio_client.GetLine(Empty())
    assert get_line_response.data == b"test line\n"


@pytest.mark.asyncio
async def test_broker_start_stream_exception_fixed(fixed_server_client):
    """Test broker StartStream handling of exceptions in the request iterator."""
    _, broker_client, _, broker_service, _ = fixed_server_client
    with patch.object(broker_service, '_start_stream') as mock_start_stream:
        mock_start_stream.side_effect = Exception("Mock iterator exception")
        mock_request_iterator = MockRequestIterator([ConnInfo(conn_id=1)])
        with pytest.raises(grpc.RpcError) as e:
            await broker_client.StartStream(mock_request_iterator)
        assert e.value.code() == grpc.StatusCode.UNKNOWN
