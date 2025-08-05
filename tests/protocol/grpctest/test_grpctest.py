# tests/grpc/test_grpctest.py

import asyncio
import pytest
import pytest_asyncio
from typing import AsyncGenerator # Added import
import grpc
from google.protobuf import empty_pb2

# Import generated classes from your compiled proto.
from .proto.grpctest_pb2 import (
    TestRequest,
    TestResponse,
    PrintKVRequest,
    PrintKVResponse,
    BidirectionalRequest,
    BidirectionalResponse,
    PrintStdioRequest,
    PingRequest,
    PongResponse,
)
from .proto.grpctest_pb2_grpc import (
    TestServicer,
    add_TestServicer_to_server,
    PingPongServicer,
    add_PingPongServicer_to_server,
    TestStub,
    PingPongStub,
)


# Dummy implementation for the Test service.
class DummyTestServicer(TestServicer):
    async def Double(self, request, context):
        # Simply double the input.
        return TestResponse(Output=request.Input * 2)

    async def PrintKV(self, request, context):
        # No return payload.
        return PrintKVResponse()

    async def Bidirectional(self, request, context):
        # Echo back the id.
        return BidirectionalResponse(id=request.id)

    async def Stream(self, request_iterator, context):
        # For each incoming request, yield a response with double the input.
        async for req in request_iterator:
            yield TestResponse(Output=req.Input * 2)

    async def PrintStdio(self, request, context):
        return empty_pb2.Empty()


# Dummy implementation for the PingPong service.
class DummyPingPongServicer(PingPongServicer):
    async def Ping(self, request, context):
        return PongResponse(msg="pong")


# Fixture that starts a grpc.aio server with our dummy servicers.
@pytest_asyncio.fixture
async def grpc_server() -> AsyncGenerator[str, None]:
    server = grpc.aio.server()
    add_TestServicer_to_server(DummyTestServicer(), server)
    add_PingPongServicer_to_server(DummyPingPongServicer(), server)
    # Bind to an ephemeral port.
    port = server.add_insecure_port("localhost:0")
    await server.start()
    yield f"localhost:{port}"
    await server.stop(0)


# Fixture that creates a channel connected to the server.
@pytest_asyncio.fixture
async def grpc_channel(grpc_server: str) -> AsyncGenerator[grpc.aio.Channel, None]:
    channel = grpc.aio.insecure_channel(grpc_server)
    await channel.channel_ready()
    yield channel
    await channel.close()


# Fixtures for the client stubs.
@pytest_asyncio.fixture
async def test_stub(grpc_channel: grpc.aio.Channel) -> TestStub:
    return TestStub(grpc_channel)


@pytest_asyncio.fixture
async def pingpong_stub(grpc_channel: grpc.aio.Channel) -> PingPongStub:
    return PingPongStub(grpc_channel)


@pytest.mark.asyncio
async def test_double_rpc(test_stub: TestStub) -> None:
    req = TestRequest(Input=10)
    resp = await test_stub.Double(req)
    assert resp.Output == 20


@pytest.mark.asyncio
async def test_printkv_rpc(test_stub: TestStub) -> None:
    req = PrintKVRequest(Key="test", ValueString="hello")
    resp = await test_stub.PrintKV(req)
    assert isinstance(resp, PrintKVResponse)


@pytest.mark.asyncio
async def test_bidirectional_rpc(test_stub: TestStub) -> None:
    req = BidirectionalRequest(id=123)
    resp = await test_stub.Bidirectional(req)
    assert resp.id == 123


@pytest.mark.asyncio
async def test_stream_rpc(test_stub: TestStub):
    async def request_gen():
        for i in range(5):
            yield TestRequest(Input=i)
            await asyncio.sleep(0.01)

    responses = [resp async for resp in test_stub.Stream(request_gen())]
    expected = [i * 2 for i in range(5)]
    assert [r.Output for r in responses] == expected


@pytest.mark.asyncio
async def test_printstdio_rpc(test_stub: TestStub) -> None:
    req = PrintStdioRequest(stdout=b"abc", stderr=b"def")
    resp = await test_stub.PrintStdio(req)
    assert isinstance(resp, empty_pb2.Empty)


@pytest.mark.asyncio
async def test_pingpong_rpc(pingpong_stub: PingPongStub) -> None:
    req = PingRequest()
    resp = await pingpong_stub.Ping(req)
    assert resp.msg == "pong"
