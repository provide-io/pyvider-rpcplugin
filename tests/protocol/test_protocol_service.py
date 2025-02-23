
# tests/grpc/test_protocol_service.py

import asyncio
import pytest

from google.protobuf import empty_pb2

from pyvider.rpcplugin.protocol import ProtocolService
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioServicer
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerServicer
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerServicer

# Create a dummy context that captures set_code and set_details.
class DummyContext:
    def __init__(self):
        self.code = None
        self.details = None

    def set_code(self, code):
        self.code = code

    def set_details(self, details):
        self.details = details

# Create a dummy request iterator with a stream_id attribute.
class DummyRequestIterator:
    stream_id = "dummy_stream"

    def __init__(self, messages):
        self.messages = messages

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self.messages:
            raise StopAsyncIteration
        return self.messages.pop(0)

@pytest.fixture
def shutdown_event():
    return asyncio.Event()

@pytest.fixture
def protocol_service(shutdown_event):
    # Instantiate ProtocolService with dummy shutdown event.
    svc = ProtocolService(shutdown_event)
    # Pre-populate _setup_complete so that StartStream doesn't time out.
    svc._setup_complete.set()
    # Initialize the active streams set and message queue.
    svc._active_streams = set()
    svc._message_queue = asyncio.Queue()
    return svc

@pytest.mark.asyncio
async def test_shutdown_returns_empty(protocol_service):
    # Test that Shutdown returns an Empty message.
    ctx = DummyContext()
    resp = await protocol_service.Shutdown(empty_pb2.Empty(), ctx)
    assert isinstance(resp, empty_pb2.Empty)
    # After shutdown, _stream_active should be False.
    assert protocol_service._stream_active is False

@pytest.mark.asyncio
async def test_stop_stream_removes_stream(protocol_service):
    # Test that StopStream removes a stream if present.
    class DummyRequest:
        stream_id = "test_stream"
    ctx = DummyContext()
    protocol_service._active_streams.add("test_stream")
    resp = await protocol_service.StopStream(DummyRequest(), ctx)
    assert isinstance(resp, empty_pb2.Empty)
    assert "test_stream" not in protocol_service._active_streams

@pytest.mark.asyncio
async def test_start_stream_success(protocol_service):
    # Test that StartStream returns Empty when _setup_complete is set.
    # We simulate a request iterator with a stream_id.
    dummy_iter = DummyRequestIterator(messages=[])
    ctx = DummyContext()
    resp = await protocol_service.StartStream(dummy_iter, ctx)
    assert isinstance(resp, empty_pb2.Empty)
    # The stream_id should have been added.
    assert "dummy_stream" in protocol_service._active_streams

@pytest.mark.asyncio
async def test_start_stream_timeout(protocol_service):
    # Test that StartStream times out if _setup_complete is not set.
    # Reset _setup_complete to a new event that's never set.
    protocol_service._setup_complete = asyncio.Event()
    dummy_iter = DummyRequestIterator(messages=[])
    ctx = DummyContext()
    with pytest.raises(asyncio.TimeoutError):
        await protocol_service.StartStream(dummy_iter, ctx)
    # Also check that the context has appropriate code set.
    assert ctx.code == 14

@pytest.mark.asyncio
async def test_stream_stdio_echo(protocol_service):
    # Test that StreamStdio yields messages from the internal queue.
    # Pre-populate the message queue.
    messages = [b"msg1", b"msg2", b"msg3"]
    for msg in messages:
        await protocol_service._message_queue.put(msg)
    # Create a dummy context; here it need not do much.
    ctx = DummyContext()
    # Run the stream generator; cancel after a few iterations.
    gen = protocol_service.StreamStdio(empty_pb2.Empty(), ctx)
    received = []
    async for msg in gen:
        received.append(msg)
        if len(received) >= len(messages):
            # Simulate shutdown to exit the loop.
            protocol_service._shutdown_event.set()
            break
    assert received == messages

@pytest.mark.asyncio
async def test_handle_shutdown(protocol_service):
    # Test that handle_shutdown clears the queue when force=True.
    # Pre-fill the queue.
    for _ in range(3):
        await protocol_service._message_queue.put(b"dummy")
    # Call handle_shutdown with force True.
    await protocol_service.handle_shutdown(force=True)
    # Queue should be empty.
    assert protocol_service._message_queue.empty()
