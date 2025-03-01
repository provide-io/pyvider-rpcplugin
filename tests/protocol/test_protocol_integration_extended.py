
# tests/protocol/test_protocol_integration_extended.py

import asyncio
import pytest
import pytest_asyncio
import grpc
from google.protobuf.empty_pb2 import Empty
from unittest.mock import MagicMock, AsyncMock, patch

from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService,
    register_protocol_service,
)
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub


@pytest_asyncio.fixture
async def real_server_client():
    """Fixture to create a real gRPC server and client pair."""
    # Create a server
    server = grpc.aio.server()

    # Create shutdown event
    shutdown_event = asyncio.Event()

    # Register services
    register_protocol_service(server, shutdown_event)

    # Start on random port
    port = server.add_insecure_port('localhost:0')
    await server.start()

    # Create client channel
    channel = grpc.aio.insecure_channel(f'localhost:{port}')

    # Wait for channel to be ready
    await channel.channel_ready()

    # Create stubs
    stdio_stub = GRPCStdioStub(channel)
    broker_stub = GRPCBrokerStub(channel)
    controller_stub = GRPCControllerStub(channel)

    yield server, channel, stdio_stub, broker_stub, controller_stub, shutdown_event

    # Cleanup
    await channel.close()
    await server.stop(0)


@pytest.mark.asyncio
async def test_stdio_end_to_end(real_server_client):
    """Test end-to-end stdio service with real server and client."""
    server, channel, stdio_stub, _, _, _ = real_server_client

    # Find the stdio service in the server
    stdio_service = None
    for handler in server._generic_handlers:
        if handler.service_name() == 'plugin.GRPCStdio':
            servicer = handler._method_handlers['StreamStdio']._unary_stream_handler._servicer
            if isinstance(servicer, GRPCStdioService):
                stdio_service = servicer
                break

    assert stdio_service is not None, "Could not find stdio service in server"

    # Create a background task to collect stdio output
    async def collect_stdio():
        results = []
        async for data in stdio_stub.StreamStdio(Empty()):
            results.append(data)
            if len(results) >= 3:
                break
        return results

    stdio_task = asyncio.create_task(collect_stdio())

    # Give stream time to establish
    await asyncio.sleep(0.1)

    # Feed data to the stdio service
    test_lines = [
        (b"stdout line 1", False),
        (b"stderr line", True),
        (b"stdout line 2", False),
    ]

    for line, is_stderr in test_lines:
        await stdio_service.put_line(line, is_stderr=is_stderr)

    # Collect results
    results = await asyncio.wait_for(stdio_task, timeout=3.0)

    # Verify results
    assert len(results) == 3

    for i, (expected_line, expected_stderr) in enumerate(test_lines):
        assert results[i].data == expected_line
        expected_channel = StdioData.STDERR if expected_stderr else StdioData.STDOUT
        assert results[i].channel == expected_channel


@pytest.mark.asyncio
async def test_broker_cancellation(real_server_client):
    """Test broker service with cancellation."""
    _, _, _, broker_stub, _, _ = real_server_client

    # Start a broker stream
    stream = broker_stub.StartStream()

    # Create a knock request
    knock_request = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error="")
    )

    # Send the request
    await stream.write(knock_request)

    # Read the response
    response = await stream.read()
    assert response.service_id == 1
    assert response.knock.ack is True

    # Abruptly cancel the stream instead of cleanly closing it
    stream._cython_call.cancel()

    # Close the write side of the stream
    await stream.done_writing()


@pytest.mark.asyncio
async def test_controller_shutdown_with_timeout(real_server_client):
    """Test controller shutdown with a timeout."""
    _, _, _, _, controller_stub, shutdown_event = real_server_client

    # Patch os.kill and sys.exit to prevent actual process termination
    with patch('os.kill'), patch('sys.exit'), patch('os.getpid', return_value=12345):
        # Call Shutdown with a timeout
        try:
            response = await asyncio.wait_for(
                controller_stub.Shutdown(ControllerEmpty()),
                timeout=2.0
            )

            # Verify response is an Empty
            assert isinstance(response, ControllerEmpty)

            # Verify shutdown event is set
            assert shutdown_event.is_set()

        except asyncio.TimeoutError:
            pytest.fail("Controller.Shutdown timed out")


@pytest.mark.asyncio
async def test_stdio_early_client_disconnect(real_server_client):
    """Test stdio service when client disconnects early."""
    _, channel, stdio_stub, _, _, _ = real_server_client

    # Start the stream
    stream_call = stdio_stub.StreamStdio(Empty())

    # Wait for stream to establish
    await asyncio.sleep(0.1)

    # Abruptly close the channel without properly closing the stream
    await channel.close()

    # Verify stream is properly terminated
    with pytest.raises((grpc.RpcError, asyncio.CancelledError)):
        async for _ in stream_call:
            pass


@pytest.mark.asyncio
async def test_broker_multiple_clients(real_server_client):
    """Test multiple clients connecting to broker service simultaneously."""
    server, _, _, _, _, _ = real_server_client

    # Find the broker service in the server
    broker_service = None
    for handler in server._generic_handlers:
        if handler.service_name() == 'plugin.GRPCBroker':
            servicer = handler._method_handlers['StartStream']._stream_stream_handler._servicer
            if isinstance(servicer, GRPCBrokerService):
                broker_service = servicer
                break

    assert broker_service is not None, "Could not find broker service in server"

    # Create multiple mock contexts and iterators
    num_clients = 3
    contexts = [MagicMock() for _ in range(num_clients)]

    # Create request iterators with different service IDs
    iterators = []
    for i in range(num_clients):
        knock_request = ConnInfo(
            service_id=i+1,
            network="tcp",
            address=f"localhost:{10000+i}",
            knock=ConnInfo.Knock(knock=True, ack=False, error="")
        )
        iterators.append(MockRequestIterator([knock_request]))

    # Start broker streams simultaneously
    broker_tasks = [
        asyncio.create_task(collect_broker_stream(broker_service.StartStream(it, ctx)))
        for it, ctx in zip(iterators, contexts)
    ]

    # Wait for all tasks to complete
    results = await asyncio.gather(*broker_tasks)

    # Verify each client got a proper response
    for i, client_results in enumerate(results):
        assert len(client_results) == 1
        assert client_results[0].service_id == i+1
        assert client_results[0].knock.ack is True

    # Verify broker service created the expected subchannels
    assert len(broker_service._subchannels) == num_clients
    for i in range(num_clients):
        assert i+1 in broker_service._subchannels


class MockRequestIterator:
    """Mock request iterator for broker stream."""
    def __init__(self, requests):
        self.requests = requests
        self.index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.index < len(self.requests):
            request = self.requests[self.index]
            self.index += 1
            return request
        raise StopAsyncIteration


async def collect_broker_stream(stream):
    """Collect all responses from a broker stream."""
    results = []
    async for response in stream:
        results.append(response)
    return results

### 🐍🏗🧪️
