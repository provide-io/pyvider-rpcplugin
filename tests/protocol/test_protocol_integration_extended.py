
# tests/protocol/test_protocol_integration_extended.py

import asyncio
import pytest
import pytest_asyncio
import grpc
from google.protobuf.empty_pb2 import Empty
from unittest.mock import MagicMock, patch, AsyncMock
from attrs import define # Added import

# Service implementations
from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService, # Added import
    # register_protocol_service, # To be removed
)

# Stubs for client-side
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub

# Servicer adders for server-side
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import add_GRPCStdioServicer_to_server # Added import
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import add_GRPCBrokerServicer_to_server # Added import
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import add_GRPCControllerServicer_to_server # Added import


@define
class ExtendedServerFixtureOutput:
    server: grpc.aio.Server
    channel: grpc.aio.Channel
    stdio_stub: GRPCStdioStub
    broker_stub: GRPCBrokerStub
    controller_stub: GRPCControllerStub
    shutdown_event: asyncio.Event
    stdio_service: GRPCStdioService
    broker_service: GRPCBrokerService
    controller_service: GRPCControllerService


@pytest_asyncio.fixture
async def real_server_client() -> ExtendedServerFixtureOutput: # Updated return type hint
    """Fixture to create a real gRPC server and client pair."""
    server = grpc.aio.server()
    shutdown_event = asyncio.Event()

    # Instantiate services
    stdio_service = GRPCStdioService()
    broker_service = GRPCBrokerService()
    controller_service = GRPCControllerService(shutdown_event, stdio_service)

    # Register services directly
    add_GRPCStdioServicer_to_server(stdio_service, server)
    add_GRPCBrokerServicer_to_server(broker_service, server)
    add_GRPCControllerServicer_to_server(controller_service, server)

    port = server.add_insecure_port('localhost:0')
    address = f'localhost:{port}' # Define address for channel
    await server.start()

    channel = grpc.aio.insecure_channel(address) # Use defined address
    await channel.channel_ready()

    stdio_stub = GRPCStdioStub(channel)
    broker_stub = GRPCBrokerStub(channel)
    controller_stub = GRPCControllerStub(channel)

    yield ExtendedServerFixtureOutput(
        server=server,
        channel=channel,
        stdio_stub=stdio_stub,
        broker_stub=broker_stub,
        controller_stub=controller_stub,
        shutdown_event=shutdown_event,
        stdio_service=stdio_service,
        broker_service=broker_service,
        controller_service=controller_service
    )

    await channel.close()
    await server.stop(0)


@pytest.mark.asyncio
async def test_stdio_end_to_end(real_server_client: ExtendedServerFixtureOutput) -> None: # Updated parameter
    """Test end-to-end stdio service with real server and client."""
    stdio_service = real_server_client.stdio_service
    stdio_stub = real_server_client.stdio_stub
    assert stdio_service is not None, "Stdio service not found in fixture output"

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
    results = await asyncio.wait_for(stdio_task, timeout=7.0) # Increased timeout

    # Verify results
    assert len(results) == 3

    for i, (expected_line, expected_stderr) in enumerate(test_lines):
        assert results[i].data == expected_line
        expected_channel = StdioData.STDERR if expected_stderr else StdioData.STDOUT
        assert results[i].channel == expected_channel


@pytest.mark.asyncio
async def test_broker_cancellation(real_server_client: ExtendedServerFixtureOutput) -> None: # Updated parameter
    """Test broker service with cancellation."""
    broker_stub = real_server_client.broker_stub

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
    stream.cancel() # Changed from stream._cython_call.cancel()

    # Close the write side of the stream
    await stream.done_writing()


async def test_controller_shutdown_with_timeout(real_server_client: ExtendedServerFixtureOutput) -> None: # Updated parameter
    """Test controller shutdown with a timeout."""
    controller_stub = real_server_client.controller_stub
    shutdown_event = real_server_client.shutdown_event
    controller_service_instance = real_server_client.controller_service

    # Patch os.kill and sys.exit to prevent actual process termination
    # The os.kill/sys.exit patches are for the _delayed_shutdown internal logic,
    # which we are now mocking externally. They can remain as they won't interfere.
    with patch('os.kill'), patch('sys.exit'), patch('os.getpid', return_value=12345):
        with patch.object(controller_service_instance, '_delayed_shutdown', new_callable=AsyncMock) as mock_delayed_shutdown:
            try:
                response = await asyncio.wait_for(
                    controller_stub.Shutdown(ControllerEmpty()),
                    timeout=2.0
                )

                # Verify response is an Empty
                assert isinstance(response, ControllerEmpty)

                # Verify shutdown event is set
                assert shutdown_event.is_set()

                # Add assertion for the new mock
                # Need a small sleep to ensure the task created by Shutdown() gets a chance to run
                await asyncio.sleep(0.01)
                mock_delayed_shutdown.assert_called_once()

            except asyncio.TimeoutError:
                pytest.fail("Controller.Shutdown timed out")


@pytest.mark.asyncio
async def test_stdio_early_client_disconnect(real_server_client: ExtendedServerFixtureOutput) -> None: # Updated parameter
    """Test stdio service when client disconnects early."""
    channel = real_server_client.channel
    stdio_stub = real_server_client.stdio_stub

    # Start the stream
    stream_call = stdio_stub.StreamStdio(Empty())

    # Wait for stream to establish
    await asyncio.sleep(0.1)

    # Abruptly close the channel without properly closing the stream
    await channel.close()

    # Verify stream is properly terminated
    with pytest.raises((grpc.RpcError, grpc.aio.AioRpcError, asyncio.CancelledError)):
        async for _ in stream_call:
            pass


@pytest.mark.asyncio
async def test_broker_multiple_clients(real_server_client: ExtendedServerFixtureOutput) -> None: # Updated parameter
    """Test multiple clients connecting to broker service simultaneously."""
    broker_service = real_server_client.broker_service
    assert broker_service is not None, "Broker service not found in fixture output"

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
    def __init__(self, requests) -> None:
        self.requests = requests
        self.index = 0

    def __aiter__(self) -> "MockRequestIterator":
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
