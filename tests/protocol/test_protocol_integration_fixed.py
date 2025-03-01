
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
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub


class ServiceContainer:
    """Container to hold service instances for test access."""
    def __init__(self):
        self.stdio_service = None
        self.broker_service = None
        self.controller_service = None


@pytest_asyncio.fixture
async def grpc_server_with_services():
    """Fixture providing a real gRPC server with services and access to service instances."""
    server = grpc.aio.server()
    shutdown_event = asyncio.Event()

    # Container for services
    container = ServiceContainer()

    # Create service instances
    stdio_service = GRPCStdioService()
    broker_service = GRPCBrokerService()
    controller_service = GRPCControllerService(shutdown_event, stdio_service)

    # Store in container
    container.stdio_service = stdio_service
    container.broker_service = broker_service
    container.controller_service = controller_service

    # Register services explicitly
    from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import add_GRPCStdioServicer_to_server
    from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import add_GRPCBrokerServicer_to_server
    from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import add_GRPCControllerServicer_to_server

    add_GRPCStdioServicer_to_server(stdio_service, server)
    add_GRPCBrokerServicer_to_server(broker_service, server)
    add_GRPCControllerServicer_to_server(controller_service, server)

    # Start on random port
    port = server.add_insecure_port('localhost:0')
    address = f'localhost:{port}'
    await server.start()

    yield server, address, container, shutdown_event

    # Cleanup
    await server.stop(grace=0.1)


@pytest_asyncio.fixture
async def grpc_channel(grpc_server_with_services):
    """Fixture providing a client channel to the gRPC server."""
    _, address, _, _ = grpc_server_with_services
    channel = grpc.aio.insecure_channel(address)
    yield channel
    await channel.close()


@pytest.mark.asyncio
async def test_stdio_integration_fixed(grpc_server_with_services, grpc_channel):
    """Integration test for the stdio service using direct service access."""
    _, _, container, _ = grpc_server_with_services
    stdio_service = container.stdio_service

    # Create a stdio stub
    stub = GRPCStdioStub(grpc_channel)

    # Create a background task to collect stdio output
    async def collect_stdio():
        results = []
        async for data in stub.StreamStdio(Empty()):
            results.append(data)
            if len(results) >= 2:  # Collect 2 messages then stop
                break
        return results

    stdio_task = asyncio.create_task(collect_stdio())

    # Give the stream time to establish
    await asyncio.sleep(0.1)

    # Send some data to the stdio service
    await stdio_service.put_line(b"Test line 1")
    await stdio_service.put_line(b"Test line 2", is_stderr=True)

    # Wait for the stdio collection to complete
    results = await asyncio.wait_for(stdio_task, timeout=2.0)

    # Verify the results
    assert len(results) == 2
    assert results[0].data == b"Test line 1"
    assert results[1].data == b"Test line 2"
    assert results[0].channel != results[1].channel


@pytest.mark.asyncio
async def test_broker_cancellation_fixed(grpc_server_with_services, grpc_channel):
    """Test broker service with cancellation."""
    # Create a broker stub
    stub = GRPCBrokerStub(grpc_channel)

    # Start a broker stream
    stream = stub.StartStream()

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

    # Correctly cancel the stream using the cancellation API
    # The correct approach depends on gRPC version, but we can try a few approaches
    try:
        # Modern approach for newer gRPC versions
        await stream.cancel()
    except (AttributeError, TypeError):
        try:
            # Alternative approach
            stream._cython_call.cancel("Client cancelled")
        except (AttributeError, TypeError):
            # Last resort for older gRPC versions
            stream.cancel()

    # Close the write side of the stream
    await stream.done_writing()


@pytest.mark.asyncio
async def test_broker_start_stream_exception_fixed():
    """Test that broker service handles exceptions properly."""
    # Create service instance
    broker_service = GRPCBrokerService()

    # Create mocks
    from unittest.mock import MagicMock, AsyncMock

    # Mock opening a subchannel to raise an exception
    original_subchannel = broker_service._subchannels.copy()

    # Create a mock iterator that raises an exception
    class MockIterator:
        def __aiter__(self):
            return self

        async def __anext__(self):
            # Always raise an exception
            raise Exception("Mock iterator exception")

    # Create a mock context
    context = MagicMock()

    # Test the service handles the exception
    results = []
    async for response in broker_service.StartStream(MockIterator(), context):
        results.append(response)

    # Should get an error response
    assert len(results) == 1
    assert results[0].knock.ack == False
    assert "error" in results[0].knock.error

### 🐍🏗🧪️
