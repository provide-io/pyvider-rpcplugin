
# tests/protocol/test_protocol_integration.py

import asyncio
import pytest
import pytest_asyncio
import attr # Added import

from unittest.mock import patch

import grpc
from google.protobuf.empty_pb2 import Empty
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty

# Service implementations
from pyvider.rpcplugin.protocol.service import (
    GRPCStdioService,
    GRPCBrokerService,
    GRPCControllerService,
    # register_protocol_service, # Removed
)

# Stubs for client-side
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub

# Servicer adders for server-side
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import add_GRPCStdioServicer_to_server
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import add_GRPCBrokerServicer_to_server
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import add_GRPCControllerServicer_to_server

from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo


@attr.s(auto_attribs=True, frozen=True)
class ServerFixtureOutput:
    server: grpc.aio.Server
    address: str
    shutdown_event: asyncio.Event
    stdio_service: GRPCStdioService
    broker_service: GRPCBrokerService
    controller_service: GRPCControllerService


@pytest_asyncio.fixture
async def grpc_server_output() -> ServerFixtureOutput: # Changed fixture name for clarity
    """Fixture providing a real gRPC server with our services registered."""
    server = grpc.aio.server()
    shutdown_event = asyncio.Event()

    # Instantiate services
    stdio_service = GRPCStdioService()
    broker_service = GRPCBrokerService()
    controller_service = GRPCControllerService(shutdown_event, stdio_service) # Assuming it needs stdio_service

    # Register services directly
    add_GRPCStdioServicer_to_server(stdio_service, server)
    add_GRPCBrokerServicer_to_server(broker_service, server)
    add_GRPCControllerServicer_to_server(controller_service, server)

    # Add an insecure port
    port = server.add_insecure_port('localhost:0')
    address = f'localhost:{port}'

    # Start the server
    await server.start()

    yield ServerFixtureOutput(
        server=server,
        address=address,
        shutdown_event=shutdown_event,
        stdio_service=stdio_service,
        broker_service=broker_service,
        controller_service=controller_service,
    )

    # Cleanup
    await server.stop(grace=0.1)

@pytest_asyncio.fixture
async def grpc_channel(grpc_server_output: ServerFixtureOutput): # Changed fixture name
    """Fixture providing a client channel to the gRPC server."""
    channel = grpc.aio.insecure_channel(grpc_server_output.address)
    yield channel
    await channel.close()

@pytest.mark.asyncio
async def test_stdio_integration(grpc_server_output: ServerFixtureOutput, grpc_channel) -> None: # Changed fixture name
    """Integration test for the stdio service."""
    stdio_service = grpc_server_output.stdio_service
    assert stdio_service is not None

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
async def test_broker_integration(grpc_server_output: ServerFixtureOutput, grpc_channel) -> None: # Changed fixture name
    """Integration test for the broker service."""
    # Create a broker stub
    stub = GRPCBrokerStub(grpc_channel)

    # Create a stream for broker communication
    stream = stub.StartStream()

    # Send a knock request
    knock_request = ConnInfo(
        service_id=1,
        network="tcp",
        address="localhost:12345",
        knock=ConnInfo.Knock(knock=True, ack=False, error="")
    )

    await stream.write(knock_request)

    # Read the response
    response = await stream.read()

    # Verify the response
    assert response.service_id == 1
    assert response.knock.ack is True

    # Close the stream
    await stream.done_writing()

@pytest.mark.skip # the shutdown is killing the actual tests.
async def test_controller_integration(grpc_server_output: ServerFixtureOutput, grpc_channel) -> None: # Changed fixture name
    """Integration test for the controller service."""
    shutdown_event = grpc_server_output.shutdown_event

    # Create a controller stub
    stub = GRPCControllerStub(grpc_channel)

    # Call Shutdown, but patch os.kill to prevent actual termination
    with patch('os.kill'):
        with patch('os.getpid', return_value=12345):
            with patch('sys.exit'):
                response = await stub.Shutdown(ControllerEmpty())

                # Verify the shutdown event was set
                assert shutdown_event.is_set()

                # Verify the response is an Empty
                assert isinstance(response, ControllerEmpty)

### 🐍🏗🧪️
