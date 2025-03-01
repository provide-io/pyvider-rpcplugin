
# tests/protocol/test_protocol_integration.py

import asyncio
import pytest
import pytest_asyncio

from unittest.mock import patch

import grpc
from google.protobuf.empty_pb2 import Empty
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty

from pyvider.rpcplugin.protocol.service import (
    GRPCBrokerService,
    GRPCStdioService,
    GRPCControllerService,
    register_protocol_service,
)
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo

@pytest_asyncio.fixture
async def grpc_server():
    """Fixture providing a real gRPC server with our services registered."""
    server = grpc.aio.server()
    shutdown_event = asyncio.Event()

    # Register our services
    register_protocol_service(server, shutdown_event)

    # Add an insecure port
    port = server.add_insecure_port('localhost:0')
    address = f'localhost:{port}'

    # Start the server
    await server.start()

    yield server, address, shutdown_event

    # Cleanup
    await server.stop(grace=0.1)

@pytest_asyncio.fixture
async def grpc_channel(grpc_server):
    """Fixture providing a client channel to the gRPC server."""
    _, address, _ = grpc_server
    channel = grpc.aio.insecure_channel(address)
    yield channel
    await channel.close()

@pytest.mark.asyncio
async def test_stdio_integration(grpc_server, grpc_channel):
    """Integration test for the stdio service."""
    server, _, _ = grpc_server

    # Extract the stdio service from the server
    stdio_service = None
    for handler in server._generic_handlers:
        if handler.service_name() == 'plugin.GRPCStdio':
            servicer = handler._method_handlers['StreamStdio']._unary_stream_handler._servicer
            if isinstance(servicer, GRPCStdioService):
                stdio_service = servicer
                break

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
async def test_broker_integration(grpc_server, grpc_channel):
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
    assert response.knock.ack == True

    # Close the stream
    await stream.done_writing()

@pytest.mark.asyncio
async def test_controller_integration(grpc_server, grpc_channel):
    """Integration test for the controller service."""
    _, _, shutdown_event = grpc_server

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
