
# tests/protocol/test_protocol_integration_helpers.py

import asyncio
import pytest
import pytest_asyncio
import grpc
from unittest.mock import patch

from pyvider.rpcplugin.protocol.service import (
    register_protocol_service,
)
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import add_GRPCStdioServicer_to_server
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import add_GRPCBrokerServicer_to_server
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import add_GRPCControllerServicer_to_server
from google.protobuf.empty_pb2 import Empty


@pytest_asyncio.fixture
async def servicer_registry():
    """A fixture that provides a registry to track and access service objects."""
    class ServicerRegistry:
        def __init__(self):
            self.service_map = {}

        def register(self, service_name, servicer):
            self.service_map[service_name] = servicer

        def get(self, service_name):
            return self.service_map.get(service_name)

    return ServicerRegistry()


@pytest_asyncio.fixture
async def patched_add_servicers(servicer_registry):
    """Patch add_*_to_server functions to register services in the registry."""

    original_add_stdio = add_GRPCStdioServicer_to_server
    original_add_broker = add_GRPCBrokerServicer_to_server
    original_add_controller = add_GRPCControllerServicer_to_server

    def patched_add_stdio(servicer, server):
        servicer_registry.register('stdio', servicer)
        return original_add_stdio(servicer, server)

    def patched_add_broker(servicer, server):
        servicer_registry.register('broker', servicer)
        return original_add_broker(servicer, server)

    def patched_add_controller(servicer, server):
        servicer_registry.register('controller', servicer)
        return original_add_controller(servicer, server)

    # Apply patches
    add_GRPCStdioServicer_to_server_patcher = patch(
        'pyvider.rpcplugin.protocol.service.add_GRPCStdioServicer_to_server',
        patched_add_stdio
    )
    add_GRPCBrokerServicer_to_server_patcher = patch(
        'pyvider.rpcplugin.protocol.service.add_GRPCBrokerServicer_to_server',
        patched_add_broker
    )
    add_GRPCControllerServicer_to_server_patcher = patch(
        'pyvider.rpcplugin.protocol.service.add_GRPCControllerServicer_to_server',
        patched_add_controller
    )

    add_GRPCStdioServicer_to_server_patcher.start()
    add_GRPCBrokerServicer_to_server_patcher.start()
    add_GRPCControllerServicer_to_server_patcher.start()

    yield

    # Remove patches
    add_GRPCStdioServicer_to_server_patcher.stop()
    add_GRPCBrokerServicer_to_server_patcher.stop()
    add_GRPCControllerServicer_to_server_patcher.stop()


@pytest_asyncio.fixture
async def grpc_server_with_registry(patched_add_servicers, servicer_registry):
    """Create a gRPC server with services registered in the registry."""
    server = grpc.aio.server()
    shutdown_event = asyncio.Event()

    # Register protocol service
    register_protocol_service(server, shutdown_event)

    # Start on random port
    port = server.add_insecure_port('localhost:0')
    address = f'localhost:{port}'
    await server.start()

    yield server, address, servicer_registry, shutdown_event

    # Cleanup
    await server.stop(grace=0.1)


@pytest.mark.asyncio
async def test_stdio_integration_registry(grpc_server_with_registry) -> None:
    """Test stdio service integration using the registry approach."""
    _, address, registry, _ = grpc_server_with_registry
    stdio_service = registry.get('stdio')

    assert stdio_service is not None, "Could not find stdio service in registry"

    # Create a channel and stub
    channel = grpc.aio.insecure_channel(address)

    try:
        from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
        stub = GRPCStdioStub(channel)

        # Collect stdio output
        async def collect_stdio():
            results = []
            async for data in stub.StreamStdio(Empty()):
                results.append(data)
                if len(results) >= 2:
                    break
            return results

        stdio_task = asyncio.create_task(collect_stdio())

        # Wait for stream to establish
        await asyncio.sleep(0.1)

        # Feed data to stdio service
        await stdio_service.put_line(b"Test line 1")
        await stdio_service.put_line(b"Test line 2", is_stderr=True)

        # Collect results
        results = await asyncio.wait_for(stdio_task, timeout=5.0) # Increased timeout

        # Verify results
        assert len(results) == 2
        assert results[0].data == b"Test line 1"
        assert results[1].data == b"Test line 2"

    finally:
        await channel.close()

### 🐍🏗🧪️
