# tests/kv/test_kv_integration.py

import pytest
import pytest_asyncio
import asyncio
import os

import grpc
import contextlib

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.server import RPCPluginServer

from tests.fixtures import *

from tests.kv.proto import (
    KVProtocol,
    kv_pb2,
    kv_pb2_grpc,
)


@pytest_asyncio.fixture
async def kv_handler():
    """Provides a real KV handler implementation"""

    class TestKVHandler(kv_pb2_grpc.KVServicer):
        def __init__(self):
            self._store = {}

        async def Get(self, request, context):
            value = self._store.get(request.key, None)
            if value is None:
                context.abort(grpc.StatusCode.NOT_FOUND, "Key not found")
            return kv_pb2.GetResponse(value=value)

        ###
        async def Put(self, request: kv_pb2.PutRequest, context) -> kv_pb2.Empty:
            """Fixed Put implementation handling both bytes and str values."""
            try:
                key = request.key
                logger.info(f"🛎️📡🚀 Put: Received request for key: '{key}'")
                
                # Handle value correctly regardless of type
                if isinstance(request.value, bytes):
                    value_str = request.value.decode("utf-8", errors="replace")
                else:
                    value_str = str(request.value)
                    
                summary = summarize_text(value_str)
                logger.debug(f"🛎️📡📝 Put: Storing key '{key}' with value: {summary}")
                
                filename = f"/tmp/kv-data-{key}"
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(value_str)
                    
                logger.debug(f"🛎️📡✅ Put: Successfully stored key '{key}'")
                return kv_pb2.Empty()
            except Exception as e:
                logger.error(f"🛎️📡❌ Put error for key '{request.key}': {e}")
                await context.abort(grpc.StatusCode.INTERNAL, str(e))


    return TestKVHandler()

@pytest_asyncio.fixture
async def kv_server(
    server_with_mocks,
    kv_handler,
    mock_server_config,
    mock_server_transport,
):

    transport = mock_server_transport

    server = RPCPluginServer(
        protocol=KVProtocol(),
        handler=kv_handler,
        config=mock_server_config,
        transport=transport,
    )

    # Create task for serve() instead of awaiting directly
    endpoint = await transport.listen()

    serve_task = asyncio.create_task(server.serve())

    # Wait for server to be ready
    await asyncio.sleep(0.5)  # Give server time to start

    try:
        yield server

    finally:
        # Proper cleanup
        await server.stop()
        serve_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await serve_task

@pytest_asyncio.fixture
async def kv_client(kv_server):
    """Provides connected KV client"""
    client = RPCPluginClient(
        command=[sys.executable, "-m", "tests.kv.py_kv_server"],
        config={
            "env": {
                "PLUGIN_MAGIC_COOKIE": "hello",
                "PLUGIN_PROTOCOL_VERSIONS": "1",
                "PLUGIN_AUTO_MTLS": "true",
            }
        },
    )
    await client.start()
    yield client
    await client.close()

@pytest.mark.asyncio
async def test_kv_put_get_flow(kv_client, mock_server_config):
    """Test basic Put/Get operations"""
    stub = kv_pb2_grpc.KVStub(kv_client._channel)

    # Put a value
    key = "test_key"
    value = b"test_value"
    await stub.Put(kv_pb2.PutRequest(key=key, value=value))

    # Get it back
    response = await stub.Get(kv_pb2.GetRequest(key=key))
    assert response.value == value

@pytest.mark.asyncio
async def test_kv_missing_key(kv_client):
    """Test Get with nonexistent key"""
    stub = kv_pb2_grpc.KVStub(kv_client._channel)

    with pytest.raises(grpc.RpcError) as exc:
        await stub.Get(kv_pb2.GetRequest(key="nonexistent"))
    assert exc.value.code() == grpc.StatusCode.NOT_FOUND

@pytest.mark.asyncio
async def test_kv_concurrent_operations(kv_client):
    """Test concurrent Put/Get operations"""
    stub = kv_pb2_grpc.KVStub(kv_client._channel)

    # Create multiple concurrent operations
    async def put_get(i):
        key = f"key_{i}"
        value = f"value_{i}".encode()
        await stub.Put(kv_pb2.PutRequest(key=key, value=value))
        response = await stub.Get(kv_pb2.GetRequest(key=key))
        assert response.value == value

    # Run concurrent operations
    tasks = [put_get(i) for i in range(10)]
    await asyncio.gather(*tasks)


### 🐍🏗🧪️
