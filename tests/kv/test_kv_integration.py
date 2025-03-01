#!/usr/bin/env python3
# tests/kv/test_kv_integration.py

import pytest
import pytest_asyncio
import asyncio
import os
import sys
import time
import uuid

import grpc
import contextlib

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport

from tests.fixtures import *

from tests.kv.proto import (
    KVProtocol,
    kv_pb2,
    kv_pb2_grpc,
)


def summarize_text(text: str, max_len: int = 20) -> str:
    """Helper function to summarize text for logging"""
    if len(text) <= max_len * 2:
        return text
    return f"{text[:max_len]}...{text[-max_len:]}"


@pytest_asyncio.fixture
async def kv_handler():
    """Provides a real KV handler implementation"""

    class TestKVHandler(kv_pb2_grpc.KVServicer):
        def __init__(self):
            self._store = {}
            logger.debug("🛎️🔧✅ TestKVHandler initialized with empty store")

        async def Get(self, request, context):
            key = request.key
            logger.debug(f"🛎️📖🔍 Get request for key: '{key}'")
            
            value = self._store.get(key, None)
            if value is None:
                logger.debug(f"🛎️📖❌ Key not found: '{key}'")
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Key not found: {key}")
                return kv_pb2.GetResponse()
            
            # Always ensure value is bytes
            if not isinstance(value, bytes):
                value = str(value).encode('utf-8')
                logger.debug(f"🛎️📖🔄 Converted value to bytes for key: '{key}'")
            
            logger.debug(f"🛎️📖✅ Returning value for key: '{key}', size: {len(value)} bytes")
            return kv_pb2.GetResponse(value=value)

        async def Put(self, request, context):
            try:
                key = request.key
                logger.debug(f"🛎️📤🔍 Put request for key: '{key}'")
                
                # Always store as bytes
                if isinstance(request.value, bytes):
                    value = request.value
                    logger.debug(f"🛎️📤✅ Storing bytes value for key: '{key}', size: {len(value)} bytes")
                else:
                    value = str(request.value).encode('utf-8')
                    logger.debug(f"🛎️📤🔄 Converted and storing string value for key: '{key}'")
                
                self._store[key] = value
                logger.debug(f"🛎️📤✅ Successfully stored value for key: '{key}'")
                return kv_pb2.Empty()
            except Exception as e:
                logger.error(f"🛎️📤❌ Error storing key '{key}': {e}")
                await context.abort(grpc.StatusCode.INTERNAL, str(e))
                return kv_pb2.Empty()

    return TestKVHandler()


@pytest.fixture(scope="function", autouse=True)
def ensure_socket_cleanup():
    """Ensure all test sockets are cleaned up after tests"""
    yield
    
    # Force cleanup any remaining test sockets
    import glob
    for socket_path in glob.glob("/tmp/pyvider_test_*"):
        try:
            logger.debug(f"🧹🔒🔍 Cleaning up leftover socket: {socket_path}")
            if os.path.exists(socket_path):
                os.chmod(socket_path, 0o777)
                os.unlink(socket_path)
                logger.debug(f"🧹🔒✅ Removed leftover socket: {socket_path}")
        except (OSError, PermissionError) as e:
            logger.warning(f"🧹🔒⚠️ Could not remove socket {socket_path}: {e}")


@pytest_asyncio.fixture
async def kv_transport(request):
    """Creates a transport for the KV server"""
    transport_type = getattr(request, "param", "unix")
    
    # Generate unique path with timestamp to prevent collisions
    unique_id = f"{time.time()}_{uuid.uuid4().hex[:8]}"
    
    if transport_type == "unix":
        unique_path = f"/tmp/pyvider_test_{unique_id}.sock"
        # Ensure path doesn't exist
        if os.path.exists(unique_path):
            os.unlink(unique_path)
        transport = UnixSocketTransport(path=unique_path)
        logger.debug(f"🧪🔌🚀 Created Unix transport with path: {unique_path}")
    else:
        transport = TCPSocketTransport(host="127.0.0.1")
        logger.debug(f"🧪🔌🚀 Created TCP transport")
    
    try:
        logger.debug(f"🧪🔌🔍 Starting transport listen")
        endpoint = await transport.listen()
        logger.debug(f"🧪🔌✅ Transport listening at: {endpoint}")
        yield transport
    finally:
        logger.debug(f"🧪🔌🔒 Closing transport")
        await transport.close()
        
        # Force socket cleanup for Unix sockets
        if transport_type == "unix" and hasattr(transport, 'path'):
            path = transport.path
            if os.path.exists(path):
                try:
                    logger.debug(f"🧪🔌🧹 Removing socket file: {path}")
                    os.chmod(path, 0o777)
                    os.unlink(path)
                except OSError as e:
                    logger.warning(f"🧪🔌⚠️ Failed to remove socket file: {e}")
        
        # Wait for resources to be properly released
        await asyncio.sleep(0.2)


@pytest_asyncio.fixture
async def kv_server(kv_handler, kv_transport, mock_server_config):
    """Provides KV server with proper resource management"""
    logger.debug(f"🧪🛎️🔧 Setting up KV server with transport: {kv_transport}")
    
    # Create server with transport that's already listening
    server = RPCPluginServer(
        protocol=KVProtocol(),
        handler=kv_handler,
        config=mock_server_config,
        transport=kv_transport,
    )
    
    # Initialize the server futures/events
    server._serving_future = asyncio.Future()
    server._serving_event = asyncio.Event()
    
    # Start server in background task
    logger.debug(f"🧪🛎️🚀 Starting KV server")
    serve_task = asyncio.create_task(server.serve())
    
    # Wait for server to be ready with timeout
    try:
        await asyncio.wait_for(server.wait_for_server_ready(), timeout=5.0)
        logger.debug(f"🧪🛎️✅ KV server ready")
    except asyncio.TimeoutError:
        logger.error("🧪🛎️❌ Timed out waiting for server to become ready")
        serve_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await serve_task
        raise
    
    try:
        yield server
    finally:
        # Proper cleanup in reverse order
        logger.debug(f"🧪🛎️🔒 Stopping KV server")
        await server.stop()
        
        logger.debug(f"🧪🛎️🔒 Canceling server task")
        serve_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await serve_task
        
        # Wait for cleanup to complete
        await asyncio.sleep(0.2)
        logger.debug(f"🧪🛎️✅ Server cleanup complete")


@pytest_asyncio.fixture
async def kv_client(kv_server):
    """Provides connected KV client"""
    logger.debug(f"🧪🙋🔧 Creating KV client")
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
    
    try:
        logger.debug(f"🧪🙋🚀 Starting KV client")
        await client.start()
        logger.debug(f"🧪🙋✅ KV client ready")
        yield client
    finally:
        logger.debug(f"🧪🙋🔒 Closing KV client")
        await client.close()
        logger.debug(f"🧪🙋✅ KV client closed")


@pytest.mark.asyncio
@pytest.mark.parametrize("kv_transport", ["tcp", "unix"], indirect=True)
async def test_kv_put_get_flow(kv_client, mock_server_config):
    """Test basic Put/Get operations"""
    stub = kv_pb2_grpc.KVStub(kv_client._channel)
    logger.debug("🧪🔍🚀 Starting Put/Get test")

    # Put a value
    key = "test_key"
    value = b"test_value"
    logger.debug(f"🧪🔍📤 Putting key: {key}, value size: {len(value)}")
    await stub.Put(kv_pb2.PutRequest(key=key, value=value))

    # Get it back
    logger.debug(f"🧪🔍📥 Getting key: {key}")
    response = await stub.Get(kv_pb2.GetRequest(key=key))
    logger.debug(f"🧪🔍✅ Retrieved value size: {len(response.value)}")
    assert response.value == value


@pytest.mark.asyncio
@pytest.mark.parametrize("kv_transport", ["tcp", "unix"], indirect=True)
async def test_kv_missing_key(kv_client):
    """Test Get with nonexistent key"""
    stub = kv_pb2_grpc.KVStub(kv_client._channel)
    logger.debug("🧪🔍🚀 Starting missing key test")

    with pytest.raises(grpc.RpcError) as exc:
        logger.debug("🧪🔍📥 Getting nonexistent key")
        await stub.Get(kv_pb2.GetRequest(key="nonexistent"))
    
    logger.debug(f"🧪🔍✅ Got expected error: {exc.value.code()}")
    assert exc.value.code() == grpc.StatusCode.NOT_FOUND


@pytest.mark.asyncio
@pytest.mark.parametrize("kv_transport", ["tcp", "unix"], indirect=True)
async def test_kv_concurrent_operations(kv_client):
    """Test concurrent Put/Get operations"""
    stub = kv_pb2_grpc.KVStub(kv_client._channel)
    logger.debug("🧪🔍🚀 Starting concurrent operations test")

    # Create multiple concurrent operations
    async def put_get(i):
        key = f"key_{i}"
        value = f"value_{i}".encode()
        logger.debug(f"🧪🔍📤 Task {i}: Putting key: {key}")
        await stub.Put(kv_pb2.PutRequest(key=key, value=value))
        
        logger.debug(f"🧪🔍📥 Task {i}: Getting key: {key}")
        response = await stub.Get(kv_pb2.GetRequest(key=key))
        
        logger.debug(f"🧪🔍✅ Task {i}: Verifying value")
        assert response.value == value

    # Run concurrent operations
    logger.debug(f"🧪🔍🔄 Starting 10 concurrent put/get operations")
    tasks = [put_get(i) for i in range(10)]
    await asyncio.gather(*tasks)
    logger.debug(f"🧪🔍✅ All concurrent operations completed successfully")

### 🐍🏗🧪️
