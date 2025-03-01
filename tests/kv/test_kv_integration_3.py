
# tests/kv/test_kv_integration_3.py

import asyncio
import contextlib
import os
import sys
import time
import uuid
from typing import AsyncGenerator, Optional

import grpc
import pytest
import pytest_asyncio

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport

from tests.fixtures import *
from tests.kv.proto import KVProtocol, kv_pb2, kv_pb2_grpc


def summarize_text(text: str, length: int = 32) -> str:
    """Helper to summarize text for logging."""
    if len(text) <= 2 * length:
        return text
    return f"{text[:length]} ... {text[-length:]}"


@pytest_asyncio.fixture
async def kv_handler():
    """Provides a real KV handler implementation with proper bytes/string handling."""
    class TestKVHandler(kv_pb2_grpc.KVServicer):
        def __init__(self):
            self._store = {}
            logger.debug("🔌🚀✅ KV handler initialized")

        async def Get(self, request, context):
            key = request.key
            logger.debug(f"🔌📖🔍 Get request for key: '{key}'")
            
            value = self._store.get(key, None)
            if value is None:
                logger.debug(f"🔌📖❌ Key not found: '{key}'")
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Key not found: {key}")
                return None
            
            # Ensure value is returned as bytes
            if isinstance(value, str):
                value = value.encode('utf-8')
                
            logger.debug(f"🔌📖✅ Retrieved value for key '{key}', size: {len(value)} bytes")
            return kv_pb2.GetResponse(value=value)

        async def Put(self, request, context):
            try:
                key = request.key
                value = request.value
                logger.debug(f"🔌📤🔍 Put request for key: '{key}', value type: {type(value).__name__}")
                
                # Store value as bytes regardless of input type
                if isinstance(value, str):
                    value = value.encode('utf-8')
                    
                self._store[key] = value
                
                value_summary = summarize_text(value.decode('utf-8', errors='replace'))
                logger.debug(f"🔌📤✅ Stored key '{key}' with value: {value_summary}")
                return kv_pb2.Empty()
                
            except Exception as e:
                logger.error(f"🔌📤❌ Error in Put operation: {e}")
                await context.abort(grpc.StatusCode.INTERNAL, str(e))
                return None

    return TestKVHandler()


@pytest_asyncio.fixture
async def unique_transport_path():
    """Generate a unique path for Unix socket transport with timestamp."""
    unique_id = f"{time.time()}_{uuid.uuid4().hex}"
    socket_path = f"/tmp/pyvider_kv_test_{unique_id}.sock"
    
    # Ensure path doesn't exist before starting
    if os.path.exists(socket_path):
        try:
            os.chmod(socket_path, 0o777)  # Ensure permissions
            os.unlink(socket_path)
        except OSError as e:
            logger.warning(f"🔌🧹⚠️ Failed to clean up existing socket: {e}")
    
    yield socket_path
    
    # Cleanup after test
    if os.path.exists(socket_path):
        try:
            os.chmod(socket_path, 0o777)
            os.unlink(socket_path)
        except OSError as e:
            logger.warning(f"🔌🧹⚠️ Failed to clean up socket: {e}")


@pytest_asyncio.fixture(params=["tcp", "unix"])
async def transport_fixture(request, unique_transport_path) -> AsyncGenerator[tuple[str, TransportT], None]:
    """Fixture providing different transport types with proper cleanup."""
    transport_type = request.param
    transport = None
    
    try:
        if transport_type == "tcp":
            transport = TCPSocketTransport(host="127.0.0.1")
            logger.debug(f"🔌🚀✅ Created TCP transport")
        else:
            transport = UnixSocketTransport(path=unique_transport_path)
            logger.debug(f"🔌🚀✅ Created Unix transport at {unique_transport_path}")
            
        yield transport_type, transport
    finally:
        # Clean up transport
        if transport:
            logger.debug(f"🔌🔒🚀 Closing {transport_type} transport")
            await transport.close()
            if transport_type == "unix" and os.path.exists(unique_transport_path):
                try:
                    os.chmod(unique_transport_path, 0o777)
                    os.unlink(unique_transport_path)
                except OSError as e:
                    logger.warning(f"🔌🧹⚠️ Error during socket cleanup: {e}")


@pytest_asyncio.fixture
async def kv_server(transport_fixture, kv_handler, mock_server_config):
    """Provides a running KV server with proper lifecycle management."""
    transport_type, transport = transport_fixture
    ready_event = asyncio.Event()
    
    logger.debug(f"🛎️🚀🔍 Starting KV server with {transport_type} transport")
    
    server = RPCPluginServer(
        protocol=KVProtocol(),
        handler=kv_handler,
        config=mock_server_config,
        transport=transport,
    )
    
    # Prepare for serving but don't start yet
    server._serving_future = asyncio.Future()
    server._serving_event = asyncio.Event()
    
    # Start listener before serving
    endpoint = await transport.listen()
    logger.debug(f"🛎️🕹✅ Server transport listening at {endpoint}")
    
    # Start server in background task
    serve_task = asyncio.create_task(server.serve())
    
    # Wait for server to be ready
    try:
        await asyncio.wait_for(server.wait_for_server_ready(), timeout=5.0)
        logger.debug("🛎️✅👍 KV server is ready")
        ready_event.set()
    except asyncio.TimeoutError:
        logger.error("🛎️⏱️❌ Timeout waiting for server to be ready")
        raise RuntimeError("Server failed to become ready in time")
    
    try:
        yield server
    finally:
        logger.debug("🛎️🔒🚀 Stopping KV server")
        # Stop server gracefully
        await server.stop()
        
        # Cancel and clean up server task
        serve_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await serve_task
            
        logger.debug("🛎️🔒✅ KV server stopped")


@pytest_asyncio.fixture
async def kv_client(kv_server, transport_fixture):
    """Provides a properly configured KV client that connects to the server."""
    transport_type, _ = transport_fixture
    logger.debug(f"🙋🚀🔍 Creating KV client with {transport_type} transport")
    
    # Set up environment for client
    env = {
        "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
        "PLUGIN_MAGIC_COOKIE": "hello",
        "PLUGIN_PROTOCOL_VERSIONS": "1",
        "PLUGIN_TRANSPORTS": transport_type,
        "PLUGIN_AUTO_MTLS": "true",
    }
    
    # Create client directly - we're not using a subprocess as we're
    # connecting to an already running server
    client = RPCPluginClient(
        command=[sys.executable, "-m", "tests.kv.py_kv_server"],
        config={"env": env},
    )
    
    try:
        logger.debug("🙋🚀🚀 Starting KV client")
        await client.start()
        logger.debug("🙋🚀✅ KV client started")
        yield client
    finally:
        logger.debug("🙋🔒🚀 Closing KV client")
        await client.close()
        logger.debug("🙋🔒✅ KV client closed")


@pytest.mark.asyncio
async def test_kv_put_get_flow(kv_client):
    """Test basic Put/Get operations with proper error handling."""
    stub = kv_pb2_grpc.KVStub(kv_client._channel)
    logger.debug("🔌🧪🚀 Starting Put/Get flow test")
    
    # Put a value
    key = "test_key"
    value = b"test_value"
    
    try:
        await stub.Put(kv_pb2.PutRequest(key=key, value=value))
        logger.debug(f"🔌🧪✅ Put operation successful for key '{key}'")
        
        # Get it back
        response = await stub.Get(kv_pb2.GetRequest(key=key))
        logger.debug(f"🔌🧪✅ Get operation successful for key '{key}'")
        
        # Verify the value
        assert response.value == value, f"Expected {value!r}, got {response.value!r}"
        logger.debug("🔌🧪👍 Value verification successful")
        
    except grpc.RpcError as e:
        logger.error(f"🔌🧪❌ gRPC error during Put/Get test: {e.code()}: {e.details()}")
        raise
    except Exception as e:
        logger.error(f"🔌🧪❌ Unexpected error during Put/Get test: {e}")
        raise


@pytest.mark.asyncio
async def test_kv_missing_key(kv_client):
    """Test Get with nonexistent key and verify proper error handling."""
    stub = kv_pb2_grpc.KVStub(kv_client._channel)
    logger.debug("🔌🧪🚀 Starting missing key test")
    
    with pytest.raises(grpc.RpcError) as exc_info:
        await stub.Get(kv_pb2.GetRequest(key="nonexistent_key"))
    
    # Verify the error code
    assert exc_info.value.code() == grpc.StatusCode.NOT_FOUND, \
        f"Expected NOT_FOUND, got {exc_info.value.code()}"
    
    logger.debug(f"🔌🧪✅ Missing key test passed: received expected NOT_FOUND error")


@pytest.mark.asyncio
async def test_kv_concurrent_operations(kv_client):
    """Test concurrent Put/Get operations with proper validation."""
    stub = kv_pb2_grpc.KVStub(kv_client._channel)
    logger.debug("🔌🧪🚀 Starting concurrent operations test")
    
    # Number of concurrent operations
    operation_count = 10
    success_count = 0
    
    # Create operation function
    async def put_get(i: int) -> bool:
        try:
            key = f"concurrent_key_{i}"
            value = f"concurrent_value_{i}".encode('utf-8')
            
            logger.debug(f"🔌🧪🔍 Concurrent operation {i}: Put")
            await stub.Put(kv_pb2.PutRequest(key=key, value=value))
            
            logger.debug(f"🔌🧪🔍 Concurrent operation {i}: Get")
            response = await stub.Get(kv_pb2.GetRequest(key=key))
            
            # Verify response
            assert response.value == value, \
                f"Operation {i}: Expected {value!r}, got {response.value!r}"
                
            logger.debug(f"🔌🧪✅ Concurrent operation {i} successful")
            return True
        except Exception as e:
            logger.error(f"🔌🧪❌ Concurrent operation {i} failed: {e}")
            return False
    
    # Run concurrent operations
    results = await asyncio.gather(
        *[put_get(i) for i in range(operation_count)], 
        return_exceptions=False
    )
    
    # Count successes
    success_count = sum(1 for result in results if result)
    
    logger.debug(f"🔌🧪🔄 Concurrent operations completed: {success_count}/{operation_count} successful")
    assert success_count == operation_count, f"Only {success_count}/{operation_count} operations succeeded"
