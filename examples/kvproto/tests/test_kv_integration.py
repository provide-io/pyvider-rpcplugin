# examples/kvproto/test_kv_integration.py

import asyncio
import contextlib
import sys
from collections.abc import AsyncGenerator  # Added Dict, Any
from pathlib import Path  # Added
from typing import Any

import grpc
import pytest
import pytest_asyncio

from examples.kvproto.py_rpc.proto import KVProtocol, kv_pb2, kv_pb2_grpc
from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.telemetry import logger


@pytest_asyncio.fixture
async def mock_server_config() -> dict[str, Any]:
    """Provides a mock server configuration dictionary."""
    logger.debug("🔧🚀✅ Using mock server config")
    return {
        "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
        "PLUGIN_MAGIC_COOKIE_VALUE": "hello",
        # Add other necessary mock config values if the server fixture depends on them
    }


@pytest_asyncio.fixture
async def managed_unix_socket_path(tmp_path: Path) -> AsyncGenerator[str]:
    """Generate a unique Unix socket path in a temporary directory and ensure cleanup."""
    socket_file = tmp_path / "kv_test_socket.sock"
    socket_path = str(socket_file)
    logger.debug(f"🔌🔧🚀 Generated managed Unix socket path: {socket_path}")
    try:
        yield socket_path
    finally:
        # Ensure socket file is removed after test, if it exists
        if socket_file.exists():
            try:
                socket_file.unlink()
                logger.debug(f"🔌🔧✅ Cleaned up managed Unix socket: {socket_path}")
            except OSError as e:
                logger.error(f"🔌🔧❌ Error removing socket file {socket_path}: {e}")


def summarize_text(text: str, length: int = 32) -> str:
    """Helper to summarize text for logging."""
    if len(text) <= 2 * length:
        return text
    return f"{text[:length]} ... {text[-length:]}"


class TestKVHandler(kv_pb2_grpc.KVServicer):
    """KV service handler implementation with proper type handling."""

    def __init__(self) -> None:
        """Initialize an in-memory key-value store."""
        self._store = {}
        logger.debug("🔌🚀✅ KV handler initialized")

    async def Get(self, request, context):
        """Get a value by key with proper error handling."""
        key = request.key
        logger.debug(f"🔌📖🔍 Get request for key: '{key}'")

        value = self._store.get(key, None)
        if value is None:
            logger.debug(f"🔌📖❌ Key not found: '{key}'")
            await context.abort(grpc.StatusCode.NOT_FOUND, f"Key not found: {key}")
            return (
                kv_pb2.GetResponse()
            )  # Return empty response, will not be used because of abort

        # Ensure value is returned as bytes
        if isinstance(value, str):
            value = value.encode("utf-8")

        logger.debug(
            f"🔌📖✅ Retrieved value for key '{key}', size: {len(value)} bytes"
        )
        return kv_pb2.GetResponse(value=value)

    async def Put(self, request, context):
        try:
            key = request.key
            value = request.value

            # Store value as-is (should be bytes from gRPC)
            self._store[key] = value

            # For logging, convert to string if needed
            if isinstance(value, bytes):
                value_str = value.decode("utf-8", errors="replace")
                value_summary = summarize_text(value_str)
            else:
                # Handle case where value is already a string
                value_summary = summarize_text(str(value))

            logger.debug(f"🔌📤✅ Stored key '{key}' with value: {value_summary}")
            return kv_pb2.Empty()
        except Exception as e:
            logger.error(f"🔌📤❌ Error in Put operation: {e}")
            await context.abort(grpc.StatusCode.INTERNAL, str(e))
            return (
                kv_pb2.Empty()
            )  # Return empty response, will not be used because of abort


@pytest_asyncio.fixture
async def kv_handler() -> TestKVHandler:
    """Provides a test KV handler instance."""
    handler = TestKVHandler()
    logger.debug("🔌🚀✅ Created KV handler")
    return handler


@pytest_asyncio.fixture(params=["tcp", "unix"])
async def transport_fixture(request, managed_unix_socket_path):
    """Parameterized fixture for different transport types."""
    transport_type = request.param
    transport = None

    try:
        if transport_type == "tcp":
            transport = TCPSocketTransport(host="127.0.0.1")
            logger.debug("🔌🚀✅ Created TCP transport")
        else:
            transport = UnixSocketTransport(path=managed_unix_socket_path)
            logger.debug(f"🔌🚀✅ Created Unix transport at {managed_unix_socket_path}")

        yield transport_type, transport
    finally:
        # Clean up transport
        if transport:
            logger.debug(f"🔌🔒🚀 Closing {transport_type} transport")
            try:
                await transport.close()
                logger.debug(f"🔌🔒✅ {transport_type} transport closed")
            except Exception as e:
                logger.error(f"🔌🔒❌ Error closing {transport_type} transport: {e}")


@pytest_asyncio.fixture
async def kv_server(transport_fixture, kv_handler, monkeypatch): # Removed mock_server_config, added monkeypatch
    """Provides a running KV server with proper lifecycle management."""
    transport_type, transport = transport_fixture
    logger.debug(f"🛎️🚀🔍 Starting KV server with {transport_type} transport")

    # Store original config values to restore them later
    # Ensure rpcplugin_config is imported for direct use
    from pyvider.rpcplugin.config import rpcplugin_config as global_rpc_config

    original_config_values = {
        "PLUGIN_MAGIC_COOKIE_KEY": global_rpc_config.get("PLUGIN_MAGIC_COOKIE_KEY"),
        "PLUGIN_MAGIC_COOKIE_VALUE": global_rpc_config.get("PLUGIN_MAGIC_COOKIE_VALUE"),
    }

    # Set config for this test directly on the global config object
    test_cookie_key_name = "BASIC_PLUGIN"  # This is what the server will expect as the env var name
    test_expected_cookie_value = "hello"   # This is the value the server will expect in that env var

    global_rpc_config.set("PLUGIN_MAGIC_COOKIE_KEY", test_cookie_key_name)
    global_rpc_config.set("PLUGIN_MAGIC_COOKIE_VALUE", test_expected_cookie_value)

    # Simulate the client providing the cookie via environment variable
    monkeypatch.setenv(test_cookie_key_name, test_expected_cookie_value)
    logger.debug(f"🔑 Configured global rpcplugin_config and patched env for KV Server: {test_cookie_key_name}={test_expected_cookie_value}")

    server = RPCPluginServer(
        protocol=KVProtocol(),
        handler=kv_handler,
        config=None, # Explicitly None, so RPCPluginServer uses the (modified) global rpcplugin_config
        transport=transport,
    )

    # Prepare for serving
    server._serving_future = asyncio.Future()
    server._serving_event = asyncio.Event()
    server._shutdown_event = asyncio.Event()

    # Start server in background task
    serve_task = asyncio.create_task(server.serve())

    try:
        # Wait for server to be ready with increased timeout
        await asyncio.wait_for(server._serving_event.wait(), timeout=10.0)
        logger.debug("🛎️✅👍 KV server is ready")

        yield server
    except TimeoutError:
        logger.error("🛎️⏱️❌ Timeout waiting for server to be ready")
        # Try to stop server even if it didn't become ready
        await server.stop()
        serve_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await serve_task
        raise RuntimeError("Server failed to become ready in time")

    finally:
        logger.debug("🛎️🔒🚀 Stopping KV server")
        # Stop server gracefully
        await server.stop()

        # Cancel and clean up server task
        if not serve_task.done():
            serve_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await serve_task
        logger.debug("🛎️🔒✅ KV server stopped")

        # Restore original config values
        for key, val in original_config_values.items():
            global_rpc_config.set(key, val)
        logger.debug("🔧⚙️ Restored original rpcplugin_config values")


@pytest_asyncio.fixture
async def kv_client(kv_server, transport_fixture):
    """Provides a KV client connected to the server."""
    transport_type, transport = transport_fixture
    logger.debug(f"🙋🚀🔍 Creating KV client with {transport_type} transport")

    # Set up environment for client
    env = {
        "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
        "PLUGIN_MAGIC_COOKIE": "hello",  # This is what the client (test) sends to the plugin server via env var BASIC_PLUGIN
        "PLUGIN_MAGIC_COOKIE_VALUE": "hello",  # This is what the plugin server (py_kv_server.py) will expect
        "PLUGIN_PROTOCOL_VERSIONS": "1",
        "PLUGIN_TRANSPORTS": transport_type,
        "PLUGIN_AUTO_MTLS": "false",  # Ensure py_kv_server runs insecurely
    }

    # Create client
    client = RPCPluginClient(
        command=[sys.executable, "-m", "examples.kvproto.py_rpc.py_kv_server"],
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
async def test_kv_put_get_flow(kv_client) -> None:
    """Test basic Put/Get operations."""
    stub = kv_pb2_grpc.KVStub(kv_client.grpc_channel)
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
        logger.error(
            f"🔌🧪❌ gRPC error during Put/Get test: {e.code()}: {e.details()}"
        )
        raise
    except Exception as e:
        logger.error(f"🔌🧪❌ Unexpected error during Put/Get test: {e}")
        raise


@pytest.mark.asyncio
async def test_kv_missing_key(kv_client) -> None:
    """Test Get with nonexistent key."""
    stub = kv_pb2_grpc.KVStub(kv_client.grpc_channel)
    logger.debug("🔌🧪🚀 Starting missing key test")

    with pytest.raises(grpc.RpcError) as exc_info:
        await stub.Get(kv_pb2.GetRequest(key="nonexistent_key"))

    # Verify the error code
    assert exc_info.value.code() == grpc.StatusCode.NOT_FOUND, (
        f"Expected NOT_FOUND, got {exc_info.value.code()}"
    )

    logger.debug("🔌🧪✅ Missing key test passed: received expected NOT_FOUND error")


# TODO: Fix this.
# There is a race condition somewhere around here. I've seen it fail with:
# test_kv_concurrent_operations[unix] - AssertionError: Only 4/5 operations succeeded
@pytest.mark.asyncio
async def test_kv_concurrent_operations(kv_client) -> None:
    """Test concurrent Put/Get operations."""
    stub = kv_pb2_grpc.KVStub(kv_client.grpc_channel)
    logger.debug("🔌🧪🚀 Starting concurrent operations test")

    # Number of concurrent operations
    operation_count = 5  # Reduced count for faster tests

    # Create operation function
    async def put_get(i: int) -> bool:
        try:
            key = f"concurrent_key_{i}"
            value = f"concurrent_value_{i}".encode()

            logger.debug(f"🔌🧪🔍 Concurrent operation {i}: Put")
            await stub.Put(kv_pb2.PutRequest(key=key, value=value))

            logger.debug(f"🔌🧪🔍 Concurrent operation {i}: Get")
            response = await stub.Get(kv_pb2.GetRequest(key=key))

            # Verify response
            assert response.value == value, (
                f"Operation {i}: Expected {value!r}, got {response.value!r}"
            )

            logger.debug(f"🔌🧪✅ Concurrent operation {i} successful")
            return True
        except Exception as e:
            logger.error(f"🔌🧪❌ Concurrent operation {i} failed: {e}")
            return False

    # Run concurrent operations
    results = await asyncio.gather(
        *[put_get(i) for i in range(operation_count)], return_exceptions=True
    )

    # Count successes
    success_count = sum(1 for result in results if result is True)

    logger.debug(
        f"🔌🧪🔄 Concurrent operations completed: {success_count}/{operation_count} successful"
    )
    assert success_count == operation_count, (
        f"Only {success_count}/{operation_count} operations succeeded"
    )


### 🐍🏗🧪️
