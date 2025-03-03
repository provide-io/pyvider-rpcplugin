#!/usr/bin/env python3
# tests/kv/test_go_python_interop.py

import asyncio
import os
import pytest
import pytest_asyncio
import time
from typing import AsyncGenerator, Callable, Dict, Generator, Optional

import grpc

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.exception import HandshakeError, TransportError
from pyvider.rpcplugin.logger import logger
from tests.kv.proto import KVProtocol, kv_pb2, kv_pb2_grpc
from tests.fixtures import *

# Constants
DEFAULT_GO_SERVER_PATH = "./tests/kv/go-plugin/bin/kv-go-server"
TEST_TIMEOUT = 15.0  # seconds
LARGE_VALUE_SIZE = 1 * 1024 * 1024  # 1MB
SPECIAL_CHARACTERS = "!@#$%^&*()_+{}|:<>?[];',./`~"


@pytest_asyncio.fixture
async def go_server_path() -> str:
    """Return the path to the Go server executable."""
    path = os.environ.get("GO_SERVER_PATH", DEFAULT_GO_SERVER_PATH)
    logger.debug(f"🧪🔍✅ Using Go server path: {path}")

    # Verify the path exists
    if not os.path.exists(path):
        logger.error(f"🧪🔍❌ Go server binary not found at {path}")
        pytest.skip(f"Go server binary not found at {path}")

    return path


@pytest_asyncio.fixture
async def go_server_env() -> Dict[str, str]:
    """Return the environment variables for the Go server."""
    return {
        "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
        "PLUGIN_MAGIC_COOKIE": "hello",
        "PLUGIN_PROTOCOL_VERSIONS": "1",
        "PLUGIN_TRANSPORTS": "unix",  # Force Unix transport for stability
        "PLUGIN_AUTO_MTLS": "true",   # Enable mTLS
        "PYTHONUNBUFFERED": "1",      # Disable Python buffering
        "PLUGIN_SHOW_EMOJI_MATRIX": "true",  # Show emoji matrix for better logs
        "GODEBUG": "asyncpreemptoff=1",      # Improve Go output behavior
    }


@pytest_asyncio.fixture
async def kv_go_client(go_server_path: str, go_server_env: Dict[str, str]) -> AsyncGenerator[RPCPluginClient, None]:
    """Create and yield a RPCPluginClient connected to a Go KV server."""
    client = None
    logger.debug(f"🧪🚀🔍 Creating RPCPluginClient for Go server at {go_server_path}")

    try:
        # Create client with Go server command
        client = RPCPluginClient(
            command=[go_server_path],
            config={"env": go_server_env}
        )

        # Start client with timeout
        logger.debug(f"🧪🚀🔄 Starting client with {TEST_TIMEOUT}s timeout")
        start_time = time.time()
        await asyncio.wait_for(client.start(), timeout=TEST_TIMEOUT)
        logger.debug(f"🧪🚀✅ Client started successfully in {time.time() - start_time:.2f}s")

        yield client

    except asyncio.TimeoutError:
        logger.error("🧪🚀❌ Client start timed out")
        if client:
            await client.close()
        pytest.fail("Client connection to Go server timed out")
    except Exception as e:
        logger.error(f"🧪🚀❌ Failed to create/start client: {e}")
        if client:
            await client.close()
        pytest.fail(f"Failed to connect to Go server: {e}")
    finally:
        # Clean up
        if client:
            logger.debug("🧪🔒🚀 Closing client...")
            try:
                await client.close()
                logger.debug("🧪🔒✅ Client closed successfully")
            except Exception as e:
                logger.error(f"🧪🔒❌ Error closing client: {e}")


@pytest_asyncio.fixture
async def kv_stub(kv_go_client: RPCPluginClient) -> kv_pb2_grpc.KVStub:
    """Create and return a KV stub for the Go server."""
    logger.debug("🧪🔌🚀 Creating KV stub")
    stub = kv_pb2_grpc.KVStub(kv_go_client._channel)
    logger.debug("🧪🔌✅ KV stub created successfully")
    return stub


@pytest.mark.asyncio
async def test_go_server_basic_operations(kv_stub: kv_pb2_grpc.KVStub):
    """Test basic Put/Get operations with Go server."""
    logger.debug("🧪📤🚀 Testing basic Put operation")

    # Prepare test data
    key = "test_basic_key"
    value = "test_basic_value".encode("utf-8")

    # Put
    try:
        await kv_stub.Put(kv_pb2.PutRequest(key=key, value=value))
        logger.debug(f"🧪📤✅ Put operation successful for key '{key}'")
    except grpc.RpcError as e:
        logger.error(f"🧪📤❌ Put operation failed: {e.details()}")
        pytest.fail(f"Put operation failed: {e.details()}")

    # Get
    try:
        logger.debug(f"🧪📥🚀 Testing Get operation for key '{key}'")
        response = await kv_stub.Get(kv_pb2.GetRequest(key=key))
        logger.debug(f"🧪📥✅ Get operation successful for key '{key}'")

        # Verify value
        assert response.value == value, f"Value mismatch: expected {value!r}, got {response.value!r}"
        logger.debug("🧪🔍✅ Value verification successful")
    except grpc.RpcError as e:
        logger.error(f"🧪📥❌ Get operation failed: {e.details()}")
        pytest.fail(f"Get operation failed: {e.details()}")


@pytest.mark.asyncio
async def test_go_server_empty_values(kv_stub: kv_pb2_grpc.KVStub):
    """Test operations with empty values."""
    logger.debug("🧪🔍🚀 Testing operations with empty values")

    # Empty key (should be accepted)
    empty_key = ""
    value = "value_for_empty_key".encode("utf-8")

    try:
        await kv_stub.Put(kv_pb2.PutRequest(key=empty_key, value=value))
        logger.debug("🧪📤✅ Put operation with empty key successful")

        response = await kv_stub.Get(kv_pb2.GetRequest(key=empty_key))
        logger.debug("🧪📥✅ Get operation with empty key successful")
        assert response.value == value
    except grpc.RpcError as e:
        # Some implementations may reject empty keys - log but don't fail
        logger.warning(f"🧪⚠️ Empty key operation returned error: {e.details()}")

    # Empty value
    key = "key_for_empty_value"
    empty_value = b""

    try:
        await kv_stub.Put(kv_pb2.PutRequest(key=key, value=empty_value))
        logger.debug("🧪📤✅ Put operation with empty value successful")

        response = await kv_stub.Get(kv_pb2.GetRequest(key=key))
        logger.debug("🧪📥✅ Get operation for key with empty value successful")
        assert response.value == empty_value
    except grpc.RpcError as e:
        logger.error(f"🧪❌ Empty value operation failed: {e.details()}")
        pytest.fail(f"Empty value operation failed: {e.details()}")


@pytest.mark.asyncio
async def test_go_server_special_characters(kv_stub: kv_pb2_grpc.KVStub):
    """Test operations with special characters in keys and values."""
    logger.debug("🧪🔍🚀 Testing operations with special characters")

    # Special characters in key
    key_with_special = f"special_key_{SPECIAL_CHARACTERS}"
    value = "value_for_special_key".encode("utf-8")

    try:
        await kv_stub.Put(kv_pb2.PutRequest(key=key_with_special, value=value))
        logger.debug("🧪📤✅ Put operation with special characters in key successful")

        response = await kv_stub.Get(kv_pb2.GetRequest(key=key_with_special))
        logger.debug("🧪📥✅ Get operation with special characters in key successful")
        assert response.value == value
    except grpc.RpcError as e:
        logger.error(f"🧪❌ Special character key operation failed: {e.details()}")
        pytest.fail(f"Special character key operation failed: {e.details()}")

    # Special characters in value
    key = "key_for_special_value"
    value_with_special = f"special_value_{SPECIAL_CHARACTERS}".encode("utf-8")

    try:
        await kv_stub.Put(kv_pb2.PutRequest(key=key, value=value_with_special))
        logger.debug("🧪📤✅ Put operation with special characters in value successful")

        response = await kv_stub.Get(kv_pb2.GetRequest(key=key))
        logger.debug("🧪📥✅ Get operation for key with special characters in value successful")
        assert response.value == value_with_special
    except grpc.RpcError as e:
        logger.error(f"🧪❌ Special character value operation failed: {e.details()}")
        pytest.fail(f"Special character value operation failed: {e.details()}")


@pytest.mark.asyncio
async def test_go_server_nonexistent_key(kv_stub: kv_pb2_grpc.KVStub):
    """Test Get operation for nonexistent key."""
    logger.debug("🧪🔍🚀 Testing Get operation for nonexistent key")

    nonexistent_key = "nonexistent_key_" + str(time.time())

    try:
        await kv_stub.Get(kv_pb2.GetRequest(key=nonexistent_key))
        logger.warning("🧪⚠️ Get operation for nonexistent key succeeded unexpectedly")
    except grpc.RpcError as e:
        # This should fail with NOT_FOUND
        if e.code() == grpc.StatusCode.NOT_FOUND:
            logger.debug("🧪🔍✅ Get operation for nonexistent key correctly returned NOT_FOUND")
        else:
            logger.error(f"🧪❌ Get operation for nonexistent key failed with unexpected error: {e.details()}")
            pytest.fail(f"Get operation for nonexistent key failed with unexpected error: {e.details()}")


@pytest.mark.asyncio
async def test_go_server_large_value(kv_stub: kv_pb2_grpc.KVStub):
    """Test operations with large values."""
    logger.debug(f"🧪🔍🚀 Testing operations with large value ({LARGE_VALUE_SIZE/1024:.1f} KB)")

    key = "key_for_large_value"
    large_value = b"x" * LARGE_VALUE_SIZE

    try:
        start_time = time.time()
        await kv_stub.Put(kv_pb2.PutRequest(key=key, value=large_value))
        put_duration = time.time() - start_time
        logger.debug(f"🧪📤✅ Put operation with large value successful ({put_duration:.3f}s)")

        start_time = time.time()
        response = await kv_stub.Get(kv_pb2.GetRequest(key=key))
        get_duration = time.time() - start_time
        logger.debug(f"🧪📥✅ Get operation for large value successful ({get_duration:.3f}s)")

        assert len(response.value) == LARGE_VALUE_SIZE, f"Large value size mismatch: expected {LARGE_VALUE_SIZE}, got {len(response.value)}"
        assert response.value == large_value, "Large value content mismatch"
        logger.debug("🧪🔍✅ Large value verification successful")
    except grpc.RpcError as e:
        # Some implementations might have size limits
        if e.code() == grpc.StatusCode.RESOURCE_EXHAUSTED:
            logger.warning(f"🧪⚠️ Large value operation returned RESOURCE_EXHAUSTED: {e.details()}")
            pytest.skip(f"Server doesn't support large values: {e.details()}")
        else:
            logger.error(f"🧪❌ Large value operation failed: {e.details()} (code={e.code()})")
            pytest.fail(f"Large value operation failed: {e.details()}")


@pytest.mark.asyncio
async def test_go_server_rapid_operations(kv_stub: kv_pb2_grpc.KVStub):
    """Test rapid sequence of Put/Get operations."""
    logger.debug("🧪🚀🔄 Testing rapid sequence of operations")

    operation_count = 10
    tasks = []

    # Create tasks for concurrent operations
    for i in range(operation_count):
        key = f"rapid_key_{i}"
        value = f"rapid_value_{i}".encode("utf-8")

        # Add Put task
        tasks.append(kv_stub.Put(kv_pb2.PutRequest(key=key, value=value)))

        # Add immediate Get task
        tasks.append(
            asyncio.create_task(
                verify_kv_operation(kv_stub, key, value)
            )
        )

    # Run all tasks concurrently
    start_time = time.time()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    duration = time.time() - start_time

    # Check results
    errors = [r for r in results if isinstance(r, Exception)]
    logger.debug(f"🧪🚀✅ Completed {len(tasks)} rapid operations in {duration:.3f}s")

    if errors:
        logger.error(f"🧪❌ {len(errors)}/{len(tasks)} rapid operations failed")
        for i, error in enumerate(errors[:3]):  # Log first 3 errors
            logger.error(f"🧪❌ Error {i+1}: {error}")
        pytest.fail(f"{len(errors)}/{len(tasks)} rapid operations failed")


async def verify_kv_operation(stub: kv_pb2_grpc.KVStub, key: str, expected_value: bytes) -> bool:
    """Helper to verify a key-value pair."""
    response = await stub.Get(kv_pb2.GetRequest(key=key))
    assert response.value == expected_value, f"Value mismatch for {key}"
    return True


if __name__ == "__main__":
    # Allow running the test directly
    import sys
    pytest.main(["-v", __file__])
