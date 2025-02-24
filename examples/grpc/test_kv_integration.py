# test_kv_integration.py

import os
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.client import RPCPluginClient


# Define the KV Protocol class
class KVRPCPlugin:
    """Plugin for KV service."""

    def get_grpc_descriptors(self):
        """Get the gRPC service descriptors."""
        # In real implementation, we'd return protobuf descriptors
        return None, "kv_grpc"

    def add_to_server(self, instance: Any, server: Any) -> None:
        pass  # Client only in this test

@pytest_asyncio.fixture(scope="session")
def kv_server_bin():
    """Build the Go KV client and server binaries."""
    # Get the example directory path
    parent_dir = Path(__file__).parent
    server_path = str(parent_dir / "bin/kv-go-server")

    yield server_path

@pytest_asyncio.fixture(scope="function")
async def PLUGIN_CLIENT_PATH(kv_server_bin):
    """Create a KV client connected to the plugin."""
    # Setup environment
    os.environ.update({
        "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
        "PLUGIN_MAGIC_COOKIE": "hello",
        "PLUGIN_PROTOCOL_VERSIONS": "6",
        "PLUGIN_TRANSPORTS": "tcp",
    })

    # Create client with config
    client = RPCPluginClient(
        command=[kv_server_bin],
        config={
            "plugins": {
                "kv_grpc": KVRPCPlugin()
            }
        }
    )

    try:
        # Start the client and establish connection
        await client.start()
        await client.connect()
        yield client
    finally:
        await client.stop()

@pytest.mark.asyncio
async def test_kv_basic_operations(PLUGIN_CLIENT_PATH):
    """Test basic KV operations."""
    # Get the actual client instance
    client = await anext(PLUGIN_CLIENT_PATH)

    # Get the service
    kv_service = await client.client.dispense("kv_grpc")

    # Test data
    key = "test_key"
    value = b"test_value"

    # Try to get non-existent key
    result = await kv_service.get(key)
    assert result is None, "Expected None for non-existent key"

    # Put a value
    await kv_service.put(key, value)

    # Get the value back
    result = await kv_service.get(key)
    assert result == value, f"Expected {value}, got {result}"

@pytest.mark.asyncio
async def test_kv_multiple_operations(PLUGIN_CLIENT_PATH):
    """Test multiple KV operations in sequence."""
    # Get the actual client instance
    client = await anext(PLUGIN_CLIENT_PATH)

    # Get the service
    kv_service = await client.client.dispense("kv_grpc")

    test_data = {
        "key1": b"value1",
        "key2": b"value2",
        "key3": b"value3"
    }

    # Put multiple values
    for key, value in test_data.items():
        await kv_service.put(key, value)
        logger.debug(f"Put {key}={value}")

    # Get them back
    for key, expected_value in test_data.items():
        value = await kv_service.get(key)
        assert value == expected_value, f"Key {key}: expected {expected_value}, got {value}"

@pytest.mark.asyncio
async def test_kv_overwrite(PLUGIN_CLIENT_PATH):
    """Test overwriting an existing key."""
    # Get the actual client instance
    client = await anext(PLUGIN_CLIENT_PATH)

    # Get the service
    kv_service = await client.client.dispense("kv_grpc")

    key = "overwrite_key"
    value1 = b"original_value"
    value2 = b"new_value"

    # Put initial value
    await kv_service.put(key, value1)

    # Verify initial value
    result = await kv_service.get(key)
    assert result == value1

    # Overwrite with new value
    await kv_service.put(key, value2)

    # Verify new value
    result = await kv_service.get(key)
    assert result == value2

@pytest.mark.asyncio
async def test_kv_empty_values(PLUGIN_CLIENT_PATH):
    """Test handling of empty values."""
    # Get the actual client instance
    client = await anext(PLUGIN_CLIENT_PATH)

    # Get the service
    kv_service = await client.client.dispense("kv_grpc")

    # Test empty value
    await kv_service.put("empty_key", b"")
    result = await kv_service.get("empty_key")
    assert result == b"", "Empty value should be preserved"

    # Test empty key (should be ignored)
    await kv_service.put("", b"test_value")
    result = await kv_service.get("")
    assert result is None, "Empty key should be ignored"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
