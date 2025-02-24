import os
from pathlib import Path
from typing import Any, Optional

import pytest
import pytest_asyncio
from proto import kv_pb2, kv_pb2_grpc  # Import the generated protobuf code

from pyvider.rpcplugin.logger import logger

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.protocol import RPCPluginProtocol


@pytest_asyncio.fixture(scope="function", autouse=True)
async def kv_test_env():
    """Setup test environment."""
    # Save original env
    old_env = {}
    for key in ['PLUGIN_MAGIC_COOKIE_KEY', 'PLUGIN_MAGIC_COOKIE',
                'PLUGIN_PROTOCOL_VERSIONS', 'PLUGIN_TRANSPORTS']:
        old_env[key] = os.environ.get(key)

    # Set test env
    os.environ.update({
        "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
        "PLUGIN_MAGIC_COOKIE": "hello",
        "PLUGIN_PROTOCOL_VERSIONS": "6",
        "PLUGIN_TRANSPORTS": "unix",
    })

    yield

    # Restore original env
    for key, value in old_env.items():
        if value is None:
            del os.environ[key]
        else:
            os.environ[key] = value

class KVRPCPlugin(RPCPluginProtocol):
    """Plugin for KV service that matches the Go server implementation."""

    def get_grpc_descriptors(self):
        """Get the gRPC service descriptors from the generated protobuf."""
        from proto import kv_pb2, kv_pb2_grpc
        # Return grpc module and service descriptor
        return kv_pb2_grpc, "KV"

    def add_to_server(self, instance: Any, server: Any) -> None:
        """Client only implementation."""
        pass

class KVClient:
    """Wrapper for KV operations."""
    def __init__(self, stub):
        self.stub = stub

    async def get(self, key: str) -> Optional[bytes]:
        """Get value for key."""
        try:
            from proto import kv_pb2
            response = await self.stub.Get(kv_pb2.GetRequest(key=key))
            return response.value
        except Exception as e:
            logger.error(f"Error in get operation: {e}")
            return None

    async def put(self, key: str, value: bytes) -> bool:
        """Put value for key."""
        try:
            from proto import kv_pb2
            await self.stub.Put(kv_pb2.PutRequest(key=key, value=value))
            return True
        except Exception as e:
            logger.error(f"Error in put operation: {e}")
            return False

@pytest_asyncio.fixture(scope="session")
def kv_server_bin():
    """Get path to the Go KV server binary."""
    parent_dir = Path(__file__).parent
    server_path = str(parent_dir / "bin/kv-go-server")

    # Verify binary exists
    if not os.path.exists(server_path):
        pytest.fail(f"KV server binary not found at {server_path}")

    return server_path

@pytest_asyncio.fixture(scope="function")
async def PLUGIN_CLIENT_PATH(kv_server_bin):
    """Create a KV client connected to the plugin server."""
    from proto import kv_pb2_grpc

    # Setup plugin environment
    env = {
        "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
        "PLUGIN_MAGIC_COOKIE": "hello",
        "PLUGIN_PROTOCOL_VERSIONS": "6",
        "PLUGIN_TRANSPORTS": "tcp,unix",
    }

    # Create client with config
    client = RPCPluginClient(
        command=[kv_server_bin],
        config={
            "env": env,
            "plugins": {
                "kv_grpc": KVRPCPlugin()
            }
        }
    )

    try:
        # Start client and establish connection
        await client.start()
        await client.connect()

        # Create the stub using the gRPC channel
        stub = kv_pb2_grpc.KVStub(client._channel)
        kv_service = KVClient(stub)

        yield kv_service

    finally:
        # Cleanup
        await client.stop()

@pytest.mark.asyncio
async def test_kv_basic_operations(PLUGIN_CLIENT_PATH):
    """Test basic KV operations."""
    # Test data
    key = "test_key"
    value = b"test_value"

    # Test get on non-existent key
    result = await PLUGIN_CLIENT_PATH.get(key)
    assert result is None, "Expected None for non-existent key"

    # Test put
    success = await PLUGIN_CLIENT_PATH.put(key, value)
    assert success, "Put operation failed"

    # Test get after put
    result = await PLUGIN_CLIENT_PATH.get(key)
    assert result == value, f"Expected {value}, got {result}"

# /*
# @pytest.mark.asyncio
# async def test_kv_multiple_operations(PLUGIN_CLIENT_PATH):
#     """Test multiple KV operations in sequence."""
#     test_data = {
#         "key1": b"value1",
#         "key2": b"value2",
#         "key3": b"value3"
#     }
# 
#     # Put multiple values
#     for key, value in test_data.items():
#         success = await PLUGIN_CLIENT_PATH.put(key, value)
#         assert success, f"Put failed for {key}"
# 
#     # Get them back
#     for key, expected_value in test_data.items():
#         value = await PLUGIN_CLIENT_PATH.get(key)
#         assert value == expected_value, f"Key {key}: expected {expected_value}, got {value}"
# 
# @pytest.mark.asyncio
# async def test_kv_empty_values(PLUGIN_CLIENT_PATH):
#     """Test handling of empty values."""
#     # Test empty value
#     success = await PLUGIN_CLIENT_PATH.put("empty_key", b"")
#     assert success, "Failed to put empty value"
# 
#     value = await PLUGIN_CLIENT_PATH.get("empty_key")
#     assert value == b"", "Empty value was not preserved"
# 
#     # Test empty key (should be ignored)
#     success = await PLUGIN_CLIENT_PATH.put("", b"test_value")
#     assert success, "Failed to put with empty key"
# 
#     value = await PLUGIN_CLIENT_PATH.get("")
#     assert value is None, "Empty key should be ignored"
# 

