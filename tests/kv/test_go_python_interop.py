
# tests/kv/test_go_python_interop.py

import asyncio
import logging
import os
import sys
import time

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.logger import logger
from tests.kv.proto import KVProtocol, kv_pb2, kv_pb2_grpc

# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s.%(msecs)03d %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Get Go server path from environment or use default
GO_SERVER_PATH = os.environ.get("GO_SERVER_PATH", "./go-plugin/bin/kv-go-server")

async def test_go_server_python_client():
    """Test Python client with Go server interoperability."""
    logger.info(f"🧪 Starting Go Server + Python Client interop test")
    logger.info(f"🧪 Using Go server at: {GO_SERVER_PATH}")

    # Set up environment for client
    env = {
        "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
        "PLUGIN_MAGIC_COOKIE": "hello",
        "PLUGIN_PROTOCOL_VERSIONS": "1",
        "PLUGIN_TRANSPORTS": "unix",  # Force Unix transport
        "PLUGIN_AUTO_MTLS": "true",   # Enable mTLS
        "PYTHONUNBUFFERED": "1",      # Disable Python buffering
    }

    # Create and start client
    client = None
    try:
        # Create client with go server command
        logger.info("🧪 Creating Python client for Go server")
        client = RPCPluginClient(
            command=[GO_SERVER_PATH],
            config={"env": env}
        )

        # Start with extended timeout
        logger.info("🧪 Starting client (with 15s timeout)")
        start_time = time.time()
        await asyncio.wait_for(client.start(), timeout=15.0)
        logger.info(f"🧪 Client started successfully in {time.time() - start_time:.2f}s")

        # Create KV stub
        logger.info("🧪 Creating KV stub")
        stub = kv_pb2_grpc.KVStub(client._channel)

        # Test Put operation
        logger.info("🧪 Testing Put operation")
        key = "test_interop_key"
        value = "test_interop_value".encode('utf-8')

        await stub.Put(kv_pb2.PutRequest(key=key, value=value))
        logger.info(f"🧪 Put operation successful for key '{key}'")

        # Test Get operation
        logger.info("🧪 Testing Get operation")
        response = await stub.Get(kv_pb2.GetRequest(key=key))

        # Verify result
        assert response.value == value, f"Value mismatch: expected {value!r}, got {response.value!r}"
        logger.info(f"🧪 Get operation successful for key '{key}'")

        logger.info("🧪 Interoperability test PASSED! 🎉")
        return True

    except Exception as e:
        logger.error(f"🧪 Interoperability test failed: {e}", exc_info=True)
        return False

    finally:
        # Close client
        if client:
            logger.info("🧪 Closing client")
            try:
                await client.close()
                logger.info("🧪 Client closed successfully")
            except Exception as e:
                logger.error(f"🧪 Error closing client: {e}")

if __name__ == "__main__":
    try:
        result = asyncio.run(test_go_server_python_client())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        logger.info("🧪 Test interrupted by user")
        sys.exit(130)

### 🐍🏗🧪️
