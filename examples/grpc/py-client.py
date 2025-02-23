#!/usr/bin/env python3

from __future__ import annotations

import os

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.protocol import RPCPluginProtocol


class KVRPCProtocol(RPCPluginProtocol):
    """Protocol implementation for Go KV server."""

    def get_grpc_descriptors(self):
        """Get the gRPC service descriptors."""
        from proto import kv_pb2_grpc
        return kv_pb2_grpc, "KV"

    def add_to_server(self, instance: Any, server: Any) -> None:
        """Client-only implementation."""
        pass

class KVClient:
    """Client for Go KV server using pyvider-rpcplugin."""

    def __init__(self, server_path: str):
        """Initialize KV client.

        Args:
            server_path: Path to Go KV server executable
        """
        self.server_path = server_path
        self._client: RPCPluginClient | None = None
        self._stub = None

        # Configure environment for plugin
        os.environ.update({
            "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
            "PLUGIN_MAGIC_COOKIE": "hello",
            "PLUGIN_PROTOCOL_VERSIONS": "1",
            "PLUGIN_TRANSPORTS": "unix",
            "PLUGIN_AUTO_MTLS": "true"
        })

    async def connect(self):
        """Connect to the KV server."""
        try:
            # Create plugin client
            self._client = RPCPluginClient(
                command=[self.server_path],
                config={"plugins": {"kv_grpc": KVRPCProtocol()}}
            )

            # Start client and establish connection
            await self._client.start()
            await self._client.connect()

            # Verify channel exists
            if not self._client._channel:
                raise RuntimeError("🚨 gRPC channel not established")

            # Create gRPC stub
            from proto import kv_pb2_grpc
            self._stub = kv_pb2_grpc.KVStub(self._client._channel)

            logger.info("✅ Connected to KV server successfully")

        except Exception as e:
            logger.error(f"❌ Failed to connect to KV server: {e}")
            await self.close()
            raise

    async def close(self):
        """Close the connection."""
        if self._client:
            await self._client.stop()
            self._client = None
            self._stub = None

    async def put(self, key: str, value: bytes) -> None:
        """Put a value into the KV store.

        Args:
            key: Key to store value under
            value: Value to store
        """
        if not self._stub:
            raise RuntimeError("Not connected to KV server")

        try:
            logger.debug(f"📀 Attempting Put RPC with key={key}, value_size={len(value)}")
            from proto import kv_pb2
            await self._stub.Put(kv_pb2.PutRequest(
                key=key,
                value=value
            ))
            logger.debug(f"✅ Put successful: key={key}")

        except Exception as e:
            logger.error(f"❌ Put failed: key={key}, error={e}")
            raise

    async def get(self, key: str) -> bytes | None:
        """Get a value from the KV store.

        Args:
            key: Key to retrieve

        Returns:
            Value if found, None if not found
        """
        if not self._stub:
            raise RuntimeError("Not connected to KV server")

        try:
            from proto import kv_pb2
            response = await self._stub.Get(kv_pb2.GetRequest(key=key))
            value = response.value if response else None
            logger.debug(f"✅ Get successful: key={key}, found={'yes' if value else 'no'}")
            return value

        except Exception as e:
            logger.error(f"❌ Get failed: key={key}, error={e}")
            raise

# Example usage:
async def main():
    # Create client
    server_path = os.environ.get("PLUGIN_SERVER_PATH")
    if not server_path:
        pytest.fail("PLUGIN_SERVER_PATH environment variable not set")

    client = KVClient(server_path)

    try:
        # Connect to server
        await client.connect()

        # Store a value
        await client.put("hello", b"world")

        # Retrieve the value
        value = await client.get("hello")
        print(f"Value: {value.decode() if value else None}")

    finally:
        await client.close()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())