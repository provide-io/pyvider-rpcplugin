#!/usr/bin/env python3

import argparse
import asyncio
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, cast

import grpc

# Simple, robust path setup for plugin system
examples_dir = Path(__file__).resolve().parent.parent.parent
project_root = examples_dir.parent
src_dir = project_root / "src"

if src_dir.exists() and str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Generated code imports
try:
    from .proto import kv_pb2, kv_pb2_grpc
except ImportError:
    # Fallback for absolute imports
    from examples.kvproto.py_rpc.proto import kv_pb2, kv_pb2_grpc

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.telemetry import logger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)s: 🐍 C> %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

class KVClient:
    """Client for KV plugin server with proper plugin system integration."""
    
    def __init__(self, server_command: list[str] | None = None):
        """Initialize KV client.
        
        Args:
            server_command: Command to start the KV server plugin.
                          If None, assumes server is already running externally.
        """
        self.server_command = server_command or ["python", "py_kv_server.py"]
        self.plugin_client = None
        self.stub = None
    
    async def connect(self):
        """Connect to the KV server via plugin system."""
        logger.info(f"🔗 Starting KV plugin client")
        
        # Create plugin client
        self.plugin_client = RPCPluginClient(
            command=self.server_command,
            config={"timeout": 30.0}
        )
        
        try:
            # Start the plugin client (this starts the server subprocess)
            await self.plugin_client.start()
            
            # Get the gRPC channel from the plugin client
            if self.plugin_client.grpc_channel:
                self.stub = kv_pb2_grpc.KVStub(self.plugin_client.grpc_channel)
                logger.info("✅ Connected to KV plugin server")
            else:
                raise RuntimeError("Failed to get gRPC channel from plugin client")
                
        except Exception as e:
            logger.error(f"❌ Failed to connect to KV plugin: {e}")
            raise
    
    async def put(self, key: str, value: bytes):
        """Store a key-value pair."""
        if not self.stub:
            await self.connect()
        
        request = kv_pb2.PutRequest(key=key, value=value)
        try:
            await self.stub.Put(request)
            logger.info(f"✅ PUT {key} = {len(value)} bytes")
        except grpc.RpcError as e:
            logger.error(f"❌ PUT failed: {e}")
            raise
    
    async def get(self, key: str) -> bytes:
        """Retrieve a value by key."""
        if not self.stub:
            await self.connect()
        
        request = kv_pb2.GetRequest(key=key)
        try:
            response = await self.stub.Get(request)
            logger.info(f"✅ GET {key} = {len(response.value)} bytes")
            return response.value
        except grpc.RpcError as e:
            logger.error(f"❌ GET failed: {e}")
            raise
    
    async def close(self):
        """Close the plugin client connection."""
        if self.plugin_client:
            await self.plugin_client.stop()
            logger.info("🔌 Plugin client connection closed")

async def main():
    """Main client function."""
    parser = argparse.ArgumentParser(description="KV Plugin Client")
    parser.add_argument("operation", choices=["put", "get"], help="Operation to perform")
    parser.add_argument("key", help="Key to operate on")
    parser.add_argument("value", nargs="?", help="Value for put operation")
    parser.add_argument("--server-cmd", nargs="+", 
                       default=["python", "py_kv_server.py"],
                       help="Command to start KV server plugin")
    
    args = parser.parse_args()
    
    # Create client with server command
    client = KVClient(server_command=args.server_cmd)
    
    try:
        if args.operation == "put":
            if not args.value:
                logger.error("❌ Value required for put operation")
                return
            await client.put(args.key, args.value.encode())
        elif args.operation == "get":
            value = await client.get(args.key)
            print(f"Value: {value.decode()}")
    except Exception as e:
        logger.error(f"❌ Operation failed: {e}")
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())

# 🐍🔑
