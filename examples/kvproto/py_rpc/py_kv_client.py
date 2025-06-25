#!/usr/bin/env python3

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Any, cast

import grpc

# Simple, robust path setup
examples_dir = Path(__file__).resolve().parent.parent.parent
project_root = examples_dir.parent
src_dir = project_root / "src"

if src_dir.exists() and str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Generated code import - simplified
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
    """Client for KV plugin server with improved error handling & diagnostics."""
    
    def __init__(self, address: str = "localhost:50051"):
        self.address = address
        self.channel = None
        self.stub = None
    
    async def connect(self):
        """Connect to the KV server."""
        logger.info(f"🔗 Connecting to KV server at {self.address}")
        self.channel = grpc.aio.insecure_channel(self.address)
        self.stub = kv_pb2_grpc.KVStub(self.channel)
        logger.info("✅ Connected to KV server")
    
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
        """Close the connection."""
        if self.channel:
            await self.channel.close()
            logger.info("🔌 Connection closed")

async def main():
    """Main client function."""
    parser = argparse.ArgumentParser(description="KV Client")
    parser.add_argument("operation", choices=["put", "get"], help="Operation to perform")
    parser.add_argument("key", help="Key to operate on")
    parser.add_argument("value", nargs="?", help="Value for put operation")
    parser.add_argument("--address", default="localhost:50051", help="Server address")
    
    args = parser.parse_args()
    
    client = KVClient(args.address)
    
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
