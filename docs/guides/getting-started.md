---
title: Getting Started
description: Quick start guide for using Pyvider RPC Plugin
---

# Getting Started with Pyvider RPC Plugin

This guide will help you quickly set up a basic plugin system using Pyvider RPC Plugin. We'll create a simple key-value store plugin and a host application to use it.

## Prerequisites

- Python 3.12 or later
- Basic understanding of async/await in Python
- Familiarity with gRPC concepts (recommended but not required)

## Installation

```bash
pip install pyvider-rpcplugin
```

## Basic Architecture

In our example, we'll create:

1. A **plugin server** that implements a key-value store
2. A **client application** that connects to the plugin and makes requests

## Step 1: Define the Protocol

First, let's create a protobuf file that defines our key-value store service. Save this as `keyvalue.proto`:

```protobuf
syntax = "proto3";
package keyvalue;

service KeyValue {
  rpc Get(GetRequest) returns (GetResponse);
  rpc Put(PutRequest) returns (PutResponse);
  rpc List(ListRequest) returns (ListResponse);
}

message GetRequest {
  string key = 1;
}

message GetResponse {
  string value = 1;
}

message PutRequest {
  string key = 1;
  string value = 2;
}

message PutResponse {
  bool success = 1;
}

message ListRequest {}

message ListResponse {
  repeated string keys = 1;
}
```

Now, generate the Python code from this proto file:

```bash
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. keyvalue.proto
```

This will create `keyvalue_pb2.py` and `keyvalue_pb2_grpc.py` files.

## Step 2: Implement the Plugin Server

Create a file named `kv_plugin.py` with the following content:

```python
#!/usr/bin/env python3
# kv_plugin.py

import asyncio
import os

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.logger import logger

import keyvalue_pb2
import keyvalue_pb2_grpc


class KVServicer(keyvalue_pb2_grpc.KeyValueServicer):
    """Implementation of the KeyValue service."""
    
    def __init__(self):
        logger.debug("🔌🚀✅ Initializing KVServicer")
        self._data = {}
    
    async def Get(self, request, context):
        """Get a value by key."""
        key = request.key
        logger.debug(f"🔌📥✅ Get request for key: {key}")
        
        value = self._data.get(key, "")
        logger.debug(f"🔌📤✅ Returning value: {value}")
        
        return keyvalue_pb2.GetResponse(value=value)
    
    async def Put(self, request, context):
        """Store a key-value pair."""
        key = request.key
        value = request.value
        logger.debug(f"🔌📥✅ Put request for key: {key}, value: {value}")
        
        self._data[key] = value
        logger.debug(f"🔌📤✅ Successfully stored key: {key}")
        
        return keyvalue_pb2.PutResponse(success=True)
    
    async def List(self, request, context):
        """List all keys."""
        logger.debug("🔌📥✅ List request received")
        
        keys = list(self._data.keys())
        logger.debug(f"🔌📤✅ Returning {len(keys)} keys")
        
        return keyvalue_pb2.ListResponse(keys=keys)


class KVProtocol(RPCPluginProtocol):
    """Protocol definition for the KeyValue service."""
    
    def get_grpc_descriptors(self):
        """Return the protobuf descriptor and service name."""
        return keyvalue_pb2.DESCRIPTOR, "KeyValue"
    
    def add_to_server(self, server, handler):
        """Add the service to a gRPC server."""
        keyvalue_pb2_grpc.add_KeyValueServicer_to_server(handler, server)


async def main():
    """Start the plugin server."""
    logger.debug("🔌🚀✅ Starting KeyValue plugin server")
    
    server = RPCPluginServer(
        protocol=KVProtocol(),
        handler=KVServicer()
    )
    
    try:
        await server.serve()
    except Exception as e:
        logger.error(f"🔌🚀❌ Server error: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
```

## Step 3: Create the Client Application

Now, let's create a client application that uses the plugin. Create a file named `kv_client.py`:

```python
#!/usr/bin/env python3
# kv_client.py

import asyncio
import sys

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.logger import logger

import keyvalue_pb2
import keyvalue_pb2_grpc


async def main():
    """Run the KeyValue client."""
    logger.debug("🙋🚀✅ Starting KeyValue client")
    
    # Create and start the plugin client
    client = RPCPluginClient(
        command=["python", "kv_plugin.py"],
        config={
            "env": {
                "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
                "PLUGIN_MAGIC_COOKIE": "hello",
            }
        }
    )
    
    try:
        # Launch the plugin process and establish connection
        await client.start()
        logger.debug("🙋🚀✅ Plugin started successfully")
        
        # Get the KeyValue service stub
        kv = await client.get_interface(keyvalue_pb2_grpc.KeyValueStub)
        logger.debug("🙋🔌✅ Obtained KeyValue interface")
        
        # Store some values
        await kv.Put(keyvalue_pb2.PutRequest(key="hello", value="world"))
        await kv.Put(keyvalue_pb2.PutRequest(key="foo", value="bar"))
        logger.debug("🙋📤✅ Put operations complete")
        
        # Retrieve a value
        response = await kv.Get(keyvalue_pb2.GetRequest(key="hello"))
        logger.debug(f"🙋📥✅ Get response: {response.value}")
        print(f"hello => {response.value}")
        
        # List all keys
        list_response = await kv.List(keyvalue_pb2.ListRequest())
        logger.debug(f"🙋📥✅ List response: {list_response.keys}")
        print(f"Keys: {', '.join(list_response.keys)}")
        
    except Exception as e:
        logger.error(f"🙋❌ Client error: {e}")
        raise
    finally:
        # Always close the client to terminate the plugin
        await client.close()
        logger.debug("🙋🔒✅ Client closed")


if __name__ == "__main__":
    asyncio.run(main())
```

## Step 4: Run the Example

Now, run the client application:

```bash
python kv_client.py
```

You should see output like:

```
hello => world
Keys: hello, foo
```

And if you enable debug logging (by setting `PLUGIN_LOG_LEVEL=DEBUG`), you'll see the detailed emoji-prefixed log messages showing the entire interaction.

## Understanding What's Happening

Let's break down what's happening:

1. The client application launches the plugin as a separate process.
2. The plugin performs a handshake with the client to negotiate protocol version, transport, and exchange certificates.
3. The client connects to the plugin using the negotiated transport.
4. The client makes RPC calls to the plugin's service methods.
5. The plugin processes these calls and returns responses.
6. Finally, the client closes the connection and terminates the plugin.

## Going Further

This basic example demonstrates the core functionality of Pyvider RPC Plugin. Here are some ways to enhance it:

- **Add persistence**: Modify the KVServicer to save data to disk
- **Implement authentication**: Add custom authentication checks in your service methods
- **Add streaming support**: Create streaming RPC methods for real-time updates
- **Handle errors**: Add proper error handling and status codes
- **Create multiple plugins**: Build a system with several specialized plugins

## Next Steps

Now that you have a basic understanding of Pyvider RPC Plugin, you might want to explore:

- [Server Implementation](server-implementation.md) for more details on creating plugin servers
- [Client Implementation](client-implementation.md) for more details on client features
- [Transport Layer](../concepts/transport.md) to understand how communication works
- [Security Model](../concepts/security.md) to learn about securing plugin communication
