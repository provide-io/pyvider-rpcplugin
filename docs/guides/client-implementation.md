---
title: Client Implementation
description: How to implement a plugin client in Pyvider RPC Plugin
---

# Client Implementation Guide

This guide provides detailed instructions on implementing a plugin client using Pyvider RPC Plugin. The client is the host application side of the client-server relationship—it launches plugins, communicates with them, and uses their functionality.

## Client Lifecycle

A Pyvider plugin client follows this typical lifecycle:

1. **Initialization**: Create the client instance
2. **Launch**: Start the plugin process
3. **Connection**: Establish a secure connection
4. **Interface Access**: Get a type-safe interface to the plugin
5. **Operation**: Make RPC calls to the plugin
6. **Termination**: Close the connection and shut down the plugin

Let's go through each step in detail.

## 1. Client Initialization

First, create an instance of `RPCPluginClient`:

```python
from pyvider.rpcplugin.client import RPCPluginClient

client = RPCPluginClient(
    command=["python", "my_plugin.py"],
    config={
        "env": {
            "PLUGIN_MAGIC_COOKIE_KEY": "MY_PLUGIN",
            "PLUGIN_MAGIC_COOKIE": "supersecret",
            "PLUGIN_LOG_LEVEL": "INFO"
        }
    }
)
```

The parameters are:
- `command`: List of command-line arguments to launch the plugin process
- `config`: Optional configuration dictionary with settings like environment variables

Think of this as gathering all the information needed before making a phone call—you need the phone number and any special codes before you can dial.

## 2. Plugin Launch and Connection

Start the plugin and establish a connection:

```python
# Launch the plugin and establish connection
await client.start()
```

The `start()` method:
1. Launches the plugin process
2. Sets up client certificates if using mTLS
3. Waits for the plugin to output its handshake response
4. Parses the handshake information
5. Connects to the plugin's transport endpoint
6. Establishes a secure gRPC channel

This is where the actual "phone call" begins—you dial the number, wait for the other party to answer, and establish a connection.

## 3. Interface Access

Get a type-safe interface to the plugin's functionality:

```python
# Get a typed interface to the plugin's service
my_service = await client.get_interface(my_service_pb2_grpc.MyServiceStub)
```

The `get_interface()` method:
1. Takes a gRPC stub class generated from your protobuf
2. Returns an initialized stub connected to the plugin
3. Provides a type-safe interface for making RPC calls

This is like getting through to the specific department you want to talk to—now you can make specific requests.

## 4. Plugin Operation

Now you can make RPC calls to the plugin:

```python
# Make RPC calls to the plugin
response = await my_service.SomeMethod(
    my_service_pb2.SomeRequest(input="Hello, plugin!")
)

print(f"Plugin response: {response.result}")
```

You can make as many calls as needed, just like having a conversation with multiple exchanges.

## 5. Plugin Termination

When you're done, close the client:

```python
# Close the connection and terminate the plugin
await client.close()
```

The `close()` method:
1. Closes the gRPC channel
2. Terminates the plugin process
3. Cleans up any resources

This is like politely ending the call and hanging up the phone.

## Complete Example

Here's a complete example combining all the steps:

```python
#!/usr/bin/env python3
# client_example.py

import asyncio

from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.logger import logger

import my_service_pb2
import my_service_pb2_grpc


async def main():
    """Example client usage."""
    logger.debug("🙋🚀✅ Starting client")
    
    # 1. Initialize the client
    client = RPCPluginClient(
        command=["python", "my_plugin.py"],
        config={
            "env": {
                "PLUGIN_MAGIC_COOKIE_KEY": "MY_PLUGIN",
                "PLUGIN_MAGIC_COOKIE": "supersecret",
            }
        }
    )
    
    try:
        # 2. Launch and connect to the plugin
        await client.start()
        logger.debug("🙋🚀✅ Plugin started successfully")
        
        # 3. Get a typed interface
        service = await client.get_interface(my_service_pb2_grpc.MyServiceStub)
        logger.debug("🙋🔌✅ Got service interface")
        
        # 4. Make RPC calls
        response = await service.SomeMethod(
            my_service_pb2.SomeRequest(input="Hello, plugin!")
        )
        logger.debug(f"🙋📥✅ Got response: {response.result}")
        
        print(f"Plugin response: {response.result}")
        
    except Exception as e:
        logger.error(f"🙋❌ Client error: {e}")
        raise
    finally:
        # 5. Close the client
        await client.close()
        logger.debug("🙋🔒✅ Client closed")


if __name__ == "__main__":
    asyncio.run(main())
```

## Advanced Client Features

### Custom Environment Variables

Pass custom environment variables to the plugin:

```python
client = RPCPluginClient(
    command=["python", "my_plugin.py"],
    config={
        "env": {
            "PLUGIN_MAGIC_COOKIE_KEY": "MY_PLUGIN",
            "PLUGIN_MAGIC_COOKIE": "supersecret",
            "MY_CUSTOM_VAR": "value",
            "PLUGIN_LOG_LEVEL": "DEBUG"
        }
    }
)
```

This allows configuring the plugin behavior without modifying its code.

### Custom Certificate Management

Provide custom certificates for mTLS:

```python
client = RPCPluginClient(
    command=["python", "my_plugin.py"],
    config={
        "PLUGIN_CLIENT_CERT": cert_pem,
        "PLUGIN_CLIENT_KEY": key_pem,
        "PLUGIN_AUTO_MTLS": "false"  # Disable auto mTLS when using custom certs
    }
)
```

This is useful for using persistent certificates or integrating with certificate management systems.

### Error Handling

Implement robust error handling for RPC calls:

```python
try:
    response = await service.SomeMethod(request)
except grpc.RpcError as e:
    status_code = e.code()
    if status_code == grpc.StatusCode.INVALID_ARGUMENT:
        logger.error(f"🙋❌ Invalid argument: {e.details()}")
        # Handle validation errors
    elif status_code == grpc.StatusCode.UNAVAILABLE:
        logger.error(f"🙋❌ Service unavailable: {e.details()}")
        # Handle connection issues
    else:
        logger.error(f"🙋❌ RPC error: {status_code}, {e.details()}")
        # Handle other errors
except Exception as e:
    logger.error(f"🙋❌ Unexpected error: {e}")
    # Handle non-gRPC errors
```

This differentiates between various error types and provides appropriate handling for each.

### Streaming Calls

Handle streaming RPC methods:

```python
# Server streaming
async def stream_data():
    request = streaming_pb2.StreamRequest(count=10)
    async for response in service.StreamData(request):
        logger.debug(f"🙋📥✅ Received stream item: {response.value}")
        yield response.value

# Client streaming
async def upload_data(items):
    async def request_iterator():
        for item in items:
            yield upload_pb2.UploadRequest(data=item)
            await asyncio.sleep(0.1)
    
    response = await service.Upload(request_iterator())
    logger.debug(f"🙋📥✅ Upload complete: {response.success}")
    return response.success

# Bidirectional streaming
async def chat():
    async def request_iterator():
        messages = ["Hello", "How are you?", "Goodbye"]
        for msg in messages:
            yield chat_pb2.ChatMessage(text=msg)
            await asyncio.sleep(1)
    
    async for response in service.Chat(request_iterator()):
        logger.debug(f"🙋📥✅ Received chat response: {response.text}")
        yield response.text
```

Streaming enables more efficient handling of scenarios like:
- Large data transfers
- Real-time communication
- Progress reporting
- Long-running operations

### Timeout Configuration

Set timeouts for RPC calls:

```python
# Global timeout
client = RPCPluginClient(
    command=["python", "my_plugin.py"],
    config={"timeout": 10.0}  # 10-second global timeout
)

# Per-call timeout
try:
    response = await asyncio.wait_for(
        service.SlowMethod(request),
        timeout=5.0  # 5-second timeout for this call
    )
except asyncio.TimeoutError:
    logger.error("🙋⏱️❌ RPC call timed out")
```

Timeouts prevent your application from hanging if a plugin becomes unresponsive.

### Plugin Restart

Implement a restart mechanism for plugins:

```python
async def restart_plugin():
    """Restart the plugin if it crashes."""
    await client.close()
    await client.start()
    return await client.get_interface(my_service_pb2_grpc.MyServiceStub)
```

This allows recovering from plugin crashes without restarting the host application.

## Best Practices

1. **Error Handling**: Always wrap RPC calls in try-except blocks
2. **Resource Management**: Use try-finally to ensure client.close() is called
3. **Timeouts**: Set reasonable timeouts for all RPC calls
4. **Retry Logic**: Implement retry logic for transient failures
5. **Versioning**: Handle protocol version negotiation gracefully

## Common Pitfalls

1. **Missing Magic Cookie**: Both key and value must be correct for the handshake to succeed
2. **Path Issues**: Ensure the plugin executable is at the specified path
3. **Protocol Mismatch**: Verify the client and plugin use compatible protocol versions
4. **Resource Leaks**: Always call client.close() when done with a plugin
5. **Blocking Operations**: Use asyncio.gather for concurrent operations

## Next Steps

Now that you understand how to implement a client, you might want to explore:

- [Server Implementation](server-implementation.md) for creating your own plugins
- [Protocol Definition](protocol-definition.md) for designing service interfaces
- [Application Integration](application-integration.md) for integrating plugins into your application
