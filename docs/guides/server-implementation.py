---
title: Server Implementation
description: How to implement a plugin server in Pyvider RPC Plugin
---

# Server Implementation Guide

This guide provides detailed instructions on implementing a plugin server using Pyvider RPC Plugin. The server is the plugin side of the client-server relationship—it provides the actual functionality that the host application will consume.

## Server Components

A Pyvider plugin server requires three key components:

1. **Protocol Definition**: Defines your service interface using gRPC
2. **Handler Implementation**: Implements the actual functionality
3. **Server Bootstrap**: Sets up and runs the plugin server

Let's explore each component in detail.

## 1. Protocol Definition

The protocol defines the interface between client and server. It specifies what methods are available and what data structures they use.

### Implementing `RPCPluginProtocol`

Create a class that extends `RPCPluginProtocol`:

```python
class MyProtocol(RPCPluginProtocol):
    """Protocol definition for your service."""
    
    def get_grpc_descriptors(self):
        """Return the protobuf descriptor and service name."""
        return my_service_pb2.DESCRIPTOR, "MyService"
    
    def add_to_server(self, server, handler):
        """Add the service to a gRPC server."""
        my_service_pb2_grpc.add_MyServiceServicer_to_server(handler, server)
```

The protocol class has two key responsibilities:
- Provide the protobuf descriptor and service name
- Register your handler with the gRPC server

Think of this as the diplomat who knows how to translate between your service's language and the gRPC protocol language.

## 2. Handler Implementation

The handler contains your actual business logic. It implements the service interface defined in your protobuf file.

### Implementing the Service

Create a class that implements the generated servicer interface:

```python
class MyServiceHandler(my_service_pb2_grpc.MyServiceServicer):
    """Implementation of your service."""
    
    def __init__(self):
        logger.debug("🔌🚀✅ Initializing MyServiceHandler")
        # Initialize your state here
        self._data = {}
    
    async def SomeMethod(self, request, context):
        """Implement a method from your service."""
        logger.debug(f"🔌📥✅ Received request: {request}")
        
        # Your implementation logic goes here
        result = self._process_request(request)
        
        logger.debug(f"🔌📤✅ Sending response: {result}")
        return my_service_pb2.SomeResponse(result=result)
    
    def _process_request(self, request):
        """Internal helper method."""
        # Your business logic goes here
        return f"Processed: {request.input}"
```

The handler should:
- Implement all methods defined in your protobuf service
- Use proper logging for debugging
- Handle errors appropriately
- Manage any state or resources

This is where your actual plugin functionality lives—like the chef who actually prepares the meal after the order comes in.

## 3. Server Bootstrap

The bootstrap code sets up and runs the plugin server. It initializes your protocol and handler, creates the server, and starts serving requests.

### Setting Up the Server

```python
#!/usr/bin/env python3
# my_plugin.py

import asyncio

from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.logger import logger

from my_protocol import MyProtocol
from my_handler import MyServiceHandler


async def main():
    """Start the plugin server."""
    logger.debug("🔌🚀✅ Starting plugin server")
    
    # Create the server with your protocol and handler
    server = RPCPluginServer(
        protocol=MyProtocol(),
        handler=MyServiceHandler()
    )
    
    try:
        # This blocks until the server is shut down
        await server.serve()
    except Exception as e:
        logger.error(f"🔌🚀❌ Server error: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
```

The bootstrap code:
- Creates instances of your protocol and handler
- Initializes the RPCPluginServer with them
- Calls `serve()` to run the server until terminated

This is the maître d' who welcomes guests, seats them, and ensures everything runs smoothly.

## Advanced Server Features

### Configuration Options

The `RPCPluginServer` constructor accepts a `config` dictionary for customization:

```python
server = RPCPluginServer(
    protocol=MyProtocol(),
    handler=MyServiceHandler(),
    config={
        "PLUGIN_SERVER_CERT": custom_cert_pem,
        "PLUGIN_SERVER_KEY": custom_key_pem,
        "PLUGIN_AUTO_MTLS": "false"
    }
)
```

Common configuration options include:
- `PLUGIN_SERVER_CERT` and `PLUGIN_SERVER_KEY`: Custom TLS certificates
- `PLUGIN_AUTO_MTLS`: Enable/disable automatic mTLS negotiation
- `PLUGIN_SERVER_TRANSPORTS`: Override supported transport types

### Custom Transports

You can provide a custom transport implementation:

```python
from pyvider.rpcplugin.transport import TCPSocketTransport

# Custom transport with specific host
custom_transport = TCPSocketTransport(host="192.168.1.100")

server = RPCPluginServer(
    protocol=MyProtocol(),
    handler=MyServiceHandler(),
    transport=custom_transport
)
```

This is useful for specifying non-default network interfaces or custom Unix socket paths.

### Error Handling

Implement robust error handling in your service methods:

```python
async def SomeMethod(self, request, context):
    try:
        # Your implementation
        result = self._process_request(request)
        return my_service_pb2.SomeResponse(result=result)
    except ValueError as e:
        logger.error(f"🔌❌ Value error: {e}")
        context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
        context.set_details(str(e))
        return my_service_pb2.SomeResponse()
    except Exception as e:
        logger.error(f"🔌❌ Unexpected error: {e}")
        context.set_code(grpc.StatusCode.INTERNAL)
        context.set_details("Internal error")
        return my_service_pb2.SomeResponse()
```

Use appropriate gRPC status codes to communicate the nature of errors back to the client.

### Resource Management

Properly manage resources that need explicit cleanup:

```python
class DatabaseHandler(database_pb2_grpc.DatabaseServicer):
    
    def __init__(self):
        self._db_connection = self._connect_to_db()
    
    def _connect_to_db(self):
        # Connect to database
        return db_connection
    
    async def Close(self):
        """Custom cleanup method."""
        if hasattr(self, "_db_connection") and self._db_connection:
            await self._db_connection.close()
            self._db_connection = None
```

Then register the cleanup with the server:

```python
server = RPCPluginServer(
    protocol=DatabaseProtocol(),
    handler=db_handler
)

# Register custom cleanup
async def cleanup_hook():
    await db_handler.Close()

server._shutdown_event.add_done_callback(lambda _: asyncio.create_task(cleanup_hook()))
```

This ensures resources are properly released when the plugin shuts down.

### Streaming RPCs

Implement streaming methods from your protobuf definition:

```python
async def StreamData(self, request, context):
    """Server streaming RPC method."""
    logger.debug(f"🔌📥✅ StreamData request: {request}")
    
    # Generate multiple responses
    for i in range(request.count):
        response = data_pb2.DataResponse(value=f"Item {i}")
        logger.debug(f"🔌📤✅ Streaming response: {response}")
        yield response
        await asyncio.sleep(0.1)  # Simulate processing time
```

Streaming RPCs allow for more efficient handling of:
- Large result sets
- Real-time updates
- Progress reporting
- Long-running operations

## Best Practices

1. **Logging**: Use the emoji logging system consistently for better debugging
2. **Error Handling**: Always handle exceptions and set appropriate gRPC status codes
3. **Resource Management**: Clean up any resources (files, connections, etc.) properly
4. **Configuration**: Make your handler configurable rather than hardcoding values
5. **Testing**: Write tests that simulate the client-server interaction

## Common Pitfalls

1. **Missing Cookie Validation**: The plugin must check the magic cookie, or it will fail mysteriously
2. **Blocking Operations**: Use async versions of I/O operations to avoid blocking the event loop
3. **Resource Leaks**: Forgetting to close connections can lead to resource exhaustion
4. **Protocol Mismatch**: Ensure the protocol version matches between client and server
5. **Certificate Issues**: Double-check certificate generation and validation when using mTLS

## Next Steps

Now that you understand how to implement a server, you might want to explore:

- [Client Implementation](client-implementation.md) for connecting to your plugin
- [Protocol Definition](protocol-definition.md) for designing your service interface
- [Advanced Patterns](../advanced/index.md) for more sophisticated plugin architectures
