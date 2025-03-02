---
title: Security Model
description: Authentication and encryption in Pyvider RPC Plugin
---

# Security Model

The security model in Pyvider RPC Plugin ensures that communication between client and server is both authenticated and encrypted. It's like having a soundproof room with guards checking IDs at both doors—nobody gets in without proper credentials, and nobody can eavesdrop on the conversation.

## Mutual TLS Authentication

The primary security mechanism is mutual TLS (mTLS), where both client and server authenticate each other using X.509 certificates. This bidirectional authentication ensures that:

1. The client knows it's talking to the intended server
2. The server knows it's talking to the intended client
3. All communication is encrypted

This is different from standard TLS (as used in HTTPS), where typically only the server authenticates to the client. With mTLS, both parties check each other's ID cards.

## Certificate Management

### Certificate Generation

When auto-mTLS is enabled, both client and server generate ephemeral certificates:

```python
# Client-side
client_cert = Certificate(
    generate_keypair=True,
    key_type="ecdsa",
    common_name="localhost"
)

# Server-side
server_cert = Certificate(
    generate_keypair=True,
    key_type="ecdsa",
    common_name="localhost"
)
```

These certificates include:
- A private key (RSA or ECDSA)
- A self-signed X.509 certificate with proper extensions
- A common name of "localhost" (since communication is local)
- Key usage flags for digital signatures and key encipherment

Think of these as temporary, automatically generated passports that only last for the duration of the conversation.

### Certificate Exchange

The certificate exchange happens during the handshake:

1. **Client to Server**: The client passes its certificate to the server via the `PLUGIN_CLIENT_CERT` environment variable.
2. **Server to Client**: The server includes its certificate in the handshake response on stdout.

```
# Handshake response format
CORE_VERSION|PLUGIN_VERSION|NETWORK|ADDRESS|PROTOCOL|TLS_CERT
```

This exchange of certificates is like showing your credentials before entering a secured facility, except happening automatically and cryptographically.

### Certificate Validation

Once certificates are exchanged, each side validates the other's certificate:

```python
# Client-side validation
channel = grpc.secure_channel(
    endpoint,
    grpc.ssl_channel_credentials(
        root_certificates=server_cert.encode(),
        private_key=client_key.encode(),
        certificate_chain=client_cert.encode()
    )
)

# Server-side validation
server = grpc.server(...)
server.add_secure_port(
    endpoint,
    grpc.ssl_server_credentials(
        [(server_key.encode(), server_cert.encode())],
        root_certificates=client_cert.encode(),
        require_client_auth=True
    )
)
```

The validation ensures:
- The certificate is properly formatted
- The certificate hasn't expired
- The certificate is cryptographically valid
- The certificate matches the expected one from the exchange

## Security Configurations

Several security configurations are available:

### Auto mTLS (Default)

The auto-mTLS mode handles everything automatically:
- Generates temporary certificates
- Manages certificate exchange
- Sets up secure channels with proper validation

This is the easiest and recommended approach—like having a security system that automatically arms itself when you leave and disarms when you return.

### Manual Certificate Management

For advanced use cases, you can manually provide certificates:

```python
client = RPCPluginClient(
    command=["python", "my_plugin.py"],
    config={
        "PLUGIN_CLIENT_CERT": my_cert_pem,
        "PLUGIN_CLIENT_KEY": my_key_pem
    }
)

server = RPCPluginServer(
    protocol=MyProtocol(),
    handler=MyHandler(),
    config={
        "PLUGIN_SERVER_CERT": server_cert_pem,
        "PLUGIN_SERVER_KEY": server_key_pem
    }
)
```

This allows for using persistent certificates, certificate chains, or integration with certificate management systems—like bringing your own custom-designed security badge instead of using the standard visitor pass.

### Insecure Mode (Not Recommended)

For testing or in fully trusted environments, you can disable security:

```python
client = RPCPluginClient(
    command=["python", "my_plugin.py"],
    config={"PLUGIN_AUTO_MTLS": "false"}
)
```

This is like leaving your door unlocked—convenient, but not recommended unless you live in an exceptionally safe neighborhood with trustworthy neighbors.

## Certificate Implementation

The `Certificate` class handles all aspects of certificate management:

```python
class Certificate:
    """Encapsulates X.509 certificate functionality."""
    
    def __init__(
        self,
        cert: str | None = None,
        key: str | None = None,
        generate_keypair: bool = False,
        key_type: str = "ecdsa",
        key_size: int = 2048,
        ecdsa_curve: str = "secp384r1",
        common_name: str = "localhost",
        alt_names: list[str] = None,
        organization_name: str = "HashiCorp",
        **kwargs
    ) -> None:
        # Handles loading or generating certificates
```

Key features include:
- Support for both RSA (2048, 3072, 4096 bit) and ECDSA (secp256r1, secp384r1, secp521r1)
- PEM format handling
- Certificate validation
- Trust chain management
- Detailed logging of certificate operations

## Security Considerations

When using Pyvider RPC Plugin, keep these security considerations in mind:

1. **Process Isolation**: Even with mTLS, plugins run with the same user permissions as the host. Use OS-level isolation mechanisms for additional security.

2. **Certificate Handling**: Temporary certificates are stored in memory only. Never write private keys to disk.

3. **Environment Variables**: Environment variables used for certificate exchange are sensitive. Ensure they aren't logged or exposed.

4. **Go Compatibility**: When working with go-plugin, use ECDSA with secp521r1 curve for maximum compatibility.

5. **Certificate Reuse**: By default, each connection uses fresh certificates. If reusing certificates, ensure proper key management practices.

## Next Steps

Now that you understand the security model, explore:

- [Transport Layer](transport.md) to learn about the secured communication channels
- [gRPC Interface](grpc-interface.md) to see how secured services are defined
- [Server Implementation](../guides/server-implementation.md) for practical security configuration
```

## docs/concepts/grpc-interface.md

```markdown
---
title: gRPC Interface
description: Service definitions and RPC architecture in Pyvider
---

# gRPC Interface

The gRPC interface is the heart of Pyvider's plugin system—where the actual communication between client and server happens. If the transport layer is the highway and the security model is the armored car, then the gRPC interface is the package delivery system that knows exactly what packages to deliver where.

## What is gRPC?

gRPC (gRPC Remote Procedure Call) is an open-source RPC framework initially developed by Google. It uses:

- **Protocol Buffers** (protobuf) as the Interface Definition Language (IDL)
- **HTTP/2** for transport
- **Binary serialization** for efficiency

Think of gRPC as the evolved, enterprise-grade cousin of the old JSON-RPC interfaces—it's faster, more structured, and much more capable. It's like the difference between sending instructions via a handwritten letter versus a precisely formatted digital document with validation.

## Interface Definition

### Protocol Buffers

Services in Pyvider are defined using Protocol Buffers (protobuf), which provide a language-neutral way to specify:

- **Data structures** (messages)
- **Service interfaces** (methods)
- **Field types** and validation

A simple protobuf definition might look like:

```protobuf
syntax = "proto3";
package example;

service KeyValue {
  rpc Get(GetRequest) returns (GetResponse);
  rpc Put(PutRequest) returns (PutResponse);
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
```

This is like creating a detailed contract that both client and server agree to follow—specifying exactly what information should be in the request, what to expect in the response, and what methods are available.

### Python Service Implementation

On the server side, you implement the service by creating a class that provides the methods defined in the protobuf:

```python
class KVServicer(keyvalue_pb2_grpc.KeyValueServicer):
    """Implementation of the KeyValue service."""
    
    def __init__(self):
        self._data = {}
    
    async def Get(self, request, context):
        """Get a value by key."""
        key = request.key
        value = self._data.get(key, "")
        return keyvalue_pb2.GetResponse(value=value)
    
    async def Put(self, request, context):
        """Store a key-value pair."""
        key = request.key
        value = request.value
        self._data[key] = value
        return keyvalue_pb2.PutResponse(success=True)
```

This implementation is registered with a gRPC server through a protocol class:

```python
class KVProtocol(RPCPluginProtocol):
    """Protocol definition for the KeyValue service."""
    
    def get_grpc_descriptors(self):
        """Return the protobuf descriptor and service name."""
        return keyvalue_pb2.DESCRIPTOR, "KeyValue"
    
    def add_to_server(self, server, handler):
        """Add the service to a gRPC server."""
        keyvalue_pb2_grpc.add_KeyValueServicer_to_server(handler, server)
```

## Protocol Integration

### Server Side

On the server side, the `RPCPluginServer` takes your protocol and handler, then:

1. Creates a gRPC server
2. Adds your service to the server
3. Starts the server at a network endpoint
4. Performs the handshake to tell the client where to connect

```python
server = RPCPluginServer(
    protocol=KVProtocol(),
    handler=KVServicer()
)

# This handles all the registration and setup
await server.serve()
```

### Client Side

On the client side, the `RPCPluginClient` connects to the server and creates a gRPC stub for making calls:

```python
client = RPCPluginClient(command=["python", "kv_plugin.py"])
await client.start()

# Get the specific interface for this plugin
kv_client = await client.get_interface(keyvalue_pb2_grpc.KeyValueStub)

# Now make RPC calls
response = await kv_client.Get(keyvalue_pb2.GetRequest(key="hello"))
print(f"Got value: {response.value}")
```

## Advanced gRPC Features

Pyvider leverages many advanced gRPC features:

### Streaming

gRPC supports bidirectional streaming for continuous data transfer:

```protobuf
service Logger {
  rpc LogStream(stream LogEntry) returns (stream LogResponse);
}
```

This enables patterns like real-time logging, event streaming, and push notifications—like having a phone conversation instead of sending individual text messages.

### Metadata

gRPC allows sending metadata alongside requests and responses:

```python
# Client side
metadata = [("client-name", "example")]
response = await stub.Get(request, metadata=metadata)

# Server side
def Get(self, request, context):
    client_name = dict(context.invocation_metadata()).get("client-name", "unknown")
    logger.debug(f"🔌📥✅ Get request from client: {client_name}")
    # Process request...
```

This metadata provides context for requests without cluttering the actual message—like putting information on an envelope without changing the letter inside.

### Timeouts and Cancellation

Requests can have timeouts and cancellation support:

```python
# With timeout
try:
    response = await asyncio.wait_for(
        stub.LongRunningOperation(request),
        timeout=5.0
    )
except asyncio.TimeoutError:
    # Handle timeout
```

This ensures that operations don't hang indefinitely—like setting a timer when cooking eggs so you don't forget about them.

## Protocol Versioning

Pyvider supports multiple protocol versions, allowing for evolution over time. During the handshake, the client and server negotiate which version to use:

```python
# Client advertises supported versions
env = {
    "PLUGIN_PROTOCOL_VERSIONS": "1,2,3,4,5,6,7"
}

# Server selects highest common version
def negotiate_protocol_version(server_versions: list[int]) -> int:
    client_versions = [int(v) for v in os.getenv("PLUGIN_PROTOCOL_VERSIONS").split(",")]
    for version in sorted(server_versions, reverse=True):
        if version in client_versions:
            return version
    raise ProtocolError("No compatible protocol version")
```

This versioning allows plugins to evolve without breaking compatibility—like how USB devices from fifteen years ago still work in modern computers, even though newer devices have additional capabilities.

## Next Steps

Now that you understand the gRPC interface, you might want to explore:

- [Server Implementation](../guides/server-implementation.md) for practical service implementation
- [Client Implementation](../guides/client-implementation.md) for connecting to services
- [Protocol Definition](../guides/protocol-definition.md) for writing protobuf definitions
```

## docs/guides/getting-started.md

```markdown
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
```

## docs/guides/server-implementation.md

```markdown
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
```

## docs/guides/client-implementation.md

```markdown
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
```

## docs/reference/env-variables.md

```markdown
---
title: Environment Variables
description: Reference for environment variables used in Pyvider RPC Plugin
---

# Environment Variables Reference

Pyvider RPC Plugin uses environment variables for configuration and communication between the client and server. This reference documents all supported environment variables.

## Core Environment Variables

These variables are essential for the handshake process:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PLUGIN_MAGIC_COOKIE_KEY` | Yes | The name of the environment variable that contains the cookie value | `"BASIC_PLUGIN"` |
| `PLUGIN_MAGIC_COOKIE_VALUE` | Yes | The expected value of the cookie | `"hello"` |
| `PLUGIN_MAGIC_COOKIE` | Yes | The actual value of the cookie (should match `PLUGIN_MAGIC_COOKIE_VALUE`) | `"hello"` |
| `PLUGIN_PROTOCOL_VERSIONS` | Yes | Comma-separated list of protocol versions supported by the client | `"1,2,3,4,5,6,7"` |
| `PLUGIN_TRANSPORTS` | Yes | Comma-separated list of transport mechanisms supported by the client | `"unix,tcp"` |

## Security Environment Variables

These variables control the security aspects:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PLUGIN_AUTO_MTLS` | No | Whether to use automatic mTLS (true/false) | `"true"` |
| `PLUGIN_CLIENT_CERT` | No | PEM-encoded client certificate for mTLS | `"-----BEGIN CERTIFICATE-----\nMII..."` |
| `PLUGIN_CLIENT_KEY` | No | PEM-encoded client private key for mTLS | `"-----BEGIN PRIVATE KEY-----\nMII..."` |
| `PLUGIN_SERVER_CERT` | No | PEM-encoded server certificate for mTLS | `"-----BEGIN CERTIFICATE-----\nMII..."` |
| `PLUGIN_SERVER_KEY` | No | PEM-encoded server private key for mTLS | `"-----BEGIN PRIVATE KEY-----\nMII..."` |

## Logging Environment Variables

These variables control logging behavior:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PLUGIN_LOG_LEVEL` | No | The minimum log level to display (DEBUG, INFO, WARNING, ERROR, CRITICAL) | `"DEBUG"` |
| `PLUGIN_SHOW_EMOJI_MATRIX` | No | Whether to show the emoji matrix at startup (true/false) | `"true"` |

## Transport Environment Variables

These variables configure transport-specific behavior:

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PLUGIN_SERVER_ENDPOINT` | No | Default server endpoint for listening | `"127.0.0.1:0"` |
| `PLUGIN_CLIENT_ENDPOINT` | No | Default client endpoint for connection | `"127.0.0.1:12345"` |

## Variable Usage and Precedence

### Server-Side Variables

When a client launches a plugin server, it sets environment variables that the server reads to determine how it should behave. The critical variables are:

1. **Magic Cookie**: The server validates this to ensure it's being launched as a plugin
2. **Protocol Versions**: The server uses this to select a protocol version
3. **Transports**: The server uses this to select a transport mechanism
4. **Client Certificate**: The server uses this for mutual TLS authentication

### Client-Side Variables

The client uses environment variables to configure its own behavior and to pass information to servers:

```python
client = RPCPluginClient(
    command=["python", "plugin.py"],
    config={
        "env": {
            "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
            "PLUGIN_MAGIC_COOKIE": "hello",
            "PLUGIN_PROTOCOL_VERSIONS": "1,2,3,4,5,6,7",
            "PLUGIN_TRANSPORTS": "unix,tcp",
            "PLUGIN_AUTO_MTLS": "true",
            "PLUGIN_LOG_LEVEL": "DEBUG",
        }
    }
)
```

### Variable Resolution

Variables are resolved in this order of precedence:

1. Variables explicitly set in the client's `config["env"]` dictionary
2. Variables set in the current process's environment
3. Default values from the configuration system

### File-Based Values

Some environment variables can reference files using the `file://` prefix:

```python
config = {
    "env": {
        "PLUGIN_CLIENT_CERT": "file:///path/to/cert.pem",
        "PLUGIN_CLIENT_KEY": "file:///path/to/key.pem"
    }
}
```

This is particularly useful for certificate material that may be stored in files rather than directly in environment variables.

## Best Practices

1. **Security**: Never hardcode sensitive values like certificates or keys
2. **Isolation**: Use separate environment variable sets for different plugins
3. **Defaults**: Provide sensible defaults for optional variables
4. **Validation**: Validate all environment variables before use
5. **Cleanup**: Clear sensitive environment variables when done

## Environment Variable Examples

### Basic Plugin Launch

```python
env = {
    "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
    "PLUGIN_MAGIC_COOKIE": "hello",
    "PLUGIN_PROTOCOL_VERSIONS": "6",
    "PLUGIN_TRANSPORTS": "unix,tcp"
}
```

### Secure Plugin Launch with mTLS

```python
env = {
    "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
    "PLUGIN_MAGIC_COOKIE": "hello",
    "PLUGIN_PROTOCOL_VERSIONS": "6",
    "PLUGIN_TRANSPORTS": "unix,tcp",
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_CLIENT_CERT": "file:///path/to/cert.pem",
    "PLUGIN_CLIENT_KEY": "file:///path/to/key.pem"
}
```

### Debug-Mode Plugin Launch

```python
env = {
    "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
    "PLUGIN_MAGIC_COOKIE": "hello",
    "PLUGIN_PROTOCOL_VERSIONS": "6",
    "PLUGIN_TRANSPORTS": "unix,tcp",
    "PLUGIN_LOG_LEVEL": "DEBUG",
    "PLUGIN_SHOW_EMOJI_MATRIX": "true"
}
```

## Related Topics

- [Handshake Protocol](../concepts/handshake.md): Details on how environment variables are used in the handshake
- [Security Model](../concepts/security.md): Information on security-related environment variables
- [Client Implementation](../guides/client-implementation.md): Guide on using environment variables in clients
```

## docs/reference/emoji-matrix.md

```markdown
---
title: Emoji Logging Matrix
description: Reference for the emoji-based logging system in Pyvider
---

# Emoji Logging Matrix

Pyvider uses a structured emoji-based logging system that prefixes log messages with three emojis to indicate the domain, action, and status of each operation. This provides a visual, scannable way to understand logs at a glance—because wading through walls of text is so 2020.

## Emoji Structure

Each log message follows this pattern:

```
[Domain] → [Action] → [Status]  Message
```

For example:
```
🔌🚀✅ Starting plugin server
```

This indicates:
- Domain (`🔌`): Plugin component
- Action (`🚀`): Starting operation
- Status (`✅`): Success

## Domain Emojis (First Position)

| Emoji | Domain | Description |
|-------|--------|-------------|
| 🛎️ | Server | Server component operations |
| 🙋 | Client | Client component operations |
| 🔌 | Plugin | Plugin component operations |
| 🌐 | TCP | TCP transport operations |
| 📞 | Unix | Unix socket transport operations |
| 🤝 | Handshake | Handshake protocol operations |
| 🔐 | Security | Security and certificate operations |
| ⚙️ | Config | Configuration management |
| 📡 | Protocol | Protocol and gRPC operations |
| 🧰 | Utils | Utility functions |
| ❗ | Exception | Exception handling |
| 🛰️ | Telemetry | Monitoring and metrics |
| 💉 | DI | Dependency injection |

## Action Emojis (Second Position)

| Emoji | Action | Description |
|-------|--------|-------------|
| 🚀 | Start | Starting processes or operations |
| 🤝 | Handshake | Handshake operations |
| 🕵️ | Connect | Connection attempts |
| 🕹 | Listen | Listening for connections |
| 📖 | Read | Reading data |
| 📤 | Write | Writing or sending data |
| 📥 | Receive | Receiving data |
| 🔒 | Close | Closing or shutting down |
| 🔍 | Parse | Parsing or validating data |
| 📝 | Build | Building or constructing objects |
| 🔁 | Retry | Retrying operations |
| 🧪 | Test | Testing operations |
| 📜 | Cert | Certificate operations |
| 🔑 | Key | Key operations |
| 🛡️ | Encrypt | Encryption operations |

## Status Emojis (Third Position)

| Emoji | Status | Description |
|-------|--------|-------------|
| ✅ | Success | Operation succeeded |
| ❌ | Error | Operation failed with error |
| 🚫 | Fail | Operation failed without error |
| ⚠️ | Warn | Warning condition |
| 🛑 | Stop | Operation stopped |
| 👍 | Affirm | Positive acknowledgment |
| 👀 | Monitor | Monitoring or observing |
| 💥 | Crash | System crash |
| ⭕ | None | No particular status |
| ⏸️ | Suspend | Operation suspended |
| ▶️ | Resume | Operation resumed |
| ⏳ | Pending | Operation pending |
| 💤 | Idle | System idle |
| 🔄 | Ongoing | Operation in progress |

## Usage Examples

Here are some common logging patterns:

### Server Operations

```python
logger.debug("🛎️🚀✅ Starting plugin server")
logger.debug("🛎️🕹✅ Server listening on transport")
logger.error("🛎️🚀❌ Server startup failed: {e}")
logger.debug("🛎️🔒✅ Server shutdown complete")
```

### Client Operations

```python
logger.debug("🙋🚀✅ Starting plugin client")
logger.debug("🙋🕵️✅ Client connecting to plugin")
logger.error("🙋🕵️❌ Connection failed: {e}")
logger.debug("🙋🔒✅ Client closed successfully")
```

### Handshake Operations

```python
logger.debug("🤝🚀✅ Starting handshake negotiation")
logger.debug("🤝🔍✅ Validating magic cookie")
logger.error("🤝🔍❌ Invalid magic cookie")
logger.debug("🤝📝✅ Handshake response built")
```

### Transport Operations

```python
logger.debug("🌐🚀✅ Starting TCP transport")
logger.debug("🌐🕵️✅ TCP connecting to {endpoint}")
logger.debug("📞🕹✅ Unix socket listening on {path}")
logger.error("📞🕵️❌ Unix socket connection failed: {e}")
```

### Security Operations

```python
logger.debug("🔐🚀✅ Initializing security")
logger.debug("🔐📜✅ Generated self-signed certificate")
logger.debug("🔐🛡️✅ Established secure channel")
logger.error("🔐📜❌ Certificate validation failed: {e}")
```

## Integration with Logger

This emoji system is integrated with Pyvider's logger:

```python
from pyvider.rpcplugin.logger import logger

# Usage in your code
logger.debug("🔌🚀✅ Starting plugin initialization")
logger.info("🔌🤝✅ Plugin handshake completed")
logger.warning("🔌📥⚠️ Received unexpected message")
logger.error("🔌❌ Plugin error: {e}")
```

## Configuring Emoji Logging

To enable or configure the emoji logging system:

```python
# Enable emoji display on startup
os.environ["PLUGIN_SHOW_EMOJI_MATRIX"] = "true"

# Set log level
os.environ["PLUGIN_LOG_LEVEL"] = "DEBUG"
```

You can also disable emoji logging by setting a formatting environment variable, but why would you want to make your logs less fun?

## Display Considerations

The emojis are designed to be displayed in a monospaced font terminal with Unicode support. Most modern terminals support this, but if you're logging to a file or a system that doesn't support Unicode, you might want to use a custom formatter.

## Benefits of Emoji Logging

1. **Visual Scanning**: Quickly identify patterns and issues by scanning for emoji combinations
2. **Contextual Clues**: Understand the domain and operation without reading the entire message
3. **Status Highlighting**: Immediately spot errors (❌) and warnings (⚠️)
4. **Component Identification**: Easily differentiate between client, server, and transport logs
5. **Fun Factor**: Because debugging should be at least a little enjoyable

Remember, logs should be more than just text—they should tell a story. And sometimes that story involves tiny pictures.
```

Now all of these files have been created with a touch of subtle humor while prioritizing technical accuracy. Let me know if you would like me to create any other documentation files or make any revisions to these ones!