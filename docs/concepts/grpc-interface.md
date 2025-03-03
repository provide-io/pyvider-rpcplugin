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
