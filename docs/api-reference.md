# Pyvider RPC Plugin API Reference

Complete reference for all public APIs in the `pyvider-rpcplugin` framework.

## Factory Functions

### `plugin_server()`

Create a new plugin server with sensible defaults.

```python
from pyvider.rpcplugin import plugin_server

server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    transport="tcp",  # or "unix"
    port=50051,       # for TCP
    transport_path="/tmp/socket",  # for Unix
    config={"max_workers": 10}
)
```

**Parameters:**
- `protocol` (ProtocolT): Protocol implementation
- `handler` (HandlerT): Service handler implementation  
- `transport` (str): Transport type ("tcp" or "unix")
- `port` (int): Port for TCP transport (default: 0 = auto-assign)
- `host` (str): Host for TCP transport (default: "127.0.0.1")
- `transport_path` (str|None): Path for Unix socket transport
- `config` (dict|None): Additional configuration options

**Returns:** `RPCPluginServer` instance

### `plugin_client()`

Create a new plugin client for connecting to servers.

```python
from pyvider.rpcplugin import plugin_client

client = plugin_client(
    command=["./my_plugin_executable"],
    config={"timeout": 30.0},
    auto_connect=False
)
```

**Parameters:**
- `command` (list[str]): Command to execute plugin server
- `config` (dict|None): Configuration options
- `auto_connect` (bool): Whether to auto-connect (default: False)

**Returns:** `RPCPluginClient` instance

### `plugin_protocol()`

Create a protocol implementation.

```python
from pyvider.rpcplugin import plugin_protocol

# Basic protocol
protocol = plugin_protocol(service_name="MyService")

# Custom protocol class
protocol = plugin_protocol(
    protocol_class=MyCustomProtocol,
    service_name="CustomService"
)
```

## Core Classes

### `RPCPluginServer`

Main server class for hosting RPC services.

#### Methods

##### `async serve()`
Start the server and begin accepting connections.

```python
await server.serve()
```

##### `async stop(grace_period=None)`
Stop the server gracefully.

```python
await server.stop(grace_period=5.0)
```

##### `get_address()`
Get the server's listening address.

```python
address = server.get_address()  # e.g., "127.0.0.1:50051"
```

### `RPCPluginClient`

Client for connecting to plugin servers.

#### Methods

##### `async start()`
Start the client and establish connection.

```python
await client.start()
```

##### `async stop()`
Stop the client and close connections.

```python
await client.stop()
```

##### `property grpc_channel`
Access the underlying gRPC channel.

```python
if client.grpc_channel:
    stub = MyServiceStub(client.grpc_channel)
    response = await stub.MyMethod(request)
```

### `RPCPluginProtocol`

Base class for protocol implementations.

#### Abstract Methods

##### `async get_grpc_descriptors()`
Return gRPC service descriptors.

```python
async def get_grpc_descriptors(self):
    return my_pb2_grpc, "MyService"
```

##### `get_method_type(method_name)`
Return the gRPC method type.

```python
def get_method_type(self, method_name: str) -> str:
    return "unary_unary"  # or "unary_stream", "stream_unary", "stream_stream"
```

##### `async add_to_server(server, handler)`
Register the service with a gRPC server.

```python
async def add_to_server(self, server, handler):
    my_pb2_grpc.add_MyServiceServicer_to_server(handler, server)
```

## Transport Classes

### `TCPSocketTransport`

TCP socket transport implementation.

```python
from pyvider.rpcplugin.transport import TCPSocketTransport

transport = TCPSocketTransport(
    host="127.0.0.1",
    port=50051
)
```

### `UnixSocketTransport`

Unix domain socket transport implementation.

```python
from pyvider.rpcplugin.transport import UnixSocketTransport

transport = UnixSocketTransport(
    path="/tmp/my_service.sock"
)
```

## Exception Classes

### `RPCPluginError`

Base exception for all plugin errors.

```python
class RPCPluginError(Exception):
    def __init__(self, message: str, hint: str = None, code: int|str = None):
        # ...
```

**Attributes:**
- `message`: Error message
- `hint`: Optional hint for resolution
- `code`: Optional error code

### `TransportError`

Network transport and communication errors.

```python
try:
    await client.start()
except TransportError as e:
    print(f"Connection failed: {e}")
    if e.hint:
        print(f"Hint: {e.hint}")
```

### `ProtocolError`

Protocol layer errors (service registration, gRPC issues).

```python
class ProtocolError(RPCPluginError):
    """Errors related to protocol layer operations."""
```

### `HandshakeError`

Authentication and handshake errors.

```python
class HandshakeError(RPCPluginError):
    """Errors during connection handshake or authentication."""
```

### `SecurityError`

Security-related errors (certificate validation, mTLS).

```python
class SecurityError(RPCPluginError):
    """Errors related to security operations."""
```

## Type Definitions

### Core Types

```python
# Handler type for service implementations
HandlerT = TypeVar('HandlerT')

# Protocol type for RPC protocol definitions  
ProtocolT = TypeVar('ProtocolT', bound=RPCPluginProtocol)

# Transport type for communication layers
TransportT = TypeVar('TransportT', bound=RPCPluginTransport)

# Configuration type
ConfigT = Dict[str, Any]
```

### Transport Types

```python
# Supported transport types
TRANSPORT_TYPES = Literal["unix", "tcp"]
```

### gRPC Types

```python
# gRPC channel type
GrpcChannelType = grpc.aio.Channel

# gRPC credentials type
GrpcCredentialsType = grpc.ChannelCredentials

# RPC configuration type
RpcConfigType = Dict[str, Any]
```

## Usage Patterns

### Basic Server Setup

```python
from pyvider.rpcplugin import plugin_server, plugin_protocol

# Create protocol
protocol = plugin_protocol(
    service_name="MyService",
    descriptor_module=my_service_pb2,
    servicer_add_fn=add_MyServiceServicer_to_server
)

# Create server
server = plugin_server(
    protocol=protocol,
    handler=MyServiceHandler(),
    transport="tcp",
    port=50051
)

# Start server
await server.serve()
```

### Error Handling

```python
from pyvider.rpcplugin.exception import RPCPluginError, TransportError, HandshakeError

try:
    client = plugin_client(command=["./my_plugin"])
    await client.start()
    
    if client.grpc_channel:
        stub = MyServiceStub(client.grpc_channel)
        response = await stub.MyMethod(MyRequest())

except TransportError as e:
    print(f"Connection error: {e}")
    # Check network connectivity, server status
except HandshakeError as e:
    print(f"Authentication error: {e}")
    # Check credentials, magic cookies
except RPCPluginError as e:
    print(f"Plugin error: {e}")
    # Handle other plugin-specific errors
finally:
    await client.stop()
```

### Custom Protocol Implementation

```python
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol

class MyCustomProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self):
        return my_service_pb2_grpc, "MyCustomService"
    
    def get_method_type(self, method_name: str) -> str:
        method_types = {
            "UnaryMethod": "unary_unary",
            "StreamMethod": "unary_stream",
            "UploadMethod": "stream_unary",
            "BidirectionalMethod": "stream_stream"
        }
        return method_types.get(method_name, "unary_unary")
    
    async def add_to_server(self, server, handler):
        my_service_pb2_grpc.add_MyCustomServiceServicer_to_server(handler, server)
```

### Secure Configuration

```python
# Set environment variables for mTLS
import os

os.environ.update({
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_CA_CERT": "/path/to/ca.crt",
    "PLUGIN_SERVER_CERT": "/path/to/server.crt",
    "PLUGIN_SERVER_KEY": "/path/to/server.key",
    "PLUGIN_CLIENT_CERT": "/path/to/client.crt",
    "PLUGIN_CLIENT_KEY": "/path/to/client.key"
})

# Create secure server
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="tcp",
    config={"security_enabled": True}
)
```

## Configuration Options

### Server Configuration

```python
server_config = {
    "max_workers": 50,                    # Maximum worker threads
    "max_concurrent_rpcs": 1000,          # Maximum concurrent RPCs
    "keepalive_time": 30,                 # Keepalive time (seconds)
    "keepalive_timeout": 5,               # Keepalive timeout (seconds)
    "max_connection_idle": 300,           # Max connection idle time
    "max_connection_age": 3600,           # Max connection age
    "security_enabled": True,             # Enable security features
    "log_level": "INFO"                   # Logging level
}
```

### Client Configuration

```python
client_config = {
    "timeout": 30.0,                      # Connection timeout
    "max_retries": 3,                     # Maximum retry attempts
    "retry_delay": 1.0,                   # Delay between retries
    "keepalive_time": 30,                 # Keepalive time
    "max_receive_message_length": 1024*1024*4,  # 4MB max message
    "max_send_message_length": 1024*1024*4      # 4MB max message
}
```

## Environment Variables

### Security Variables

- `PLUGIN_AUTO_MTLS`: Enable automatic mTLS ("true"/"false")
- `PLUGIN_CA_CERT`: Path to CA certificate
- `PLUGIN_SERVER_CERT`: Path to server certificate
- `PLUGIN_SERVER_KEY`: Path to server private key
- `PLUGIN_CLIENT_CERT`: Path to client certificate
- `PLUGIN_CLIENT_KEY`: Path to client private key

### Plugin Variables

- `PLUGIN_MAGIC_COOKIE_KEY`: Magic cookie key for handshake
- `PLUGIN_MAGIC_COOKIE_VALUE`: Magic cookie value for handshake
- `PLUGIN_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

## Best Practices

### Production Deployment

1. **Always use mTLS in production**
2. **Set appropriate timeouts and limits**
3. **Implement proper error handling**
4. **Monitor performance metrics**
5. **Use connection pooling for high load**
6. **Implement graceful shutdown**
7. **Validate all input parameters**
8. **Use structured logging**

### Performance Optimization

1. **Use async/await properly**
2. **Implement connection pooling**
3. **Batch operations when possible**
4. **Set appropriate buffer sizes**
5. **Monitor memory usage**
6. **Profile critical paths**
7. **Use generators for large datasets**

### Security Considerations

1. **Never commit certificates to version control**
2. **Rotate certificates regularly**
3. **Validate certificate chains**
4. **Use secure cipher suites**
5. **Monitor certificate expiration**
6. **Implement proper access controls**
7. **Audit security configurations**

---

For more examples and detailed usage patterns, see the [examples directory](../examples/) and [examples README](examples_readme.md).
