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
    host="127.0.0.1", # Default for TCP
    port=0,           # Default for TCP (0 means auto-assign)
    transport_path=None, # Default for Unix (auto-generates if None)
    config={"PLUGIN_MAX_WORKERS": 10} # Example: Use PLUGIN_ prefixed keys for library config
)
```

**Parameters:**
- `protocol` (ProtocolT): Protocol implementation.
- `handler` (HandlerT): Service handler implementation.
- `transport` (str): Transport type ("tcp" or "unix"). Defaults to "unix" if available, else "tcp".
- `host` (str): Host for TCP transport. Defaults to "127.0.0.1".
- `port` (int): Port for TCP transport. Defaults to `0` (OS assigns an available port).
- `transport_path` (str | None): Path for Unix socket transport. If `None` (default) and Unix transport is chosen, a path is auto-generated in a temporary directory.
- `config` (dict | None): Additional configuration options that can override global settings for this server instance. Keys should generally be `PLUGIN_` prefixed.

**Returns:** `RPCPluginServer` instance.

### `plugin_client()`

Create a new plugin client for launching and connecting to plugin executables.

```python
from pyvider.rpcplugin import plugin_client

# Example: Launching a plugin executable
client = plugin_client(
    command=["python", "./my_plugin_server_script.py"],
    config={"PLUGIN_HANDSHAKE_TIMEOUT": 15.0} # Example: Override specific config for this client
)

# After creating the client, you must start it
# await client.start()
# ... use client.grpc_channel ...
# await client.close()
```

**Parameters:**
- `command` (list[str]): The command and its arguments to launch the plugin server executable.
- `config` (dict | None): Optional configuration dictionary to customize client behavior (e.g., timeouts, specific environment variables for the plugin). These can override global configurations for this client instance.

**Returns:** `RPCPluginClient` instance. The client is not automatically started; you must call `await client.start()` to launch the plugin and establish a connection.

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
        transport="tcp"
        # mTLS is configured via environment variables or pyvider.rpcplugin.configure()
        # For example, ensure PLUGIN_AUTO_MTLS="true" and certificate paths are set.
)
```

## Configuration Options

Configuration is primarily managed through environment variables (e.g., `PLUGIN_LOG_LEVEL`) or programmatically using `pyvider.rpcplugin.configure()`. The `config` parameter in `plugin_server` or `plugin_client` can override these for specific instances. Refer to `docs/configuration.md` for a full list of `PLUGIN_` prefixed variables.

**Example Server-Side Overrides (passed to `plugin_server` `config`):**
```python
server_instance_config = {
    "PLUGIN_MAX_WORKERS": 50,       # Max gRPC worker threads for this server
    "PLUGIN_LOG_LEVEL": "DEBUG"     # Specific log level for this server
}
```

**Example Client-Side Overrides (passed to `plugin_client` `config`):**
```python
client_instance_config = {
    "PLUGIN_HANDSHAKE_TIMEOUT": 20.0, # Custom handshake timeout for this client
    "PLUGIN_CLIENT_MAX_RETRIES": 5    # Custom max retries for this client
}
```
These dictionaries are examples of what you *could* pass to the `config` parameter. The actual effective gRPC options (like keepalive, max message size) are often set internally by `pyvider-rpcplugin` or can be influenced by underlying `grpcio` environment variables if not directly exposed.

## Environment Variables

`pyvider-rpcplugin` uses environment variables prefixed with `PLUGIN_` for global configuration. See `docs/configuration.md` for a comprehensive list. Key variables include:

### Security Variables
- `PLUGIN_AUTO_MTLS`: Enable automatic mTLS ("true"/"false"). Default: "true".
- `PLUGIN_SERVER_CERT`: Path to server's own certificate file (PEM or file:// URI).
- `PLUGIN_SERVER_KEY`: Path to server's private key file.
- `PLUGIN_CLIENT_ROOT_CERTS`: Path to CA certificate(s) server uses to verify clients.
- `PLUGIN_CLIENT_CERT`: Path to client's own certificate file (for client executables).
- `PLUGIN_CLIENT_KEY`: Path to client's private key file.
- `PLUGIN_SERVER_ROOT_CERTS`: Path to CA certificate(s) client uses to verify the server.

### Core Plugin Variables
- `PLUGIN_MAGIC_COOKIE_KEY`: Name of the env var the plugin host expects the plugin to provide the cookie in. Default: "PLUGIN_MAGIC_COOKIE".
- `PLUGIN_MAGIC_COOKIE_VALUE`: The secret cookie value the plugin host expects. Default: "rpcplugin-default-cookie".
- `PLUGIN_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Default: "INFO".
- `PLUGIN_SERVER_TRANSPORTS`: Comma-separated list of server's preferred transports (e.g., "unix,tcp"). Default: "unix,tcp".
- `PLUGIN_HANDSHAKE_TIMEOUT`: Handshake timeout in seconds. Default: 10.0.

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
