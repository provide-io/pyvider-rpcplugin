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
    transport="unix",  # or "tcp"
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
    config={"PLUGIN_HANDSHAKE_TIMEOUT": 15.0}, # Example: Override specific config for this client
    auto_connect=False # Recommended to set to False and call await client.start() explicitly
)

# After creating the client, you must start it
# await client.start()
# ... use client.grpc_channel ...
# await client.close()
```

**Parameters:**
- `command` (list[str]): The command and its arguments to launch the plugin server executable.
- `config` (dict | None): Optional configuration dictionary to customize client behavior (e.g., timeouts, specific environment variables for the plugin). These can override global configurations for this client instance.
- `auto_connect` (bool): Defaults to `True`. If `True`, the synchronous factory logs a warning because `client.start()` (which performs connection) is async and must be `await`ed by the caller. Set to `False` to avoid the warning and manage `client.start()` explicitly.

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
    handler_class=MyCustomHandler, # Optional: if your protocol needs a specific handler base
    service_name="CustomService",
    custom_arg_for_protocol="example_value" # Example of using **kwargs
)
```

**Parameters:**
- `protocol_class` (type[ProtocolT] | None): The class to instantiate for the protocol. If `None`, `BasicRPCPluginProtocol` is used.
- `handler_class` (type[HandlerT] | None): Optional: Specifies the expected base class for handlers compatible with this protocol. (Currently informational, not strictly enforced by the basic factory).
- `service_name` (str | None): The name of the service. If `protocol_class` is not provided (i.e., `BasicRPCPluginProtocol` is used), this name is passed as `service_name_override` to `BasicRPCPluginProtocol`.
- `**kwargs` (Any): Additional keyword arguments passed to the constructor of `protocol_class`.

**Returns:** An instance of the specified (or default) protocol class.

## Core Classes

### `RPCPluginServer`

Main server class for hosting RPC services.

#### Methods

##### `async serve()`
Start the server and begin accepting connections.

```python
await server.serve()
```

##### `async stop()`
Stop the server gracefully. A fixed grace period of 0.5 seconds is used for the underlying gRPC server shutdown.

```python
await server.stop()
```

The server's listening address can be obtained from its `transport.endpoint` attribute after the transport has successfully listened (e.g., after `server.serve()` has been called and the server is running). Example: `server.transport.endpoint`.

### `RPCPluginClient`

Client for connecting to plugin servers.

#### Methods

##### `async start()`
Start the client and establish connection.

```python
await client.start()
```

##### `async close()`
Stop the client, close connections, and terminate the plugin subprocess if launched by this client.

```python
await client.close()
```

##### `async shutdown_plugin()`
Request graceful shutdown of the plugin server process (if applicable). Does not close the client itself; `close()` should still be called.
```python
await client.shutdown_plugin()
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

##### `get_method_type(self, method_name: str) -> str`
Gets the gRPC method type for a given method name (e.g., "unary_unary", "stream_stream").
```python
def get_method_type(self, method_name: str) -> str:
    # Implementation depends on the protocol
    if "Stream" in method_name:
        return "stream_stream" # Example logic
    return "unary_unary"
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

### `CertificateError`
Errors related to security certificates, private keys, or other credential validation and management issues.
```python
class CertificateError(SecurityError):
    """Errors related to certificate operations."""
```

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
TransportT = TypeVar('TransportT', bound=RPCPluginTransport) # from pyvider.rpcplugin.types

# Configuration type
ConfigT = TypeVar("ConfigT", bound="RPCPluginConfig") # from pyvider.rpcplugin.config
```

### Transport Types

```python
# Supported transport types
TRANSPORT_TYPES = Literal["unix", "tcp"]
```

### gRPC Types

```python
# gRPC channel type
GrpcChannelType = grpc.aio.Channel | grpc.Channel # Can be sync or async

# gRPC credentials type
GrpcCredentialsType = grpc.ChannelCredentials | None

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
    # For client to verify server:
    "PLUGIN_SERVER_ROOT_CERTS": "/path/to/your_ca_or_server_ca.crt",
    # For server to verify client (if mTLS):
    "PLUGIN_CLIENT_ROOT_CERTS": "/path/to/your_ca_or_client_ca.crt",
    "PLUGIN_SERVER_CERT": "/path/to/server.crt", # Server's own cert
    "PLUGIN_SERVER_KEY": "/path/to/server.key",  # Server's own key
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
# These PLUGIN_ prefixed keys will be passed to an internal pyvider.rpcplugin.configure()
# call for this server instance, allowing instance-specific overrides of global settings.
server_instance_config = {
    "PLUGIN_LOG_LEVEL": "DEBUG",              # Specific log level for this server
    "PLUGIN_HANDSHAKE_TIMEOUT": 25.0,       # Custom handshake timeout
    "PLUGIN_RATE_LIMIT_ENABLED": "true",      # Enable rate limiting for this server
    "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 50.0
}
```

**Example Client-Side Overrides (passed to `plugin_client` `config`):**
```python
# Similar to server, these PLUGIN_ prefixed keys customize this client instance.
client_instance_config = {
    "PLUGIN_HANDSHAKE_TIMEOUT": 20.0, # Custom handshake timeout for this client
    "PLUGIN_CLIENT_MAX_RETRIES": 5,   # Custom max retries for this client
    "PLUGIN_LOG_LEVEL": "DEBUG"
}
```
The `config` parameter in factory functions like `plugin_server` and `plugin_client` primarily processes `PLUGIN_` prefixed keys by passing them to an internal `pyvider.rpcplugin.configure()` call for that specific instance. This allows overriding global settings for that instance. Non-`PLUGIN_` prefixed keys are generally stored on the instance's `config` attribute but not automatically used by the core library. For direct gRPC server/channel options not exposed via `PLUGIN_` variables, further customization of server/channel creation might be needed (e.g., by subclassing or using gRPC specific environment variables if supported by `grpcio`).

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
