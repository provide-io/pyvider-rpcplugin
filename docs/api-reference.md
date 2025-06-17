# API Reference - pyvider-rpcplugin

This document provides comprehensive API documentation for all public classes, functions, and interfaces in `pyvider-rpcplugin`.

## Table of Contents

- [Factory Functions](#factory-functions)
- [Core Classes](#core-classes)
- [Configuration](#configuration)
- [Transport Layer](#transport-layer)
- [Protocol Layer](#protocol-layer)
- [Security & Certificates](#security--certificates)
- [Exceptions](#exceptions)
- [Type Definitions](#type-definitions)

## Factory Functions

The factory functions provide the primary entry points for creating RPC plugin components with sensible defaults.

### `plugin_server()`

Creates a configured RPC plugin server instance.

```python
def plugin_server(
    protocol: ProtocolT,
    handler: HandlerT,
    transport: str = "unix",
    transport_path: Optional[str] = None,
    host: str = "127.0.0.1",
    port: int = 0,
    config: Optional[Dict[str, Any]] = None,
) -> RPCPluginServer
```

**Parameters:**
- `protocol` - The RPC protocol definition (from `plugin_protocol()` or `create_basic_protocol()`)
- `handler` - Service handler instance implementing the RPC methods
- `transport` - Transport type: `"unix"` or `"tcp"`
- `transport_path` - Custom Unix socket path (optional, for "unix" transport)
- `host` - TCP bind address (default: `"127.0.0.1"`, for "tcp" transport)
- `port` - TCP port number (default: 0 for auto-assignment)
- `config` - Additional configuration options

**Returns:** Configured `RPCPluginServer` instance

**Example:**
```python
server = plugin_server(
    protocol=my_protocol,
    handler=MyServiceHandler(),
    transport="tcp",
    host="0.0.0.0",
    port=50051
)
await server.serve()
```

### `plugin_client()`

Creates a configured RPC plugin client instance.

```python
def plugin_client(
    server_path: str,
    protocol: Optional[ProtocolT] = None, # Assuming ProtocolT is defined
    env: Optional[Dict[str, str]] = None,
    auto_connect: bool = False, # Note: if True, client.start() is called
    timeout: float = 10.0,
    **kwargs: Any,
) -> RPCPluginClient
```

**Parameters:**
- `server_path` - Path to the plugin server executable.
- `protocol` - Optional custom protocol implementation.
- `env` - Environment variables to pass to the server process.
- `auto_connect` - If True, `client.start()` is called implicitly (not generally recommended to await in factory).
- `timeout` - Connection timeout for some internal operations if/when `auto_connect` leads to connection attempts.
- `**kwargs` - Additional configuration options passed to `RPCPluginClient`.

**Returns:** Configured `RPCPluginClient` instance.

**Example:**
```python
# client = plugin_client(server_path="./my_plugin_executable")
# await client.start() # Typically called after instantiation
# # ... use client.grpc_channel ...
# await client.close()
print("Note: plugin_client is for executable plugins.")
```

### `plugin_protocol()`

Creates a custom RPC protocol definition.

```python
def plugin_protocol(
    service_name: str,
    descriptor_module: Any,
    servicer_add_fn: Callable,
) -> RPCPluginProtocol
```

**Parameters:**
- `service_name` - Name of the gRPC service
- `descriptor_module` - Generated protobuf descriptor module
- `servicer_add_fn` - Function to add servicer to gRPC server

**Returns:** Configured `RPCPluginProtocol` instance

**Example:**
```python
protocol = plugin_protocol(
    service_name="GreeterService",
    descriptor_module=greeter_pb2,
    servicer_add_fn=add_GreeterServicer_to_server
)
```

### `create_basic_protocol()`

Creates a basic protocol for testing and development.

```python
def create_basic_protocol() -> RPCPluginProtocol
```

**Returns:** Basic `RPCPluginProtocol` instance for testing

## Core Classes

### `RPCPluginServer`

Main server class for hosting RPC services.

#### Constructor

```python
class RPCPluginServer:
    def __init__(
        self,
        protocol: ProtocolT,
        handler: HandlerT,
        config: Optional[Dict[str, Any]] = None,
        transport: Optional[TransportT] = None,
    )
```

#### Methods

##### `serve()`

Start the server and begin accepting connections.

```python
async def serve(self) -> None
```

**Raises:**
- `TransportError` - If transport setup fails
- `ProtocolError` - If protocol registration fails

**Example:**
```python
server = RPCPluginServer(protocol, handler)
await server.serve()  # Runs until stopped
```

##### `stop()`

Gracefully stop the server and cleanup resources.

```python
async def stop(self) -> None
```

**Example:**
```python
await server.stop()
```

##### `get_status()`

Get current server status and metrics.

```python
async def get_status(self) -> Dict[str, Any]
```

**Returns:** Dictionary with server status information

### `RPCPluginClient`

Client class for connecting to RPC services.

#### Constructor

```python
class RPCPluginClient:
    def __init__(
        self,
        command: List[str], # typically [server_path, arg1, ...]
        config: Optional[Dict[str, Any]] = None,
    )
```

#### Methods

##### `start()`

Launch the plugin subprocess, perform handshake, and establish connection.

```python
async def start(self) -> None
```

**Raises:**
- `HandshakeError` - If the handshake fails
- `TransportError` - If the transport encounters an error or connection cannot be established

##### `close()`

Clean up all resources and connections, including terminating the plugin subprocess.

```python
async def close(self) -> None
```

##### `channel`

Property providing access to the gRPC channel for making RPC calls.

```python
@property
def channel(self) -> grpc.aio.Channel
```

**Example:**
```python
# client = plugin_client(server_path="./my_plugin_executable")
# await client.start()
# if client.grpc_channel:
#     # stub = MyServiceStub(client.grpc_channel)
#     # response = await stub.MyMethod(MyRequest())
#     print("Conceptual: Client started, channel available for stubs.")
# await client.close()
print("Note: plugin_client example is conceptual for executable plugins.")
```

## Configuration

### `configure()`

Configure global RPC plugin settings using `PLUGIN_` prefixed keys.

```python
def configure(
    PLUGIN_MAGIC_COOKIE_VALUE: Optional[str] = None, # Or PLUGIN_MAGIC_COOKIE
    PLUGIN_PROTOCOL_VERSIONS: Optional[List[int]] = None,
    PLUGIN_SERVER_TRANSPORTS: Optional[List[str]] = None, # For server capabilities
    PLUGIN_CLIENT_TRANSPORTS: Optional[List[str]] = None, # For client preferences
    PLUGIN_AUTO_MTLS: Optional[bool] = None,
    PLUGIN_HANDSHAKE_TIMEOUT: Optional[float] = None,
    PLUGIN_CONNECTION_TIMEOUT: Optional[float] = None,
    PLUGIN_SERVER_CERT: Optional[str] = None,
    PLUGIN_SERVER_KEY: Optional[str] = None,
    PLUGIN_CLIENT_CERT: Optional[str] = None,
    PLUGIN_CLIENT_KEY: Optional[str] = None,
    **kwargs: Any, # For other PLUGIN_ prefixed keys
) -> None
```

**Parameters (examples, use actual `PLUGIN_` prefixed keys):**
- `PLUGIN_MAGIC_COOKIE_VALUE` - Authentication cookie for handshake validation.
- `PLUGIN_PROTOCOL_VERSIONS` - List of protocol versions supported/announced by this instance.
- `PLUGIN_SERVER_TRANSPORTS` - List of transports the server supports (e.g., `["unix", "tcp"]`).
- `PLUGIN_CLIENT_TRANSPORTS` - List of transports the client prefers.
- `PLUGIN_AUTO_MTLS` - Enable automatic mTLS configuration.
- `PLUGIN_HANDSHAKE_TIMEOUT` - Timeout for connection handshake (seconds).
- `PLUGIN_CONNECTION_TIMEOUT` - Timeout for maintaining connections (seconds).
- `PLUGIN_SERVER_CERT` - Server certificate (PEM format or file path).
- `PLUGIN_SERVER_KEY` - Server private key (PEM format or file path).
- `PLUGIN_CLIENT_CERT` - Client certificate for mTLS (PEM format or file path).
- `PLUGIN_CLIENT_KEY` - Client private key for mTLS (PEM format or file path).
- `**kwargs` - Other `PLUGIN_` prefixed configuration options.

### `RPCPluginConfig`

Configuration management class.

#### Methods

##### `get()`

Get a configuration value.

```python
def get(self, key: str, default: Any = None) -> Any
```

##### `set()`

Set a configuration value.

```python
def set(self, key: str, value: Any) -> None
```

##### `instance()`

Get the singleton configuration instance.

```python
@classmethod
def instance(cls) -> RPCPluginConfig
```

### `load_config_from_file()`

Load configuration from a file.

```python
def load_config_from_file(config_file: Union[str, Path]) -> None
```

**Parameters:**
- `config_file` - Path to configuration file (.env, .json, .yaml, .yml)

**Supported formats:**
- **`.env`** - Environment variable format (`KEY=value`)
- **`.json`** - JSON object format
- **`.yaml/.yml`** - YAML format

## Transport Layer

### `UnixSocketTransport`

Unix domain socket transport implementation.

```python
class UnixSocketTransport(RPCPluginTransport):
    def __init__(self, path: Optional[str] = None)
    
    async def listen(self) -> str
    async def connect(self, endpoint: str) -> None
    async def close(self) -> None
```

### `TCPSocketTransport`

TCP socket transport implementation.

```python
class TCPSocketTransport(RPCPluginTransport):
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0
    )
    
    async def listen(self) -> str
    async def connect(self, endpoint: str) -> None
    async def close(self) -> None
```

## Protocol Layer

### `RPCPluginProtocol`

Base protocol interface.

```python
class RPCPluginProtocol(ABC):
    @abstractmethod
    async def get_grpc_descriptors(self) -> Tuple[Any, str]
    
    @abstractmethod
    async def add_to_server(self, handler: Any, server: grpc.aio.Server) -> None
```

## Security & Certificates

### `Certificate`

Certificate management utilities.

#### Class Methods

##### `generate_ca()`

Generate a Certificate Authority.

```python
@classmethod
def generate_ca(
    cls,
    common_name: str,
    organization: str = "Pyvider RPC",
    validity_days: int = 365
) -> Certificate
```

##### `generate_server_certificate()`

Generate a server certificate.

```python
@classmethod
def generate_server_certificate(
    cls,
    ca_cert: Certificate,
    common_name: str,
    san_dns: Optional[List[str]] = None,
    validity_days: int = 90
) -> Certificate
```

##### `generate_client_certificate()`

Generate a client certificate.

```python
@classmethod
def generate_client_certificate(
    cls,
    ca_cert: Certificate,
    common_name: str,
    validity_days: int = 30
) -> Certificate
```

##### `verify_certificate_chain()`

Verify certificate against CA.

```python
@classmethod
def verify_certificate_chain(
    cls,
    cert_path: Union[str, Path],
    ca_cert_path: Union[str, Path]
) -> bool
```

#### Properties

```python
@property
def certificate_pem(self) -> str
    """PEM-encoded certificate."""

@property
def private_key_pem(self) -> str
    """PEM-encoded private key."""
```

## Exceptions

All exceptions inherit from `RPCPluginError`.

### `RPCPluginError`

Base exception for all RPC plugin errors.

```python
class RPCPluginError(Exception):
    """Base exception for RPC plugin framework."""
```

### `TransportError`

Transport layer errors (connection, binding, etc.).

```python
class TransportError(RPCPluginError):
    """Errors related to transport layer operations."""
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

### Secure Client Connection

```python
from pyvider.rpcplugin import plugin_client, configure

# Configure mTLS
configure(
    PLUGIN_AUTO_MTLS=True,
    PLUGIN_CLIENT_CERT="path/to/client.crt", # Used if client needs to present a specific cert
    PLUGIN_CLIENT_KEY="path/to/client.key",
    # PLUGIN_SERVER_ROOT_CERTS="path/to/ca.crt" # If server's cert is not signed by public CA
)

# Create and connect client (assuming executable plugin)
# client = plugin_client(server_path="./secure_plugin_executable")
# await client.start()

# Use client for RPC calls
# if client.grpc_channel:
    # stub = MyServiceStub(client.grpc_channel)
    # response = await stub.MyMethod(MyRequest())
    # print("Conceptual: Secure client connected.")
# await client.close()
print("Note: Secure client example is conceptual for executable plugins.")
```

### Error Handling

```python
from pyvider.rpcplugin.exception import TransportError, HandshakeError

try:
    await client.connect(endpoint)
except TransportError as e:
    logger.error(f"Connection failed: {e}")
    # Implement retry logic
except HandshakeError as e:
    logger.error(f"Authentication failed: {e}")
    # Check certificates and credentials
```

## Performance Considerations

### Connection Pooling

For high-throughput scenarios with executable plugins, you might manage multiple `RPCPluginClient` instances if connecting to different plugin types or needing distinct configurations. True connection pooling to a single plugin executable is typically handled within the gRPC channel's capabilities or by application design.

```python
# Conceptual: Managing multiple client instances for different plugins
# client_A = plugin_client(server_path="./plugin_A_executable")
# await client_A.start()
# client_B = plugin_client(server_path="./plugin_B_executable")
# await client_B.start()

# # Use client_A and client_B as needed
# await client_A.close()
# await client_B.close()
print("Note: Connection pooling example is conceptual.")
```

### Transport Selection

- **Unix Sockets**: Use for local IPC (highest performance)
- **TCP Sockets**: Use for network communication (required for remote clients)

### Configuration Optimization

```python
configure(
    PLUGIN_HANDSHAKE_TIMEOUT=5.0,  # Faster handshakes
    PLUGIN_CONNECTION_TIMEOUT=60.0,  # Reasonable connection lifetime
    PLUGIN_SERVER_TRANSPORTS=["unix"],  # Example: server configured for only Unix
    PLUGIN_CLIENT_TRANSPORTS=["unix"],  # Example: client configured to only use Unix
)
```

## See Also

- [Architecture Guide](architecture.md) - System design and patterns
- [Security Guide](security.md) - mTLS setup and best practices
- [Performance Guide](performance.md) - Optimization recommendations
- [Examples](../examples/) - Complete working examples
