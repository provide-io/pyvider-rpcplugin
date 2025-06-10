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
- `transport` - Transport type: `"unix"`, `"tcp"`, or list of transports
- `transport_path` - Custom Unix socket path (optional)
- `host` - TCP bind address (default: `"127.0.0.1"`)
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
    transport: str = "unix",
    host: str = "127.0.0.1", 
    port: int = 50051,
    config: Optional[Dict[str, Any]] = None,
) -> RPCPluginClient
```

**Parameters:**
- `transport` - Transport type: `"unix"` or `"tcp"`
- `host` - TCP connection host (default: `"127.0.0.1"`)
- `port` - TCP connection port (default: 50051)
- `config` - Additional configuration options

**Returns:** Configured `RPCPluginClient` instance

**Example:**
```python
client = plugin_client(transport="unix")
await client.connect("/tmp/my_service.sock")
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
        transport: Optional[TransportT] = None,
        config: Optional[Dict[str, Any]] = None,
    )
```

#### Methods

##### `connect()`

Connect to an RPC server.

```python
async def connect(self, endpoint: str) -> None
```

**Parameters:**
- `endpoint` - Server endpoint (Unix socket path or TCP address)

**Raises:**
- `TransportError` - If connection fails
- `HandshakeError` - If authentication fails

##### `close()`

Close the connection and cleanup resources.

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
client = plugin_client()
await client.connect("127.0.0.1:50051")

stub = MyServiceStub(client.channel)
response = await stub.MyMethod(request)
```

## Configuration

### `configure()`

Configure global RPC plugin settings.

```python
def configure(
    magic_cookie: Optional[str] = None,
    protocol_version: Optional[int] = None,
    transports: Optional[List[str]] = None,
    auto_mtls: Optional[bool] = None,
    handshake_timeout: Optional[float] = None,
    connection_timeout: Optional[float] = None,
    server_cert: Optional[str] = None,
    server_key: Optional[str] = None,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    **kwargs: Any,
) -> None
```

**Parameters:**
- `magic_cookie` - Authentication cookie for handshake validation
- `protocol_version` - RPC protocol version number
- `transports` - List of supported transport types
- `auto_mtls` - Enable automatic mTLS configuration
- `handshake_timeout` - Timeout for connection handshake (seconds)
- `connection_timeout` - Timeout for maintaining connections (seconds)
- `server_cert` - Server certificate (PEM format or file path)
- `server_key` - Server private key (PEM format or file path)
- `client_cert` - Client certificate for mTLS (PEM format or file path)
- `client_key` - Client private key for mTLS (PEM format or file path)
- `**kwargs` - Additional configuration options

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
    auto_mtls=True,
    client_cert="path/to/client.crt",
    client_key="path/to/client.key"
)

# Create and connect client
client = plugin_client(transport="tcp")
await client.connect("secure-server.example.com:50051")

# Use client for RPC calls
stub = MyServiceStub(client.channel)
response = await stub.MyMethod(MyRequest())
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

For high-throughput scenarios, maintain multiple client connections:

```python
clients = [plugin_client() for _ in range(pool_size)]
for client in clients:
    await client.connect(endpoint)

# Use clients in round-robin fashion
```

### Transport Selection

- **Unix Sockets**: Use for local IPC (highest performance)
- **TCP Sockets**: Use for network communication (required for remote clients)

### Configuration Optimization

```python
configure(
    handshake_timeout=5.0,  # Faster handshakes
    connection_timeout=60.0,  # Reasonable connection lifetime
    transports=["unix"],  # Single transport for performance
)
```

## See Also

- [Architecture Guide](architecture.md) - System design and patterns
- [Security Guide](security.md) - mTLS setup and best practices
- [Performance Guide](performance.md) - Optimization recommendations
- [Examples](../examples/) - Complete working examples
