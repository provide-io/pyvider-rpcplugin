# RPC Architecture & Handshake

The Pyvider RPC Plugin system implements a robust RPC (Remote Procedure Call) architecture built on gRPC, with a secure handshake protocol that establishes authenticated connections before any RPC operations begin.

## RPC Architecture Overview

The RPC architecture follows a client-server model where:

- **Host Application** acts as the client, launching and communicating with plugins
- **Plugin Process** acts as the server, providing RPC services to the host
- **Communication** happens over Unix sockets or TCP with optional mTLS encryption
- **Protocol** uses gRPC with automatic service discovery and method routing

```
┌─────────────────────────────────────────────────────────────────┐
│ Host Application Process                                        │
│                                                                 │
│  ┌─────────────────┐                                           │
│  │ RPCPluginClient │                                           │
│  │                 │                                           │
│  │ ┌─────────────┐ │            gRPC/HTTP2                    │
│  │ │ Service     │ │ ◄─────────────────────────────────────┐  │
│  │ │ Stubs       │ │                                        │  │
│  │ └─────────────┘ │                                        │  │
│  │                 │                                        │  │
│  │ ┌─────────────┐ │                                        │  │
│  │ │ Transport   │ │                                        │  │
│  │ │ Layer       │ │                                        │  │
│  │ └─────────────┘ │                                        │  │
│  └─────────────────┘                                        │  │
└──────────────────────────────────────────────────────────────┼──┘
                                                               │
                                                               │
┌──────────────────────────────────────────────────────────────┼──┐
│ Plugin Process                                               │  │
│                                                              │  │
│  ┌─────────────────┐                                        │  │
│  │ RPCPluginServer │                                        │  │
│  │                 │                                        │  │
│  │ ┌─────────────┐ │                                        │  │
│  │ │ gRPC Server │ │ ◄──────────────────────────────────────┘  │
│  │ │             │ │                                           │
│  │ │ ┌─────────┐ │ │                                           │
│  │ │ │Service  │ │ │                                           │
│  │ │ │Handler  │ │ │                                           │
│  │ │ └─────────┘ │ │                                           │
│  │ └─────────────┘ │                                           │
│  │                 │                                           │
│  │ ┌─────────────┐ │                                           │
│  │ │ Transport   │ │                                           │
│  │ │ Layer       │ │                                           │
│  │ │ └─────────┘ │                                           │
│  └─────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### gRPC Foundation

The architecture is built on **gRPC**, providing:

- **Protocol Buffers** for efficient serialization
- **HTTP/2** for multiplexed, bidirectional communication
- **Streaming Support** for real-time data flows
- **Built-in Load Balancing** and connection management
- **Rich Error Handling** with status codes and metadata

```python
# Example service definition (proto file)
syntax = "proto3";

package example;

service DataProcessor {
    // Unary RPC - single request, single response
    rpc ProcessData(DataRequest) returns (DataResponse);

    // Server streaming - single request, multiple responses
    rpc StreamResults(QueryRequest) returns (stream ResultItem);

    // Bidirectional streaming - multiple requests and responses
    rpc InteractiveSession(stream SessionMessage) returns (stream SessionResponse);
}

message DataRequest {
    string data = 1;
    map<string, string> options = 2;
}

message DataResponse {
    string result = 1;
    int32 status_code = 2;
}
```

### Foundation Integration

The RPC architecture seamlessly integrates with Foundation for essential services:

```python
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from provide.foundation.logger import get_logger

logger = get_logger(__name__), config
from provide.foundation.crypto import Certificate

class SecureDataProcessor:
    def __init__(self):
        # Foundation configuration
        self.config = config.get_config()

    async def ProcessData(self, request, context):
        # Foundation logging with structured context
        logger.info("Processing secure data",
                   request_id=request.id,
                   data_size=len(request.data))

        # Foundation crypto for data validation
        if self.config.validate_signatures:
            cert = Certificate.from_request(context)
            if not cert.is_valid():
                logger.warning("Invalid certificate", cert_id=cert.id)
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid certificate")

        result = await self.process_data(request.data)
        logger.info("Data processed successfully", result_size=len(result))

        return DataResponse(result=result, status_code=0)
```

**Foundation provides:**

- **Structured Logging**: Rich context and formatting for debugging and monitoring
- **Configuration Management**: Environment-aware settings with validation
- **Cryptography**: Certificate management, signing, and validation
- **Error Handling**: Comprehensive error boundaries and retry logic
- **Rate Limiting**: Token bucket implementation for request throttling

## Communication Patterns

### Unary RPC (Request-Response)

Most common pattern for simple request-response operations:

```python
# Client side
async def simple_request():
    async with plugin_client(command=cmd) as client:
        response = await client.my_service.GetStatus()
        return response.status

# Server side
class MyServiceServicer:
    async def GetStatus(self, request, context):
        return StatusResponse(
            status="healthy",
            uptime=self.get_uptime(),
            version="1.0.0"
        )
```

### Server Streaming

Server sends multiple responses for a single client request:

```python
# Client side - receive stream
async def receive_stream():
    async with plugin_client(command=cmd) as client:
        async for item in client.my_service.StreamData(request):
            print(f"Received: {item.data}")

# Server side - send stream
class MyServiceServicer:
    async def StreamData(self, request, context):
        for i in range(request.count):
            yield DataItem(
                id=i,
                data=f"item_{i}",
                timestamp=time.time()
            )
            await asyncio.sleep(0.1)
```

### Bidirectional Streaming

Both client and server can send multiple messages:

```python
# Client side - interactive session
async def interactive_session():
    async with plugin_client(command=cmd) as client:

        async def send_messages():
            for i in range(10):
                yield SessionMessage(
                    id=i,
                    content=f"message_{i}"
                )
                await asyncio.sleep(1.0)

        async for response in client.my_service.Chat(send_messages()):
            print(f"Server says: {response.content}")

# Server side - handle interactive session
class MyServiceServicer:
    async def Chat(self, request_iterator, context):
        async for message in request_iterator:
            # Process incoming message
            response_content = await self.process_message(message.content)

            # Send response
            yield SessionResponse(
                id=message.id,
                content=response_content
            )
```

## Handshake Process

The handshake establishes secure, authenticated connections before any RPC operations. It follows a multi-phase negotiation:

1. **Transport Establishment** - Set up underlying communication channel
2. **Magic Cookie Exchange** - Authenticate both parties
3. **Protocol Negotiation** - Agree on communication protocols
4. **Service Discovery** - Exchange available services and methods
5. **Ready State** - Begin normal RPC operations

```
┌─────────────────┐                    ┌─────────────────┐
│ Host Application│                    │ Plugin Process  │
└─────────┬───────┘                    └─────────┬───────┘
          │                                      │
          │ 1. Launch Process                    │
          │─────────────────────────────────────►│
          │                                      │
          │ 2. Transport Connect                 │
          │◄─────────────────────────────────────│
          │                                      │
          │ 3. Magic Cookie Exchange             │
          │◄────────────────────────────────────►│
          │                                      │
          │ 4. Protocol Negotiation              │
          │◄────────────────────────────────────►│
          │                                      │
          │ 5. Service Discovery                 │
          │◄────────────────────────────────────►│
          │                                      │
          │ 6. Ready - Begin RPC                 │
          │◄────────────────────────────────────►│
```

### Magic Cookie Authentication

The magic cookie serves as a shared secret for mutual authentication:

- **Process Isolation** - Ensures only authorized processes connect
- **Mutual Authentication** - Both client and server verify each other
- **Ephemeral Secrets** - Cookies can be rotated or session-specific
- **Simple Implementation** - No complex key exchange required

```python
import os
import secrets
from pyvider.rpcplugin import configure, plugin_server, plugin_client

# Generate secure random cookie
magic_cookie = secrets.token_hex(32)

# Configure both client and server with same cookie
os.environ.update({
    "PLUGIN_MAGIC_COOKIE_KEY": "auth",
    "PLUGIN_MAGIC_COOKIE_VALUE": magic_cookie
})

# Server receives cookie during handshake
server = plugin_server(protocol=my_protocol, handler=my_handler)

# Client sends cookie during connection
client = plugin_client(command=["python", "my_plugin.py"])
```

### Protocol Negotiation

Clients and servers negotiate protocol versions and features during handshake:

```python
# Protocol version negotiation
class ProtocolNegotiator:
    SUPPORTED_VERSIONS = ["1.0", "1.1", "2.0"]

    async def negotiate_version(self, client_versions: list[str]) -> str:
        """Find compatible protocol version."""
        # Find highest common version
        common_versions = set(self.SUPPORTED_VERSIONS) & set(client_versions)

        if not common_versions:
            raise HandshakeError(
                f"No compatible protocol version. "
                f"Server supports: {self.SUPPORTED_VERSIONS}, "
                f"Client supports: {client_versions}"
            )

        # Use highest compatible version
        return max(common_versions, key=lambda v: tuple(map(int, v.split("."))))

# Feature negotiation
class FeatureNegotiator:
    def __init__(self):
        self.server_features = {
            "streaming": True,
            "compression": ["gzip", "deflate"],
            "auth_methods": ["magic_cookie", "mtls"],
            "max_message_size": 1024 * 1024,  # 1MB
        }

    async def negotiate_features(self, client_features: dict) -> dict:
        """Negotiate compatible features."""
        agreed_features = {}

        # Negotiate boolean features (AND logic)
        for feature in ["streaming"]:
            agreed_features[feature] = (
                self.server_features.get(feature, False) and
                client_features.get(feature, False)
            )

        # Negotiate list features (intersection)
        for feature in ["compression", "auth_methods"]:
            server_options = self.server_features.get(feature, [])
            client_options = client_features.get(feature, [])
            common = list(set(server_options) & set(client_options))
            if common:
                agreed_features[feature] = common[0]  # Use first common option

        return agreed_features
```

### Transport-Specific Handshakes

=== "Unix Socket Handshake"

    ```python
    import asyncio
    import json
    from pathlib import Path

    class UnixSocketHandshake:
        def __init__(self, socket_path: Path, magic_cookie: str):
            self.socket_path = socket_path
            self.magic_cookie = magic_cookie

        async def server_handshake(self, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter) -> dict:
            """Perform server-side handshake over Unix socket."""
            try:
                # 1. Receive client hello
                hello_data = await reader.readuntil(b'\n')
                client_hello = json.loads(hello_data.decode().strip())

                # 2. Validate magic cookie
                if client_hello.get("magic_cookie") != self.magic_cookie:
                    raise HandshakeError("Invalid magic cookie")

                # 3. Negotiate protocol
                client_version = client_hello.get("protocol_version", "1.0")
                if client_version not in ["1.0", "1.1"]:
                    raise HandshakeError(f"Unsupported protocol version: {client_version}")

                # 4. Send server hello
                server_hello = {
                    "magic_cookie": self.magic_cookie,
                    "protocol_version": client_version,
                    "features": {"streaming": True, "compression": "gzip"},
                    "services": ["example.DataProcessor"]
                }

                hello_json = json.dumps(server_hello) + '\n'
                writer.write(hello_json.encode())
                await writer.drain()

                return server_hello

            except Exception as e:
                writer.close()
                await writer.wait_closed()
                raise HandshakeError(f"Handshake failed: {e}")

        async def client_handshake(self) -> dict:
            """Perform client-side handshake over Unix socket."""
            reader, writer = await asyncio.open_unix_connection(self.socket_path)

            try:
                # 1. Send client hello
                client_hello = {
                    "magic_cookie": self.magic_cookie,
                    "protocol_version": "1.1",
                    "features": {"streaming": True}
                }

                hello_json = json.dumps(client_hello) + '\n'
                writer.write(hello_json.encode())
                await writer.drain()

                # 2. Receive server hello
                hello_data = await reader.readuntil(b'\n')
                server_hello = json.loads(hello_data.decode().strip())

                # 3. Validate server cookie
                if server_hello.get("magic_cookie") != self.magic_cookie:
                    raise HandshakeError("Invalid server magic cookie")

                return server_hello

            except Exception as e:
                writer.close()
                await writer.wait_closed()
                raise HandshakeError(f"Client handshake failed: {e}")
    ```

=== "TCP Handshake with mTLS"

    ```python
    import ssl
    from provide.foundation.crypto import Certificate

    class TcpMtlsHandshake:
        def __init__(self, server_cert: Certificate, client_cert: Certificate,
                     magic_cookie: str):
            self.server_cert = server_cert
            self.client_cert = client_cert
            self.magic_cookie = magic_cookie

        def create_ssl_context(self, is_server: bool) -> ssl.SSLContext:
            """Create SSL context for mTLS."""
            if is_server:
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(
                    certfile=self.server_cert.cert_path,
                    keyfile=self.server_cert.key_path
                )
                context.verify_mode = ssl.CERT_REQUIRED
                context.load_verify_locations(cafile=self.client_cert.cert_path)
            else:
                context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                context.load_cert_chain(
                    certfile=self.client_cert.cert_path,
                    keyfile=self.client_cert.key_path
                )
                context.check_hostname = False
                context.load_verify_locations(cafile=self.server_cert.cert_path)

            return context

        async def server_handshake_mtls(self, host: str, port: int) -> dict:
            """Perform server handshake with mTLS."""
            ssl_context = self.create_ssl_context(is_server=True)

            server = await asyncio.start_server(
                self.handle_client_connection,
                host, port,
                ssl=ssl_context
            )

            return {"ssl_context": ssl_context, "server": server}

        async def handle_client_connection(self, reader: asyncio.StreamReader,
                                         writer: asyncio.StreamWriter):
            """Handle individual client connection after mTLS."""
            # mTLS validation already completed by SSL context
            peer_cert = writer.get_extra_info('peercert')

            if not peer_cert:
                raise HandshakeError("Client certificate required")

            # Continue with magic cookie handshake
            await self.complete_handshake(reader, writer)

        async def complete_handshake(self, reader: asyncio.StreamReader,
                                    writer: asyncio.StreamWriter):
            """Complete handshake after mTLS validation."""
            # Magic cookie exchange over encrypted channel
            client_data = await reader.readuntil(b'\n')
            client_hello = json.loads(client_data.decode().strip())

            if client_hello.get("magic_cookie") != self.magic_cookie:
                raise HandshakeError("Invalid magic cookie after mTLS")

            # Send server response
            server_hello = {
                "magic_cookie": self.magic_cookie,
                "tls_verified": True,
                "protocol_version": "1.1"
            }

            hello_json = json.dumps(server_hello) + '\n'
            writer.write(hello_json.encode())
            await writer.drain()
    ```

## Service Discovery

### Automatic Service Registration

The server automatically registers available gRPC services during handshake:

```python
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol

class ServiceRegistry:
    def __init__(self):
        self.registered_services = {}

    async def register_protocol(self, protocol: RPCPluginProtocol):
        """Register a protocol and its services."""
        # Get gRPC descriptors
        grpc_module, service_name = await protocol.get_grpc_descriptors()

        # Extract service methods
        service_methods = {}
        service_descriptor = getattr(grpc_module, f"{service_name}ServicerClass", None)

        if service_descriptor:
            for method_name in dir(service_descriptor):
                if not method_name.startswith("_"):
                    method_type = protocol.get_method_type(method_name)
                    service_methods[method_name] = {
                        "type": method_type,
                        "input_type": f"{service_name}Request",
                        "output_type": f"{service_name}Response"
                    }

        # Register service
        self.registered_services[service_name] = {
            "methods": service_methods,
            "protocol": protocol,
            "status": "active"
        }

    def get_service_manifest(self) -> dict:
        """Return manifest of all available services."""
        return {
            name: {
                "methods": list(info["methods"].keys()),
                "method_types": {
                    method: details["type"]
                    for method, details in info["methods"].items()
                },
                "status": info["status"]
            }
            for name, info in self.registered_services.items()
        }

# During server startup
registry = ServiceRegistry()
await registry.register_protocol(my_protocol)

# Send manifest to client during handshake
manifest = registry.get_service_manifest()
await transport.send_json(manifest)
```

### Client Service Discovery

Clients receive and process the service manifest:

```python
class ServiceDiscoveryClient:
    def __init__(self):
        self.available_services = {}
        self.service_stubs = {}

    async def process_service_manifest(self, manifest: dict, grpc_channel):
        """Process server's service manifest."""
        for service_name, service_info in manifest.items():
            # Store service information
            self.available_services[service_name] = service_info

            # Create gRPC stub for service
            if service_name == "example.DataProcessor":
                from example_pb2_grpc import DataProcessorStub
                self.service_stubs[service_name] = DataProcessorStub(grpc_channel)

    def get_available_services(self) -> list[str]:
        """Return list of available service names."""
        return list(self.available_services.keys())

    def get_service_methods(self, service_name: str) -> list[str]:
        """Return methods available for a service."""
        service_info = self.available_services.get(service_name, {})
        return service_info.get("methods", [])

    def get_service_stub(self, service_name: str):
        """Get gRPC stub for service."""
        return self.service_stubs.get(service_name)

# Client usage
discovery = ServiceDiscoveryClient()
await discovery.process_service_manifest(manifest, client.grpc_channel)

# Discover available services
services = discovery.get_available_services()
# Result: ["example.DataProcessor", "health.Health"]

# Get service methods
methods = discovery.get_service_methods("example.DataProcessor")
# Result: ["ProcessData", "StreamResults"]
```

## Error Handling

### gRPC Status Codes

```python
import grpc
from grpc import StatusCode

class MyServiceServicer:
    async def ProcessData(self, request, context):
        try:
            # Validate input
            if not request.data:
                context.set_code(StatusCode.INVALID_ARGUMENT)
                context.set_details("Data field is required")
                return DataResponse()

            # Process data
            result = await self.process(request.data)
            return DataResponse(result=result)

        except ValidationError as e:
            context.set_code(StatusCode.INVALID_ARGUMENT)
            context.set_details(str(e))
            return DataResponse()

        except PermissionError as e:
            context.set_code(StatusCode.PERMISSION_DENIED)
            context.set_details(str(e))
            return DataResponse()

        except Exception as e:
            logger.error("Unexpected error", exc_info=True)
            context.set_code(StatusCode.INTERNAL)
            context.set_details("Internal server error")
            return DataResponse()
```

### Handshake-Specific Exceptions

```python
from pyvider.rpcplugin.exception import HandshakeError

# Common handshake errors
class HandshakeTimeoutError(HandshakeError):
    """Handshake took too long to complete."""
    pass

class MagicCookieError(HandshakeError):
    """Magic cookie validation failed."""
    pass

class ProtocolNegotiationError(HandshakeError):
    """Protocol version negotiation failed."""
    pass

# Comprehensive error handling
async def robust_handshake(transport, timeout: float = 30.0):
    """Perform handshake with comprehensive error handling."""
    try:
        # Set handshake timeout
        handshake_task = perform_handshake(transport)
        result = await asyncio.wait_for(handshake_task, timeout=timeout)
        return result

    except asyncio.TimeoutError:
        raise HandshakeTimeoutError(
            f"Handshake timed out after {timeout}s",
            hint="Increase handshake timeout or check network connectivity"
        )
    except json.JSONDecodeError as e:
        raise HandshakeError(
            f"Invalid handshake message format: {e}",
            hint="Check protocol compatibility between client and server"
        )
    except ssl.SSLError as e:
        raise CertificateValidationError(
            f"mTLS certificate validation failed: {e}",
            hint="Verify certificate paths and validity"
        )
```

### Handshake Recovery Patterns

```python
async def handshake_with_retry(transport, max_retries: int = 3) -> dict:
    """Attempt handshake with retry logic."""
    last_error = None

    for attempt in range(max_retries):
        try:
            return await robust_handshake(transport, timeout=30.0)

        except HandshakeTimeoutError as e:
            last_error = e
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
                continue
            break

        except MagicCookieError:
            # Don't retry authentication failures
            raise
        except CertificateValidationError:
            # Don't retry certificate failures
            raise
        except HandshakeError as e:
            last_error = e
            if attempt < max_retries - 1:
                await asyncio.sleep(1.0)
                continue
            break

    raise last_error
```

## Performance Architecture

### Connection Multiplexing

gRPC uses HTTP/2 for efficient connection multiplexing:

```python
# Single connection handles multiple concurrent RPCs
async def concurrent_requests():
    async with plugin_client(command=cmd) as client:
        # All requests share the same connection
        tasks = [
            client.my_service.ProcessData(f"data_{i}")
            for i in range(100)
        ]

        # Requests are automatically multiplexed
        results = await asyncio.gather(*tasks)
        return results
```

### Connection Pooling

For high-throughput scenarios:

```python
class ConnectionPool:
    def __init__(self, command, pool_size=10):
        self.command = command
        self.pool_size = pool_size
        self.connections = asyncio.Queue(maxsize=pool_size)

    async def initialize(self):
        for _ in range(self.pool_size):
            client = plugin_client(command=self.command)
            await client.start()
            await self.connections.put(client)

    async def get_connection(self):
        return await self.connections.get()

    async def return_connection(self, client):
        await self.connections.put(client)

# Usage with connection pooling
pool = ConnectionPool(["python", "-m", "my_plugin"], pool_size=20)
await pool.initialize()
```

### Handshake Optimization

```python
class OptimizedHandshake:
    def __init__(self):
        self.handshake_cache = {}
        self.session_timeout = 300.0  # 5 minutes

    async def cached_handshake(self, client_id: str, transport) -> dict:
        """Use cached handshake result if valid."""
        cached_result = self.handshake_cache.get(client_id)

        if cached_result and not self.is_expired(cached_result):
            return cached_result["data"]

        # Perform new handshake
        result = await self.perform_handshake(transport)

        # Cache result
        self.handshake_cache[client_id] = {
            "data": result,
            "timestamp": time.time()
        }

        return result

    def is_expired(self, cached_result: dict) -> bool:
        """Check if cached handshake has expired."""
        age = time.time() - cached_result["timestamp"]
        return age > self.session_timeout
```

## Architecture Benefits

### Type Safety

Protocol Buffers provide compile-time type safety:

```python
# Types are automatically generated from .proto files
request = DataRequest(
    data="example",
    options={"key": "value"}  # Type-checked
)

response = await client.my_service.ProcessData(request)
# response.result is automatically typed as string
```

### Versioning Support

gRPC provides built-in API versioning:

```python
# Forward/backward compatible service evolution
service DataProcessor {
    rpc ProcessDataV1(DataRequestV1) returns (DataResponseV1);
    rpc ProcessDataV2(DataRequestV2) returns (DataResponseV2);
}
```

### Language Interoperability

gRPC enables polyglot plugin development:

```python
# Python client can communicate with any gRPC server
# Server could be implemented in Go, Java, C++, etc.
async with plugin_client(command=["./go-plugin-server"]) as client:
    response = await client.data_service.ProcessData(request)
```

## Next Steps

- **[Protocols](protocols/)** - Protocol definition and implementation patterns
- **[Transports](transports/)** - Transport layer implementation details
- **[Security Model](security/)** - Security architecture and patterns
- **[Server Development](../server/index/)** - Building secure plugin servers
- **[Client Development](../client/index/)** - Implementing robust plugin clients
