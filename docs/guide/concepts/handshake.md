# Handshake Process

The Pyvider RPC Plugin handshake establishes secure, authenticated connections between host applications and plugin processes. This process ensures both parties can communicate safely before any RPC operations begin.

## Overview

The handshake process follows a multi-phase negotiation:

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

## Magic Cookie Authentication

### Purpose and Security Model

The magic cookie serves as a shared secret for mutual authentication:

- **Process Isolation** - Ensures only authorized processes connect
- **Mutual Authentication** - Both client and server verify each other
- **Ephemeral Secrets** - Cookies can be rotated or session-specific
- **Simple Implementation** - No complex key exchange required

### Cookie Generation and Exchange

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

### Cookie Validation Process

The handshake validates cookies through a challenge-response mechanism:

```python
# Simplified handshake flow
class HandshakeHandler:
    def __init__(self, expected_cookie: str):
        self.expected_cookie = expected_cookie
    
    async def validate_client_cookie(self, received_cookie: str) -> bool:
        """Validate client's magic cookie."""
        # Timing-safe comparison prevents timing attacks
        return secrets.compare_digest(
            self.expected_cookie.encode(),
            received_cookie.encode()
        )
    
    async def send_server_cookie(self) -> str:
        """Send server's magic cookie to client."""
        return self.expected_cookie
    
    async def perform_handshake(self, transport):
        """Complete handshake sequence."""
        # 1. Receive client cookie
        client_cookie = await transport.receive_message()
        
        # 2. Validate client cookie
        if not await self.validate_client_cookie(client_cookie):
            raise HandshakeError("Invalid magic cookie from client")
        
        # 3. Send server cookie
        server_cookie = await self.send_server_cookie()
        await transport.send_message(server_cookie)
        
        # 4. Handshake complete
        return True
```

## Protocol Negotiation

### Version Compatibility

Clients and servers negotiate protocol versions during handshake:

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

# Usage during handshake
negotiator = ProtocolNegotiator()
agreed_version = await negotiator.negotiate_version(["1.0", "1.1"])
# Result: "1.1" (highest common version)
```

### Feature Negotiation

Beyond versions, handshake negotiates specific features:

```python
class FeatureNegotiator:
    def __init__(self):
        self.server_features = {
            "streaming": True,
            "compression": ["gzip", "deflate"],
            "auth_methods": ["magic_cookie", "mtls"],
            "max_message_size": 1024 * 1024,  # 1MB
            "heartbeat_interval": 30.0  # seconds
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
        
        # Negotiate numeric features (minimum)
        for feature in ["max_message_size"]:
            agreed_features[feature] = min(
                self.server_features.get(feature, float('inf')),
                client_features.get(feature, float('inf'))
            )
        
        return agreed_features
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

## Transport Layer Integration

### Unix Socket Handshake

For Unix socket transport, handshake occurs over the socket connection:

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

### TCP Handshake with mTLS

For TCP transport with mTLS, handshake includes certificate validation:

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

## Error Handling During Handshake

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

class CertificateValidationError(HandshakeError):
    """Certificate validation failed during mTLS."""
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
    except OSError as e:
        raise HandshakeError(
            f"Network error during handshake: {e}",
            hint="Check network connectivity and firewall settings"
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

## Handshake Performance

### Optimization Strategies

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
    
    async def parallel_handshake(self, transports: list) -> list[dict]:
        """Perform multiple handshakes in parallel."""
        handshake_tasks = [
            self.perform_handshake(transport)
            for transport in transports
        ]
        
        # Wait for all handshakes to complete
        results = await asyncio.gather(*handshake_tasks, return_exceptions=True)
        
        # Process results and handle errors
        successful_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Handshake {i} failed: {result}")
            else:
                successful_results.append(result)
        
        return successful_results
```

## What's Next?

Now that you understand the handshake process:

- **[Transports](transports.md)** - Transport layer implementation details
- **[Security Model](security.md)** - Complete security architecture
- **[Server Development](../server/index.md)** - Building secure plugin servers  
- **[Client Development](../client/index.md)** - Implementing robust plugin clients