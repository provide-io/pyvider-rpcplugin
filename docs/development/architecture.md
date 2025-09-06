# Architecture

This document provides a comprehensive overview of the Pyvider RPC Plugin architecture, focusing on design principles, component relationships, and integration patterns.

## System Overview

The Pyvider RPC Plugin framework uses a **layered architecture** with clear separation of concerns:

```mermaid
graph TD
    A[Client Application] --> B[RPC Plugin Client]
    B --> C[Transport Layer]
    C --> D[Protocol Layer]
    D --> E[Network]
    E --> F[Protocol Layer]
    F --> G[Transport Layer]
    G --> H[RPC Plugin Server]
    H --> I[Service Implementation]
    
    subgraph "Client Side"
        B
        C
    end
    
    subgraph "Network Boundary"
        E
    end
    
    subgraph "Server Side"
        G
        H
        I
    end
```

### Core Design Principles

1. **Separation of Concerns** - Each layer has a single, well-defined responsibility
2. **Transport Agnostic** - Support multiple transport mechanisms (Unix sockets, TCP, etc.)
3. **Protocol Flexibility** - Pluggable protocol implementations
4. **Type Safety** - Modern typing throughout (dict, list, set)
5. **Async First** - Built on asyncio for high performance
6. **Security by Default** - mTLS and authentication built-in
7. **Production Ready** - Comprehensive error handling, logging, and monitoring

## Component Architecture

### 1. Transport Layer

The transport layer handles low-level communication between client and server:

```python
# src/pyvider/transport/base.py
from abc import ABC, abstractmethod
import asyncio

class BaseTransport(ABC):
    """Abstract base class for all transport implementations."""
    
    def __init__(self, config: TransportConfig):
        self.config = config
        self._connection = None
        self._lock = asyncio.Lock()
    
    @abstractmethod
    async def connect(self, address: str) -> None:
        """Establish connection to the specified address."""
    
    @abstractmethod
    async def send(self, data: bytes) -> None:
        """Send data over the transport."""
    
    @abstractmethod
    async def receive(self) -> bytes:
        """Receive data from the transport."""
```

#### Transport Implementations

The framework supports multiple transport mechanisms:

**Unix Socket Transport** - For local communication with high performance:
```python
class UnixSocketTransport(BaseTransport):
    async def connect(self, socket_path: str) -> None:
        reader, writer = await asyncio.open_unix_connection(socket_path)
        self._connection = (reader, writer)
```

**TCP Transport** - For network communication with optional TLS:
```python
class TCPTransport(BaseTransport):
    async def connect(self, address: str) -> None:
        host, port = address.split(':', 1)
        reader, writer = await asyncio.open_connection(
            host, int(port), ssl=self._ssl_context
        )
        self._connection = (reader, writer)
```

### 2. Protocol Layer

The protocol layer handles message serialization and RPC semantics:

```python
# src/pyvider/protocol/base.py
from abc import ABC, abstractmethod
from typing import TypeVar, Generic
import asyncio

T = TypeVar('T')
U = TypeVar('U')

class BaseProtocol(ABC, Generic[T, U]):
    """Abstract base class for RPC protocols."""
    
    def __init__(self, transport: BaseTransport):
        self.transport = transport
        self._pending_requests: dict = {}
    
    @abstractmethod
    async def serialize_request(self, method: str, args: T) -> bytes:
        """Serialize request for transmission."""
    
    @abstractmethod
    async def call_method(self, method_name: str, request: T) -> U:
        """Call remote method."""
```

#### Protocol Implementations

**gRPC Protocol** - Production-ready with comprehensive feature set:
```python
class GRPCProtocol(BaseProtocol):
    async def call_method(self, method_name: str, request: Message) -> Message:
        method = getattr(self._stub, method_name)
        try:
            return await method(request)
        except grpc.RpcError as e:
            raise ProtocolError(f"RPC call failed: {e.code()}: {e.details()}")
```

### 3. Server Architecture

The server provides a high-level interface for implementing RPC services:

```python
# src/pyvider/server/server.py
import asyncio
import logging
from grpc.aio import Server, add_insecure_port, add_secure_port

class RPCPluginServer:
    """High-level RPC server implementation."""
    
    def __init__(self, config: ServerConfig):
        self.config = config
        self._server = None
        self._services: list = []
        self._interceptors: list = []
        self._shutdown_event = asyncio.Event()
    
    def add_service(self, service) -> None:
        """Add RPC service to the server."""
        self._services.append(service)
    
    async def start(self) -> None:
        """Start the RPC server."""
        self._server = Server(interceptors=self._interceptors)
        
        # Register services
        for service in self._services:
            add_servicer = getattr(service, 'add_to_server')
            add_servicer(service, self._server)
        
        # Configure port and start
        if self.config.tls_enabled:
            credentials = self._create_server_credentials()
            add_secure_port(self._server, f"{self.config.host}:{self.config.port}", credentials)
        else:
            add_insecure_port(self._server, f"{self.config.host}:{self.config.port}")
        
        await self._server.start()
    
    async def stop(self, grace_period: int = 30) -> None:
        """Stop the RPC server gracefully."""
        if self._server:
            await self._server.stop(grace_period)
```

### 4. Client Architecture

The client provides a simplified interface for making RPC calls:

```python
# src/pyvider/client/client.py
import asyncio
from typing import Generic, TypeVar, AsyncIterator
from grpc.aio import insecure_channel, secure_channel

T = TypeVar('T')
U = TypeVar('U')

class RPCPluginClient(Generic[T, U]):
    """High-level RPC client implementation."""
    
    def __init__(self, config: ClientConfig):
        self.config = config
        self._channel = None
        self._stub = None
        self._retry_policy = RetryPolicy(config.retry_config)
    
    async def connect(self) -> None:
        """Establish connection to RPC server."""
        target = f"{self.config.host}:{self.config.port}"
        
        if self.config.tls_enabled:
            credentials = self._create_client_credentials()
            self._channel = secure_channel(target, credentials)
        else:
            self._channel = insecure_channel(target)
        
        self._stub = self.config.service_stub_class(self._channel)
    
    async def call(self, method_name: str, request: T, timeout: float | None = None) -> U:
        """Make RPC call with retry logic."""
        async def _make_call() -> U:
            method = getattr(self._stub, method_name)
            return await method(request, timeout=timeout)
        
        return await self._retry_policy.execute(_make_call)
    
    async def stream_call(self, method_name: str, request_iterator: AsyncIterator[T]) -> AsyncIterator[U]:
        """Make streaming RPC call."""
        method = getattr(self._stub, method_name)
        async for response in method(request_iterator):
            yield response
```

### 5. Configuration System

Centralized configuration management with environment variable support:

```python
# src/pyvider/config/schema.py
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class TransportConfig:
    """Transport layer configuration."""
    type: str = "tcp"  # tcp, unix
    host: str = "localhost"
    port: int = 50051
    socket_path: str | None = None
    tls_enabled: bool = False
    cert_file: str | None = None
    key_file: str | None = None
    ca_cert_file: str | None = None

@dataclass
class ServerConfig:
    """Server configuration with environment variable support."""
    transport: TransportConfig = field(default_factory=TransportConfig)
    max_workers: int = 10
    max_connections: int = 1000
    request_timeout: float = 30.0
    log_level: str = "INFO"
    
    @classmethod 
    def from_env(cls) -> 'ServerConfig':
        """Load configuration from PLUGIN_* environment variables."""
        import os
        
        return cls(
            transport=TransportConfig(
                host=os.getenv('PLUGIN_HOST', 'localhost'),
                port=int(os.getenv('PLUGIN_PORT', '50051')),
                tls_enabled=os.getenv('PLUGIN_TLS_ENABLED', 'false').lower() == 'true',
                cert_file=os.getenv('PLUGIN_CERT_FILE'),
                key_file=os.getenv('PLUGIN_KEY_FILE'),
            ),
            max_workers=int(os.getenv('PLUGIN_MAX_WORKERS', '10')),
            log_level=os.getenv('PLUGIN_LOG_LEVEL', 'INFO'),
        )
```

## Service Implementation Patterns

### Basic Service

```python
# example_service.py
import asyncio
from typing import AsyncIterator
from pyvider.service import BaseService
from .generated import service_pb2, service_pb2_grpc

class EchoService(service_pb2_grpc.EchoServiceServicer, BaseService):
    """Example RPC service implementation."""
    
    async def Echo(
        self, 
        request: service_pb2.EchoRequest, 
        context: grpc.aio.ServicerContext
    ) -> service_pb2.EchoResponse:
        """Echo the received message back to client."""
        logger.info(f"Echo request: {request.message}")
        
        return service_pb2.EchoResponse(
            message=request.message,
            timestamp=time.time()
        )
    
    async def StreamEcho(
        self,
        request: service_pb2.EchoRequest,
        context: grpc.aio.ServicerContext
    ) -> AsyncIterator[service_pb2.EchoResponse]:
        """Stream echo responses."""
        for i in range(10):
            yield service_pb2.EchoResponse(
                message=f"{request.message} #{i}",
                timestamp=time.time()
            )
            await asyncio.sleep(1)
```

### Database Integration Service

```python
# database_service.py
class DatabaseService(service_pb2_grpc.DatabaseServiceServicer, BaseService):
    """Database service with connection pooling."""
    
    def __init__(self, db_pool):
        self.db_pool = db_pool
    
    async def GetUser(self, request, context) -> service_pb2.GetUserResponse:
        """Get user from database with error handling."""
        async with self.db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, name, email FROM users WHERE id = $1",
                request.user_id
            )
            
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, "User not found")
            
            return service_pb2.GetUserResponse(user=service_pb2.User(**row))
```

## Error Handling Architecture

### Exception Hierarchy

```python
# src/pyvider/exceptions.py
class RPCPluginError(Exception):
    """Base exception for all RPC Plugin errors."""
    
    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

class TransportError(RPCPluginError):
    """Transport layer errors."""
    pass

class ProtocolError(RPCPluginError):
    """Protocol layer errors."""
    pass

class ServiceError(RPCPluginError):
    """Service implementation errors."""
    pass

class ConfigurationError(RPCPluginError):
    """Configuration errors."""
    pass

class AuthenticationError(RPCPluginError):
    """Authentication failures."""
    pass

class AuthorizationError(RPCPluginError):
    """Authorization failures."""
    pass
```

### Error Propagation

```python
# Error handling middleware
class ErrorHandlingInterceptor:
    """Convert Python exceptions to gRPC status codes."""
    
    EXCEPTION_MAPPING = {
        ValidationError: grpc.StatusCode.INVALID_ARGUMENT,
        AuthenticationError: grpc.StatusCode.UNAUTHENTICATED,
        AuthorizationError: grpc.StatusCode.PERMISSION_DENIED,
        NotFoundError: grpc.StatusCode.NOT_FOUND,
        TimeoutError: grpc.StatusCode.DEADLINE_EXCEEDED,
        ServiceUnavailableError: grpc.StatusCode.UNAVAILABLE,
    }
    
    async def intercept_service(self, continuation, handler_call_details):
        try:
            return await continuation(handler_call_details)
        except Exception as e:
            status_code = self.EXCEPTION_MAPPING.get(type(e), grpc.StatusCode.INTERNAL)
            await handler_call_details.context.abort(status_code, str(e))
```

## Performance Architecture

### Connection Pooling

```python
# src/pyvider/client/pool.py
import asyncio
import time
from typing import Any
from collections import deque

class ConnectionPool:
    """Connection pool for efficient resource management."""
    
    def __init__(self, max_size: int = 10, max_idle_time: int = 300):
        self.max_size = max_size
        self.max_idle_time = max_idle_time
        self._pool: deque[tuple[Any, float]] = deque()
        self._in_use: set = set()
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> Any:
        """Acquire connection from pool."""
        async with self._lock:
            # Try to reuse existing connection
            while self._pool:
                conn, last_used = self._pool.popleft()
                
                if time.time() - last_used > self.max_idle_time:
                    await conn.close()
                    continue
                
                if await conn.is_healthy():
                    self._in_use.add(conn)
                    return conn
                else:
                    await conn.close()
            
            # Create new connection if under limit
            if len(self._in_use) < self.max_size:
                conn = await self._create_connection()
                self._in_use.add(conn)
                return conn
            
            # Wait for connection to be available
            while len(self._in_use) >= self.max_size:
                await asyncio.sleep(0.1)
            
            # Retry acquisition
            return await self.acquire()
    
    async def release(self, conn: Any) -> None:
        """Release connection back to pool."""
        async with self._lock:
            if conn in self._in_use:
                self._in_use.remove(conn)
                
                if await conn.is_healthy():
                    self._pool.append((conn, time.time()))
                else:
                    await conn.close()
```

## Security Architecture

### Authentication Flow

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    participant A as Auth Service
    
    C->>S: Connect with mTLS certificate
    S->>S: Validate client certificate
    S->>A: Verify certificate against CA
    A->>S: Certificate valid
    S->>C: Connection established
    
    C->>S: RPC request with JWT token
    S->>S: Validate JWT signature
    S->>S: Check token expiration
    S->>S: Authorize based on claims
    S->>C: RPC response
```

### Security Implementation

```python
# src/pyvider/security/auth.py
import jwt
import time
from typing import Any
from cryptography import x509
from cryptography.hazmat.primitives import hashes

class SecurityManager:
    """Centralized security management."""
    
    def __init__(self, config: SecurityConfig):
        self.config = config
        self._ca_cert = self._load_ca_certificate()
        self._jwt_secret = config.jwt_secret
    
    def validate_certificate(self, cert_der: bytes) -> dict:
        """Validate client certificate against CA."""
        try:
            cert = x509.load_der_x509_certificate(cert_der)
            
            # Check if certificate is signed by our CA
            ca_public_key = self._ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_oid._name
            )
            
            # Extract certificate information
            return {
                'subject': cert.subject.rfc4514_string(),
                'serial_number': str(cert.serial_number),
                'valid_from': cert.not_valid_before,
                'valid_to': cert.not_valid_after,
            }
        
        except Exception as e:
            raise AuthenticationError(f"Certificate validation failed: {e}")
    
    def validate_jwt_token(self, token: str) -> dict:
        """Validate JWT token."""
        try:
            payload = jwt.decode(
                token,
                self._jwt_secret,
                algorithms=['HS256']
            )
            
            # Check expiration
            if payload.get('exp', 0) < time.time():
                raise AuthenticationError("Token expired")
            
            return payload
        
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {e}")
```

This architecture provides a robust, scalable foundation for building RPC services with comprehensive security, performance, and reliability features. The modular design allows for easy extension and customization while maintaining clean separation of concerns.