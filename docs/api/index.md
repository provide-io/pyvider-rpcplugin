# API Reference

Comprehensive API documentation for Pyvider RPC Plugin. This reference covers all public classes, functions, and interfaces with detailed examples, configuration options, and integration patterns.

## Architecture Overview

The Pyvider RPC Plugin provides a complete plugin architecture built on gRPC with automatic configuration, security, and lifecycle management. Built on Foundation's infrastructure, it extends Foundation's capabilities with RPC-specific functionality.

### Foundation Integration

Pyvider RPC Plugin is built on [Foundation](https://foundation.provide.io), which provides:
- **Configuration Management**: Type-safe, validated configuration via `RuntimeConfig`
- **Structured Logging**: Consistent logging across all components
- **Cryptography**: X.509 certificate management and TLS operations  
- **Rate Limiting**: Token bucket rate limiting for server protection
- **Error Handling**: Standardized exception hierarchy

While Pyvider RPC Plugin adds:
- **RPC Protocol**: gRPC-based plugin communication
- **Transport Layer**: Unix sockets and TCP transport management
- **Plugin Lifecycle**: Handshake, serving, and shutdown coordination
- **Client Management**: Plugin discovery and connection handling

The API is organized into focused modules:

- **[Server](server/)** - Plugin server with health checks, rate limiting, and graceful shutdown
- **[Client](client/)** - Plugin client with automatic retry, connection pooling, and failover
- **[Transport](transport/)** - Network abstractions supporting Unix sockets and TCP with TLS
- **[Configuration](config/)** - Environment-driven configuration with validation and defaults
- **[Exceptions](exceptions/)** - Structured error hierarchy with debugging and recovery support
- **[Factory Functions](factories.md)** - Convenient creation functions with automatic configuration

## Core API Components

### Primary Classes

| Class | Purpose | Key Features |
|-------|---------|-------------|
| [`RPCPluginServer`](server/server.md) | Plugin hosting and management | Health checks, graceful shutdown, rate limiting, mTLS |
| [`RPCPluginClient`](client/client.md) | Client connection management | Automatic retry, connection pooling, timeout handling |
| [`RPCPluginConfig`](config/schema.md) | Configuration and validation | Environment loading, type safety, validation rules |
| [`UnixSocketTransport`](transport/unix.md) | High-performance local IPC | Permissions, path management, automatic cleanup |
| [`TCPSocketTransport`](transport/tcp.md) | Network communication | Port binding, TLS support, firewall integration |

### Factory Functions

| Function | Purpose | Configuration |
|----------|---------|---------------|
| [`plugin_server()`](factories.md#plugin-server) | Create configured server instance | Automatic transport, protocol, and security setup |
| [`plugin_client()`](factories.md#plugin-client) | Create configured client instance | Connection discovery, retry logic, timeout management |
| [`plugin_protocol()`](factories.md#plugin-protocol) | Protocol implementation factory | Service registration, descriptor management |

## API Modules

<div class="grid cards" markdown>

-   :material-server: **[Server API](server/)**
    
    ---
    
    Complete server implementation with health monitoring, rate limiting, graceful shutdown, and security features.
    
    **Key Components:** `RPCPluginServer`, health services, lifecycle management
    
    [:octicons-arrow-right-24: Explore Server API](server/)

-   :material-laptop: **[Client API](client/)**
    
    ---
    
    Robust client implementation with automatic connection management, retry logic, and failover support.
    
    **Key Components:** `RPCPluginClient`, connection pooling, timeout handling
    
    [:octicons-arrow-right-24: Explore Client API](client/)

-   :material-swap-horizontal: **[Transport API](transport/)**
    
    ---
    
    High-performance transport layer supporting Unix domain sockets and TCP with TLS encryption.
    
    **Key Components:** `UnixSocketTransport`, `TCPSocketTransport`, security patterns
    
    [:octicons-arrow-right-24: Explore Transport API](transport/)

-   :material-cog: **[Configuration API](config/)**
    
    ---
    
    Comprehensive configuration system with environment variable support, validation, and type safety.
    
    **Key Components:** `RPCPluginConfig`, environment loading, validation schemas
    
    [:octicons-arrow-right-24: Explore Config API](config/)

-   :material-alert: **[Exceptions API](exceptions/)**
    
    ---
    
    Structured exception hierarchy providing predictable error handling and debugging support.
    
    **Key Components:** Exception classes, error recovery patterns, debugging helpers
    
    [:octicons-arrow-right-24: Explore Exceptions API](exceptions/)

-   :material-factory: **[Factory Functions](factories.md)**
    
    ---
    
    Convenient factory functions for creating pre-configured server and client instances.
    
    **Key Components:** `plugin_server()`, `plugin_client()`, `plugin_protocol()`
    
    [:octicons-arrow-right-24: View Factory Functions](factories.md)

</div>

## Common Usage Patterns

### Quick Start - Server and Client

```python
import asyncio
from pyvider.rpcplugin import plugin_server, plugin_client
from provide.foundation import logger  # Foundation's structured logging
from my_services import MyProtocol, MyHandler

# Create server with automatic configuration
server = plugin_server(
    protocol=MyProtocol(),
    handler=MyHandler()
)

# Server runs with health checks, rate limiting, and security
server_task = asyncio.create_task(server.serve())

# Connect client with automatic retry and failover
async with plugin_client() as client:
    # Client handles connection management automatically
    response = await client.my_service.process_data(
        data="example", timeout=30.0
    )
    logger.info(f"Processing complete: {response}")

# Graceful shutdown
await server.stop()
await server_task
```

### Production Server Configuration

```python
from pyvider.rpcplugin import RPCPluginServer
from pyvider.rpcplugin.transport import TCPSocketTransport
from pyvider.rpcplugin.config import rpcplugin_config  # Extends Foundation's RuntimeConfig
from provide.foundation import logger

# Configure production-grade server
transport = TCPSocketTransport(
    host="0.0.0.0",
    port=8080,
    enable_tls=True
)

server = RPCPluginServer(
    protocol=MyProtocol(),
    handler=MyHandler(),
    transport=transport,
    enable_health=True,
    enable_rate_limiting=True,
    max_concurrent_rpcs=1000
)

# Server includes:
# - Automatic mTLS with cert management
# - Health check endpoints 
# - Rate limiting and circuit breaker
# - Metrics and observability
# - Graceful shutdown handling

await server.serve()
```

### Advanced Client Features

```python
from pyvider.rpcplugin import RPCPluginClient
from pyvider.rpcplugin.transport import UnixSocketTransport

# High-performance Unix socket client
client = RPCPluginClient(
    transport=UnixSocketTransport(path="/var/run/my-plugin.sock"),
    max_retries=5,
    retry_backoff=2.0,
    connection_timeout=10.0,
    request_timeout=60.0
)

async with client:
    # Client provides:
    # - Automatic connection pooling
    # - Exponential backoff retry
    # - Circuit breaker pattern
    # - Request/response middleware
    # - Automatic reconnection
    
    result = await client.call_with_timeout(
        method="heavy_computation",
        timeout=120.0,
        **parameters
    )
```

### Environment-Based Configuration

```python
import os
from pyvider.rpcplugin.config import rpcplugin_config

# Set environment variables for automatic configuration
os.environ.update({
    "PLUGIN_PROTOCOL_VERSION": "1",
    "PLUGIN_SERVER_TRANSPORTS": "[\"unix\", \"tcp\"]",
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_HANDSHAKE_TIMEOUT": "30",
    "PLUGIN_MAX_CONCURRENT_STREAMS": "1000"
})

# Configuration loads automatically from environment
config = rpcplugin_config
logger.info(f"Protocol version: {config.protocol_version()}")
logger.info(f"Transports: {config.server_transports()}")
logger.info(f"mTLS enabled: {config.auto_mtls_enabled()}")

# Factory functions use configuration automatically
server = plugin_server(protocol=MyProtocol(), handler=MyHandler())
```

## Type Safety and Development Experience

### Comprehensive Type Annotations

All APIs provide complete type annotations for excellent IDE support, autocompletion, and static analysis:

```python
from typing import TYPE_CHECKING
from collections.abc import Awaitable, AsyncContextManager

if TYPE_CHECKING:
    from pyvider.rpcplugin.server import RPCPluginServer
    from pyvider.rpcplugin.client import RPCPluginClient
    from pyvider.rpcplugin.transport.base import RPCPluginTransport
    from pyvider.rpcplugin.config import RPCPluginConfig

# Type-safe factory functions
server: RPCPluginServer = plugin_server(
    protocol=my_protocol,
    handler=my_handler
)

# Context manager types for proper resource handling
client: AsyncContextManager[RPCPluginClient] = plugin_client()
```

### Modern Python Features

Built for Python 3.11+ with modern typing and language features:

```python
# Union types with | operator
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport

transport: UnixSocketTransport | TCPSocketTransport = create_transport()

# Generic collections
endpoints: list[str] = config.server_endpoints()
options: dict[str, any] = config.transport_options()

# Optional types without typing.Optional
path: str | None = transport.socket_path()
port: int | None = transport.port()
```

## Exception Handling and Error Recovery

The API provides a comprehensive exception hierarchy with rich context and recovery patterns:

```python
from pyvider.rpcplugin.exception import (
    RPCPluginError,      # Base exception with context
    TransportError,      # Transport and network issues
    HandshakeError,      # Authentication and setup failures  
    SecurityError,       # TLS and certificate problems
    ConfigError,         # Configuration validation errors
    ProtocolError,       # RPC protocol violations
    TimeoutError,        # Operation timeout handling
)

# Production error handling with recovery
try:
    await server.serve()
except SecurityError as e:
    logger.error(f"Security setup failed: {e.details}")
    # Check certificates, verify mTLS configuration
    await handle_security_error(e)
except TransportError as e:
    logger.warning(f"Transport issue: {e}")
    # Retry with different transport or endpoints
    await retry_with_fallback_transport()
except ConfigError as e:
    logger.error(f"Configuration invalid: {e.validation_errors}")
    # Fix configuration and restart
    config.reload_from_environment()
    raise  # Re-raise after logging
except RPCPluginError as e:
    logger.error(f"Plugin error: {e}", extra=e.context)
    # Generic error handling with full context
    await cleanup_and_restart()
```

### Error Context and Debugging

```python
# Exceptions include rich debugging context
try:
    await client.connect("unix:/tmp/plugin.sock")
except TransportError as e:
    # Access detailed error information
    logger.error(f"Connection failed to {e.endpoint}")
    logger.debug(f"Error details: {e.details}")
    logger.debug(f"Retry count: {e.retry_count}")
    logger.debug(f"Last attempt: {e.timestamp}")
    
    # Make recovery decisions based on error type
    if e.is_retryable:
        await asyncio.sleep(e.suggested_backoff)
        # Retry logic here
    else:
        # Permanent failure, use fallback
        await switch_to_fallback_endpoint()
```

## Foundation Architecture Integration

Built on Foundation for enterprise-grade features. The integration is seamless - Foundation provides the infrastructure, while Pyvider RPC Plugin adds RPC-specific capabilities:

### Structured Logging and Observability

```python
from provide.foundation import logger  # Foundation's structured logging
from pyvider.rpcplugin import plugin_server

# Foundation provides rich logging with context and emoji enhancement
server = plugin_server(protocol=my_protocol, handler=my_handler)
logger.info("🚀 Plugin server started", extra={
    "server_id": server.id,
    "transport_type": server.transport.type,
    "endpoint": server.transport.endpoint
})

# Automatic request/response logging with timing
# Error logging includes full stack traces and context
# Performance metrics logged automatically
```

### Security and Cryptography

```python
from provide.foundation.crypto import Certificate, PrivateKey
from pyvider.rpcplugin.transport import TCPSocketTransport

# Automatic certificate management
transport = TCPSocketTransport(
    host="0.0.0.0",
    port=8443,
    enable_tls=True
    # Certificates managed automatically via foundation
)

# Manual certificate configuration when needed
cert = Certificate.load_from_file("server.crt")
key = PrivateKey.load_from_file("server.key")
transport.configure_tls(cert=cert, key=key)
```

### Configuration and Environment Management

```python
from provide.foundation.config import RuntimeConfig
from pyvider.rpcplugin.config import rpcplugin_config  # Extends RuntimeConfig

# Foundation provides the configuration infrastructure:
# - Environment variables loaded automatically
# - Validation and type coercion built-in  
# - Multi-source configuration loading
# - Hot-reload support for development

# Pyvider extends Foundation's RuntimeConfig with RPC-specific fields
# Access any configuration value with type safety
handshake_timeout: float = rpcplugin_config.handshake_timeout()
transports: list[str] = rpcplugin_config.server_transports()
mtls_enabled: bool = rpcplugin_config.auto_mtls_enabled()

# All configuration follows Foundation's validation patterns
class RPCPluginConfig(RuntimeConfig):  # Extends Foundation
    plugin_handshake_timeout: float = field(default=10.0, validator=validate_range(0.1, 300.0))
    plugin_server_transports: list[str] = field(validator=validate_transport_list)
```

### Performance and Resource Management

```python
# Foundation provides automatic resource management
# Connection pooling and lifecycle management
# Memory usage monitoring and optimization
# Graceful shutdown with resource cleanup

# All handled automatically by the framework
server = plugin_server(protocol=my_protocol, handler=my_handler)
# Server includes all foundation features automatically
```

## Getting Started

### Next Steps

1. **[Quick Start Guide](../getting-started/)** - Get up and running in minutes
2. **[Examples](../examples/)** - Working code samples for common scenarios
3. **[User Guide](../guide/)** - Conceptual explanations and best practices
4. **[Testing Guide](../development/testing.md)** - Testing patterns and fixtures
5. **[Configuration Guide](../guide/config/)** - Environment setup and options

### API Documentation

Browse the comprehensive API documentation using the module cards above, or jump directly to:

- **[Server API](server/)** - Complete server implementation
- **[Client API](client/)** - Robust client with retry logic
- **[Transport API](transport/)** - Network layer abstractions
- **[Configuration API](config/)** - Environment-driven configuration
- **[Exception API](exceptions/)** - Error handling patterns
- **[Factory Functions](factories.md)** - Convenient creation helpers

### Community and Support

- **Documentation Issues** - Report documentation problems on GitHub
- **API Questions** - Use GitHub Discussions for API usage questions
- **Bug Reports** - File issues for API bugs or unexpected behavior

---

*This API reference is comprehensive and includes all public interfaces. For implementation details and private APIs, refer to the source code and inline documentation.*