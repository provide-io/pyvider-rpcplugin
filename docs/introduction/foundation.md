# Foundation: The Infrastructure Layer

**Path:** [Home](../index.md) → [Introduction](index.md) → Foundation

!!! info "Canonical Foundation Reference"
    This page is the **canonical reference** for understanding Foundation's role in Pyvider RPC Plugin. Other documentation pages link here for detailed Foundation information.

## What is Foundation?

Foundation (`provide.foundation`) is a comprehensive infrastructure library that provides enterprise-grade building blocks for Python applications. Pyvider RPC Plugin is built on top of Foundation, inheriting its robust infrastructure automatically.

## Why Foundation?

Instead of reimplementing common infrastructure needs, Pyvider RPC Plugin leverages Foundation's battle-tested components:

### The Architecture Stack

```
┌─────────────────────────────────┐
│     Your Plugin Business Logic   │
├─────────────────────────────────┤
│   Pyvider RPC Plugin Framework   │
│  (gRPC, transports, protocols)   │
├─────────────────────────────────┤
│    Foundation Infrastructure     │
│ (config, logging, crypto, utils) │
├─────────────────────────────────┤
│   Python Standard Library        │
└─────────────────────────────────┘
```

## What Foundation Provides

### Core Infrastructure Components

| Component | Foundation Provides | Pyvider RPC Plugin Uses It For |
|-----------|-------------------|--------------------------------|
| **Configuration** | `RuntimeConfig` base class with validation | Plugin configuration management |
| **Logging** | Structured logging with context | All plugin logging and debugging |
| **Cryptography** | X.509 certificates, TLS operations | mTLS implementation |
| **Rate Limiting** | Token bucket algorithm | Server request throttling |
| **Error Handling** | Base exception hierarchy | Consistent error patterns |
| **Utilities** | Common patterns and helpers | Various infrastructure needs |

### What Pyvider RPC Plugin Adds

Built on Foundation's infrastructure, Pyvider RPC Plugin adds:

- **gRPC Integration**: Server and client implementation
- **Plugin Lifecycle**: Subprocess management and monitoring
- **Transport Layer**: Unix domain sockets and TCP
- **Handshake Protocol**: Magic cookie authentication
- **Protocol Buffers**: Service definition and code generation
- **Service Discovery**: Dynamic service registration

## Practical Benefits

When you use Pyvider RPC Plugin, you automatically get Foundation's benefits:

### 1. Unified Configuration

All `PLUGIN_*` environment variables are managed by Foundation's config system:

```python
from pyvider.rpcplugin.config import rpcplugin_config

# RPCPluginConfig extends Foundation's RuntimeConfig
timeout = rpcplugin_config.plugin_handshake_timeout  # Type-safe access
transports = rpcplugin_config.plugin_server_transports  # Validated values
```

### 2. Structured Logging

Every component uses Foundation's structured logging:

```python
from provide.foundation import logger

logger.info("Server starting", extra={
    "port": 50051,
    "transport": "tcp",
    "mtls_enabled": True
})
# Output: 2024-01-15 10:30:45 INFO Server starting port=50051 transport=tcp mtls_enabled=True
```

### 3. Enterprise Security

Certificate management handled by Foundation's crypto module:

```python
from provide.foundation.crypto import Certificate
from pathlib import Path

# Load certificate and private key from PEM files
# Note: from_pem() expects actual PEM content strings, not file paths
cert_path = Path("/path/to/server.crt")
key_path = Path("/path/to/server.key")

# Read the PEM content from files
cert_pem_content = cert_path.read_text()
key_pem_content = key_path.read_text()

# Create Certificate object with the PEM content
cert = Certificate.from_pem(
    cert_pem=cert_pem_content,
    key_pem=key_pem_content
)

# Or create self-signed certificates for development/testing
cert = Certificate.create_self_signed_server_cert(
    common_name="myservice.example.com",
    organization_name="My Organization",
    validity_days=365
)

# Pyvider automatically uses Foundation certificates for mTLS
# when auto_mtls is enabled via configuration
```

### 4. Rate Limiting

Foundation's token bucket protects your services:

```python
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter

# Foundation provides the algorithm
limiter = TokenBucketRateLimiter(
    capacity=100.0,
    refill_rate=50.0
)

# Use in your plugin handler
if not await limiter.is_allowed():
    raise RateLimitExceeded()
```

## Example: How They Work Together

Here's a complete example showing Foundation and Pyvider RPC Plugin integration:

```python
# Foundation provides infrastructure
from provide.foundation import logger
from provide.foundation.config import RuntimeConfig
from provide.foundation.crypto import Certificate

# Pyvider provides RPC framework
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.config import rpcplugin_config

# Your plugin uses both
class MyPlugin:
    def __init__(self):
        # Foundation logging
        logger.info("Plugin initializing")
        
        # Foundation configuration (via Pyvider's extension)
        self.timeout = rpcplugin_config.plugin_handshake_timeout
        
    async def serve(self):
        # Pyvider RPC server
        server = plugin_server(
            protocol=self.protocol,
            handler=self.handler
        )
        
        # Foundation logging
        logger.info("Server started", extra={
            "timeout": self.timeout
        })
        
        await server.serve()
```

## Foundation Features Used by Pyvider

### Configuration System

Foundation's `RuntimeConfig` provides:
- Type-safe configuration access
- Environment variable loading
- Validation and defaults
- Async configuration updates

Pyvider extends this with `RPCPluginConfig`:
```python
class RPCPluginConfig(RuntimeConfig):
    plugin_handshake_timeout: float = 10.0
    plugin_server_transports: list[str] = ["unix", "tcp"]
    # ... RPC-specific configuration
```

### Logging System

Foundation's logger provides:
- Structured logging with context
- Log level management
- Performance metrics
- Error tracking

Used throughout Pyvider:
```python
logger.info("Handshake completed", extra={
    "client_id": client_id,
    "duration_ms": duration * 1000
})
```

### Cryptography Module

Foundation's crypto provides:
- Certificate generation
- Certificate validation
- Key management
- TLS operations

Powers Pyvider's mTLS:
```python
from provide.foundation.crypto import Certificate
from pathlib import Path

# Foundation's Certificate class handles cert + key management
# Read PEM content from files
cert_pem_content = Path("/path/to/server.crt").read_text()
key_pem_content = Path("/path/to/server.key").read_text()

cert = Certificate.from_pem(
    cert_pem=cert_pem_content,
    key_pem=key_pem_content
)

# Or create self-signed certificates for development
cert = Certificate.create_self_signed_server_cert(
    common_name="myservice.example.com",
    organization_name="My Organization",
    validity_days=365
)

# Pyvider automatically uses these certificates when auto_mtls is enabled
```

## When to Use Foundation Directly

While Pyvider RPC Plugin handles most Foundation integration automatically, you might use Foundation directly for:

1. **Custom Configuration**: Extend `RuntimeConfig` for your plugin's config
2. **Advanced Logging**: Add custom log handlers or formatters
3. **Certificate Generation**: Create certificates programmatically
4. **Custom Rate Limiting**: Implement per-user or per-endpoint limits
5. **Utilities**: Use Foundation's utility functions for common patterns

## Summary

- **Foundation** provides the infrastructure layer (config, logging, crypto)
- **Pyvider RPC Plugin** provides the RPC framework (gRPC, transports, protocols)
- **Your Plugin** provides the business logic

This separation of concerns means:
- You focus on your business logic
- Pyvider handles RPC communication
- Foundation handles infrastructure
- Everything works together seamlessly

## Next Steps

Now that you understand the Foundation relationship:

1. Continue to [Architecture Overview](../development/architecture.md) to understand the system design
2. Or jump to [Installation](../getting-started/installation.md) to start building