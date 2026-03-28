# Examples Overview

This section provides a comprehensive overview of all available examples in the Pyvider RPC Plugin system. These examples demonstrate real-world usage patterns, from basic setups to production deployments.

## Quick Start Examples

### Echo Service

The simplest example demonstrating basic server-client communication:

```bash
# Terminal 1: Start echo server
cd examples/
python echo_server.py

# Terminal 2: Connect with echo client
python echo_client.py
```

**What it demonstrates:**

- Basic server setup with protocol implementation
- Client connection and RPC calls
- Error handling and graceful shutdown

**Files:**

- `echo_server.py` - Server implementation
- `echo_client.py` - Client implementation
- `proto/echo.proto` - Protocol definition

### End-to-End Greeter

A complete greeter service showing production patterns:

```bash
# Start greeter server
python examples/e2e_greeter_server.py

# Connect with greeter client
python examples/e2e_greeter_client.py
```

**What it demonstrates:**

- Custom protocol implementation
- Service handler with business logic
- Health checking and status monitoring
- Production-focused server configuration

## Development Examples

### Quick Start Server

Minimal server for rapid prototyping:

```python
# From dummy_server.py
from pyvider.rpcplugin import plugin_server, plugin_protocol

async def main():
    server = plugin_server(
        protocol=plugin_protocol(),
        handler=DummyHandler()
    )
    await server.serve()
```

**Files:**

- `dummy_server.py`
- `quick_start_client.py`

### Transport Configuration

Examples showing different transport options:

```python
# From transport_options_demo.py
# Unix socket transport
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="unix",
    transport_path="/tmp/my-plugin.sock"
)

# TCP transport
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="tcp",
    host="127.0.0.1",
    port=8080
)
```

**File:**

- `transport_options_demo.py`

## Advanced Examples

### Security and mTLS

Comprehensive security setup with mutual TLS:

```python
# From security_mtls_example.py
import os
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger

# Load certificate and key PEM content from files
# Note: from_pem() expects PEM string content, not file paths
cert_pem_content = Path("/etc/ssl/server.crt").read_text()
key_pem_content = Path("/etc/ssl/server.key").read_text()

server_cert = Certificate.from_pem(
    cert_pem=cert_pem_content,
    key_pem=key_pem_content
)

# Configure mTLS with Foundation patterns
os.environ.update({
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_SERVER_CERT": server_cert.cert_pem,
    "PLUGIN_SERVER_KEY": server_cert.key_pem,
})

logger.info("mTLS configuration loaded", extra={
    "cert_common_name": server_cert.common_name,
    "auto_mtls": True
})

server = plugin_server(protocol=protocol, handler=handler)
```

**What it demonstrates:**

- Certificate generation and management
- mTLS configuration and validation
- Secure client-server communication
- Certificate rotation patterns

**File:**

- `security_mtls_example.py`

### Custom Protocols

Building custom protocol implementations:

```python
# From custom_protocols_demo.py
class CustomProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self):
        return my_service_pb2_grpc, "mypackage.MyService"

    async def add_to_server(self, server, handler):
        add_MyServiceServicer_to_server(handler, server)
```

**What it demonstrates:**

- Protocol interface implementation
- gRPC service integration
- Service handler patterns
- Method type configuration

**File:**

- `custom_protocols_demo.py`

## Configuration Examples

### Production Configuration
Production-focused configuration patterns:

```python
# From production_config_discussion.py
def production_config():
    return {
        "auto_mtls": True,
        "server_transports": ["tcp"],
        "rate_limit_enabled": True,
        "rate_limit_requests_per_second": 100.0,
        "health_service_enabled": True,
        "log_level": "INFO"
    }
```

**What it demonstrates:**

- Environment-specific configurations
- Security best practices
- Performance tuning options
- Monitoring and observability setup

**File:**

- `production_config_discussion.py`

### Performance Tuning

Performance optimization examples:

```python
# From performance_tuning_concepts.py
# High-throughput configuration
configure(
    max_concurrent_rpcs=1000,
    grpc_options=[
        ('grpc.keepalive_time_ms', 30000),
        ('grpc.max_concurrent_streams', 100),
    ]
)
```

**What it demonstrates:**

- gRPC performance tuning
- Concurrency configuration
- Resource optimization
- Benchmarking patterns

**File:**

- `performance_tuning_concepts.py`

## Error Handling Examples

### Comprehensive Error Handling

Production-grade error handling patterns:

```python
# From error_handling_demo.py
from pyvider.rpcplugin.exception import (
    RPCPluginError, TransportError, HandshakeError
)
from provide.foundation import logger

try:
    async with client:
        result = await client.process_request(data)
except HandshakeError as e:
    logger.error("Handshake failed", extra={
        "error": str(e),
        "error_type": "handshake",
        "recovery_action": "check_magic_cookie"
    })
    # Handle authentication or protocol issues
except TransportError as e:
    logger.error("Transport error", extra={
        "error": str(e),
        "error_type": "transport",
        "recovery_action": "retry_connection"
    })
    # Handle network connectivity issues
except RPCPluginError as e:
    logger.error("Plugin error", extra={
        "error": str(e),
        "error_type": "plugin",
        "hint": getattr(e, 'hint', None)
    })
    # Handle any plugin-related error
```

**File:**

- `error_handling_demo.py`

## Async Pattern Examples

### Advanced Async Patterns

Modern async/await patterns for plugin development:

```python
# From async_patterns_demo.py
from provide.foundation import logger
import asyncio

async def concurrent_requests():
    client = plugin_client(command=["python", "-m", "my_plugin"])

    async with client:
        logger.info("Starting concurrent request processing", extra={
            "item_count": len(items),
            "concurrency_level": "high"
        })

        # Concurrent RPC calls with Foundation logging
        tasks = [
            client.process_item(item) for item in items
        ]

        with logger.contextualize(operation="concurrent_processing"):
            results = await asyncio.gather(*tasks, return_exceptions=True)

            successful_count = sum(1 for r in results if not isinstance(r, Exception))
            logger.info("Concurrent processing completed", extra={
                "total_items": len(results),
                "successful": successful_count,
                "failed": len(results) - successful_count
            })

            return results
```

**File:**

- `async_patterns_demo.py`

## Running All Examples

Use the comprehensive example runner:

```bash
# Run all examples with validation
python examples/run_all_examples.py

# Run specific example category
python examples/run_all_examples.py --category=basic
python examples/run_all_examples.py --category=security
python examples/run_all_examples.py --category=performance
```

## Example Structure

Examples are organized in a flat directory structure with descriptive names:

```
examples/
├── quick_start_client.py         # Basic client example
├── dummy_server.py                # Minimal server
├── echo_server.py                 # Echo service server
├── echo_client.py                 # Echo service client
├── e2e_greeter_server.py          # End-to-end greeter server
├── e2e_greeter_client.py          # End-to-end greeter client
├── security_mtls_example.py       # mTLS security patterns
├── transport_options_demo.py      # Transport configuration
├── [other examples...]
├── proto/                         # Protocol Buffer definitions
│   ├── echo.proto                 # Echo service definition
│   ├── e2e_greeting.proto         # Greeter service definition
│   ├── *_pb2.py                   # Generated message code
│   └── *_pb2_grpc.py              # Generated service code
└── short/                         # Short focused examples (15-30 lines)
    ├── basic_server.py
    ├── basic_client.py
    └── [other short examples...]
```

## Example Categories

| Category           | Examples                                                                | Focus                                         |
| ------------------ | ----------------------------------------------------------------------- | --------------------------------------------- |
| **Basic**          | dummy_server, echo_server, echo_client                                  | Getting started, basic patterns               |
| **Transport**      | transport_options_demo, direct_client_connection                        | Unix sockets, TCP, direct connections         |
| **Security**       | security_mtls_example                                                   | mTLS, certificates, authentication            |
| **Advanced**       | async_patterns_demo, custom_protocols_demo, performance_tuning_concepts | Async patterns, custom protocols, performance |
| **Configuration**  | production_config_discussion                                            | Production setup, environment variables       |
| **Error Handling** | error_handling_demo                                                     | Exception handling, recovery patterns         |
| **End-to-End**     | e2e_greeter_server, e2e_greeter_client                                  | Complete application examples                 |

## Next Steps

1. **Start with Basic Examples**: Begin with the Echo service for fundamental concepts
1. **Explore Security**: Review mTLS examples for production readiness
1. **Custom Development**: Use protocol and async examples for advanced features
1. **Production Setup**: Follow configuration examples for deployment

## Additional Resources

- **[Complete Example Index](../examples/index.md)** - All available examples with source code
- **[User Guide](../guide/index.md)** - Conceptual explanations and best practices
- **[API Reference](../reference/index.md)** - Complete API documentation
- **[Configuration Guide](../guide/config/index.md)** - Environment setup and options
