# Examples Overview

This section provides a comprehensive overview of all available examples in the Pyvider RPC Plugin system. These examples demonstrate real-world usage patterns, from basic setups to production deployments.

## Quick Start Examples

### Echo Service
The simplest example demonstrating basic server-client communication:

```bash
# Terminal 1: Start echo server
cd examples/
python ch05_echo_server.py

# Terminal 2: Connect with echo client  
python ch07_echo_client.py
```

**What it demonstrates:**
- Basic server setup with protocol implementation
- Client connection and RPC calls
- Error handling and graceful shutdown

**Files:**
- [`ch05_echo_server.py`](../examples/ch05_echo_server.py) - Server implementation
- [`ch07_echo_client.py`](../examples/ch07_echo_client.py) - Client implementation
- [`proto/echo.proto`](../examples/proto/echo.proto) - Protocol definition

### End-to-End Greeter
A complete greeter service showing production patterns:

```bash
# Start greeter server
python examples/ch15_e2e_server.py

# Connect with greeter client
python examples/ch15_e2e_client.py
```

**What it demonstrates:**
- Custom protocol implementation
- Service handler with business logic
- Health checking and status monitoring
- Production-ready server configuration

## Development Examples

### Quick Start Server
Minimal server for rapid prototyping:

```python
# From ch02_dummy_server.py
from pyvider.rpcplugin import plugin_server, plugin_protocol

async def main():
    server = plugin_server(
        protocol=plugin_protocol(),
        handler=DummyHandler()
    )
    await server.serve()
```

**Files:**
- [`ch02_dummy_server.py`](../examples/ch02_dummy_server.py)
- [`ch02_quick_start_client.py`](../examples/ch02_quick_start_client.py)

### Transport Configuration
Examples showing different transport options:

```python
# From ch04_transport_options_demo.py
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
- [`ch04_transport_options_demo.py`](../examples/ch04_transport_options_demo.py)

## Advanced Examples

### Security and mTLS
Comprehensive security setup with mutual TLS:

```python
# From ch09_security_mtls_example.py
import os
from provide.foundation.crypto import Certificate

# Configure mTLS
os.environ.update({
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_SERVER_CERT": server_cert.cert,
    "PLUGIN_SERVER_KEY": server_cert.key,
})

server = plugin_server(protocol=protocol, handler=handler)
```

**What it demonstrates:**
- Certificate generation and management
- mTLS configuration and validation
- Secure client-server communication
- Certificate rotation patterns

**File:**
- [`ch09_security_mtls_example.py`](../examples/ch09_security_mtls_example.py)

### Custom Protocols
Building custom protocol implementations:

```python
# From ch13_custom_protocols_demo.py
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
- [`ch13_custom_protocols_demo.py`](../examples/ch13_custom_protocols_demo.py)

## Configuration Examples

### Production Configuration
Production-ready configuration patterns:

```python
# From ch12_production_config_discussion.py
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
- [`ch12_production_config_discussion.py`](../examples/ch12_production_config_discussion.py)

### Performance Tuning
Performance optimization examples:

```python
# From ch14_performance_tuning_concepts.py
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
- [`ch14_performance_tuning_concepts.py`](../examples/ch14_performance_tuning_concepts.py)

## Error Handling Examples

### Comprehensive Error Handling
Production-grade error handling patterns:

```python
# From ch11_error_handling_demo.py
from pyvider.rpcplugin.exception import (
    RPCPluginError, TransportError, HandshakeError
)

try:
    async with client:
        result = await client.process_request(data)
except HandshakeError as e:
    logger.error(f"Handshake failed: {e}")
    # Handle authentication or protocol issues
except TransportError as e:
    logger.error(f"Transport error: {e}")
    # Handle network connectivity issues  
except RPCPluginError as e:
    logger.error(f"Plugin error: {e}")
    # Handle any plugin-related error
```

**File:**
- [`ch11_error_handling_demo.py`](../examples/ch11_error_handling_demo.py)

## Async Pattern Examples

### Advanced Async Patterns
Modern async/await patterns for plugin development:

```python
# From ch10_async_patterns_demo.py
async def concurrent_requests():
    client = plugin_client(command=["python", "-m", "my_plugin"])
    
    async with client:
        # Concurrent RPC calls
        tasks = [
            client.process_item(item) for item in items
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results
```

**File:**
- [`ch10_async_patterns_demo.py`](../examples/ch10_async_patterns_demo.py)

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

Each example follows a consistent structure:

```
examples/
├── chXX_example_name.py          # Main example script
├── proto/                        # Protocol definitions
│   ├── service.proto
│   ├── service_pb2.py           # Generated gRPC code
│   └── service_pb2_grpc.py
├── README.md                     # Example documentation
└── requirements.txt              # Dependencies
```

## Example Categories

| Category | Examples | Focus |
|----------|----------|-------|
| **Basic** | ch02, ch05, ch07 | Getting started, basic patterns |
| **Transport** | ch04, ch08 | Unix sockets, TCP, direct connections |
| **Security** | ch09 | mTLS, certificates, authentication |
| **Advanced** | ch10, ch13, ch14 | Async patterns, custom protocols, performance |
| **Configuration** | ch12 | Production setup, environment variables |
| **Error Handling** | ch11 | Exception handling, recovery patterns |
| **End-to-End** | ch15 | Complete application examples |

## Next Steps

1. **Start with Basic Examples**: Begin with the Echo service for fundamental concepts
2. **Explore Security**: Review mTLS examples for production readiness
3. **Custom Development**: Use protocol and async examples for advanced features
4. **Production Setup**: Follow configuration examples for deployment

## Additional Resources

- **[Complete Example Index](../examples/)** - All available examples with source code
- **[User Guide](../guide/)** - Conceptual explanations and best practices  
- **[API Reference](../api/)** - Complete API documentation
- **[Configuration Guide](../guide/config/)** - Environment setup and options