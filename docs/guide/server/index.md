# Server Development

The Pyvider RPC Plugin server system provides a robust foundation for building plugin servers that handle RPC requests from host applications. This section covers everything you need to know about developing, configuring, and deploying plugin servers.

## Overview

A plugin server consists of three main components:

1. **`RPCPluginServer`** - Main server class managing lifecycle and connections
2. **`RPCPluginProtocol`** - Protocol implementation defining your gRPC services  
3. **`Handler/Servicer`** - Business logic implementation for your RPC methods

```python
from pyvider.rpcplugin import plugin_server

# Create server with automatic configuration
server = plugin_server(
    protocol=MyProtocol(),
    handler=MyHandler()
)

# Start serving (blocks until shutdown)
await server.serve()
```

## Server Architecture

### Core Components

```
┌─────────────────┐
│ Host Application│
│                 │
└─────────┬───────┘
          │ launches
          ▼
┌─────────────────┐     ┌──────────────────┐
│ RPCPluginServer │────▶│ Transport Layer  │
│                 │     │ (Unix/TCP)       │
│ ┌─────────────┐ │     └──────────────────┘
│ │ gRPC Server │ │              │
│ └─────────────┘ │              │
│        │        │              │
│        ▼        │              │
│ ┌─────────────┐ │              │
│ │ Protocol    │ │              │
│ │ Handler     │ │              │
│ └─────────────┘ │              │
└─────────────────┘              │
                                 │
                        ┌────────▼────────┐
                        │ Client Connection│
                        │                 │
                        └─────────────────┘
```

### Server Lifecycle

1. **Configuration Loading** - Read environment variables and configuration
2. **Transport Setup** - Initialize Unix socket or TCP transport
3. **Service Registration** - Register gRPC services with server
4. **Handshake Output** - Print connection details to stdout for client
5. **Connection Listening** - Accept and handle client connections
6. **Graceful Shutdown** - Clean resource shutdown on termination

## Development Sections

### 🚀 [Basic Server Setup](basic-setup.md)
Learn to create and configure basic plugin servers:
- Server components and architecture
- Factory function usage
- Configuration options
- Simple examples

### 🎯 [Service Implementation](services.md) 
Implement your business logic and RPC methods:
- gRPC service definition
- Handler implementation patterns
- Request/response processing
- Error handling in services

### 🔌 [Transport Configuration](transports.md)
Configure network transports for your server:
- Unix socket configuration
- TCP transport setup
- Transport selection logic
- Security considerations

### ⚡ [Async Patterns](async-patterns.md)
Master async/await patterns for high-performance servers:
- Concurrent request handling
- Async service methods
- Resource management
- Performance optimization

### ❤️ [Health Checks](health-checks.md)
Implement health monitoring for production servers:
- Built-in health service
- Custom health checks
- Integration with orchestrators
- Monitoring and alerting

## Quick Start

### Minimal Server

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin import plugin_server, plugin_protocol

class SimpleHandler:
    """Basic handler for demonstration."""
    pass

async def main():
    server = plugin_server(
        protocol=plugin_protocol(),  # Basic protocol
        handler=SimpleHandler()
    )
    
    try:
        await server.serve()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")

if __name__ == "__main__":
    asyncio.run(main())
```

### Production Server

```python
#!/usr/bin/env python3
import asyncio
import os
from pyvider.rpcplugin import plugin_server
from my_services import MyProtocol, MyHandler

async def main():
    # Configure for production
    os.environ.update({
        "PYVIDER_PLUGIN_AUTO_MTLS": "true",
        "PYVIDER_PLUGIN_RATE_LIMIT_ENABLED": "true", 
        "PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED": "true",
        "PYVIDER_PLUGIN_LOG_LEVEL": "INFO"
    })
    
    server = plugin_server(
        protocol=MyProtocol(),
        handler=MyHandler()
    )
    
    # Server includes:
    # - Automatic mTLS with certificate management
    # - Rate limiting with configurable policies
    # - Health checking for load balancer integration
    # - Graceful shutdown handling
    
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
```

## Common Patterns

### Environment-Based Configuration

```python
import os
from pyvider.rpcplugin import plugin_server

# Development configuration
if os.getenv('ENV') == 'development':
    os.environ.update({
        "PYVIDER_PLUGIN_LOG_LEVEL": "DEBUG",
        "PYVIDER_PLUGIN_AUTO_MTLS": "false",
        "PYVIDER_PLUGIN_SERVER_TRANSPORTS": "unix"
    })

# Production configuration  
elif os.getenv('ENV') == 'production':
    os.environ.update({
        "PYVIDER_PLUGIN_LOG_LEVEL": "INFO",
        "PYVIDER_PLUGIN_AUTO_MTLS": "true",
        "PYVIDER_PLUGIN_RATE_LIMIT_ENABLED": "true",
        "PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED": "true"
    })

server = plugin_server(protocol=my_protocol, handler=my_handler)
```

### Custom Transport Configuration

```python
from pyvider.rpcplugin import RPCPluginServer
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport

# Unix socket for high-performance local communication
unix_transport = UnixSocketTransport(path="/var/run/my-plugin.sock")

# TCP for network communication with TLS
tcp_transport = TCPSocketTransport(
    host="0.0.0.0",
    port=8080,
    enable_tls=True
)

server = RPCPluginServer(
    protocol=my_protocol,
    handler=my_handler,
    transport=unix_transport  # or tcp_transport
)
```

### Graceful Shutdown

```python
import asyncio
import signal
from pyvider.rpcplugin import plugin_server

async def main():
    server = plugin_server(protocol=my_protocol, handler=my_handler)
    
    # Setup signal handling
    shutdown_event = asyncio.Event()
    
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        shutdown_event.set()
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Start server task
    server_task = asyncio.create_task(server.serve())
    
    # Wait for shutdown signal
    await shutdown_event.wait()
    
    # Graceful shutdown
    logger.info("Stopping server...")
    await server.stop()
    await server_task
    logger.info("Server stopped successfully")

if __name__ == "__main__":
    asyncio.run(main())
```

## Configuration Reference

### Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PYVIDER_PLUGIN_SERVER_TRANSPORTS` | `["unix","tcp"]` | Available transport types |
| `PYVIDER_PLUGIN_SERVER_ENDPOINT` | `None` | Force specific endpoint |
| `PYVIDER_PLUGIN_AUTO_MTLS` | `true` | Enable mutual TLS |
| `PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED` | `true` | Enable health service |
| `PYVIDER_PLUGIN_RATE_LIMIT_ENABLED` | `false` | Enable rate limiting |
| `PYVIDER_PLUGIN_LOG_LEVEL` | `INFO` | Logging verbosity |

**[📖 Complete Configuration Reference](../config/)**

## Examples and Resources

### Working Examples
- **[ch03_server_setup_concepts.py](../../examples/ch03_server_setup_concepts.py)** - Server configuration patterns
- **[ch05_echo_server.py](../../examples/ch05_echo_server.py)** - Complete echo service implementation  
- **[ch15_e2e_server.py](../../examples/ch15_e2e_server.py)** - Production-ready server example

### Related Documentation
- **[API Reference](../../api/server/)** - Complete server API documentation
- **[Configuration Guide](../config/)** - Environment and configuration setup
- **[Security Guide](../security/)** - mTLS and security best practices
- **[Examples Overview](../../getting-started/examples.md)** - All available examples

## Next Steps

1. **[Start with Basic Setup](basic-setup.md)** - Learn server fundamentals
2. **[Implement Services](services.md)** - Add your business logic  
3. **[Configure Transport](transports.md)** - Set up network communication
4. **[Add Health Checks](health-checks.md)** - Prepare for production monitoring
5. **[Optimize Performance](async-patterns.md)** - Scale for high throughput