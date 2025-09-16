# RPCPluginServer API

The `RPCPluginServer` class is the core component for hosting gRPC services in the Pyvider RPC Plugin system. It provides a secure, configurable server implementation with built-in health checking, rate limiting, and connection management.

## Overview

The server follows a lifecycle pattern: configuration → handshake negotiation → transport setup → service registration → startup → operation → shutdown. It supports multiple transport protocols (Unix sockets, TCP) with optional mutual TLS authentication and comprehensive error handling.

## Quick Start

```python
from pyvider.rpcplugin.factories import plugin_server

# Create a basic server using factory
protocol = my_protocol_instance  # Your protocol implementation
handler = my_service_handler     # Your service handler

server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="unix",
    transport_path="/tmp/my-plugin.sock"
)

# Start the server
await server.serve()
```

## Factory Function Usage

The recommended way to create servers is using the `plugin_server` factory:

```python
from pyvider.rpcplugin.factories import plugin_server

# Unix socket server
unix_server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    transport="unix",
    transport_path="/tmp/my-plugin.sock"
)

# TCP server  
tcp_server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    transport="tcp",
    host="127.0.0.1",
    port=50051
)

# TCP server with config overrides
server_with_config = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    transport="tcp",
    host="0.0.0.0",
    port=8080,
    config={
        "PLUGIN_RATE_LIMIT_ENABLED": True,
        "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 1000.0,
        "PLUGIN_AUTO_MTLS": True,
    }
)
```

## Configuration Options

Server behavior is controlled through environment variables or instance config overrides:

### Transport Configuration

**Unix Socket Transport**:
```bash
export PLUGIN_SERVER_TRANSPORTS='["unix", "tcp"]'  # Supported transports
export PLUGIN_SERVER_ENDPOINT="/tmp/my-plugin.sock"  # Socket path (optional)
```

**TCP Transport**:
```bash
export PLUGIN_SERVER_TRANSPORTS='["tcp"]'
export PLUGIN_SERVER_ENDPOINT="127.0.0.1:50051"  # Host:port (optional)
```

### Security Configuration

**Magic Cookie Authentication**:
```bash
export PLUGIN_MAGIC_COOKIE_KEY="MY_PLUGIN_COOKIE"
export PLUGIN_MAGIC_COOKIE_VALUE="super-secret-value"
```

**Automatic Mutual TLS**:
```bash
export PLUGIN_AUTO_MTLS=true  # Auto-generate self-signed certificates
export PLUGIN_CLIENT_ROOT_CERTS="file:///path/to/client-ca.crt"  # Client CA for verification
```

**Manual TLS Configuration**:
```bash
export PLUGIN_AUTO_MTLS=false
export PLUGIN_SERVER_CERT="file:///path/to/server.crt"
export PLUGIN_SERVER_KEY="file:///path/to/server.key"
export PLUGIN_SERVER_ROOT_CERTS="file:///path/to/client-ca.crt"
```

### Performance and Rate Limiting

```bash
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=100.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=200.0
```

### Health Service

```bash
export PLUGIN_HEALTH_SERVICE_ENABLED=true  # Enable gRPC health checks
```

### Shutdown Control

```bash
export PLUGIN_SHUTDOWN_FILE_PATH="/tmp/shutdown-signal"  # File-based shutdown trigger
```

## Server Lifecycle

### 1. Construction and Initialization

```python
from pyvider.rpcplugin.server import RPCPluginServer

# Direct construction (advanced usage)
server = RPCPluginServer(
    protocol=my_protocol,
    handler=my_handler,
    transport=my_transport,  # Optional pre-configured transport
    config={  # Optional config overrides
        "PLUGIN_RATE_LIMIT_ENABLED": True,
        "PLUGIN_AUTO_MTLS": False,
    }
)
```

During initialization, the server:
- Configures handshake parameters (magic cookies, protocol versions, supported transports)
- Sets up rate limiting if enabled
- Initializes health service if enabled
- Prepares transport and security configurations

### 2. Service Operation

The `serve()` method handles the complete server lifecycle:

```python
await server.serve()
```

This method:
1. **Registers signal handlers** for graceful shutdown (SIGINT, SIGTERM)
2. **Negotiates handshake** with the plugin host:
   - Validates magic cookie for authentication
   - Negotiates protocol version 
   - Negotiates transport (Unix socket or TCP)
3. **Sets up the gRPC server**:
   - Configures TLS/mTLS if enabled
   - Sets up rate limiting interceptors
   - Registers protocol services and health service
   - Binds to transport endpoint
4. **Starts file-based shutdown monitoring** if configured
5. **Outputs handshake response** to stdout for the plugin host
6. **Runs until shutdown** is requested

### 3. Graceful Shutdown

Shutdown can be triggered by:
- **Signal handling** (SIGINT/SIGTERM)
- **Shutdown file** creation (if configured)
- **Manual call** to `stop()` method

```python
# Manual shutdown with grace period
await server.stop()
```

## Advanced Usage

### Custom Transport Configuration

```python
from pyvider.rpcplugin.transport import TCPSocketTransport

# Pre-configure transport
custom_transport = TCPSocketTransport(
    host="0.0.0.0",
    port=9090
)

server = RPCPluginServer(
    protocol=my_protocol,
    handler=my_handler,
    transport=custom_transport
)
```

### Server Readiness Checking

```python
# Wait for server to be ready for connections
await server.wait_for_server_ready(timeout=10.0)
print(f"Server ready on endpoint: {server._transport.endpoint}")
```

### Production Deployment Example

```python
import asyncio
import signal
from pyvider.rpcplugin.factories import plugin_server

async def run_production_server():
    server = plugin_server(
        protocol=my_protocol,
        handler=my_handler,
        transport="tcp", 
        host="0.0.0.0",
        port=8080,
        config={
            # Security
            "PLUGIN_AUTO_MTLS": True,
            "PLUGIN_CLIENT_ROOT_CERTS": "file:///etc/ssl/certs/client-ca.crt",
            # Performance  
            "PLUGIN_RATE_LIMIT_ENABLED": True,
            "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 1000.0,
            "PLUGIN_RATE_LIMIT_BURST_CAPACITY": 2000.0,
            # Monitoring
            "PLUGIN_HEALTH_SERVICE_ENABLED": True,
            # Shutdown
            "PLUGIN_SHUTDOWN_FILE_PATH": "/tmp/shutdown-signal",
        }
    )
    
    try:
        await server.serve()
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        await server.stop()

# Run the server
asyncio.run(run_production_server())
```

## Error Handling

### Common Exception Types

```python
from pyvider.rpcplugin.exception import (
    TransportError,
    SecurityError, 
    ProtocolError,
    ConfigError
)

try:
    await server.serve()
except ConfigError as e:
    # Configuration validation errors
    print(f"Configuration error: {e}")
except SecurityError as e:
    # TLS/certificate errors
    print(f"Security error: {e}")
except TransportError as e:
    # Network/transport errors 
    print(f"Transport error: {e}")
except ProtocolError as e:
    # Protocol negotiation errors
    print(f"Protocol error: {e}")
```

### Troubleshooting Common Issues

**Permission denied on Unix socket**:
- Check directory permissions where socket is created
- Ensure process has write access to socket directory

**Port already in use**:
- Check if another service is using the TCP port
- Use port 0 for automatic port assignment

**TLS certificate errors**:
- Verify certificate file paths are correct and accessible
- Check certificate validity and format (PEM)
- Ensure private key matches certificate

**Rate limiting errors**:
- Clients will receive `RESOURCE_EXHAUSTED` status when rate limited
- Adjust rate limiting parameters based on expected load

## Security Considerations

### Mutual TLS (mTLS) Setup

For production deployments, use proper TLS certificates:

```python
server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    transport="tcp",
    config={
        "PLUGIN_AUTO_MTLS": False,  # Use manual certificates
        "PLUGIN_SERVER_CERT": "file:///etc/ssl/certs/server.crt",
        "PLUGIN_SERVER_KEY": "file:///etc/ssl/private/server.key", 
        "PLUGIN_CLIENT_ROOT_CERTS": "file:///etc/ssl/certs/client-ca.crt",
    }
)
```

### Magic Cookie Security

- Use long, random values for magic cookies
- Rotate magic cookies regularly
- Store magic cookie values securely (environment variables, not code)

## Class Reference

::: pyvider.rpcplugin.server.RPCPluginServer

## Related Components

- [Factory Functions](../factories.md) - `plugin_server()` factory function
- [Transport Layer](../transport/index.md) - Unix socket and TCP transport details
- [Configuration](../config/index.md) - Complete configuration reference
- [Health Service](health.md) - Health check implementation
- [Rate Limiting](rate-limiting.md) - Request rate limiting details
- [Client API](../client/client.md) - Corresponding client implementation