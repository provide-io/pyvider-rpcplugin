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

## Error Handling

The server handles various error conditions gracefully:

### Transport Errors

```python
from pyvider.rpcplugin.exception import TransportError

try:
    await server.serve()
except TransportError as e:
    logger.error(f"Transport failed: {e}")
    if "port" in str(e).lower():
        # Try different port
        configure(tcp_port=0)  # Auto-assign
    elif "permission" in str(e).lower():  
        # Fix socket permissions
        configure(unix_socket_permissions=0o666)
```

### Security Errors

```python  
from pyvider.rpcplugin.exception import SecurityError, CertificateError

try:
    await server.serve()
except CertificateError as e:
    logger.error(f"Certificate error: {e}")
    # Check certificate validity, paths, permissions
except SecurityError as e:
    logger.error(f"Security error: {e}")  
    # Check mTLS configuration
```

### Graceful Error Recovery

```python
import asyncio

async def robust_server():
    """Server with automatic restart on recoverable errors."""
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            server = plugin_server(protocol=protocol, handler=handler)
            await server.serve()
            break  # Success
            
        except TransportError as e:
            retry_count += 1
            logger.warning(f"Server failed (attempt {retry_count}): {e}")
            if retry_count < max_retries:
                await asyncio.sleep(2 ** retry_count)  # Exponential backoff
            else:
                logger.error("Max retries exceeded")
                raise
                
        except (SecurityError, CertificateError):
            # Don't retry security errors
            logger.error("Security configuration error, not retrying")
            raise
```

## Performance Optimization

### Concurrency Tuning

```python
configure(
    max_concurrent_rpcs=200,     # Higher concurrency
    grpc_options=[
        # Connection keep-alive
        ('grpc.keepalive_time_ms', 30000),
        ('grpc.keepalive_timeout_ms', 5000),
        
        # Message size limits
        ('grpc.max_send_message_length', 100 * 1024 * 1024),  # 100MB
        ('grpc.max_receive_message_length', 100 * 1024 * 1024),
        
        # HTTP/2 settings
        ('grpc.http2.max_pings_without_data', 0),
        ('grpc.http2.min_ping_interval_without_data_ms', 300000),
    ]
)
```

### Rate Limiting

```python
configure(
    rate_limiting_enabled=True,
    rate_limit_requests_per_second=1000,  # High throughput
    rate_limit_burst_size=100,            # Burst capacity
    rate_limit_window_seconds=1.0         # Time window
)
```

### Resource Monitoring

```python
import psutil
from provide.foundation import logger

class MonitoredHandler(MyServiceServicer):
    def __init__(self):
        self.request_count = 0
        self.error_count = 0
        
    async def MyMethod(self, request, context):
        self.request_count += 1
        start_time = time.time()
        
        try:
            result = await process_request(request)
            
            # Log performance metrics
            duration = time.time() - start_time
            memory_usage = psutil.Process().memory_info().rss / 1024 / 1024  # MB
            
            logger.info("Request processed",
                       request_count=self.request_count,
                       duration=duration,
                       memory_mb=memory_usage)
                       
            return result
            
        except Exception as e:
            self.error_count += 1
            logger.error("Request failed",
                        request_count=self.request_count,
                        error_count=self.error_count,
                        error=str(e))
            raise
```

## Complete Example

Here's a complete server implementation:

```python
#!/usr/bin/env python3
"""
Production-ready plugin server example.
"""
import asyncio
import os
import signal
from typing import Any

import grpc
from pyvider.rpcplugin import plugin_server, configure
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.exception import RPCPluginError
from provide.foundation import logger

# Import your generated Protocol Buffer code
from my_service_pb2_grpc import MyServiceServicer, add_MyServiceServicer_to_server
import my_service_pb2_grpc

class MyServiceHandler(MyServiceServicer):
    """Production service handler with comprehensive error handling."""
    
    async def MyMethod(self, request, context: grpc.aio.ServicerContext):
        try:
            logger.info("Processing request", method="MyMethod")
            result = await self.process_business_logic(request)
            return result
            
        except ValidationError as e:
            logger.warning("Validation error", error=str(e))
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))
            
        except Exception as e:
            logger.error("Unexpected error", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, "Internal server error")
    
    async def process_business_logic(self, request):
        """Your actual business logic implementation."""
        # Implementation here
        pass

class MyProtocol(RPCPluginProtocol):
    """Production protocol with proper error handling."""
    
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        return my_service_pb2_grpc, "mypackage.MyService"
    
    async def add_to_server(self, server: Any, handler: Any) -> None:
        add_MyServiceServicer_to_server(handler, server)
        logger.info("Service registered successfully")

async def main():
    """Main server function with production configuration."""
    
    # Configure for production
    configure(
        auto_mtls=os.getenv("PLUGIN_AUTO_MTLS", "false").lower() == "true",
        health_service_enabled=True,
        max_concurrent_rpcs=100,
        rate_limiting_enabled=True,
        grpc_options=[
            ('grpc.keepalive_time_ms', 30000),
            ('grpc.keepalive_timeout_ms', 5000),
        ]
    )
    
    # Create server
    protocol = MyProtocol()
    handler = MyServiceHandler()  
    server = plugin_server(protocol=protocol, handler=handler)
    
    # Setup signal handling
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully")
        asyncio.create_task(server.stop())
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        logger.info("Starting production plugin server...")
        await server.serve()  # Blocks until shutdown
        
    except RPCPluginError as e:
        logger.error(f"Plugin server error: {e.message}")
        if e.hint:
            logger.error(f"Hint: {e.hint}")
        raise
        
    except Exception as e:
        logger.error("Unexpected server error", exc_info=True)
        raise
        
    finally:
        logger.info("Server shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())
```

## Related APIs

- **[RPCPluginProtocol](../protocol/base.md)** - Protocol implementation interface
- **[Transport](../transport/)** - Network transport configuration  
- **[Configuration](../config/)** - Server configuration options
- **[Client](../client/)** - Client-side connection management
- **[Error Handling](../../guide/error-handling.md)** - Comprehensive error handling patterns