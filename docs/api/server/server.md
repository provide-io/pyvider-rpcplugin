# RPCPluginServer

The `RPCPluginServer` class is the core server implementation that handles the complete lifecycle of plugin processes, from initialization and handshake through serving RPC requests and graceful shutdown.

## Overview

The server manages several critical responsibilities:

- **Transport Setup** - Configures Unix socket or TCP transports
- **Handshake Protocol** - Outputs connection details for client discovery  
- **Security Management** - Handles mTLS certificate exchange and validation
- **Service Registration** - Registers gRPC services with the underlying server
- **Lifecycle Management** - Manages startup, serving, and shutdown phases
- **Health Monitoring** - Provides health check services and status reporting

## Class Reference

::: pyvider.rpcplugin.server.RPCPluginServer
    options:
      members:
        - __init__
        - serve  
        - stop
        - health_check
      show_source: true
      heading_level: 3

## Server Lifecycle

### 1. Initialization Phase

```python
from pyvider.rpcplugin import plugin_server

# Create server with protocol and handler
server = plugin_server(
    protocol=MyProtocol(),
    handler=MyHandler(),
    transport=custom_transport  # Optional
)
```

During initialization, the server:

- Validates configuration parameters
- Sets up the specified transport (or auto-selects)  
- Prepares security credentials (if mTLS enabled)
- Initializes the gRPC server instance
- Registers protocol services and handlers

### 2. Handshake Phase

When `serve()` is called, the server first outputs a handshake string to stdout:

```
PYVIDER_RPC|1|unix|/tmp/plugin.sock|
```

**Handshake Format:**
- `PYVIDER_RPC` - Protocol identifier
- `1` - Protocol version number
- `unix`/`tcp` - Transport type  
- `/tmp/plugin.sock` - Connection address
- Optional additional data

This handshake allows clients to discover how to connect to the plugin.

### 3. Serving Phase

After handshake output, the server:

- **Starts Listening** - Accepts connections on the configured transport
- **Handles mTLS** - Performs certificate exchange (if enabled)
- **Serves Requests** - Processes incoming RPC calls through registered handlers
- **Manages Health** - Responds to health check requests
- **Monitors Signals** - Listens for shutdown signals (SIGTERM, SIGINT)

### 4. Shutdown Phase

The server supports graceful shutdown:

```python
# Graceful shutdown with timeout
await server.stop(timeout=30.0)

# Or let serve() handle signals automatically
try:
    await server.serve()  # Blocks until signal received
except KeyboardInterrupt:
    logger.info("Server stopped by user")
```

## Configuration Options

### Transport Configuration

```python
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport

# Unix socket (recommended for local plugins)
unix_transport = UnixSocketTransport(path="/tmp/my-plugin.sock")
server = plugin_server(protocol=protocol, handler=handler, transport=unix_transport)

# TCP socket (required for Windows, optional elsewhere)
tcp_transport = TCPSocketTransport(host="127.0.0.1", port=8080)  
server = plugin_server(protocol=protocol, handler=handler, transport=tcp_transport)

# Auto-selection (Unix preferred, TCP fallback)
server = plugin_server(protocol=protocol, handler=handler)  # No transport specified
```

### Security Configuration

```python
import os

# Enable mTLS with environment variables
os.environ.update({
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_SERVER_CERT": "file:///path/to/server.crt",
    "PLUGIN_SERVER_KEY": "file:///path/to/server.key", 
    "PLUGIN_CLIENT_ROOT_CERTS": "file:///path/to/ca.crt"
})

server = plugin_server(protocol=protocol, handler=handler)
```

### Performance Configuration

```python
from pyvider.rpcplugin import configure

configure(
    max_concurrent_rpcs=100,           # Concurrent request limit
    grpc_options=[                     # gRPC server options
        ('grpc.keepalive_time_ms', 30000),
        ('grpc.keepalive_timeout_ms', 5000),
        ('grpc.max_message_length', 64 * 1024 * 1024),  # 64MB
    ],
    health_service_enabled=True,       # Enable gRPC health service
    rate_limiting_enabled=True,        # Enable request rate limiting
    rate_limit_requests_per_second=100 # Rate limit threshold
)
```

## Protocol Integration

The server integrates with your custom protocol implementation:

```python
from typing import Any
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol

class MyProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        """Return gRPC module and service name."""
        return my_service_pb2_grpc, "mypackage.MyService"
    
    async def add_to_server(self, server: Any, handler: Any) -> None:
        """Register handler with gRPC server."""
        my_service_pb2_grpc.add_MyServiceServicer_to_server(handler, server)
        
    def get_method_type(self, method_name: str) -> str:
        """Return RPC method type for routing."""
        return "unary_unary"  # or stream_unary, etc.
```

The server calls these protocol methods during initialization to:
- Discover available services and methods
- Register your handler with the gRPC server
- Configure routing and method types

## Handler Implementation

Your handler implements the actual business logic:

```python
import grpc
from my_service_pb2_grpc import MyServiceServicer

class MyHandler(MyServiceServicer):
    async def MyMethod(self, request, context: grpc.aio.ServicerContext):
        """Implement your RPC method."""
        try:
            # Your business logic here
            result = await process_request(request)
            return MyResponse(result=result)
            
        except ValidationError as e:
            # Set gRPC error status
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))
            
        except Exception as e:
            # Log and return internal error
            logger.error("Unexpected error in MyMethod", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, "Internal server error")
```

## Health Monitoring

The server provides built-in health monitoring:

```python
# Check server health status
health_status = await server.health_check()
print(f"Server health: {health_status}")

# Enable gRPC health service (accessible to clients)
configure(health_service_enabled=True)

# Custom health logic in your handler
class MyHandler(MyServiceServicer):
    async def health_check(self) -> dict:
        """Custom health check implementation."""
        return {
            "status": "healthy",
            "database_connection": await check_database(),
            "external_api": await check_external_service(),
            "memory_usage": get_memory_usage()
        }
```

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