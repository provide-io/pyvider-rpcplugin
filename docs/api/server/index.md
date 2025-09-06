# Server API

The Server API provides classes and functions for building plugin servers that handle RPC requests from host applications.

## Core Classes

### RPCPluginServer

The main server class that manages the plugin lifecycle, handshake process, and RPC serving.

```python
from pyvider.rpcplugin.server import RPCPluginServer

server = RPCPluginServer(
    protocol=my_protocol,
    handler=my_handler,
    transport=my_transport  # Optional
)

await server.serve()  # Start serving
```

**Key Methods:**
- `serve()` - Start the server and handle connections
- `stop()` - Gracefully stop the server
- `health_check()` - Check server health status

### Factory Functions

#### plugin_server()

Convenience factory for creating configured servers:

```python
from pyvider.rpcplugin import plugin_server

# Automatic configuration
server = plugin_server(protocol=protocol, handler=handler)

# Custom transport
server = plugin_server(
    protocol=protocol, 
    handler=handler,
    transport=custom_transport
)
```

## Server Lifecycle

### Startup Sequence

1. **Configuration Loading** - Read environment variables and config files
2. **Transport Setup** - Initialize Unix socket or TCP transport
3. **Service Registration** - Register RPC services with gRPC server
4. **Handshake Output** - Print connection details to stdout
5. **Connection Listening** - Start accepting client connections

### Handshake Process

The server outputs a handshake string that the client uses to connect:

```
PYVIDER_RPC|1|unix|/tmp/plugin.sock|
```

Format: `PYVIDER_RPC|<version>|<transport>|<address>|<optional_data>`

### Graceful Shutdown

Servers handle shutdown signals gracefully:

```python
try:
    await server.serve()
except KeyboardInterrupt:
    logger.info("Server stopped by user")
finally:
    await server.stop()  # Cleanup resources
```

## Configuration

### Environment Variables

Key server configuration variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PLUGIN_SERVER_TRANSPORTS` | Available transports | `unix,tcp` |
| `PLUGIN_HANDSHAKE_TIMEOUT` | Handshake timeout (seconds) | `30.0` |
| `PLUGIN_AUTO_MTLS` | Enable mutual TLS | `false` |
| `PLUGIN_LOG_LEVEL` | Logging level | `INFO` |

### Programmatic Configuration

```python
from pyvider.rpcplugin import configure

configure(
    server_transports=["unix"],
    handshake_timeout=60.0,
    auto_mtls=True,
    log_level="DEBUG"
)
```

## Transport Integration

### Unix Socket Server

```python
from pyvider.rpcplugin.transport import UnixSocketTransport

transport = UnixSocketTransport(path="/tmp/my-plugin.sock")
server = plugin_server(protocol=protocol, handler=handler, transport=transport)
```

### TCP Server

```python  
from pyvider.rpcplugin.transport import TCPSocketTransport

transport = TCPSocketTransport(host="127.0.0.1", port=8080)
server = plugin_server(protocol=protocol, handler=handler, transport=transport)
```

### Auto Transport Selection

The server automatically selects the best transport:

```python
# Server tries Unix sockets first, falls back to TCP
server = plugin_server(protocol=protocol, handler=handler)
# Transport selection logged during startup
```

## Security Features

### mTLS Configuration

Enable mutual TLS for secure communication:

```python
# Environment variables
os.environ.update({
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_SERVER_CERT": "file:///path/to/server.crt",
    "PLUGIN_SERVER_KEY": "file:///path/to/server.key", 
    "PLUGIN_CLIENT_ROOT_CERTS": "file:///path/to/ca.crt"
})

server = plugin_server(protocol=protocol, handler=handler)
```

### Magic Cookie Validation

Servers validate magic cookies during handshake:

```python
# Cookie automatically validated from environment
cookie_key = rpcplugin_config.magic_cookie_key()
expected_value = os.environ.get(cookie_key)

if not expected_value:
    raise HandshakeError("Magic cookie not found")
```

## Health Monitoring

### Built-in Health Service

Enable gRPC health checking:

```python
configure(health_service_enabled=True)

# Health check endpoint available at:
# grpc_health_v1.Health/Check
```

### Custom Health Logic

Implement custom health checks:

```python
class MyServerHandler:
    async def health_check(self) -> dict:
        """Custom health check logic."""
        return {
            "status": "healthy",
            "database": await check_database(),
            "external_api": await check_external_api()
        }
```

## Performance Tuning

### Concurrency Settings

```python
configure(
    max_concurrent_rpcs=100,     # Max concurrent RPC handlers
    grpc_options=[               # gRPC channel options
        ('grpc.keepalive_time_ms', 30000),
        ('grpc.keepalive_timeout_ms', 5000),
        ('grpc.http2.max_pings_without_data', 0),
    ]
)
```

### Resource Limits

```python
configure(
    max_message_size=64 * 1024 * 1024,  # 64MB max message size
    connection_timeout=30.0,             # Connection timeout
    request_timeout=60.0                 # Individual request timeout
)
```

## Error Handling

### Exception Management

Servers automatically handle and log exceptions:

```python
class MyHandler(MyServiceServicer):
    async def MyMethod(self, request, context):
        try:
            return await self.process_request(request)
        except ValidationError as e:
            # Set gRPC status
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))
        except Exception as e:
            # Log unexpected errors
            logger.error("Unexpected error", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, "Internal server error")
```

### Structured Error Logging

```python
from provide.foundation import logger

logger.error(
    "🚨 Server error occurred",
    error_type=type(error).__name__,
    error_message=str(error),
    client_address=context.peer(),
    method_name=context.invocation_metadata(),
)
```

## Example Implementations

### Basic Server

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin import plugin_server, plugin_protocol
from provide.foundation import logger

class SimpleHandler:
    def __init__(self):
        logger.info("🔌 Simple handler initialized")

async def main():
    protocol = plugin_protocol()  # Basic protocol
    handler = SimpleHandler()
    server = plugin_server(protocol=protocol, handler=handler)
    
    try:
        await server.serve()
    except KeyboardInterrupt:
        logger.info("Server stopped")

if __name__ == "__main__":
    asyncio.run(main())
```

### Custom Protocol Server

```python
#!/usr/bin/env python3
import asyncio
from typing import Any
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from my_service_pb2_grpc import MyServiceServicer, add_MyServiceServicer_to_server
import my_service_pb2_grpc

class MyProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        return my_service_pb2_grpc, "mypackage.MyService"
    
    async def add_to_server(self, server: Any, handler: Any) -> None:
        add_MyServiceServicer_to_server(handler, server)

class MyHandler(MyServiceServicer):
    async def MyMethod(self, request, context):
        # Your business logic here
        return MyResponse(result="processed")

async def main():
    server = plugin_server(
        protocol=MyProtocol(),
        handler=MyHandler()
    )
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
```

## API Reference

### Classes

- [`RPCPluginServer`](server.md) - Main server implementation
- [`plugin_server()`](../factories.md#plugin_server) - Server factory function

### Related APIs

- **[Transport API](../transport/)** - Network transport implementations
- **[Protocol API](../protocol/)** - RPC protocol definitions  
- **[Configuration API](../config/)** - Server configuration management
- **[Exceptions API](../exceptions/)** - Server error handling