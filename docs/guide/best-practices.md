# Best Practices

This guide covers recommended patterns and best practices for building production-focused plugins with pyvider-rpcplugin.

## Import Patterns

### Recommended Import Style

Import from the main package namespace for public APIs:

```python
# ✅ Recommended: Import from main package
from pyvider.rpcplugin import (
    plugin_server,
    plugin_client,
    plugin_protocol,
    configure,
)
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import (
    RPCPluginError,
    HandshakeError,
    TransportError,
)
from provide.foundation import logger
```

### Avoid Deep Imports

Don't import from internal submodules unless necessary:

```python
# ❌ Avoid: Internal implementation details
from pyvider.rpcplugin.client.core import RPCPluginClient
from pyvider.rpcplugin.server.core import RPCPluginServer

# ✅ Better: Use factory functions
from pyvider.rpcplugin import plugin_client, plugin_server
```

### Protocol Imports

For protocol definitions, import the base class from the protocol module:

```python
# ✅ Recommended: Protocol base class
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol

# Or use the main package export
from pyvider.rpcplugin import RPCPluginProtocol
```

## Configuration Patterns

### Use Environment Variables

Environment variables are the primary configuration method:

```python
# ✅ Recommended: Environment-driven configuration
import os

os.environ["PLUGIN_AUTO_MTLS"] = "true"
os.environ["PLUGIN_LOG_LEVEL"] = "DEBUG"

from pyvider.rpcplugin import plugin_server
# Configuration automatically loaded
```

### Configuration Access

Access configuration via direct attributes (not method calls):

```python
from pyvider.rpcplugin.config import rpcplugin_config

# ✅ Correct: Direct attribute access
timeout = rpcplugin_config.plugin_handshake_timeout
transports = rpcplugin_config.plugin_server_transports

# ❌ Wrong: Method calls (not supported - will raise AttributeError)
# timeout = rpcplugin_config.handshake_timeout()
# AttributeError: 'RPCPluginConfig' object has no attribute 'handshake_timeout'
```

### Use the configure() Helper

For programmatic configuration, use the `configure()` function:

```python
from pyvider.rpcplugin import configure

# ✅ Recommended: Use helper function
configure(
    magic_cookie="my-secure-cookie",
    auto_mtls=True,
    handshake_timeout=10.0,
    log_level="INFO"
)
```

## Error Handling

### Catch Specific Exceptions

Use specific exception types for different error scenarios:

```python
from pyvider.rpcplugin import plugin_client
from pyvider.rpcplugin.exception import (
    HandshakeError,
    TransportError,
    SecurityError,
)
from provide.foundation import logger

async def safe_client_startup():
    """Example of proper error handling."""
    try:
        client = plugin_client(command=["python", "my_plugin.py"])
        await client.start()

    except HandshakeError as e:
        logger.error(f"Authentication failed: {e.message}")
        # Handle auth issues

    except TransportError as e:
        logger.error(f"Connection failed: {e.message}")
        # Handle network issues

    except SecurityError as e:
        logger.error(f"Security error: {e.message}")
        # Handle certificate/mTLS issues
```

### Provide Helpful Context

Include context in error messages:

```python
from provide.foundation import logger

try:
    await server.serve()
except Exception as e:
    logger.error(
        "Server failed to start",
        extra={
            "error": str(e),
            "transport": transport.name,
            "port": server.port,
            "mtls_enabled": rpcplugin_config.plugin_auto_mtls,
        },
        exc_info=True
    )
```

## Logging Patterns

### Use Foundation Logger

Always use Foundation's structured logger:

```python
from provide.foundation import logger

# ✅ Recommended: Foundation logger with context
logger.info(
    "Plugin started successfully",
    extra={
        "plugin_name": "my-plugin",
        "version": "1.0.0",
        "transport": "unix",
        "mtls_enabled": True,
    }
)

# ❌ Avoid: print() or standard logging
# print("Plugin started")
```

### Log Levels

Use appropriate log levels:

```python
# DEBUG: Detailed diagnostic information
logger.debug("Handshake details", extra={"cookie_key": cookie_key})

# INFO: Normal operational events
logger.info("Plugin connected", extra={"endpoint": endpoint})

# WARNING: Unexpected but handled situations
logger.warning("Retry attempt failed", extra={"attempt": retry_count})

# ERROR: Error events that might allow recovery
logger.error("Connection lost", extra={"reason": error_message})
```

## Security Best Practices

### Always Enable mTLS in Production

```python
# ✅ Production: Enable mTLS
configure(
    auto_mtls=True,
    server_cert="file:///etc/ssl/plugin-server.crt",
    server_key="file:///etc/ssl/plugin-server.key",
)

# ⚠️  Development only: Disable for local testing
configure(auto_mtls=False)  # Never in production!
```

### Use Strong Magic Cookies

```python
import secrets

# ✅ Recommended: Cryptographically secure random cookie
magic_cookie = secrets.token_urlsafe(32)
os.environ["PLUGIN_MAGIC_COOKIE_VALUE"] = magic_cookie

# ❌ Avoid: Weak or predictable cookies
# magic_cookie = "test123"  # Too weak!
```

### Secure Certificate Management

```bash
# ✅ Recommended: Proper file permissions
chmod 600 /etc/ssl/private/plugin-server.key
chmod 644 /etc/ssl/certs/plugin-server.crt

# ✅ Use environment variables for sensitive data
export PLUGIN_SERVER_KEY="$(cat /etc/ssl/private/plugin-server.key)"
export PLUGIN_SERVER_CERT="$(cat /etc/ssl/certs/plugin-server.crt)"
```

## Performance Optimization

### Choose Appropriate Transports

```python
# ✅ Local IPC: Use Unix sockets (fastest)
configure(
    server_transports=["unix"],
    client_transports=["unix"],
)

# ✅ Network communication: Use TCP
configure(
    server_transports=["tcp"],
    client_transports=["tcp"],
)

# ✅ Flexible: Try Unix first, fallback to TCP
configure(
    server_transports=["unix", "tcp"],
    client_transports=["unix", "tcp"],
)
```

### Tune Timeouts

```python
# ✅ Fast local network: Shorter timeouts
configure(
    handshake_timeout=5.0,
    connection_timeout=10.0,
)

# ✅ Slow network or remote: Longer timeouts
configure(
    handshake_timeout=30.0,
    connection_timeout=60.0,
)
```

### Enable Rate Limiting

```python
# ✅ Protect server from abuse
configure(
    rate_limit_enabled=True,
    rate_limit_requests_per_second=100.0,
    rate_limit_burst_capacity=200,
)
```

## Testing Patterns

### Use Test Mode

```python
import os

# ✅ Enable test mode for testing
os.environ["PLUGIN_TEST_MODE"] = "true"

# Disable mTLS for local testing
os.environ["PLUGIN_AUTO_MTLS"] = "false"

# Use test magic cookie
os.environ["PLUGIN_MAGIC_COOKIE_VALUE"] = "test_cookie_value"
```

### Reset Foundation in Tests

```python
import pytest
from provide.testkit import reset_foundation_setup_for_testing

@pytest.fixture(autouse=True)
def reset_foundation():
    """Reset Foundation state before each test."""
    reset_foundation_setup_for_testing()
```

## Project Structure

### Recommended Organization

```
my-plugin/
├── src/
│   └── my_plugin/
│       ├── __init__.py
│       ├── server.py          # Plugin server implementation
│       ├── protocol.py        # Protocol definition
│       ├── handler.py         # Service handler
│       └── proto/
│           ├── service.proto  # Protocol Buffer definitions
│           ├── service_pb2.py # Generated
│           └── service_pb2_grpc.py  # Generated
├── tests/
│   ├── __init__.py
│   ├── test_server.py
│   ├── test_handler.py
│   └── conftest.py           # Shared fixtures
├── examples/
│   └── example_client.py     # Example usage
├── pyproject.toml            # Project metadata
└── README.md
```

## Code Organization

### Separate Concerns

```python
# ✅ Recommended: Separate protocol, handler, and server

# protocol.py
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol

class MyProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self):
        import my_pb2_grpc
        return my_pb2_grpc, "my.Service"

    async def add_to_server(self, server, handler):
        from my_pb2_grpc import add_MyServiceServicer_to_server
        add_MyServiceServicer_to_server(handler, server)

# handler.py
from provide.foundation import logger

class MyHandler:
    async def MyMethod(self, request, context):
        logger.info("Processing request", extra={"request_id": request.id})
        # Business logic here
        return response

# server.py
import asyncio
from pyvider.rpcplugin import plugin_server
from .protocol import MyProtocol
from .handler import MyHandler

async def main():
    server = plugin_server(
        protocol=MyProtocol(),
        handler=MyHandler()
    )
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
```

## Async Patterns

### Use Async Context Managers

```python
# ✅ Recommended: Async context manager for cleanup
async with plugin_client(command=["python", "plugin.py"]) as client:
    result = await client.call_service_method()
# Automatically closed on exit
```

### Proper Async/Await

```python
# ✅ Correct: await async operations
result = await client.start()
response = await stub.CallMethod(request)

# ❌ Wrong: Forgetting await
# result = client.start()  # Returns coroutine, not result!
```

## Documentation

### Document Your Protocol

````python
class MyProtocol(RPCPluginProtocol):
    """
    Protocol for My Plugin service.

    This protocol defines RPC methods for:
    - Processing requests
    - Managing resources
    - Health monitoring

    Example:
        ```python
        protocol = MyProtocol()
        server = plugin_server(protocol=protocol, handler=MyHandler())
        ```
    """
    service_name: str = "my.Service"
````

### Document Configuration Requirements

```python
"""
My Plugin - Configuration Requirements

Required Environment Variables:
- PLUGIN_MAGIC_COOKIE_VALUE: Authentication secret
- MY_PLUGIN_DATABASE_URL: Database connection string

Optional Environment Variables:
- PLUGIN_LOG_LEVEL: Logging level (default: INFO)
- PLUGIN_AUTO_MTLS: Enable mTLS (default: true)
- MY_PLUGIN_CACHE_SIZE: Cache size limit (default: 1000)

Example:
    export PLUGIN_MAGIC_COOKIE_VALUE="secure-random-value"
    export MY_PLUGIN_DATABASE_URL="postgresql://localhost/mydb"
    python -m my_plugin.server
"""
```

## Related Documentation

- **[Configuration Reference](../guide/config/configuration-reference.md)** - Complete configuration options
- **[Security Guide](security/index.md)** - Security implementation details
- **[Testing Guide](../development/testing.md)** - Testing patterns and fixtures
- **[Examples](../examples/index.md)** - Working code examples
