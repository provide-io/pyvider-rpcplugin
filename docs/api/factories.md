# Factory Functions

The Pyvider RPC Plugin system provides convenient factory functions that encapsulate common setup patterns for creating servers, clients, and protocols. These factories simplify component creation and promote consistent configuration across different use cases.

## Overview

Factory functions provide:
- **Simplified Component Creation**: Reduce boilerplate code for common patterns
- **Configuration Encapsulation**: Handle complex setup logic internally
- **Consistent Interfaces**: Standardized parameter patterns across components
- **Reasonable Defaults**: Pre-configured settings that work out of the box
- **Flexibility**: Support for both simple and advanced usage scenarios

All factory functions follow the `plugin_*` naming convention and return fully configured, ready-to-use component instances.

## Available Factory Functions

### `plugin_server()`

Creates a fully configured `RPCPluginServer` instance with transport and protocol setup.

**Signature**:
```python
def plugin_server(
    protocol: BaseProtocolTDefinition,
    handler: HandlerT,
    transport: str = "unix",
    transport_path: str | None = None,
    host: str = "127.0.0.1", 
    port: int = 0,
    config: dict[str, Any] | None = None,
) -> RPCPluginServer[_ServerT, ServerHandlerT, _TransportT]
```

**Parameters**:
- `protocol`: Protocol implementation (must inherit from `RPCPluginProtocol`)
- `handler`: Service handler implementing your business logic  
- `transport`: Transport type ("unix" or "tcp", default: "unix")
- `transport_path`: Unix socket path (optional, auto-generated if not provided)
- `host`: TCP host address (default: "127.0.0.1")
- `port`: TCP port (default: 0 for auto-assignment)
- `config`: Configuration overrides (optional)

**Returns**: Configured `RPCPluginServer` instance

### `plugin_client()`

Creates a fully configured `RPCPluginClient` instance for connecting to plugin servers.

**Signature**:
```python
def plugin_client(
    command: list[str],
    config: dict[str, Any] | None = None,
    auto_connect: bool = True,
) -> RPCPluginClient
```

**Parameters**:
- `command`: Plugin server command and arguments
- `config`: Configuration overrides (optional)
- `auto_connect`: Whether to attempt immediate connection (default: True, but note: this is synchronous so it just warns)

**Returns**: Configured `RPCPluginClient` instance

### `plugin_protocol()`

Creates a protocol instance, either custom or default basic protocol.

**Signature**:
```python
def plugin_protocol(
    protocol_class: type[PT_co] | None = None,
    handler_class: type[RPCPluginHandler] | None = None,
    service_name: str | None = None,
    **kwargs: Any,
) -> PT_co
```

**Parameters**:
- `protocol_class`: Custom protocol class (optional, uses BasicRPCPluginProtocol if not provided)
- `handler_class`: Handler class (optional, for future use)
- `service_name`: Service name override (optional)
- `**kwargs`: Additional keyword arguments passed to protocol constructor

**Returns**: Configured protocol instance

## Usage Examples

### Basic Server Creation

```python
from pyvider.rpcplugin.factories import plugin_server, plugin_protocol

# Create a basic protocol
protocol = plugin_protocol(service_name="MyService")

# Create your handler
class MyHandler:
    async def my_method(self, request, context):
        return MyResponse(message="Hello World")

handler = MyHandler()

# Create server with Unix socket (recommended for local plugins)
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="unix",
    transport_path="/tmp/my-plugin.sock"
)

# Start the server
await server.serve()
```

### TCP Server with Custom Configuration

```python
from pyvider.rpcplugin.factories import plugin_server

# Create server with TCP transport and custom configuration
server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    transport="tcp",
    host="0.0.0.0",  # Listen on all interfaces
    port=8080,       # Specific port
    config={
        # Security settings
        "PLUGIN_AUTO_MTLS": True,
        "PLUGIN_CLIENT_ROOT_CERTS": "file:///etc/ssl/certs/ca.crt",
        
        # Performance settings
        "PLUGIN_RATE_LIMIT_ENABLED": True,
        "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 1000.0,
        
        # Monitoring
        "PLUGIN_HEALTH_SERVICE_ENABLED": True,
    }
)

await server.serve()
```

### Client Creation and Usage

```python
from pyvider.rpcplugin.factories import plugin_client

# Create client for local plugin
client = plugin_client(
    command=["python", "-m", "my_plugin_server"],
    config={
        "env": {
            "PLUGIN_LOG_LEVEL": "DEBUG",
            "PLUGIN_AUTO_MTLS": "true"
        }
    }
)

# Start client (performs handshake and establishes connection)
await client.start()

# Create service stub for your protocol
my_service_stub = MyServiceStub(client.grpc_channel)

# Make RPC calls
response = await my_service_stub.MyMethod(request)

# Clean shutdown
await client.shutdown_plugin()
await client.close()
```

### Context Manager Usage

```python
from pyvider.rpcplugin.factories import plugin_client

# Automatic resource cleanup with context manager
async with plugin_client(command=["./my-plugin"]) as client:
    # Client is automatically started
    stub = MyServiceStub(client.grpc_channel)
    response = await stub.SomeMethod(request)
    # Client is automatically shut down and closed on exit
```

## Advanced Usage Patterns

### Custom Protocol Factory

```python
from pyvider.rpcplugin.factories import plugin_protocol
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol

class MyCustomProtocol(RPCPluginProtocol):
    def __init__(self, service_name_override=None, custom_option=None):
        super().__init__()
        self.service_name = service_name_override or "MyCustomService"
        self.custom_option = custom_option
    
    async def get_grpc_descriptors(self):
        return my_pb2_grpc, self.service_name
    
    async def add_to_server(self, server, handler):
        my_pb2_grpc.add_MyServiceServicer_to_server(handler, server)

# Create custom protocol instance
protocol = plugin_protocol(
    protocol_class=MyCustomProtocol,
    service_name="CustomServiceName",
    custom_option="custom_value"
)

# Use in server
server = plugin_server(
    protocol=protocol,
    handler=my_handler,
    transport="tcp"
)
```

### Multi-Service Server Setup

```python
from pyvider.rpcplugin.factories import plugin_server, plugin_protocol

# Create multiple protocols for different services
user_protocol = plugin_protocol(
    protocol_class=UserServiceProtocol,
    service_name="UserService"
)

auth_protocol = plugin_protocol(
    protocol_class=AuthServiceProtocol, 
    service_name="AuthService"
)

# Create composite handler
class CompositeHandler:
    def __init__(self):
        self.user_handler = UserServiceHandler()
        self.auth_handler = AuthServiceHandler()

# Note: Current factory supports single protocol
# For multi-service, use direct RPCPluginServer construction
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.transport import TCPSocketTransport

server = RPCPluginServer(
    protocol=user_protocol,  # Primary protocol
    handler=composite_handler,
    transport=TCPSocketTransport(host="0.0.0.0", port=8080)
)

# Additional service registration after creation
# server.register_additional_service(auth_protocol, auth_handler)  # If supported
```

### Environment-Specific Factory Usage

```python
import os
from pyvider.rpcplugin.factories import plugin_server

def create_environment_server(protocol, handler):
    """Create server configured for current environment."""
    
    env = os.getenv("ENVIRONMENT", "development")
    
    if env == "development":
        return plugin_server(
            protocol=protocol,
            handler=handler,
            transport="unix",
            transport_path=f"/tmp/dev-plugin-{os.getpid()}.sock",
            config={
                "PLUGIN_LOG_LEVEL": "DEBUG",
                "PLUGIN_AUTO_MTLS": True,
                "PLUGIN_HANDSHAKE_TIMEOUT": 30.0,
                "PLUGIN_RATE_LIMIT_ENABLED": False,
            }
        )
    
    elif env == "testing":
        return plugin_server(
            protocol=protocol,
            handler=handler,
            transport="unix",  # Fast for tests
            config={
                "PLUGIN_LOG_LEVEL": "WARNING",
                "PLUGIN_AUTO_MTLS": True,
                "PLUGIN_HANDSHAKE_TIMEOUT": 5.0,
                "PLUGIN_CLIENT_RETRY_ENABLED": False,
                "PLUGIN_RATE_LIMIT_ENABLED": False,
            }
        )
    
    elif env == "production":
        return plugin_server(
            protocol=protocol,
            handler=handler,
            transport="tcp",
            host="0.0.0.0",
            port=int(os.getenv("PLUGIN_PORT", "8080")),
            config={
                "PLUGIN_LOG_LEVEL": "INFO",
                "PLUGIN_AUTO_MTLS": False,
                "PLUGIN_SERVER_CERT": "file:///etc/ssl/certs/server.crt",
                "PLUGIN_SERVER_KEY": "file:///etc/ssl/private/server.key",
                "PLUGIN_RATE_LIMIT_ENABLED": True,
                "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 2000.0,
                "PLUGIN_HEALTH_SERVICE_ENABLED": True,
            }
        )
    
    else:
        raise ValueError(f"Unknown environment: {env}")

# Usage
server = create_environment_server(my_protocol, my_handler)
await server.serve()
```

### Factory with Dependency Injection

```python
from typing import Protocol as TypingProtocol
from pyvider.rpcplugin.factories import plugin_server, plugin_client

class DatabaseService(TypingProtocol):
    async def get_user(self, user_id: str) -> dict: ...

class LoggingService(TypingProtocol):
    def log_request(self, method: str, duration: float) -> None: ...

class PluginFactory:
    """Factory class with dependency injection for plugin components."""
    
    def __init__(self, db_service: DatabaseService, log_service: LoggingService):
        self.db_service = db_service
        self.log_service = log_service
    
    def create_server(self, transport="unix", **kwargs):
        """Create server with injected dependencies."""
        
        # Create handler with dependencies
        handler = MyServiceHandler(
            db_service=self.db_service,
            log_service=self.log_service
        )
        
        # Create protocol
        protocol = plugin_protocol(
            protocol_class=MyServiceProtocol,
            service_name="MyService"
        )
        
        return plugin_server(
            protocol=protocol,
            handler=handler,
            transport=transport,
            **kwargs
        )
    
    def create_client(self, command, **kwargs):
        """Create client with logging."""
        
        client = plugin_client(command=command, **kwargs)
        
        # Add logging wrapper
        original_start = client.start
        
        async def logged_start():
            start_time = time.time()
            try:
                result = await original_start()
                duration = time.time() - start_time
                self.log_service.log_request("client_start", duration)
                return result
            except Exception as e:
                duration = time.time() - start_time
                self.log_service.log_request("client_start_failed", duration)
                raise
        
        client.start = logged_start
        return client

# Usage
db_service = MyDatabaseService()
log_service = MyLoggingService()
factory = PluginFactory(db_service, log_service)

server = factory.create_server(transport="tcp", port=8080)
client = factory.create_client(["./my-plugin"])
```

## Configuration Integration

### Global Configuration Override

```python
from pyvider.rpcplugin.factories import plugin_server
from pyvider.rpcplugin.config import rpcplugin_config

# Factory functions automatically use global configuration
# You can override specific values via config parameter

server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    transport="tcp",
    config={
        # Override global configuration
        "PLUGIN_LOG_LEVEL": "DEBUG",  # Override global log level
        "PLUGIN_RATE_LIMIT_ENABLED": True,  # Override global rate limiting
        
        # Add server-specific configuration
        "PLUGIN_HANDSHAKE_TIMEOUT": 15.0,
    }
)
```

### Configuration Validation with Factories

```python
from pyvider.rpcplugin.factories import plugin_server
from pyvider.rpcplugin.exception import ConfigError

def create_validated_server(protocol, handler, **kwargs):
    """Create server with configuration validation."""
    
    # Validate required configuration
    config = kwargs.get('config', {})
    
    if not config.get('PLUGIN_MAGIC_COOKIE_VALUE') and not os.getenv('PLUGIN_MAGIC_COOKIE_VALUE'):
        raise ConfigError(
            message="Magic cookie value is required",
            hint="Set PLUGIN_MAGIC_COOKIE_VALUE or provide in config parameter"
        )
    
    # Validate transport-specific requirements
    transport = kwargs.get('transport', 'unix')
    if transport == 'tcp':
        port = kwargs.get('port', 0)
        if port == 0 and not config.get('PLUGIN_SERVER_ENDPOINT'):
            print("Warning: Using auto-assigned port for TCP transport")
    
    # Create server with validation passed
    return plugin_server(protocol=protocol, handler=handler, **kwargs)
```

## Testing with Factory Functions

### Test Factory Setup

```python
import pytest
from pyvider.rpcplugin.factories import plugin_server, plugin_client, plugin_protocol

@pytest.fixture
def test_protocol():
    """Create protocol for testing."""
    return plugin_protocol(service_name="TestService")

@pytest.fixture
def test_handler():
    """Create handler for testing."""
    class TestHandler:
        async def test_method(self, request, context):
            return TestResponse(message="test")
    return TestHandler()

@pytest.fixture
async def test_server(test_protocol, test_handler):
    """Create test server."""
    server = plugin_server(
        protocol=test_protocol,
        handler=test_handler,
        transport="unix",
        transport_path=f"/tmp/test-{os.getpid()}.sock",
        config={
            "PLUGIN_LOG_LEVEL": "WARNING",  # Reduce test noise
            "PLUGIN_HANDSHAKE_TIMEOUT": 5.0,  # Quick timeout for tests
            "PLUGIN_AUTO_MTLS": True,  # Use auto-generated certs
        }
    )
    
    # Start server
    asyncio.create_task(server.serve())
    
    # Wait for server to be ready
    await server.wait_for_server_ready(timeout=5.0)
    
    yield server
    
    # Cleanup
    await server.stop()

@pytest.mark.asyncio
async def test_factory_integration(test_server):
    """Test server created by factory."""
    # Create client to connect to test server
    client = plugin_client(
        command=["echo"],  # Dummy command for testing
        config={"PLUGIN_LOG_LEVEL": "WARNING"}
    )
    
    # Test would connect and make calls
    # Implementation depends on your specific testing needs
```

### Mock Factory for Testing

```python
from unittest.mock import AsyncMock
from pyvider.rpcplugin.factories import plugin_client

class MockPluginFactory:
    """Mock factory for testing without real plugin processes."""
    
    @staticmethod
    def create_mock_client(command, config=None):
        """Create mock client for testing."""
        client = plugin_client(command, config)
        
        # Replace real methods with mocks
        client.start = AsyncMock()
        client.shutdown_plugin = AsyncMock()
        client.close = AsyncMock()
        
        # Mock gRPC channel
        client.grpc_channel = AsyncMock()
        
        return client
    
    @staticmethod
    def create_mock_server(protocol, handler, **kwargs):
        """Create mock server for testing."""
        server = plugin_server(protocol, handler, **kwargs)
        
        # Replace real methods with mocks
        server.serve = AsyncMock()
        server.stop = AsyncMock()
        server.wait_for_server_ready = AsyncMock()
        
        return server

# Usage in tests
@pytest.mark.asyncio
async def test_with_mock_factory():
    mock_client = MockPluginFactory.create_mock_client(["./test-plugin"])
    await mock_client.start()  # Mock call, no real process started
    assert mock_client.start.called
```

## Error Handling in Factories

### Factory Error Patterns

```python
from pyvider.rpcplugin.factories import plugin_server
from pyvider.rpcplugin.exception import ConfigError, TransportError

def robust_server_factory(protocol, handler, **kwargs):
    """Create server with comprehensive error handling."""
    
    try:
        # Validate parameters
        if not protocol:
            raise ConfigError("Protocol is required")
        if not handler:
            raise ConfigError("Handler is required")
        
        # Create server
        server = plugin_server(
            protocol=protocol,
            handler=handler,
            **kwargs
        )
        
        return server
        
    except ValueError as e:
        # Handle factory parameter errors
        raise ConfigError(
            message=f"Invalid factory parameters: {e}",
            hint="Check plugin_server() parameter documentation"
        ) from e
    
    except Exception as e:
        # Handle unexpected errors
        raise ConfigError(
            message=f"Server factory failed: {e}",
            hint="Check protocol, handler, and configuration parameters"
        ) from e

# Usage with error handling
try:
    server = robust_server_factory(my_protocol, my_handler, transport="tcp")
    await server.serve()
except ConfigError as e:
    print(f"Configuration error: {e.message}")
    if e.hint:
        print(f"Hint: {e.hint}")
```

## Best Practices

### Factory Usage Guidelines

```python
# ✅ Good: Use factories for common patterns
server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    transport="unix"
)

# ✅ Good: Override configuration when needed
server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    transport="tcp",
    port=8080,
    config={"PLUGIN_RATE_LIMIT_ENABLED": True}
)

# ✅ Good: Use direct construction for complex scenarios
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.transport import TCPSocketTransport

server = RPCPluginServer(
    protocol=my_protocol,
    handler=my_handler,
    transport=TCPSocketTransport(host="0.0.0.0", port=8080),
    config=complex_config
)

# ❌ Avoid: Hardcoding sensitive values in factory calls
server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    config={
        "PLUGIN_MAGIC_COOKIE_VALUE": "hardcoded-secret"  # Use environment variables instead
    }
)
```

### Factory Customization

```python
from pyvider.rpcplugin.factories import plugin_server

def create_production_server(protocol, handler, port=8080):
    """Production server factory with secure defaults."""
    return plugin_server(
        protocol=protocol,
        handler=handler,
        transport="tcp",
        host="0.0.0.0",
        port=port,
        config={
            "PLUGIN_LOG_LEVEL": "INFO",
            "PLUGIN_AUTO_MTLS": False,  # Use manual certificates in production
            "PLUGIN_RATE_LIMIT_ENABLED": True,
            "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 1000.0,
            "PLUGIN_HEALTH_SERVICE_ENABLED": True,
        }
    )

def create_development_server(protocol, handler):
    """Development server factory with debugging enabled."""
    return plugin_server(
        protocol=protocol,
        handler=handler,
        transport="unix",  # Faster for local development
        config={
            "PLUGIN_LOG_LEVEL": "DEBUG",
            "PLUGIN_AUTO_MTLS": True,  # Auto-generated certificates
            "PLUGIN_HANDSHAKE_TIMEOUT": 30.0,  # Generous timeout for debugging
            "PLUGIN_RATE_LIMIT_ENABLED": False,  # No limits in development
        }
    )
```

## Class Reference

The following sections provide detailed API reference for each factory function:

::: pyvider.rpcplugin.factories.plugin_server
::: pyvider.rpcplugin.factories.plugin_client
::: pyvider.rpcplugin.factories.plugin_protocol

## Related Documentation

- [Server API](server/server.md) - Server configuration and usage
- [Client API](client/client.md) - Client configuration and usage
- [Transport Layer](transport/) - Transport configuration options
- [Configuration](config/) - Configuration system and options
- [Testing Guide](../development/testing.md) - Testing with factory functions