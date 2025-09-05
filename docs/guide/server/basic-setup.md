# Basic Server Setup

At the heart of a Pyvider RPC Plugin server are three main components that work together to handle RPC requests from host applications. Understanding these components is essential for building effective plugin servers.

## Core Components

### 1. RPCPluginServer

The **`RPCPluginServer`** is the main class that manages the plugin server's lifecycle:

- **Handshake Protocol**: Validates magic cookies and negotiates protocol versions and transports
- **Transport Setup**: Configures Unix socket or TCP transport based on negotiation
- **gRPC Server Management**: Starts and stops the underlying gRPC server
- **Graceful Shutdown**: Manages clean resource shutdown

You typically create an instance using the `plugin_server()` factory function for automatic configuration.

### 2. RPCPluginProtocol

The **`RPCPluginProtocol`** is an abstract base class that you implement to define your gRPC services:

- **Service Descriptors**: Provides gRPC service descriptors from your `.proto` files
- **Service Names**: Specifies the names of your services
- **Server Integration**: Defines how to add your service implementation to the gRPC server

The `plugin_protocol()` factory can provide a basic implementation if you don't have custom services yet.

### 3. Handler/Servicer

The **Handler** is where you implement your actual business logic:

- **RPC Methods**: Each method corresponds to an RPC method from your `.proto` file
- **Request Processing**: Handles incoming requests and generates responses
- **Error Handling**: Manages errors and exceptions in your service logic

Inherits from the gRPC-generated `YourServiceServicer` class.

## Basic Server Configuration

### Factory Function Approach

The simplest way to create a server is using the factory function:

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin import plugin_server, plugin_protocol

class BasicHandler:
    """Simple handler for demonstration."""
    
    def __init__(self):
        self.request_count = 0
    
    def get_status(self):
        """Return current handler status."""
        return {
            "status": "running",
            "requests_handled": self.request_count
        }

async def main():
    # Create server with automatic configuration
    server = plugin_server(
        protocol=plugin_protocol(),  # Basic protocol implementation
        handler=BasicHandler()
    )
    
    logger.info("🚀 Starting plugin server...")
    
    try:
        await server.serve()  # Blocks until shutdown
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped by user")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
```

### Manual Configuration Approach

For more control over server configuration:

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.transport import UnixSocketTransport
from provide.foundation import logger

class CustomProtocol(RPCPluginProtocol):
    """Custom protocol implementation."""
    
    service_name: str = "example.CustomService"
    
    async def get_grpc_descriptors(self):
        """Return gRPC service descriptors."""
        # For basic example, return None
        return None, self.service_name
    
    async def add_to_server(self, server, handler):
        """Add services to the gRPC server."""
        logger.info(f"Adding {self.service_name} to server")
        # Service registration logic goes here

class CustomHandler:
    """Custom handler implementation."""
    
    def __init__(self, name="CustomHandler"):
        self.name = name
        self.start_time = asyncio.get_event_loop().time()
    
    async def get_info(self):
        """Return handler information."""
        uptime = asyncio.get_event_loop().time() - self.start_time
        return {
            "name": self.name,
            "uptime_seconds": uptime
        }

async def main():
    # Custom transport configuration
    transport = UnixSocketTransport(path="/tmp/custom-plugin.sock")
    
    # Create server with custom components
    server = RPCPluginServer(
        protocol=CustomProtocol(),
        handler=CustomHandler(name="MyCustomHandler"),
        transport=transport
    )
    
    logger.info(f"🔧 Custom server configured with {transport}")
    
    try:
        await server.serve()
    except KeyboardInterrupt:
        logger.info("🛑 Custom server stopped")

if __name__ == "__main__":
    asyncio.run(main())
```

## Configuration Options

### Transport Configuration

Configure which transport types your server supports:

```python
import os
from pyvider.rpcplugin import plugin_server

# Unix sockets only (high performance, same machine)
os.environ["PYVIDER_PLUGIN_SERVER_TRANSPORTS"] = "unix"

# TCP only (network communication)  
os.environ["PYVIDER_PLUGIN_SERVER_TRANSPORTS"] = "tcp"

# Both transports (client negotiates)
os.environ["PYVIDER_PLUGIN_SERVER_TRANSPORTS"] = "unix,tcp"

server = plugin_server(protocol=my_protocol, handler=my_handler)
```

### Factory Function Parameters

The `plugin_server()` factory accepts several configuration parameters:

```python
from pyvider.rpcplugin import plugin_server

server = plugin_server(
    protocol=my_protocol,           # Required: Protocol implementation
    handler=my_handler,             # Required: Handler implementation
    transport="unix",               # Transport type: "unix" or "tcp"
    transport_path="/tmp/my.sock",  # Unix socket path (if transport="unix")
    host="127.0.0.1",              # TCP host (if transport="tcp")
    port=8080,                      # TCP port (if transport="tcp", 0=auto)
    config={"timeout": 30.0}        # Additional configuration options
)
```

### Environment-Based Configuration

Configure servers using environment variables:

```python
#!/usr/bin/env python3
import os
import asyncio
from pyvider.rpcplugin import plugin_server

def configure_development():
    """Development server configuration."""
    os.environ.update({
        "PYVIDER_PLUGIN_LOG_LEVEL": "DEBUG",
        "PYVIDER_PLUGIN_SHOW_EMOJI_MATRIX": "true",
        "PYVIDER_PLUGIN_SERVER_TRANSPORTS": "unix",
        "PYVIDER_PLUGIN_AUTO_MTLS": "false"  # Disable TLS for local dev
    })

def configure_production():
    """Production server configuration."""
    os.environ.update({
        "PYVIDER_PLUGIN_LOG_LEVEL": "INFO",
        "PYVIDER_PLUGIN_SHOW_EMOJI_MATRIX": "false", 
        "PYVIDER_PLUGIN_SERVER_TRANSPORTS": "tcp",
        "PYVIDER_PLUGIN_AUTO_MTLS": "true",           # Enable TLS
        "PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED": "true",
        "PYVIDER_PLUGIN_RATE_LIMIT_ENABLED": "true"
    })

async def main():
    # Configure based on environment
    env = os.getenv("ENVIRONMENT", "development")
    
    if env == "production":
        configure_production()
        logger.info("🏭 Configured for production")
    else:
        configure_development()
        logger.info("🧪 Configured for development")
    
    server = plugin_server(
        protocol=my_protocol,
        handler=my_handler
    )
    
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
```

## Server Lifecycle Management

### Startup Sequence

Understanding the server startup sequence helps with debugging:

```python
import asyncio
from provide.foundation import logger
from pyvider.rpcplugin import plugin_server

async def main():
    logger.info("1️⃣ Creating server instance...")
    server = plugin_server(protocol=my_protocol, handler=my_handler)
    
    logger.info("2️⃣ Starting server (this will:")
    logger.info("   - Load configuration from environment")
    logger.info("   - Initialize transport (Unix socket or TCP)")
    logger.info("   - Register gRPC services")
    logger.info("   - Print handshake string to stdout")
    logger.info("   - Begin accepting connections")
    
    try:
        await server.serve()
    except Exception as e:
        logger.error(f"❌ Server startup failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
```

### Handshake Protocol

The server outputs a handshake string that clients use to connect:

```
Format: PYVIDER_RPC|<version>|<transport>|<address>|<optional_data>

Examples:
PYVIDER_RPC|1|unix|/tmp/plugin_12345.sock|
PYVIDER_RPC|1|tcp|127.0.0.1:8080|
```

### Graceful Shutdown

Implement proper shutdown handling:

```python
#!/usr/bin/env python3
import asyncio
import signal
from pyvider.rpcplugin import plugin_server
from provide.foundation import logger

async def main():
    # Create server
    server = plugin_server(protocol=my_protocol, handler=my_handler)
    
    # Setup shutdown handling
    shutdown_event = asyncio.Event()
    
    def signal_handler(signum, frame):
        logger.info(f"📡 Received signal {signum}")
        shutdown_event.set()
    
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)  # Termination
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    
    # Start server in background task
    server_task = asyncio.create_task(server.serve())
    logger.info("🚀 Server started, waiting for connections...")
    
    # Wait for shutdown signal
    await shutdown_event.wait()
    logger.info("🛑 Shutdown signal received")
    
    # Graceful shutdown
    logger.info("⏳ Stopping server...")
    await server.stop()  # Signal server to stop accepting new connections
    
    # Wait for server task to complete
    try:
        await asyncio.wait_for(server_task, timeout=10.0)
        logger.info("✅ Server stopped successfully")
    except asyncio.TimeoutError:
        logger.warning("⚠️ Server shutdown timeout, forcing exit")
        server_task.cancel()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🛑 Server interrupted by user")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
        raise
```

## Common Configuration Patterns

### Development Server

```python
import os
from pyvider.rpcplugin import plugin_server

# Development-friendly configuration
os.environ.update({
    "PYVIDER_PLUGIN_LOG_LEVEL": "DEBUG",
    "PYVIDER_PLUGIN_SHOW_EMOJI_MATRIX": "true",
    "PYVIDER_PLUGIN_SERVER_TRANSPORTS": "unix",  # Faster for local dev
    "PYVIDER_PLUGIN_HANDSHAKE_TIMEOUT": "5.0",   # Shorter timeout
    "PYVIDER_PLUGIN_AUTO_MTLS": "false"          # No TLS complexity
})

server = plugin_server(protocol=my_protocol, handler=my_handler)
```

### Testing Server

```python
import tempfile
import os
from pyvider.rpcplugin import plugin_server

# Testing configuration with temporary paths
with tempfile.TemporaryDirectory() as temp_dir:
    socket_path = os.path.join(temp_dir, "test_plugin.sock")
    
    server = plugin_server(
        protocol=test_protocol,
        handler=test_handler,
        transport="unix",
        transport_path=socket_path
    )
    
    # Server is isolated and cleanup is automatic
```

### Production Server

```python
import os
from pyvider.rpcplugin import plugin_server

# Production-ready configuration
os.environ.update({
    "PYVIDER_PLUGIN_LOG_LEVEL": "INFO",
    "PYVIDER_PLUGIN_SHOW_EMOJI_MATRIX": "false",
    "PYVIDER_PLUGIN_AUTO_MTLS": "true",
    "PYVIDER_PLUGIN_RATE_LIMIT_ENABLED": "true",
    "PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED": "true",
    "PYVIDER_PLUGIN_SERVER_TRANSPORTS": "tcp"
})

server = plugin_server(
    protocol=production_protocol,
    handler=production_handler,
    transport="tcp",
    host="0.0.0.0",  # Listen on all interfaces
    port=8080
)
```

## Troubleshooting Common Issues

### Server Won't Start

```python
# Check configuration and permissions
import os
from pyvider.rpcplugin.config import rpcplugin_config

def debug_server_startup():
    config = rpcplugin_config
    
    logger.info("🔍 Server Configuration Debug:")
    logger.info(f"  Protocol Version: {config.protocol_version()}")
    logger.info(f"  Server Transports: {config.server_transports()}")
    logger.info(f"  Auto mTLS: {config.auto_mtls_enabled()}")
    logger.info(f"  Log Level: {config.log_level()}")
    
    # Check magic cookie configuration
    cookie_key = config.magic_cookie_key()
    cookie_value = os.environ.get(cookie_key)
    if cookie_value:
        logger.info(f"  Magic Cookie: {cookie_key} = [REDACTED]")
    else:
        logger.warning(f"⚠️ Magic Cookie not set: {cookie_key}")

# Run before server creation
debug_server_startup()
server = plugin_server(protocol=my_protocol, handler=my_handler)
```

### Transport Issues

```python
# Debug transport configuration
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport

def test_transports():
    """Test transport creation and configuration."""
    
    # Test Unix socket
    try:
        unix_transport = UnixSocketTransport(path="/tmp/test.sock")
        logger.info("✅ Unix socket transport created successfully")
    except Exception as e:
        logger.error(f"❌ Unix socket transport failed: {e}")
    
    # Test TCP socket  
    try:
        tcp_transport = TCPSocketTransport(host="127.0.0.1", port=0)
        logger.info("✅ TCP transport created successfully")
    except Exception as e:
        logger.error(f"❌ TCP transport failed: {e}")

test_transports()
```

## Next Steps

1. **[Service Implementation](services.md)** - Learn to implement your RPC methods
2. **[Transport Configuration](transports.md)** - Configure Unix sockets and TCP
3. **[Async Patterns](async-patterns.md)** - Handle concurrent requests efficiently
4. **[Health Checks](health-checks.md)** - Add monitoring and health endpoints

## Examples and Resources

- **[ch03_server_setup_concepts.py](../../examples/ch03_server_setup_concepts.py)** - Server configuration examples
- **[ch05_echo_server.py](../../examples/ch05_echo_server.py)** - Complete working server
- **[API Reference](../../api/server/)** - Complete server API documentation
- **[Configuration Guide](../config/)** - Environment variables and options