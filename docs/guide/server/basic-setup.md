# Basic Server Setup

Learn the fundamentals of creating and configuring plugin servers with comprehensive examples and best practices.

## Minimal Server

```python
import asyncio
from pyvider.rpcplugin import plugin_server, RPCPluginProtocol
from provide.foundation import logger

class EchoProtocol(RPCPluginProtocol):
    """Echo service protocol implementation."""

    async def get_grpc_descriptors(self):
        """Return the gRPC module and service name."""
        import echo_pb2_grpc
        return echo_pb2_grpc, "echo.Echo"

    async def add_to_server(self, server, handler):
        """Register the service with the gRPC server."""
        echo_pb2_grpc.add_EchoServicer_to_server(handler, server)

class EchoHandler:
    async def Echo(self, request, context):
        from echo_pb2 import EchoResponse
        
        logger.info("Processing Echo request", extra={
            "message": request.message,
            "peer": context.peer()
        })
        
        response_message = f"Echo: {request.message}"
        logger.debug("Echo response prepared", extra={"response": response_message})
        
        return EchoResponse(message=response_message)

async def main():
    logger.info("Starting Echo plugin server")
    
    server = plugin_server(
        protocol=EchoProtocol(),
        handler=EchoHandler()
    )
    
    try:
        logger.info("Echo server ready to serve requests")
        await server.serve()
    except Exception as e:
        logger.error("Server error", extra={"error": str(e)}, exc_info=True)
        raise

if __name__ == "__main__":
    asyncio.run(main())
```

## Environment Configuration

Configure your server using environment variables (recommended) or the `configure()` function:

### Option 1: Environment Variables (Recommended)

```python
import os
from pyvider.rpcplugin import plugin_server
from provide.foundation import logger

# Set configuration via environment variables
os.environ.update({
    "PLUGIN_AUTO_MTLS": "false",
    "PLUGIN_SERVER_TRANSPORTS": "unix,tcp",
    "PLUGIN_LOG_LEVEL": "DEBUG",
    "PLUGIN_HANDSHAKE_TIMEOUT": "30.0"
})

# Configuration is automatically loaded from environment
server = plugin_server(
    protocol=EchoProtocol(),
    handler=EchoHandler()
)

logger.info("Server created with environment configuration")
```

### Option 2: Using configure()

```python
from pyvider.rpcplugin import configure, plugin_server
from provide.foundation import logger

# Configure programmatically
configure(
    auto_mtls=False,           # Explicit parameter
    transports=["unix", "tcp"], # Explicit parameter
    handshake_timeout=30.0,    # Explicit parameter
    log_level="DEBUG"          # Via **kwargs: sets plugin_log_level
)

server = plugin_server(
    protocol=EchoProtocol(),
    handler=EchoHandler()
)

logger.info("Server created with programmatic configuration")
```

### Option 3: Direct Configuration Access

```python
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.config import rpcplugin_config
from provide.foundation import logger

# Modify configuration directly
rpcplugin_config.plugin_auto_mtls = False
rpcplugin_config.plugin_server_transports = ["unix", "tcp"]
rpcplugin_config.plugin_log_level = "DEBUG"
rpcplugin_config.plugin_handshake_timeout = 30.0

server = plugin_server(
    protocol=EchoProtocol(),
    handler=EchoHandler()
)

logger.info("Server created with direct configuration")
```

## Graceful Shutdown

```python
import signal
import asyncio
from provide.foundation import logger

class GracefulServer:
    def __init__(self, protocol, handler):
        self.protocol = protocol
        self.handler = handler
        self.server = None
        self.shutdown_event = asyncio.Event()
        logger.info("Graceful server initialized", extra={
            "protocol": type(protocol).__name__,
            "handler": type(handler).__name__
        })
    
    async def start(self):
        logger.info("Starting graceful server with signal handlers")
        self.setup_signal_handlers()
        
        self.server = plugin_server(
            protocol=self.protocol,
            handler=self.handler
        )
        
        try:
            logger.info("Server ready, beginning to serve requests")
            await self.server.serve()
        except Exception as e:
            logger.error("Server error during operation", extra={"error": str(e)}, exc_info=True)
            raise
    
    async def stop(self):
        logger.info("Initiating graceful server shutdown")
        if self.server:
            logger.debug("Stopping server instance")
            await self.server.stop()
            logger.info("Server stopped successfully")
        
        self.shutdown_event.set()
        logger.info("Shutdown event set")
    
    def setup_signal_handlers(self):
        def signal_handler(signum, frame):
            signal_name = signal.Signals(signum).name
            logger.info("Received shutdown signal", extra={"signal": signal_name})
            asyncio.create_task(self.stop())
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        logger.debug("Signal handlers configured for SIGTERM and SIGINT")

async def main():
    logger.info("Initializing graceful server example")
    server = GracefulServer(EchoProtocol(), EchoHandler())
    
    try:
        await server.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error("Unhandled exception in main", extra={"error": str(e)}, exc_info=True)
    finally:
        logger.info("Main function cleanup complete")
```

## Development vs Production

### Development Setup
```python
from pyvider.rpcplugin import configure

def setup_development():
    """Configure for local development."""
    configure(
        auto_mtls=False,              # Disable mTLS for local testing
        handshake_timeout=30.0,       # Longer timeout for debugging
        log_level="DEBUG",            # Verbose logging
        # Use TCP with auto-assigned port for flexibility
        # Or use Unix sockets (default): transports=["unix"]
    )
```

### Production Setup
```python
from pyvider.rpcplugin import configure

def setup_production():
    """Configure for production deployment."""
    configure(
        auto_mtls=True,               # Enable mTLS security
        handshake_timeout=10.0,       # Standard timeout
        log_level="INFO",             # Production logging
        server_cert="file:///etc/ssl/server.pem",
        server_key="file:///etc/ssl/server.key",
        rate_limit_enabled=True,      # Enable rate limiting
        rate_limit_requests_per_second=1000.0,
        rate_limit_burst_capacity=2000,
        health_service_enabled=True,  # Enable health checks
    )
```

## Error Handling

```python
from provide.foundation import logger

class ValidatedServer:
    def __init__(self, protocol, handler):
        self.protocol = protocol
        self.handler = handler
    
    def validate_config(self):
        """Validate server configuration."""
        errors = []
        
        # Check required environment variables
        if not os.environ.get("PLUGIN_SERVICE_NAME"):
            errors.append("PLUGIN_SERVICE_NAME required")
        
        # Validate certificates if mTLS enabled
        if os.environ.get("PLUGIN_ENABLE_MTLS") == "true":
            if not os.environ.get("PLUGIN_SERVER_CERT"):
                errors.append("PLUGIN_SERVER_CERT required for mTLS")
        
        if errors:
            raise ValueError(f"Configuration errors: {'; '.join(errors)}")
    
    async def start(self):
        try:
            self.validate_config()

            server = plugin_server(
                protocol=self.protocol,
                handler=self.handler
            )

            logger.info("Server starting...")
            await server.serve()

        except Exception as e:
            logger.error(f"Server failed: {e}")
            raise

server = ValidatedServer(EchoProtocol(), EchoHandler())
await server.start()
```

## Next Steps

- **[Service Implementation](services/)** - Build robust gRPC services
- **[Transport Configuration](transports/)** - Optimize communication layers
- **[Async Patterns](async-patterns/)** - Master concurrency patterns