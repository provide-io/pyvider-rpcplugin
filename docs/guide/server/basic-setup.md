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

```python
import os
from dataclasses import dataclass

from pyvider.rpcplugin import configure
from provide.foundation import logger
from provide.foundation.config import RuntimeConfig

@dataclass
class ServerConfig(RuntimeConfig):
    """Server configuration using Foundation's RuntimeConfig base class."""
    max_workers: int = int(os.environ.get("PLUGIN_MAX_WORKERS", "10"))
    timeout: float = float(os.environ.get("PLUGIN_TIMEOUT", "30.0"))
    transport: str = os.environ.get("PLUGIN_TRANSPORT", "auto")
    enable_mtls: bool = os.environ.get("PLUGIN_ENABLE_MTLS", "false").lower() == "true"
    
    def apply(self):
        logger.info("Applying server configuration", extra={
            "max_workers": self.max_workers,
            "timeout": self.timeout,
            "transport": self.transport,
            "mtls_enabled": self.enable_mtls
        })
        
        # Use configure() with explicit params and **kwargs
        transport_list = [self.transport] if self.transport != "auto" else ["unix", "tcp"]
        configure(
            transports=transport_list,  # Explicit parameter
            auto_mtls=self.enable_mtls,  # Explicit parameter
            # Additional settings via **kwargs (automatically prefixed with 'plugin_')
            # max_workers=self.max_workers,  # Would set plugin_max_workers (if exists)
        )
        
        logger.debug("Configuration applied successfully")

# Initialize and apply Foundation-based configuration
config = ServerConfig()
config.apply()

logger.info("Creating plugin server with applied configuration")
server = plugin_server(protocol=EchoProtocol(), handler=EchoHandler())
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
def setup_development():
    configure(
        log_level="DEBUG",
        enable_reflection=True,
        auto_mtls=False,
        transports=["tcp"],
        tcp_port=0  # Auto-assign
    )
```

### Production Setup
```python
def setup_production():
    configure(
        log_level="INFO",
        enable_reflection=False,
        auto_mtls=True,
        transports=["unix"],
        server_cert="file:///etc/ssl/server.pem",
        server_key="file:///etc/ssl/server.key",
        max_workers=20,
        compression="gzip"
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

- **[Service Implementation](services.md)** - Build robust gRPC services
- **[Transport Configuration](transports.md)** - Optimize communication layers
- **[Async Patterns](async-patterns.md)** - Master concurrency patterns