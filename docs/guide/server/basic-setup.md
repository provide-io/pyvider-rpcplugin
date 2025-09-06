# Basic Server Setup

Learn the fundamentals of creating and configuring plugin servers with comprehensive examples and best practices.

## Minimal Server

```python
import asyncio
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol

class EchoProtocol(RPCPluginProtocol):
    service_name = "echo.Echo"
    
    async def get_grpc_descriptors(self):
        import echo_pb2_grpc
        return echo_pb2_grpc, "echo.Echo"
    
    async def add_to_server(self, server, handler):
        echo_pb2_grpc.add_EchoServicer_to_server(handler, server)

class EchoHandler:
    async def Echo(self, request, context):
        from echo_pb2 import EchoResponse
        return EchoResponse(message=f"Echo: {request.message}")

async def main():
    server = plugin_server(
        protocol=EchoProtocol(),
        handler=EchoHandler()
    )
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
```

## Environment Configuration

```python
import os
from dataclasses import dataclass
from pyvider.rpcplugin import configure

@dataclass
class ServerConfig:
    max_workers: int = int(os.environ.get("PLUGIN_MAX_WORKERS", "10"))
    timeout: float = float(os.environ.get("PLUGIN_TIMEOUT", "30.0"))
    transport: str = os.environ.get("PLUGIN_TRANSPORT", "auto")
    enable_mtls: bool = os.environ.get("PLUGIN_ENABLE_MTLS", "false").lower() == "true"
    
    def apply(self):
        configure(
            max_workers=self.max_workers,
            timeout=self.timeout,
            transports=[self.transport] if self.transport != "auto" else ["unix", "tcp"],
            auto_mtls=self.enable_mtls
        )

# Usage
config = ServerConfig()
config.apply()
server = plugin_server(protocol=EchoProtocol(), handler=EchoHandler())
```

## Graceful Shutdown

```python
import signal
import asyncio

class GracefulServer:
    def __init__(self, protocol, handler):
        self.protocol = protocol
        self.handler = handler
        self.server = None
        self.shutdown_event = asyncio.Event()
    
    async def start(self):
        self.setup_signal_handlers()
        
        self.server = plugin_server(
            protocol=self.protocol,
            handler=self.handler
        )
        
        await self.server.serve()
    
    async def stop(self):
        if self.server:
            await self.server.stop()
        self.shutdown_event.set()
    
    def setup_signal_handlers(self):
        def handler(signum, frame):
            asyncio.create_task(self.stop())
        
        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGINT, handler)

# Usage
async def main():
    server = GracefulServer(EchoProtocol(), EchoHandler())
    await server.start()
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
import logging

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
            
            logging.info("Server starting...")
            await server.serve()
            
        except Exception as e:
            logging.error(f"Server failed: {e}")
            raise

# Usage
server = ValidatedServer(EchoProtocol(), EchoHandler())
await server.start()
```

## Next Steps

- **[Service Implementation](services.md)** - Build robust gRPC services
- **[Transport Configuration](transports.md)** - Optimize communication layers
- **[Async Patterns](async-patterns.md)** - Master concurrency patterns