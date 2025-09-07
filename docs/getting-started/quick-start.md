# Quick Start

Get up and running with Pyvider RPC Plugin in 5 minutes. This guide demonstrates the most common pattern: a host application launching and communicating with a plugin process.

## Prerequisites

- Python 3.11+ installed
- Pyvider RPC Plugin installed (`pip install pyvider-rpcplugin`)

## Core Components

Before diving in, let's understand the key components:

- **🏠 Host Application (Client)**: Your main program that launches and manages plugins
- **🔌 Plugin Process (Server)**: External executable providing specific services
- **📡 RPC Communication**: gRPC-based calls between host and plugin
- **🤝 Handshake**: Secure connection establishment with magic cookie authentication
- **🏗️ Foundation**: Companion library providing logging, configuration, cryptography, and utilities

### Foundation Integration

Pyvider RPC Plugin is built on Foundation's infrastructure. Foundation provides:

- **Configuration System**: Type-safe configuration with `RuntimeConfig`
- **Structured Logging**: Consistent logging across all components
- **Cryptography**: X.509 certificate management for mTLS
- **Rate Limiting**: Token bucket rate limiting for servers
- **Error Handling**: Standardized exception handling

```python
# Foundation imports you'll commonly use
from provide.foundation import logger
from provide.foundation.config import RuntimeConfig
from provide.foundation.crypto import Certificate
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter

from pyvider.rpcplugin import plugin_server, plugin_client
from pyvider.rpcplugin.config import rpcplugin_config
```

## Advanced Foundation Integration Examples

### Configuration with Environment Variables

Foundation's `RuntimeConfig` system automatically loads configuration from environment variables:

```python
import os
from provide.foundation.config import RuntimeConfig
from pyvider.rpcplugin.config import rpcplugin_config

# Set environment variables for advanced configuration
os.environ.update({
    "PLUGIN_HANDSHAKE_TIMEOUT": "15.0",
    "PLUGIN_SERVER_TRANSPORTS": '["unix", "tcp"]',
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_MAX_CONCURRENT_STREAMS": "500",
    "PLUGIN_LOG_LEVEL": "DEBUG"
})

# Configuration automatically loaded
logger.info(f"Handshake timeout: {rpcplugin_config.handshake_timeout()}")  
logger.info(f"Transports: {rpcplugin_config.server_transports()}")
logger.info(f"mTLS: {rpcplugin_config.auto_mtls_enabled()}")
```

### Structured Logging with Context

Foundation's logger supports rich contextual information:

```python
from provide.foundation import logger

class EnhancedPluginHandler:
    def __init__(self, plugin_id: str):
        self.plugin_id = plugin_id
        logger.info("Plugin handler initialized", extra={
            "plugin_id": plugin_id,
            "version": "1.0.0",
            "capabilities": ["processing", "storage"]
        })
    
    async def process_request(self, request_id: str, data: dict[str, str] | str):
        with logger.contextualize(request_id=request_id, plugin_id=self.plugin_id):
            logger.info("Processing request", extra={"data_size": len(str(data))})
            
            # Simulate processing
            await asyncio.sleep(0.1)
            
            logger.info("Request processed successfully")
            return {"status": "completed", "processed_at": time.time()}
```

### Cryptography Integration for mTLS

Foundation handles certificate management for secure communication:

```python
import ssl
from provide.foundation.crypto import Certificate, PrivateKey
from pyvider.rpcplugin.transport import TCPSocketTransport

# Load certificates using Foundation crypto
server_cert = Certificate.load_from_file("/etc/ssl/plugin-server.crt")
server_key = PrivateKey.load_from_file("/etc/ssl/plugin-server.key")
ca_cert = Certificate.load_from_file("/etc/ssl/ca.crt")

# Create TLS context with Foundation certificates
ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_context.load_cert_chain(server_cert.file_path, server_key.file_path)
ssl_context.load_verify_locations(ca_cert.file_path)
ssl_context.verify_mode = ssl.CERT_REQUIRED

# Configure transport with Foundation-managed certificates
transport = TCPSocketTransport(
    host="0.0.0.0",
    port=8443,
    ssl_context=ssl_context
)

server = plugin_server(
    protocol=plugin_protocol(),
    handler=EnhancedPluginHandler("secure-plugin"),
    transport=transport
)
```

### Rate Limiting with Foundation

Use Foundation's token bucket rate limiter to protect your plugin server:

```python
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter
from pyvider.rpcplugin import plugin_server

class RateLimitedHandler:
    def __init__(self):
        # Foundation's rate limiter: 100 requests per minute
        self.rate_limiter = TokenBucketRateLimiter(
            tokens_per_second=100/60,
            bucket_size=100
        )
        logger.info("Rate limiting enabled: 100 req/min")
    
    async def handle_request(self, request):
        if not await self.rate_limiter.acquire():
            logger.warning("Request rate limited", extra={
                "bucket_tokens": self.rate_limiter.available_tokens()
            })
            raise Exception("Rate limit exceeded")
        
        logger.debug("Request approved by rate limiter")
        return await self.process_request(request)

# Server automatically integrates with Foundation's rate limiter
server = plugin_server(
    protocol=plugin_protocol(),
    handler=RateLimitedHandler()
)
```

## Your First Plugin

### 1. Create the Plugin Server

Create a file called `my_plugin.py`:

```python
#!/usr/bin/env python3
"""
A minimal RPC plugin server example.

Demonstrates Foundation integration:
- Foundation provides structured logging via logger
- Configuration is managed through Foundation's RuntimeConfig
- Plugin extends Foundation's capabilities for RPC communication
"""
import asyncio

from pyvider.rpcplugin import plugin_protocol, plugin_server
from provide.foundation import logger
class DummyHandler:
    def __init__(self):
        logger.info("🔌 Plugin handler initialized")
        logger.debug("Foundation logging system active")

async def main():
    logger.info("🚀 Starting plugin server...")
    
    # Create protocol and server
    protocol = plugin_protocol()  # Uses basic protocol
    handler = DummyHandler()
    server = plugin_server(protocol=protocol, handler=handler)
    
    try:
        logger.info("Plugin server ready to serve...")
        await server.serve()  # This prints handshake and starts serving
        logger.info("Plugin server finished")
    except KeyboardInterrupt:
        logger.info("Plugin server stopped")
    except Exception as e:
        logger.error(f"Plugin server error: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())
```

!!! note "About Imports"
    Notice the `from provide.foundation import logger` import. Foundation is the companion library that provides structured logging, configuration, cryptography, and utilities for plugin development.

### 2. Create the Host Application

Create a file called `host_app.py`:

```python
#!/usr/bin/env python3
"""
Host application that launches and connects to a plugin.

Demonstrates Foundation integration:
- Uses Foundation's logger for consistent output
- Configuration is automatically loaded from environment
- Error handling follows Foundation patterns
"""
import asyncio
import sys
from pathlib import Path

from pyvider.rpcplugin import plugin_client
from pyvider.rpcplugin.exception import RPCPluginError
from provide.foundation import logger

async def main():
    logger.info("🚀 Starting host application...")
    
    # Define plugin command
    plugin_path = Path(__file__).parent / "my_plugin.py"
    plugin_command = [sys.executable, str(plugin_path)]
    
    client = None
    try:
        logger.info(f"Launching plugin: {' '.join(plugin_command)}")
        
        # Create and start client
        client = plugin_client(command=plugin_command)
        await client.start()
        
        logger.info("✅ Successfully connected to plugin!")
        logger.info("Plugin is running and ready for RPC calls")
        
        # Keep connection alive for demonstration
        await asyncio.sleep(2)
        
    except RPCPluginError as e:
        logger.error(f"❌ Plugin error: {e.message}")
        if e.hint:
            logger.error(f"Hint: {e.hint}")
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)
    finally:
        if client:
            logger.info("Shutting down...")
            await client.close()
            logger.info("Shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())
```

### 3. Run Your First Plugin

Execute the host application:

```bash
python host_app.py
```

You should see output like:

```
2024-01-15 10:30:45.123 [info     ] 🚀 Starting host application...
2024-01-15 10:30:45.124 [info     ] Launching plugin: python my_plugin.py
2024-01-15 10:30:45.200 [info     ] 🚀 Starting plugin server...
2024-01-15 10:30:45.201 [info     ] 🔌 Plugin handler initialized
2024-01-15 10:30:45.202 [info     ] Plugin server ready to serve...
2024-01-15 10:30:45.250 [info     ] ✅ Successfully connected to plugin!
2024-01-15 10:30:45.251 [info     ] Plugin is running and ready for RPC calls
2024-01-15 10:30:47.252 [info     ] Shutting down...
2024-01-15 10:30:47.253 [info     ] Shutdown complete
```

🎉 **Congratulations!** You've successfully created and run your first plugin system!

## What Just Happened?

1. **Foundation Bootstrap**: Foundation's logging and configuration systems initialized
2. **Plugin Launch**: The host application spawned `my_plugin.py` as a subprocess
3. **Handshake**: Plugin server printed connection details to stdout using Foundation logging
4. **Connection**: Host application parsed handshake and established gRPC channel
5. **Communication**: Both processes are now connected via RPC (ready for method calls)
6. **Cleanup**: Host gracefully shut down the connection and plugin process

### Foundation's Role

- **Logging**: All log messages use Foundation's structured logging format
- **Configuration**: Environment variables automatically loaded via Foundation's config system
- **Transport**: Connection management follows Foundation's patterns
- **Error Handling**: Exceptions use Foundation's standardized error types

## Key Concepts

### 🤝 The Handshake Process

The handshake is automatic and includes:
- **Magic Cookie**: Shared secret for authentication
- **Protocol Version**: Ensures compatibility
- **Transport Method**: Unix sockets (Linux/macOS) or TCP (Windows)
- **Connection Info**: How the host should connect to the plugin

### 🔧 Configuration

Everything works with sensible defaults, but you can customize:

```python
from pyvider.rpcplugin.config import rpcplugin_config

# View current configuration
logger.info(f"Handshake timeout: {rpcplugin_config.handshake_timeout()}")
logger.info(f"Available transports: {rpcplugin_config.server_transports()}")
logger.info(f"mTLS enabled: {rpcplugin_config.auto_mtls_enabled()}")
```

### 🚀 Next Steps

Now that you have the basics working:

1. **[Build a Real Service](first-plugin.md)** - Create an Echo plugin with custom RPC methods
2. **[Learn Core Concepts](../guide/concepts/)** - Understand the architecture in depth
3. **[Security Setup](../guide/concepts/security.md)** - Enable mTLS for production
4. **[Advanced Patterns](../guide/)** - Explore async patterns, error handling, and more

### 📝 Short Examples

For focused, executable examples (15-30 lines each):

- **[Basic Client](../examples/short/basic-client.md)** - Minimal client connection
- **[Basic Server](../examples/short/basic-server.md)** - Simple plugin server  
- **[Health Checks](../examples/short/health-check.md)** - Server with health monitoring
- **[Rate Limiting](../examples/short/rate-limiting.md)** - Request throttling with token bucket
- **[TCP Transport](../examples/short/tcp-transport.md)** - Network transport configuration
- **[Custom Protocol](../examples/short/custom-protocol.md)** - Custom gRPC service integration

## Common Issues

### Plugin Won't Start
```bash
# Check if plugin file exists and is executable
ls -la my_plugin.py
chmod +x my_plugin.py
```

### Connection Timeout
```bash
# Check for port conflicts or firewall issues
# Plugin logs will show transport details
```

### Import Errors
```bash
# Ensure pyvider-rpcplugin is installed
pip list | grep pyvider
pip install --upgrade pyvider-rpcplugin
```

Ready to build something more substantial? Let's create your [First Plugin](first-plugin.md) with custom RPC methods!