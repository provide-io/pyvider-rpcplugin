# Quick Start

Get up and running with Pyvider RPC Plugin in 5 minutes. This guide demonstrates the most common pattern: a host application launching and communicating with a plugin process.

## Prerequisites

- Python 3.11+ installed
- Pyvider RPC Plugin installed (`uv add pyvider-rpcplugin` or `uv sync`)

## Core Components

Before diving in, let's understand the key components:

- **🏠 Host Application (Client)**: Your main program that launches and manages plugins
- **🔌 Plugin Process (Server)**: External executable providing specific services
- **📡 RPC Communication**: gRPC-based calls between host and plugin
- **🤝 Handshake**: Secure connection establishment with magic cookie authentication
- **🏗️ Foundation**: Companion library providing logging, configuration, cryptography, and utilities

!!! info "Built on Foundation" Pyvider RPC Plugin is built on **Foundation** (`provide.foundation`), which provides infrastructure for logging, configuration, cryptography, and utilities. This means you get enterprise-grade patterns out of the box.

    **→ [Understanding Foundation](../introduction/foundation/)** - Learn how Foundation and Pyvider work together

!!! tip "Tutorial Code vs Production Code" The examples below are **simplified for teaching** to focus on core concepts.

    **For production-focused, runnable code**, see:

- `examples/dummy_server.py` - Full-featured version of `my_plugin.py`
- `examples/quick_start_client.py` - Full-featured version of `host_app.py`

Run with: `python examples/quick_start_client.py`

    → [Complete example file mapping](../examples/index/#tutorial-example-actual-file-mapping)

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

!!! note "About Imports" Notice the `from provide.foundation import logger` import. Foundation is the companion library that provides structured logging, configuration, cryptography, and utilities for plugin development.

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

    try:
        logger.info(f"Launching plugin: {' '.join(plugin_command)}")

        # Use async context manager for automatic cleanup
        async with plugin_client(command=plugin_command) as client:
            # Start the plugin
            await client.start()

            logger.info("✅ Successfully connected to plugin!")
            logger.info("Plugin is running and ready for RPC calls")

            # Keep connection alive for demonstration
            await asyncio.sleep(2)

        # Client automatically closed on context exit
        logger.info("Shutdown complete")

    except RPCPluginError as e:
        logger.error(f"❌ Plugin error: {e.message}")
        if e.hint:
            logger.error(f"Hint: {e.hint}")
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)

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

!!! note "Actual Runnable Examples" The simplified examples above (`my_plugin.py`, `host_app.py`) are for teaching. **For working code you can run**, see:

    - **`examples/dummy_server.py`** - Production-focused version of `my_plugin.py`
    - **`examples/quick_start_client.py`** - Production-focused version of `host_app.py`

Run them with:
```bash
python examples/quick_start_client.py
```

    See [Example File Mapping](../examples/index/#tutorial-example-actual-file-mapping) for more details.

## What Just Happened?

1. **Foundation Bootstrap**: Foundation's logging and configuration systems initialized
1. **Plugin Launch**: The host application spawned `my_plugin.py` as a subprocess
1. **Handshake**: Plugin server printed connection details to stdout using Foundation logging
1. **Connection**: Host application parsed handshake and established gRPC channel
1. **Communication**: Both processes are now connected via RPC (ready for method calls)
1. **Cleanup**: Host gracefully shut down the connection and plugin process

### The Role of Foundation

Foundation handles infrastructure concerns automatically:

- **Logging**: Structured output with `logger.info()`
- **Configuration**: Environment variable management
- **Error Handling**: Standardized exception types

**→ [Foundation Architecture](../introduction/foundation/)** explains the complete separation of concerns between Foundation (infrastructure), Pyvider (RPC), and your business logic.

## Key Concepts

### 🤝 The Handshake Process

The handshake is automatic and includes:

- **Magic Cookie**: Shared secret for authentication
- **Protocol Version**: Ensures compatibility
- **Transport Method**: Unix sockets (Linux/macOS) or TCP (Windows)
- **Connection Info**: How the host should connect to the plugin

### 🔒 Security Defaults

!!! warning "mTLS is Enabled by Default" Pyvider RPC Plugin follows a **security-first design**: `PLUGIN_AUTO_MTLS` defaults to `True`, which means mutual TLS (mTLS) is **automatically enabled** for all connections.

````
**For local development/testing**, mTLS may fail if certificates aren't configured. You have two options:

**Option 1 - Disable mTLS for Development (Quick):**
```python
from pyvider.rpcplugin import configure

configure(auto_mtls=False)  # Disable mTLS for local testing
```

**Option 2 - Use mTLS with Auto-Generated Certificates (Recommended):**
```python
# mTLS works automatically with self-signed certificates
# No configuration needed - certificates auto-generated
# This is the default behavior and most secure
```

**For production**, keep `auto_mtls=True` (the default) and optionally provide your own certificates:
```python
import os
os.environ["PLUGIN_SERVER_CERT"] = "file:///path/to/server.crt"
os.environ["PLUGIN_SERVER_KEY"] = "file:///path/to/server.key"
# mTLS enabled with your production certificates
```

    📖 **Learn more:** [Security Guide](../guide/security/index/) | [mTLS Configuration](../guide/security/mtls/)

### 🔧 Configuration

Everything works with sensible defaults, but you can customize:

```python
from pyvider.rpcplugin.config import rpcplugin_config

# View current configuration
logger.info(f"Handshake timeout: {rpcplugin_config.plugin_handshake_timeout}")
logger.info(f"Available transports: {rpcplugin_config.plugin_server_transports}")
logger.info(f"mTLS enabled: {rpcplugin_config.plugin_auto_mtls}")
```

### 🚀 Next Steps

Now that you have the basics working:

1. **[Build a Real Service](first-plugin/)** - Create an Echo plugin with custom RPC methods
2. **[Learn Core Concepts](../guide/concepts/index/)** - Understand the architecture in depth
3. **[Security Setup](../guide/concepts/security/)** - Configure mTLS with production certificates
4. **[Advanced Patterns](../guide/index/)** - Explore async patterns, error handling, and more

### 📝 Short Examples

For focused, executable examples (15-30 lines each):

- **[Basic Client](../examples/short/basic-client/)** - Minimal client connection
- **[Basic Server](../examples/short/basic-server/)** - Simple plugin server  
- **[Health Checks](../examples/short/health-check/)** - Server with health monitoring
- **[Rate Limiting](../examples/short/rate-limiting/)** - Request throttling with token bucket
- **[TCP Transport](../examples/short/tcp-transport/)** - Network transport configuration
- **[Custom Protocol](../examples/short/custom-protocol/)** - Custom gRPC service integration

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
uv add pyvider-rpcplugin
# Or if already in pyproject.toml
uv sync
```

Ready to build something more substantial? Let's create your [First Plugin](first-plugin/) with custom RPC methods!