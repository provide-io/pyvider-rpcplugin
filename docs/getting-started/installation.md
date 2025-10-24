# Installation

**Path:** [Home](../index.md) → [Getting Started](index.md) → Installation

Get started with Pyvider RPC Plugin by installing it in your Python environment.

## Requirements

- **Python 3.11+** (3.13+ recommended)
- **pip**, **uv**, or **poetry** for package management
- **protoc** (Protocol Buffer compiler) - automatically handled by dependencies

## Installation Options

### Using uv (Recommended)

[uv](https://github.com/astral-sh/uv) is the recommended package manager - it's extremely fast and handles dependencies efficiently:

```bash
uv add pyvider-rpcplugin
```

### Using pip

```bash
pip install pyvider-rpcplugin
```

### Using Poetry

```bash
poetry add pyvider-rpcplugin
```

### Development Installation

If you want to contribute or use the latest development version:

```bash
# Clone the repository
git clone https://github.com/provide-io/pyvider-rpcplugin.git
cd pyvider-rpcplugin

# Install in development mode
pip install -e .

# Or with additional development dependencies
pip install -e ".[dev]"
```

## Verify Installation

Test that the installation was successful:

```python
import pyvider.rpcplugin

# Check version
print(f"Pyvider RPC Plugin version: {pyvider.rpcplugin.__version__}")

from provide.foundation import logger
from provide.foundation.config import RuntimeConfig
from pyvider.rpcplugin import plugin_server, plugin_client
from pyvider.rpcplugin.config import rpcplugin_config

logger.info("Installation successful!")
logger.info(f"Config system: {type(rpcplugin_config).__name__}")
print("Foundation integration verified!")
```

## Dependencies

Pyvider RPC Plugin automatically installs these key dependencies:

### Core Dependencies
- **provide-foundation** - Foundation library providing structured logging, type-safe configuration, cryptography utilities, and rate limiting
- **grpcio** - gRPC runtime for Python
- **grpcio-health-checking** - gRPC health checking implementation
- **protobuf** - Protocol Buffers runtime and serialization
- **attrs** - Modern Python data classes with excellent typing support
- **cryptography** - Cryptographic primitives and utilities
- **structlog** - Structured logging library
- **google** - Google API core libraries

### Foundation Integration

Pyvider RPC Plugin is built on Foundation's infrastructure:

```python
from provide.foundation.config import RuntimeConfig
from provide.foundation import logger
from provide.foundation.crypto import Certificate
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin import plugin_server, plugin_client
```

Foundation handles:
- **Configuration Management**: Type-safe, validated configuration with multi-source loading
- **Structured Logging**: Consistent, structured logging across all components  
- **Cryptography**: X.509 certificate management and TLS operations
- **Rate Limiting**: Token bucket rate limiting for server protection
- **Utilities**: Common patterns and helper functions

While Pyvider RPC Plugin focuses on:
- **RPC Protocol**: gRPC-based plugin communication
- **Transport Management**: Unix sockets and TCP transport handling
- **Plugin Lifecycle**: Handshake, serving, and shutdown logic
- **Client Integration**: Plugin discovery and connection management

### Optional Dependencies

For development and testing:

```bash
# Install with test dependencies (includes grpcio-tools for protobuf compilation)
pip install "pyvider-rpcplugin[test]"

# Install with full development dependencies (recommended for contributors)
uv sync --all-groups
```

Test dependencies (`[test]` extra) include:
- **grpcio-tools** - Protocol Buffer compiler and gRPC tools
- **grpc-stubs** - Type stubs for gRPC
- **types-grpcio** - Type hints for grpcio
- **types-protobuf** - Type hints for protobuf

Development dependencies (installed via `uv sync --all-groups`) include:
- All test dependencies above
- **provide-testkit** - Testing utilities, type checking, profiling, and build tools

For documentation building:

```bash
# Install with docs dependencies
pip install pyvider-rpcplugin[docs]
```

## Platform Support

Pyvider RPC Plugin supports:

- **Linux** (Ubuntu, RHEL, Alpine, etc.)
- **macOS** (Intel and Apple Silicon)
- **Windows** (Windows 10/11, Windows Server)

### Transport Availability

| Transport | Linux | macOS | Windows |
|-----------|-------|-------|---------|
| Unix Sockets | ✅ | ✅ | ❌ |
| TCP Sockets | ✅ | ✅ | ✅ |

!!! note "Windows Support"
    On Windows, only TCP transport is available. Unix socket support is planned for future releases using named pipes.

## Quick Test

Create a simple test to verify everything works:

```python
# test_installation.py
import asyncio
from pyvider.rpcplugin import plugin_server, plugin_client
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from provide.foundation import logger

class TestProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self):
        return None, "test_service"
    
    async def add_to_server(self, server, handler):
        pass

class TestHandler:
    def test_method(self):
        return "Installation working!"

async def test_installation():
    logger.info("Testing Pyvider RPC Plugin installation...")
    
    # Test server creation
    server = plugin_server(
        protocol=TestProtocol(),
        handler=TestHandler()
    )
    logger.info("Server creation successful")
    
    # Test configuration access
    config = server._config if hasattr(server, '_config') else None
    logger.info("Configuration access successful")
    
    logger.info("Installation test completed successfully!")

if __name__ == "__main__":
    asyncio.run(test_installation())
```

Run the test:

```bash
python test_installation.py
```

Expected output:
```
2024-01-15 10:30:45.123 [info     ] Testing Pyvider RPC Plugin installation...
2024-01-15 10:30:45.124 [info     ] Server creation successful
2024-01-15 10:30:45.125 [info     ] Configuration access successful
2024-01-15 10:30:45.126 [info     ] Installation test completed successfully!
```

## Troubleshooting

### Common Issues

#### Import Error: `No module named 'pyvider'`

This usually means the installation failed. Try:

```bash
pip install --upgrade pip
pip install pyvider-rpcplugin --force-reinstall
```

#### Protocol Buffer Compiler Missing

If you get protoc-related errors:

**On Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install protobuf-compiler
```

**On macOS:**
```bash
brew install protobuf
```

**On Windows:**
Download from [Protocol Buffers releases](https://github.com/protocolbuffers/protobuf/releases)

#### Version Conflicts

If you have conflicting versions of grpcio or other dependencies:

```bash
pip install pyvider-rpcplugin --force-reinstall --no-deps
pip install grpcio grpcio-tools  # Install compatible versions
```

### Getting Help

If you encounter issues:

1. **Check the logs** - Foundation provides detailed error messages
2. **Verify Python version** - Ensure you're using Python 3.11+
3. **Update pip** - `pip install --upgrade pip`
4. **Report issues** - [GitHub Issues](https://github.com/provide-io/pyvider-rpcplugin/issues)

## Next Steps

### Get Started Quickly
1. **[Quick Start](quick-start.md)** - Run your first plugin in 5 minutes
2. **[First Plugin](first-plugin.md)** - Build a complete echo service with all RPC patterns

### Explore Examples
- **[Basic Server Example](../examples/short/basic-server.md)** - Minimal server implementation using factory functions
- **[Echo Service Examples](../examples/echo-basic.md)** - Complete service examples from basic to advanced patterns

### Learn Core Concepts
- **[Transport Concepts](../guide/concepts/transports.md)** - Understanding Unix sockets, TCP, and transport selection
- **[Security Model](../guide/concepts/security.md)** - Learn about mTLS, certificates, and authentication
- **[Configuration Guide](../guide/config/index.md)** - Environment-driven configuration and deployment patterns

### Advanced Topics
- **[Server Development](../guide/server/index.md)** - Production-ready server patterns and optimization
- **[Security Implementation](../guide/security/index.md)** - Complete security setup and certificate management

Ready to create your first plugin? Let's go to the [Quick Start](quick-start.md)!