# Installation

**Path:** [Home](../index/) → [Getting Started](index/) → Installation

Get started with Pyvider RPC Plugin by installing it in your Python environment.

## Prerequisites

--8<-- ".provide/foundry/docs/_partials/python-requirements.md"

**Additional Requirements:**
- **protoc** (Protocol Buffer compiler) - automatically handled by dependencies

--8<-- ".provide/foundry/docs/_partials/uv-installation.md"

--8<-- ".provide/foundry/docs/_partials/python-version-setup.md"

## Installation Methods

### As a Library Dependency

If you're using pyvider-rpcplugin in your project, add it to your dependencies:

**Using uv (Recommended):**
```bash
# Add to your project
uv add pyvider-rpcplugin

# Or sync from pyproject.toml
uv sync
```

**In your `pyproject.toml`:**
```toml
[project]
dependencies = [
    "pyvider-rpcplugin>=0.1.0",
]
```

### For Development

Clone the repository and set up the development environment:

```bash
# Clone the repository
git clone https://github.com/provide-io/pyvider-rpcplugin.git
cd pyvider-rpcplugin

# Set up development environment
uv sync

# Or install in editable mode with all dev dependencies
uv sync --all-groups
```

This creates a `.venv/` virtual environment with all dependencies installed.

--8<-- ".provide/foundry/docs/_partials/virtual-env-setup.md"

--8<-- ".provide/foundry/docs/_partials/platform-specific-macos.md"

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
    On Windows, only TCP transport is available. Unix sockets are not supported.

## Verifying Installation

### Basic Verification

--8<-- ".provide/foundry/docs/_partials/verification-commands.md"

### RPC Plugin Verification

**1. Test Core Imports:**
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

**2. Test Plugin Server Creation:**
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

**3. Run Integration Tests:**
```bash
# Run core plugin tests
uv run pytest tests/test_factories.py -v

# Run transport tests
uv run pytest tests/transport/ -v

# Run handshake tests
uv run pytest tests/handshake/ -v
```

## Development Workflow

--8<-- ".provide/foundry/docs/_partials/testing-setup.md"

**Additional Testing Options:**

```bash
# Run tests excluding slow tests
uv run pytest -m "not slow"

# Run tests excluding long running tests
uv run pytest -m "not long_running"

# Run specific test directory
uv run pytest tests/client/ -v
```

!!! important "Foundation Reset Required"
    When testing pyvider-rpcplugin, **always use `reset_foundation_setup_for_testing()`** from `provide-testkit`:
    ```python
    import pytest
    from provide.testkit import reset_foundation_setup_for_testing

    @pytest.fixture(autouse=True)
    def reset_foundation():
        """Reset Foundation state before each test."""
        reset_foundation_setup_for_testing()
    ```

--8<-- ".provide/foundry/docs/_partials/code-quality-setup.md"

**Additional Type Checking:**

```bash
# Run pyre (primary type checker for this project)
pyre check
```

### Pre-commit Hooks

```bash
# Install pre-commit hooks
pre-commit install

# Run all hooks manually
pre-commit run --all-files
```

### Building the Package

```bash
# Build distribution packages
uv build

# The wheel will be in dist/
```

## Dependencies

Pyvider RPC Plugin automatically installs these key dependencies:

### Core Dependencies

| Dependency | Purpose |
|------------|---------|
| **provide-foundation** | Foundation library providing structured logging, type-safe configuration, cryptography utilities, and rate limiting |
| **grpcio** | gRPC runtime for Python |
| **grpcio-health-checking** | gRPC health checking implementation |
| **protobuf** | Protocol Buffers runtime and serialization |
| **attrs** | Modern Python data classes with excellent typing support |
| **cryptography** | Cryptographic primitives and utilities |
| **structlog** | Structured logging library |
| **google** | Google API core libraries |

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

!!! tip "Understanding the Architecture" **Foundation** provides infrastructure (config, logging, crypto, utilities) **Pyvider RPC Plugin** provides RPC communication (gRPC, transports, protocols) **Your Plugin** provides business logic

    **→ [Complete Foundation Overview](../introduction/foundation/)** for detailed architecture and practical examples

### Optional Dependencies

For development and testing:

```bash
# Install with test dependencies (includes grpcio-tools for protobuf compilation)
# Using uv (recommended):
uv sync --group test

# Install with full development dependencies (recommended for contributors)
uv sync --all-groups
```

Test dependencies include:

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
uv sync --group docs
```

## Troubleshooting

--8<-- ".provide/foundry/docs/_partials/troubleshooting-common.md"

### RPC Plugin-Specific Issues

#### Import Error: `No module named 'pyvider'`

This usually means the installation failed. Try:

```bash
uv add pyvider-rpcplugin
# Or if already in pyproject.toml
uv sync
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

**On Windows:** Download from [Protocol Buffers releases](https://github.com/protocolbuffers/protobuf/releases)

#### Version Conflicts

If you have conflicting versions of grpcio or other dependencies:

```bash
# Remove and re-add to resolve conflicts
uv remove pyvider-rpcplugin
uv add pyvider-rpcplugin
```

#### Foundation Setup Issues

If tests fail with Foundation-related errors:
```python
# Always use reset in test fixtures
from provide.testkit import reset_foundation_setup_for_testing

@pytest.fixture(autouse=True)
def reset_foundation():
    reset_foundation_setup_for_testing()
```

#### gRPC Connection Issues

If you encounter connection problems:
```bash
# Check transport availability
python -c "
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPTransport
import platform
print(f'Platform: {platform.system()}')
print('Unix sockets available:', platform.system() != 'Windows')
print('TCP sockets available: True')
"
```

### Getting Help

If you encounter issues:

1. **Check the logs** - Foundation provides detailed error messages
2. **Verify Python version** - Ensure you're using Python 3.11+
3. **Check [Troubleshooting Guide](../development/troubleshooting/)** - Common issues and solutions
5. **Report issues** - [GitHub Issues](https://github.com/provide-io/pyvider-rpcplugin/issues)

## Next Steps

### Get Started Quickly

1. **[Quick Start](quick-start/)** - Run your first plugin in 5 minutes
2. **[First Plugin](first-plugin/)** - Build a complete echo service with all RPC patterns

### Explore Examples

- **[Basic Server Example](../examples/short/basic-server/)** - Minimal server implementation using factory functions
- **[Echo Service Examples](../examples/echo-basic/)** - Complete service examples from basic to advanced patterns

### Learn Core Concepts

- **[Transport Concepts](../guide/concepts/transports/)** - Understanding Unix sockets, TCP, and transport selection
- **[Security Model](../guide/concepts/security/)** - Learn about mTLS, certificates, and authentication
- **[Configuration Guide](../guide/config/index/)** - Environment-driven configuration and deployment patterns

### Advanced Topics

- **[Server Development](../guide/server/index/)** - Production-focused server patterns and optimization
- **[Security Implementation](../guide/security/index/)** - Complete security setup and certificate management

Ready to create your first plugin? Let's go to the [Quick Start](quick-start/)!
