# AGENTS.md

This file provides guidance for AI assistants when working with code in this repository.

## Project Overview

`pyvider-rpcplugin` is a high-performance, type-safe RPC plugin framework for Python built on gRPC. It provides the communication infrastructure layer for the pyvider ecosystem, implementing a Terraform-compatible plugin protocol with async-first design, mTLS security, and production-ready patterns.

## Development Environment Setup

- Always run `uv sync` to set up the development environment
- The environment uses `uv` for dependency management
- Python 3.11+ required

## Common Development Commands

### Environment
```bash
uv sync          # Set up development environment (ALWAYS run this first)
```

### Testing
```bash
uv run pytest                 # Run all tests with parallel execution
uv run pytest tests/          # Run tests in specific directory
uv run pytest -n auto         # Explicitly run tests in parallel
uv run pytest -m "not slow"   # Skip slow tests
uv run pytest -m "not long_running"  # Skip long running tests
uv run pytest --cov=pyvider.rpcplugin --cov-report=term-missing  # Run with coverage
```

### Code Quality
```bash
uv run ruff check src tests   # Lint code
uv run ruff format src tests  # Format code
pyre check                    # Type checking (primary type checker)
uv run mypy src/              # Alternative type checker
bandit -r src                 # Security analysis
```

### Build and Release
```bash
uv sync --all-groups   # Sync all dependencies
uv build               # Build the package
```

### Documentation
```bash
mkdocs serve           # Serve documentation locally (port 11006)
mkdocs build           # Build documentation
mkdocs build --strict  # Build with strict error checking
```

## Architecture Overview

This is a high-performance, type-safe RPC plugin framework for Python built on gRPC. The architecture follows a layered design:

### Core Components

**Transport Layer** (`src/pyvider/rpcplugin/transport/`):
- `base.py`: Abstract base class `RPCPluginTransport` defining the transport contract
- `tcp.py`: TCP socket implementation for network IPC
- `unix/transport.py`: Unix Domain Socket implementation for local IPC
- `unix/utils.py`: Unix socket utilities
- `unix/__init__.py`: Unix transport module exports
- `types.py`: Transport-related type definitions

**Protocol Layer** (`src/pyvider/rpcplugin/protocol/`):
- `base.py`: Abstract protocol interface
- `service.py`: Protocol service implementations
- `grpc_*_pb2.py`: Generated protobuf definitions for controller, broker, and stdio
- `grpc_*_pb2_grpc.py`: Generated gRPC service stubs

**Client/Server Layer**:
- `server/core.py`: `RPCPluginServer` - manages gRPC server lifecycle, handshake, and transport
- `server/network.py`: Network configuration utilities
- `client/core.py`: `RPCPluginClient` - manages plugin connections and subprocess lifecycle
- `client/connection.py`: Connection management utilities
- `client/handshake.py`: Client-side handshake implementation
- `client/process.py`: Subprocess management
- `client/types.py`: Client-specific type definitions

**Handshake Layer** (`src/pyvider/rpcplugin/handshake/`):
- `core.py`: Secure handshake protocol with magic cookie validation
- `negotiation.py`: Protocol and transport version negotiation

**Configuration System** (`src/pyvider/rpcplugin/config/`):
- `configure.py`: Configuration functions and `configure()` API
- `manager.py`: Configuration manager implementation
- `runtime.py`: Runtime configuration and `RPCPluginConfig`
- `validators.py`: Configuration validation logic

**Core Infrastructure**:
- `factories.py`: Factory functions for common patterns (`plugin_client`, `plugin_server`, etc.)
- `exception.py`: Comprehensive exception hierarchy
- `health_servicer.py`: gRPC health check implementation
- `telemetry.py`: Telemetry and observability integration
- `defaults.py`: Default configuration values
- `types.py`: Core type definitions

### Key Design Patterns

1. **Factory Pattern**: Use `factories.py` functions like `plugin_client()` and `plugin_server()` for standard setups
2. **Transport Abstraction**: All network communication goes through the `RPCPluginTransport` interface
3. **Async-First**: Built for `asyncio` with comprehensive async/await support
4. **Security by Default**: mTLS with certificate management, handshake validation
5. **Type Safety**: Modern Python typing with `attrs` classes, no legacy `Dict`/`List` types

### Protocol Negotiation

The framework implements a Terraform-compatible plugin protocol:
1. Subprocess launches with environment variables for transport configuration
2. Secure handshake with magic cookie validation
3. Protocol version negotiation
4. Transport type negotiation (Unix vs TCP)
5. mTLS certificate exchange
6. Service registration and RPC communication

## Testing Strategy

### Core Testing Requirements

**CRITICAL**: When testing pyvider-rpcplugin, `provide-testkit` MUST be available and used.

- **provide-testkit dependency**: Required in dev dependencies (already configured)
- **Foundation reset**: ALWAYS use `reset_foundation_setup_for_testing()` in test fixtures
- **Async testing**: Use `pytest-asyncio` with `asyncio_mode = "auto"`
- **Test markers**: Use `slow` and `long_running` markers appropriately

### Standard Testing Pattern

```python
import pytest
from provide.testkit import reset_foundation_setup_for_testing

@pytest.fixture(autouse=True)
def reset_foundation():
    """Reset Foundation state before each test."""
    reset_foundation_setup_for_testing()
```

### Testing Infrastructure

- Comprehensive test suite in `tests/` with structure mirroring `src/`
- Tests use `pytest` with async support via `pytest-asyncio`
- Parallel test execution with `pytest-xdist`
- Coverage tracking with `pytest-cov`
- Test markers:
  - `@pytest.mark.slow` - Tests taking significant time
  - `@pytest.mark.long_running` - Tests taking very long time

## Documentation

### Structure

Documentation is organized using MkDocs with Material theme:
- `docs/getting-started/` - Installation and quick start guides
- `docs/guide/` - Comprehensive guides (concepts, server, client, security, config, advanced)
- `docs/examples/` - Example documentation
- `docs/reference/` - API reference (auto-generated)
- `docs/development/` - Contributing, architecture, testing, CI/CD

### Building Documentation

```bash
# Serve documentation locally
mkdocs serve

# Build documentation
mkdocs build

# Build in strict mode (fails on warnings)
mkdocs build --strict
```

## Development Guidelines

### Type Annotations
- Use modern Python 3.11+ type syntax: `dict`, `list`, `set` (lowercase)
- Use union operator `|` instead of `Union`
- Use `from __future__ import annotations` for unquoted types (already used in 8+ files)
- Comprehensive type annotations required (enforced by mypy/pyre)

### Code Style
- Ruff formatting with 111-character line length
- No generated protobuf files in linting (`**/*pb2*.py` excluded)
- Pre-commit hooks enforce code quality
- Target version: Python 3.11

### Imports
- Never use relative imports. Only absolute imports always.
- Import from `pyvider.rpcplugin.*` namespace
- Example: `from pyvider.rpcplugin.client.core import RPCPluginClient`

### Logging
- Always use `provide.foundation.logger` - never use `print()` when debugging
- Import with: `from provide.foundation import logger`
- Library logs to stderr only
- Example: `logger.debug("Internal state changed", state=new_state)`

### Testing
- Comprehensive test suite in `tests/` with transport-specific subdirectories
- Async test support with `pytest-asyncio`
- Coverage reporting configured
- Markers for `slow` and `long_running` tests
- Use `provide-testkit` for Foundation integration

### Security
- Bandit security analysis on `src/` directory
- Pre-commit safety checks for dependencies
- No hardcoded secrets or credentials
- If it makes sense to be more specific for an exception, implement that across the tests and the code

## Common Issues & Solutions

1. **ModuleNotFoundError for dependencies**: Ensure dependencies are installed with `uv sync`
2. **Import errors**: Ensure PYTHONPATH includes `src/` (automatically configured in pytest via `pythonpath = ["src"]` in pyproject.toml)
3. **Type checking with generated protobuf files**: Already excluded in mypy/pyre configuration
4. **Async event loop conflicts**: Use `pytest-asyncio` fixtures and `asyncio_mode = "auto"`
5. **Foundation setup issues**: Use `reset_foundation_setup_for_testing()` in test fixtures
