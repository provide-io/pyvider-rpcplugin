# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Environment Setup

**IMPORTANT**: This project uses a custom environment setup script instead of standard Python venv.

- Always run `source env.sh` to set up the development environment
- The environment uses `uv` for dependency management and creates virtual environments in `workenv/`
- Do NOT use `.venv` - the project explicitly avoids this in favor of the workenv structure
- The environment script handles Python version compatibility (requires >=3.11) and will recreate the venv if needed

## Common Development Commands

### Environment
```bash
source env.sh          # Set up development environment (ALWAYS run this first)
```

### Testing
```bash
pytest                 # Run all tests with parallel execution
pytest tests/          # Run tests in specific directory
pytest -n auto         # Explicitly run tests in parallel
pytest -m "not slow"   # Skip slow tests
pytest -m "not long_running"  # Skip long running tests
pytest --cov=pyvider.rpcplugin --cov-report=term-missing  # Run with coverage
```

### Code Quality
```bash
ruff check src tests   # Lint code
ruff format src tests  # Format code
pyre check            # Type checking (primary type checker)
mypy src/             # Alternative type checker
bandit -r src         # Security analysis
```

### Build and Release
```bash
uv sync --all-groups   # Sync all dependencies
uv build              # Build the package
```

## Architecture Overview

This is a high-performance, type-safe RPC plugin framework for Python built on gRPC. The architecture follows a layered design:

### Core Components

**Transport Layer** (`src/pyvider/rpcplugin/transport/`):
- `base.py`: Abstract base class `RPCPluginTransport` defining the transport contract
- `unix.py`: Unix Domain Socket implementation for local IPC
- `tcp.py`: TCP socket implementation for network IPC
- `types.py`: Transport-related type definitions

**Protocol Layer** (`src/pyvider/rpcplugin/protocol/`):
- `base.py`: Abstract protocol interface
- `service.py`: Protocol service implementations
- `grpc_*_pb2.py`: Generated protobuf definitions for controller, broker, and stdio
- `grpc_*_pb2_grpc.py`: Generated gRPC service stubs

**Client/Server Layer**:
- `server.py`: `RPCPluginServer` - manages gRPC server lifecycle, handshake, and transport
- `client/base.py`: `RPCPluginClient` - manages plugin connections and subprocess lifecycle
- `client/connection.py`: Connection management utilities
- `client/types.py`: Client-specific type definitions

**Core Infrastructure**:
- `handshake.py`: Secure handshake protocol with magic cookie validation
- `config.py`: Configuration management with `RPCPluginConfig`
- `factories.py`: Factory functions for common patterns (`plugin_client`, `plugin_server`, etc.)
- `exception.py`: Comprehensive exception hierarchy
- `health_servicer.py`: gRPC health check implementation
- `rate_limiter.py`: Token bucket rate limiting

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

## Development Guidelines

### Type Annotations
- Use modern Python 3.11+ type syntax: `dict`, `list`, `set` (lowercase)
- Use union operator `|` instead of `Union`
- No `__future__` imports needed
- Comprehensive type annotations required (enforced by mypy/pyre)

### Code Style
- Ruff formatting with 88-character line length
- No generated protobuf files in linting (`**/*pb2*.py` excluded)
- Pre-commit hooks enforce code quality

### Testing
- Comprehensive test suite in `tests/` with transport-specific subdirectories
- Async test support with `pytest-asyncio`
- Coverage reporting configured
- Markers for `slow` and `long_running` tests

### Security
- Bandit security analysis on `src/` directory
- Pre-commit safety checks for dependencies
- No hardcoded secrets or credentials
- If it makes sense to be more specific for an exception, then implement that across the tests and the code.