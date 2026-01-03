# Contributing to pyvider-rpcplugin

Thank you for your interest in contributing to pyvider-rpcplugin! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Python 3.11 or higher
- `uv` package manager

### Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/provide-io/pyvider-rpcplugin.git
   cd pyvider-rpcplugin
   ```

2. Set up the development environment:
   ```bash
   uv sync
   ```

This will create a virtual environment and install all development dependencies.

## Development Workflow

### Running Tests

```bash
# Run all tests
uv run pytest

# Run tests in parallel
uv run pytest -n auto

# Run with coverage
uv run pytest --cov=pyvider.rpcplugin --cov-report=term-missing

# Run specific test markers
uv run pytest -m "not slow"          # Skip slow tests
uv run pytest -m "not long_running"  # Skip long running tests

# Run specific test file
uv run pytest tests/test_handshake.py

# Run tests matching a pattern
uv run pytest -k "test_client"
```

### Code Quality

Before submitting a pull request, ensure your code passes all quality checks:

```bash
# Format code
uv run ruff format src tests

# Lint code
uv run ruff check src tests

# Auto-fix linting issues
uv run ruff check src tests --fix

# Type check (primary)
pyre check

# Type check (alternative)
uv run mypy src/

# Security analysis
bandit -r src
```

### Code Style

- Follow PEP 8 guidelines (enforced by `ruff`)
- Use modern Python 3.11+ type hints (e.g., `list[str]` not `List[str]`)
- Use absolute imports, never relative imports
- Add comprehensive type hints to all functions and methods
- Write docstrings for public APIs
- Use `from __future__ import annotations` for unquoted types

## Project Structure

```
pyvider-rpcplugin/
├── src/pyvider/rpcplugin/    # Main package
│   ├── transport/            # Transport layer (TCP, Unix)
│   │   ├── base.py          # Abstract transport interface
│   │   ├── tcp.py           # TCP socket implementation
│   │   └── unix/            # Unix socket implementation
│   ├── protocol/            # Protocol layer (gRPC)
│   │   ├── base.py          # Protocol interface
│   │   └── service.py       # Protocol services
│   ├── server/              # Server implementation
│   │   ├── core.py          # RPCPluginServer
│   │   └── network.py       # Network utilities
│   ├── client/              # Client implementation
│   │   ├── core.py          # RPCPluginClient
│   │   ├── connection.py    # Connection management
│   │   ├── handshake.py     # Client handshake
│   │   └── process.py       # Subprocess management
│   ├── handshake/           # Handshake protocol
│   │   ├── core.py          # Handshake implementation
│   │   └── negotiation.py   # Protocol negotiation
│   ├── config/              # Configuration system
│   │   ├── configure.py     # Configuration API
│   │   ├── manager.py       # Config manager
│   │   └── runtime.py       # Runtime config
│   ├── factories.py         # Factory functions
│   ├── exception.py         # Exception hierarchy
│   └── defaults.py          # Default values
├── tests/                   # Test suite
├── docs/                    # Documentation
└── examples/                # Usage examples
```

## Testing Guidelines

### Writing Tests

- Place tests in the `tests/` directory mirroring the `src/` structure
- Name test files with `test_` prefix (e.g., `test_handshake.py`)
- Use descriptive test names that explain what is being tested
- Include both positive and negative test cases
- Add edge case tests
- Use `pytest` markers for slow/long-running tests

### Test Requirements

**CRITICAL**: Always use `provide-testkit` for Foundation integration:

```python
import pytest
from provide.testkit import reset_foundation_setup_for_testing

@pytest.fixture(autouse=True)
def reset_foundation():
    """Reset Foundation state before each test."""
    reset_foundation_setup_for_testing()
```

### Test Structure

```python
@pytest.mark.asyncio
async def test_feature_name_scenario():
    """Test description explaining what this test validates."""
    # Arrange
    config = RPCPluginConfig(...)
    server = RPCPluginServer(config)

    # Act
    result = await server.start()

    # Assert
    assert result is not None
```

## Documentation

### Docstring Format

Use Google-style docstrings:

```python
async def start_server(
    config: RPCPluginConfig,
    transport: RPCPluginTransport,
) -> RPCPluginServer:
    """Start an RPC plugin server.

    Args:
        config: Server configuration
        transport: Transport layer implementation

    Returns:
        Started server instance

    Raises:
        RPCPluginError: If server startup fails

    Example:
        >>> config = RPCPluginConfig(...)
        >>> transport = UnixTransport()
        >>> server = await start_server(config, transport)
    """
```

### Updating Documentation

When adding new features or changing APIs:

1. Update relevant docstrings
2. Update `README.md` if adding user-facing features
3. Update documentation in `docs/` directory
4. Update `CHANGELOG.md` under `[Unreleased]`

## Development Guidelines

### Architecture Principles

1. **Async-First Design**: Use async/await throughout
2. **Transport Abstraction**: All communication through `RPCPluginTransport`
3. **Type Safety**: Comprehensive type annotations required
4. **Security by Default**: mTLS and handshake validation
5. **Factory Pattern**: Use factory functions for common setups

### Logging

- Use `provide.foundation.logger` for all logging
- Never use `print()` for debugging
- Include structured context in log messages

Example:
```python
from provide.foundation import logger

logger.debug("Connection established", transport=transport_type, peer=peer_addr)
```

### Security Considerations

- Always validate handshake with magic cookie
- Use mTLS for production deployments
- Never hardcode secrets or credentials
- Run `bandit` security analysis before submitting

## Submitting Changes

### Pull Request Process

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name main
   ```

2. Make your changes and commit with clear messages:
   ```bash
   git commit -m "Add feature: description of what was added"
   ```

3. Ensure all tests pass and code quality checks pass:
   ```bash
   uv run pytest -n auto
   uv run ruff check src tests
   uv run mypy src/
   ```

4. Push your branch and create a pull request

5. Ensure your PR:
   - Has a clear title and description
   - References any related issues
   - Includes tests for new functionality
   - Updates documentation as needed
   - Passes all CI checks

### Commit Message Guidelines

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and pull requests when relevant

Examples:
- `Add Unix domain socket transport support`
- `Fix handshake timeout handling`
- `Update documentation for client configuration`

## Code Review Process

All submissions require review. The maintainers will:

- Review code for quality, style, and correctness
- Ensure tests are comprehensive
- Verify documentation is updated
- Check for security issues
- Verify async patterns are correct

## Getting Help

- Open an issue for bugs or feature requests
- Check existing issues and documentation first
- See [CLAUDE.md](CLAUDE.md) for detailed development instructions

## License

By contributing to pyvider-rpcplugin, you agree that your contributions will be licensed under the Apache-2.0 License.
