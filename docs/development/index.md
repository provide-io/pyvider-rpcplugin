# Development

Welcome to the development section for Pyvider RPC Plugin. This section provides comprehensive resources for contributors, maintainers, and developers who want to understand the internal architecture, contribute code, or extend the framework.

## Overview

The development documentation covers:

- **Contributing Guide** - Complete guide for code, testing, CI/CD, and PR workflows
- **Architecture Documentation** - Internal system design and component interaction
- **Testing Framework** - Comprehensive testing patterns and tools
- **Troubleshooting** - Common issues and debugging techniques

## Development Sections

### 🤝 [Contributing Guide](contributing-guide.md)

**Complete development workflow documentation covering:**

- Getting started and environment setup
- Development workflow and branch strategy
- Code standards and best practices
- Testing guidelines and patterns
- CI/CD pipeline configuration
- Pull request process
- Issue reporting and community guidelines

**Perfect for:** New contributors, understanding the full development lifecycle

### 🏗️ [Architecture](architecture.md)

**Internal system architecture and design:**

- Component architecture overview
- Plugin protocol design
- Transport layer implementation
- Security architecture
- Type system and Foundation integration

**Perfect for:** Understanding internal design, extending the framework

### 🧪 [Testing](testing.md)

**Comprehensive testing documentation:**

- Testing framework and patterns
- Unit and integration testing
- Mock implementations and fixtures
- Performance and security testing
- Test configuration and best practices

**Perfect for:** Writing tests, understanding test patterns

### 🔧 [Troubleshooting](troubleshooting.md)

**Common issues and debugging:**

- Connection and handshake problems
- Configuration issues
- Performance bottlenecks
- Security troubleshooting
- Diagnostic tools

**Perfect for:** Debugging issues, performance optimization

## Quick Start

### Initial Setup

```bash
# Clone the repository
git clone https://github.com/provide-io/pyvider-rpcplugin.git
cd pyvider-rpcplugin

# Set up development environment
uv sync

# Run tests to verify setup
uv run pytest tests/
```

### Essential Commands

```bash
# Testing
uv run pytest                    # Run all tests
uv run pytest --cov             # With coverage

# Code quality
uv run ruff check src tests     # Linting
uv run ruff format src tests    # Formatting
uv run pyre check               # Type checking

# Documentation
mkdocs serve                    # Serve docs locally
mkdocs build --strict           # Build with strict checking
```

See the [Contributing Guide](contributing-guide.md) for complete development workflow documentation.

## Development Principles

The project follows these core principles:

1. **Type Safety** - Comprehensive type annotations throughout
1. **Modern Python** - Python 3.11+ features, no legacy patterns
1. **Async First** - Built on asyncio for high performance
1. **Security by Default** - mTLS and authentication built-in
1. **Comprehensive Testing** - All features require tests
1. **Clear Documentation** - All public APIs documented

## Getting Help

### Communication Channels

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - Questions and community discussions
- **Pull Requests** - Code contributions and reviews

### Development Questions

For development-specific questions:

1. **Check Documentation** - Review architecture and contributing docs
1. **Search Issues** - Look for similar issues or discussions
1. **Ask in Discussions** - Post in GitHub Discussions
1. **Create Issue** - For bugs or feature requests

## Next Steps

1. **[Read Contributing Guide](contributing-guide.md)** - Understand contribution process
1. **[Study Architecture](architecture.md)** - Learn internal system design
1. **[Review Testing](testing.md)** - Understand testing framework
1. **[Check Troubleshooting](troubleshooting.md)** - Common development issues

Ready to contribute? Start with the [Contributing Guide](contributing-guide.md) and explore the codebase!
