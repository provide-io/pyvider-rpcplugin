# Development

Welcome to the development section for Pyvider RPC Plugin. This section provides comprehensive resources for contributors, maintainers, and developers who want to understand the internal architecture, contribute code, or extend the framework.

## Overview

The development documentation covers:

- **Contributing Guidelines** - How to contribute code, documentation, and bug reports
- **Architecture Documentation** - Internal system design and component interaction  
- **Testing Framework** - Comprehensive testing patterns and tools
- **CI/CD Processes** - Build, test, and deployment pipelines
- **Troubleshooting** - Common issues and debugging techniques

## Development Sections

### 🤝 [Contributing](contributing.md)
Guidelines for contributing to the project:
- Code contribution workflow
- Documentation standards
- Issue reporting and feature requests
- Code review process

### 🏗️ [Architecture](architecture.md)
Internal system architecture and design:
- Component architecture overview
- Plugin protocol design
- Transport layer implementation
- Security architecture

### 🧪 [Testing](testing.md)
Comprehensive testing documentation:
- Testing framework and patterns
- Unit and integration testing
- Mock implementations and fixtures
- Performance and security testing

### ⚙️ [CI/CD](ci-cd.md)
Continuous integration and deployment:
- Build and test pipelines
- Automated testing and validation
- Release process and versioning
- Deployment strategies

### 🔧 [Troubleshooting](troubleshooting.md)
Common issues and debugging:
- Connection and handshake problems
- Configuration issues
- Performance bottlenecks
- Security troubleshooting

## Development Quick Start

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/provide-io/pyvider-rpcplugin.git
cd pyvider-rpcplugin

# Set up development environment using workenv
uv sync

# Install development dependencies
uv pip install -e ".[dev]"

# Run tests to verify setup
pytest tests/

# Run linting and type checking
ruff check src tests
pyre check

# Run all development checks
hatch run test:coverage
hatch run test:lint
hatch run test:typecheck
```

### Development Workflow

```bash
# Create feature branch
git checkout -b feature/my-new-feature

# Make your changes
# ... edit code, add tests, update docs ...

# Run comprehensive testing
pytest tests/ -v --cov=pyvider.rpcplugin

# Check code quality
ruff check src tests
ruff format src tests
pyre check

# Commit changes
git add .
git commit -m "Add feature: my new feature"

# Push and create pull request
git push origin feature/my-new-feature
# Create PR on GitHub
```

### Running Examples

```bash
# Run all examples to test functionality
python examples/run_all_examples.py

# Run specific example categories
python examples/run_all_examples.py --category=basic
python examples/run_all_examples.py --category=security

# Test example manually
python examples/ch05_echo_server.py &  # Background
python examples/ch07_echo_client.py   # Foreground
```

## Development Tools

### Code Quality Tools

| Tool | Purpose | Command |
|------|---------|---------|
| **Ruff** | Linting and formatting | `ruff check src tests` |
| **Pyre** | Type checking | `pyre check` |
| **Bandit** | Security analysis | `bandit -r src` |
| **pytest** | Testing framework | `pytest tests/` |
| **pytest-cov** | Coverage analysis | `pytest --cov=pyvider.rpcplugin` |

### Development Scripts

```bash
# Available development scripts (via hatch)
hatch run test:test          # Run tests
hatch run test:coverage      # Run tests with coverage
hatch run test:lint          # Run linting
hatch run test:format        # Format code
hatch run test:typecheck     # Type checking
hatch run test:security      # Security analysis

# Run all quality checks
hatch run test:lint && hatch run test:typecheck && hatch run test:security
```

## Project Structure

```
pyvider-rpcplugin/
├── src/pyvider/rpcplugin/     # Main source code
│   ├── client/                # Client implementation
│   ├── transport/             # Transport layer
│   ├── protocol/              # Protocol definitions
│   ├── server.py              # Server implementation
│   ├── config.py              # Configuration system
│   └── exception.py           # Exception hierarchy
├── tests/                     # Test suite
│   ├── fixtures/              # Test fixtures and mocks
│   ├── transport/             # Transport tests
│   ├── client/                # Client tests
│   └── server/                # Server tests
├── examples/                  # Working examples
│   ├── proto/                 # Protocol definitions
│   └── chXX_*.py             # Example implementations
├── docs/                      # Documentation
│   ├── api/                   # API reference
│   ├── guide/                 # User guides
│   ├── getting-started/       # Getting started guides
│   └── development/           # Development docs (this section)
└── workenv/                   # Development environment
```

## Contribution Areas

### Code Contributions

- **Core Framework** - Server, client, transport, protocol implementations
- **Security Features** - mTLS, authentication, process isolation enhancements
- **Performance Optimizations** - Concurrent operations, connection pooling
- **Platform Support** - Windows, macOS, Linux compatibility improvements
- **Integration** - Framework integrations (FastAPI, Django, etc.)

### Documentation Contributions

- **User Guides** - Usage patterns, best practices, tutorials
- **API Documentation** - Function and class documentation improvements
- **Examples** - Working examples for common use cases
- **Troubleshooting** - Common issues and solutions

### Testing Contributions

- **Unit Tests** - Component-level test coverage
- **Integration Tests** - End-to-end workflow testing
- **Performance Tests** - Benchmarking and performance regression testing
- **Security Tests** - Security vulnerability testing

## Development Principles

### Code Quality Standards

1. **Type Safety** - All code must have comprehensive type annotations
2. **Modern Python** - Use Python 3.11+ features (union types, modern collections)
3. **No Legacy Code** - No `__future__` imports, use modern syntax throughout
4. **Comprehensive Testing** - All features must have corresponding tests
5. **Documentation** - All public APIs must be documented

### Security First

1. **Secure by Default** - Default configurations should be secure
2. **Defense in Depth** - Multiple security layers (mTLS, auth, isolation)
3. **No Hardcoded Secrets** - All secrets must be configurable
4. **Regular Security Reviews** - Code changes undergo security review

### Performance Focus

1. **Async First** - All I/O operations must be async
2. **Resource Efficient** - Minimal memory and CPU footprint
3. **Connection Pooling** - Efficient connection reuse
4. **Benchmarking** - Performance impact measurement

## Release Process

### Version Management

The project follows semantic versioning (SemVer):

- **Major** (X.0.0) - Breaking changes
- **Minor** (1.X.0) - New features, backward compatible  
- **Patch** (1.0.X) - Bug fixes, backward compatible

### Release Checklist

```bash
# Pre-release checks
pytest tests/ --cov=pyvider.rpcplugin --cov-report=term-missing
ruff check src tests
pyre check
bandit -r src

# Update version and changelog
# ... edit VERSION file and CHANGELOG.md ...

# Create release commit
git add VERSION CHANGELOG.md
git commit -m "Release version X.Y.Z"
git tag -a vX.Y.Z -m "Release version X.Y.Z"

# Push release
git push origin main --tags
```

## Getting Help

### Communication Channels

- **GitHub Issues** - Bug reports and feature requests
- **GitHub Discussions** - Questions and community discussions
- **Pull Requests** - Code contributions and reviews

### Development Questions

For development-specific questions:

1. **Check Documentation** - Review architecture and contributing docs
2. **Search Issues** - Look for similar issues or discussions
3. **Ask in Discussions** - Post in GitHub Discussions
4. **Create Issue** - For bugs or feature requests

## Next Steps

1. **[Read Contributing Guidelines](contributing.md)** - Understand contribution process
2. **[Study Architecture](architecture.md)** - Learn internal system design
3. **[Review Testing](testing.md)** - Understand testing framework
4. **[Check Troubleshooting](troubleshooting.md)** - Common development issues

Ready to contribute? Start with the [Contributing Guide](contributing.md) and explore the codebase!