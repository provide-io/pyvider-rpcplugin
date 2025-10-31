# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- 🔄 Migrated from local `_version.py` to use `get_version()` from provide-foundation for consistent version handling across provide-io projects
- 📝 Added comprehensive module docstrings to core source files (`pyvider/__init__.py`, `pyvider.rpcplugin.types`)
- 📚 Added educational docstrings to example files for improved user guidance
- 🔧 Updated pre-commit hook versions (ruff: v0.8.0, mypy: v1.13.0, bandit: 1.8.0)

### Fixed
- 🐛 Fixed CI workflow coverage reporting path (`--cov=pyvider.rpcplugin` instead of `--cov=src/pyvider_rpcplugin`)
- 📋 Added `coverage.json` to .gitignore to prevent test artifacts from being committed
- 🧹 Removed duplicate file splitting artifacts (chunk files and python_files.txt)

### Improved
- ✨ Enhanced code quality with proper module documentation throughout the codebase
- 🎯 Cleaner module-level lazy loading for version information

## [0.0.1000] - 2025-10-16

### Added
- 🎉 **Initial release of pyvider-rpcplugin**
- 🚀 **High-performance async RPC plugin framework** with Python 3.11+ support (3.13+ recommended)
- 🔌 **Dual transport support** - Unix domain sockets and TCP sockets with automatic negotiation
- 🔒 **Built-in mTLS security** with comprehensive certificate management and validation
- ⚙️ **Factory functions** for simplified plugin creation (`plugin_server`, `plugin_client`, `plugin_protocol`)
- 📊 **Production-ready logging** integration with `pyvider.telemetry` for observability
- 🛠️ **Comprehensive configuration system** supporting environment variables, files (.env, .json, .yaml), and programmatic setup
- 🎯 **Complete type annotations** with modern Python 3.11+ typing features and `attrs` integration
- 🧪 **Robust error handling** with custom exception hierarchy and detailed context
- 📖 **Extensive documentation** with comprehensive examples from quick-start to production patterns
- 🤖 **GitHub Actions integration** for automated testing and documentation validation
- 🔧 **Development tooling** with comprehensive test suite, type checking, and code quality enforcement

### Core Components
- **RPCPluginServer** - Full-featured async gRPC server with transport abstraction
- **RPCPluginClient** - Robust client with connection management and retry logic
- **Transport Layer** - Unix socket and TCP socket implementations with security
- **Protocol Layer** - gRPC protocol integration with service registration
- **Configuration System** - Flexible config management with validation and schemas
- **Certificate Management** - mTLS certificate generation, validation, and rotation utilities
- **Factory Functions** - Simple APIs for common plugin creation patterns

### Security Features
- **Magic cookie validation** for handshake authentication
- **Mutual TLS (mTLS)** support with automatic certificate validation
- **Transport layer encryption** for secure network communication
- **Certificate utilities** for easy cert generation and management
- **Secure configuration** with file-based and environment-based secret handling

### Performance Features
- **Async-first design** with complete `asyncio` integration
- **High-throughput transports** optimized for 10,000+ requests/second
- **Efficient serialization** using Protocol Buffers with zero-copy optimizations
- **Connection pooling** and reuse for improved client performance
- **Graceful shutdown** with proper resource cleanup and connection termination

### Developer Experience
- **Modern Python 3.11+ (3.13+ recommended)** with complete type annotations and IDE support
- **Rich error messages** with context and recovery suggestions
- **Comprehensive examples** covering basic usage to production deployment
- **Integrated logging** with structured output and performance metrics
- **Development tools** including testing utilities and debugging helpers

### Documentation
- **Complete README** with quick start, examples, and API overview
- **Comprehensive examples** from basic setup to production optimization
- **API reference** documentation for all public interfaces
- **Security guide** for mTLS setup and certificate management
- **Architecture documentation** with design patterns and best practices
- **Troubleshooting guide** for common issues and debugging

### Testing & Quality
- **Comprehensive test suite** with 88% code coverage
- **Integration tests** for all transport and protocol combinations
- **Security testing** for certificate validation and mTLS scenarios
- **Performance benchmarks** and regression testing
- **Type checking** with mypy and runtime validation
- **Code quality** enforcement with ruff formatting and linting

## [Unreleased]

### Planned
- 📈 **Performance optimizations** - Connection pooling improvements and caching
- 🔄 **Plugin hot-reloading** - Dynamic plugin updates without service restart
- 📱 **Additional transports** - WebSocket and HTTP/2 transport options
- 🌐 **Service discovery** - Automatic service registration and discovery
- 📊 **Enhanced metrics** - Prometheus integration and health check endpoints
- 🧩 **Plugin templates** - Code generation for common plugin patterns
- 📚 **Tutorial series** - Step-by-step guides for complex scenarios
