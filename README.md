# 🐍🔌 `pyvider.rpcplugin`

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![uv](https://img.shields.io/badge/uv-package_manager-FF6B35.svg)](https://github.com/astral-sh/uv)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![CI](https://github.com/provide-io/pyvider-rpcplugin/actions/workflows/ci.yml/badge.svg)](https://github.com/provide-io/pyvider-rpcplugin/actions)

**High-performance, type-safe RPC plugin framework for Python.**

Modern gRPC-based plugin architecture with async support, mTLS security, and comprehensive transport options.

---

**Build lightning-fast, secure RPC plugins!** `pyvider.rpcplugin` provides a complete framework for creating high-performance RPC-based plugins with built-in security, async support, and production-ready patterns. Perfect for microservices, plugin architectures, and inter-process communication.

</div>

## Key Features
- gRPC-based plugin framework with strong typing.
- Async-first APIs with secure mTLS support.
- Designed to integrate with provide.foundation utilities.

## Quick Start
1. Install: `pip install pyvider-rpcplugin`
2. Follow the [Quick Start guide](https://github.com/provide-io/pyvider-rpcplugin/blob/main/docs/getting-started/quick-start.md).
3. Build your first plugin via [docs/getting-started/first-plugin.md](https://github.com/provide-io/pyvider-rpcplugin/blob/main/docs/getting-started/first-plugin.md).

## Documentation
- [Documentation index](https://github.com/provide-io/pyvider-rpcplugin/blob/main/docs/index.md)
- [Getting started](https://github.com/provide-io/pyvider-rpcplugin/blob/main/docs/getting-started/index.md)
- [Guide](https://github.com/provide-io/pyvider-rpcplugin/blob/main/docs/guide/index.md)

## Development
- See [CLAUDE.md](https://github.com/provide-io/pyvider-rpcplugin/blob/main/CLAUDE.md) for local development notes.
- Run `uv sync --extra dev` to set up the dev environment.

## 🤝 Contributing

We welcome contributions! Please see [Contributing to Pyvider RPCPlugin](https://github.com/provide-io/pyvider-rpcplugin/blob/main/docs/development/contributing-guide.md) for details.

## 📜 License

This project is licensed under the **Apache 2.0 License**. See the [LICENSE](https://github.com/provide-io/pyvider-rpcplugin/blob/main/LICENSE) file for details.

## 📖 Full Documentation

For a comprehensive guide to installing, using, and understanding `pyvider.rpcplugin`, including tutorials, advanced topics, and API references, please see the:

➡️ **[Documentation Home](https://github.com/provide-io/pyvider-rpcplugin/blob/main/docs/index.md)**

Complete documentation with tutorials, examples, API reference, and deployment guides.

## Overview

`pyvider.rpcplugin` is a Python framework designed to simplify the creation of robust, secure, and high-performance RPC-based plugin systems. It leverages gRPC for efficient communication and integrates with Foundation for:

-   **Async Operations**: Native `asyncio` integration.
-   **Secure Communication**: mTLS with Foundation's certificate management utilities.
-   **Flexible Transports**: Unix Domain Sockets (for local IPC) and TCP sockets (for network IPC).
-   **Standardized Handshake**: Secure plugin authentication using magic cookies and protocol/transport negotiation.
-   **Developer-Friendly Features**: Type safety, factory functions for common patterns, and Foundation's structured logging.

## Quick Installation

```bash
# With uv (recommended)
uv add pyvider-rpcplugin

# With pip
pip install pyvider-rpcplugin
```

Dive into the **[Documentation](https://github.com/provide-io/pyvider-rpcplugin/blob/main/docs/index.md)** to get started!

Copyright (c) Provide.io LLC.
