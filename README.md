<div align="center">

# 🐍🔌 `pyvider.rpcplugin`

**High-performance, type-safe RPC plugin framework for Python.**

Modern gRPC-based plugin architecture with async support, mTLS security, and comprehensive transport options.

[![Awesome: uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![PyPI Version](https://img.shields.io/pypi/v/pyvider-rpcplugin?style=flat-square)](https://pypi.org/project/pyvider-rpcplugin/)
[![Python Versions](https://img.shields.io/pypi/pyversions/pyvider-rpcplugin?style=flat-square)](https://pypi.org/project/pyvider-rpcplugin/)
[![Downloads](https://static.pepy.tech/badge/pyvider-rpcplugin/month)](https://pepy.tech/project/pyvider-rpcplugin)

[![CI](https://github.com/provide-io/pyvider-rpcplugin/actions/workflows/ci.yml/badge.svg)](https://github.com/provide-io/pyvider-rpcplugin/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/provide-io/pyvider-rpcplugin/branch/main/graph/badge.svg)](https://codecov.io/gh/provide-io/pyvider-rpcplugin)
[![Type Checked](https://img.shields.io/badge/type--checked-mypy-blue?style=flat-square)](https://mypy.readthedocs.io/)
[![Code style: ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json&style=flat-square)](https://github.com/astral-sh/ruff)

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache-blue.svg?style=flat-square)](https://opensource.org/license/apache-2-0)

---

**Build lightning-fast, secure RPC plugins!** `pyvider.rpcplugin` provides a complete framework for creating high-performance RPC-based plugins with built-in security, async support, and production-ready patterns. Perfect for microservices, plugin architectures, and inter-process communication.

</div>

## 📖 Full Documentation

For a comprehensive guide to installing, using, and understanding `pyvider.rpcplugin`, including tutorials, advanced topics, and API references, please see the:

➡️ **[User and Developer Guide](./docs/USER_GUIDE.md)**

This guide provides a book-style walkthrough of the framework.

## Overview

`pyvider.rpcplugin` is a Python framework designed to simplify the creation of robust, secure, and high-performance RPC-based plugin systems. It leverages gRPC for efficient communication and provides built-in support for:

-   **Async Operations**: Native `asyncio` integration.
-   **Secure Communication**: mTLS with certificate management utilities.
-   **Flexible Transports**: Unix Domain Sockets (for local IPC) and TCP sockets (for network IPC).
-   **Standardized Handshake**: Secure plugin authentication using magic cookies and protocol/transport negotiation.
-   **Developer-Friendly Features**: Type safety, factory functions for common patterns, and comprehensive logging.

## Quick Installation

```bash
# With uv (recommended)
uv add pyvider-rpcplugin

# With pip
pip install pyvider-rpcplugin
```

Dive into the **[User and Developer Guide](./docs/USER_GUIDE.md)** to get started!

## 🤝 Contributing

We welcome contributions! Please see [Chapter 19: Contributing to Pyvider RPCPlugin](./docs/guide/ch19_contributing.md) in the main guide for details.

## 📜 License

This project is licensed under the **Apache 2.0 License**. See the [LICENSE](LICENSE) file for details.
