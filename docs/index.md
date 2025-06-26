# Pyvider RPC Plugin Documentation

Welcome to the official documentation for `pyvider.rpcplugin`, a high-performance, type-safe RPC plugin framework for Python. This page serves as your central guide to understanding, using, and extending the framework.

## 🚀 Getting Started

New to `pyvider.rpcplugin`? Here's a suggested path:

1.  **Understand the Basics**: Start with the main [**README.md**](../README.md) for a high-level overview, features, and a quick start example.
2.  **Explore Core Examples**: Work through the initial examples in the [**Examples Guide**](../examples/README.md) (especially 01-04) to see practical usage.
3.  **Key Concepts**:
    *   Learn about the overall [**Architecture**](architecture.md) of the framework.
    *   Understand the [**Configuration System**](configuration.md) (environment variables, programmatic setup).

## 📖 User Guides

Dive deeper into specific aspects of the framework:

*   **[Examples Guide](../examples/README.md)**: A comprehensive walkthrough of all provided examples, from basic setup to advanced patterns.
    *   *Covers: Step-by-step examples, runnable code, learning paths.*
*   **[Configuration Guide](configuration.md)**: Detailed information on all configuration options, environment variables, and setup methods.
    *   *Covers: Magic cookies, mTLS settings, timeouts, transport options.*
*   **[Security Guide](security.md)**: Best practices for securing your RPC plugin communication, including mTLS setup, certificate management, and operational security.
    *   *Covers: mTLS, certificate generation, transport security, authentication.*
*   **[Troubleshooting Guide](troubleshooting.md)**: Diagnose and resolve common issues encountered when working with the framework.
    *   *Covers: Connection problems, certificate errors, performance diagnosis, debugging tools.*

## 🛠️ API & Developer Reference

For developers building with or extending the framework:

*   **[API Reference](api-reference.md)**: Complete reference for all public classes, methods, factory functions, and type definitions.
    *   *Covers: `plugin_server`, `plugin_client`, `RPCPluginServer`, `RPCPluginClient`, `Certificate`, exceptions, etc.*
*   **[Architecture Deep Dive](architecture.md)**: A detailed look at the internal components, design patterns, and data flows.
    *   *Covers: Transport layer, protocol layer, security architecture, handshake sequence.*
*   **[Examples Source Code](../examples/)**: Browse the source code of all examples directly.

## 📦 Project Information

*   **[Main Project README](../README.md)**: Overview, installation, quick start, and contribution guidelines.
*   **[Changelog](changelog.md)**: A record of all notable changes made to the project.
    *   *(Also see the root [CHANGELOG.md](../CHANGELOG.md) for the most concise version history).*

## ❓Need Help?

*   If you encounter issues, please check the [**Troubleshooting Guide**](troubleshooting.md) first.
*   For bugs or feature requests, please open an issue on the [project's GitHub repository](https://github.com/provide-io/pyvider-rpcplugin) (assuming this is the correct link).

---

We hope this documentation helps you build amazing things with `pyvider.rpcplugin`!
