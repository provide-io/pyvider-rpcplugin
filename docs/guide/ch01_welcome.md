# Chapter 1: Welcome to Pyvider RPCPlugin

**High-performance, type-safe RPC plugin framework for Python.**

`pyvider.rpcplugin` provides a complete framework for creating high-performance RPC-based plugins with built-in security, async support, and production-ready patterns. It is perfect for microservices, plugin architectures, and inter-process communication.

This guide will walk you through from initial setup and basic usage to advanced topics and best practices, catering to both new users looking to integrate or use plugins, and developers aiming to build robust plugins or understand the framework's internals.

#### Why `pyvider.rpcplugin`?

##### ⚡ **Performance-First**
-   **Async-native**: Full `asyncio` integration for maximum concurrency.
-   **Efficient transports**: Unix domain sockets for local Inter-Process Communication (IPC) and TCP for network communication.
-   **Optimized serialization**: Utilizes Protocol Buffers.
-   **High throughput**: Designed to handle a high volume of requests with low latency.

##### 🔒 **Security-Focused**
-   **Built-in mTLS**: Mutual TLS authentication with utilities for certificate management.
-   **Process Isolation**: Plugins run as separate processes, enhancing host application stability.
-   **Transport encryption**: Secure communication over any network when mTLS is enabled.
-   **Magic cookie validation**: Handshake verification for establishing trusted connections.

##### 🛠️ **Developer Experience**
-   **Modern Python**: Leverages Python 3.13+ features with complete type annotations and `attrs` for data classes.
-   **Factory functions**: Simplified APIs for common plugin client and server setup.
-   **Comprehensive logging**: Integrated with `pyvider.telemetry` for observability.
-   **Rich error handling**: Detailed exceptions with contextual information and guidance.

##### 🏗️ **Production Ready**
-   **Robust configuration**: Supports environment variables, file-based (via file URI in env vars), and programmatic setup.
-   **Graceful shutdown**: Ensures clean resource cleanup and connection termination.
-   **Health monitoring**: Includes built-in health checking capabilities.
