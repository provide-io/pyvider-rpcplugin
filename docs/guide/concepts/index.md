# Core Concepts

Understanding the fundamental concepts behind Pyvider RPC Plugin will help you build more effective and secure plugin systems.

## Overview

Pyvider RPC Plugin enables **process-based plugin architectures** where plugins run as separate processes and communicate via RPC (Remote Procedure Call). This approach provides isolation, security, and language flexibility while maintaining high performance.

### Plugin vs Host Application

<div class="rpc-important">
The plugin architecture separates concerns between the **Host Application** (your main program) and **Plugin Processes** (separate executables that provide specific functionality).
</div>

- **🏠 Host Application (Client)**: The main application that launches, manages, and communicates with plugins. Uses `RPCPluginClient` to initiate connections.
- **🔌 Plugin Process (Server)**: An external executable that provides specific services. Uses `RPCPluginServer` to serve RPC requests.
- **📡 RPC Communication**: gRPC-based communication allows the host to call plugin functions as if they were local.

### Core Classes

| Class | Role | Description |
|-------|------|-------------|
| `RPCPluginClient` | Host Application | Manages plugin lifecycle and RPC communication |
| `RPCPluginServer` | Plugin Process | Serves RPC requests from the host |
| `RPCPluginProtocol` | Both | Defines the RPC interface and service methods |
| `Handler/Servicer` | Plugin Process | Implements the actual business logic |

## Essential Concepts

### 🤝 RPC Architecture & Handshake

The plugin system implements a robust RPC architecture built on gRPC with a secure handshake protocol:

1. **gRPC Foundation** - Protocol Buffers for efficient serialization, HTTP/2 for multiplexed communication
2. **Handshake Process** - Multi-phase negotiation including magic cookie authentication, protocol negotiation, and service discovery
3. **Foundation Integration** - Seamless integration with provide.foundation for logging, configuration, and cryptography

**Learn more:** [RPC Architecture & Handshake](architecture-and-handshake.md)

### 🌐 Transport Layer

Communication happens over different transport mechanisms:

<div class="transport-badge unix">Unix Sockets</div>

- **Best for**: Local IPC, high performance, security
- **Platforms**: Linux, macOS
- **Performance**: ~45,000 msg/sec, ~0.02ms latency

<div class="transport-badge tcp">TCP Sockets</div>

- **Best for**: Network communication, Windows compatibility
- **Platforms**: Linux, macOS, Windows
- **Performance**: ~35,000 msg/sec (localhost)

**Learn more:** [Transports](transports.md)

### 📋 Protocol Definition

`RPCPluginProtocol` defines the interface between host and plugin using Protocol Buffers:

```python
class MyProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self):
        """Return Protocol Buffer descriptors and service name"""
        return my_pb2.DESCRIPTOR, "MyService"

    async def add_to_server(self, server, handler):
        """Add your service implementation to the gRPC server"""
        my_pb2_grpc.add_MyServiceServicer_to_server(handler, server)
```

**Learn more:** [Protocols](protocols.md)

### 🔒 Security Model

Multi-layered security approach:

- **Process Isolation** - Memory isolation, resource limits, crash resilience
- **Magic Cookie Authentication** - Shared secret passed via environment variable
- **Mutual TLS (mTLS)** - Certificate-based authentication and encrypted communication

**Learn more:** [Security Model](security.md)

## Configuration Architecture

Pyvider RPC Plugin uses [provide.foundation](https://foundation.provide.io) for configuration:

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Access configuration
timeout = rpcplugin_config.plugin_handshake_timeout
transports = rpcplugin_config.plugin_server_transports
mtls_enabled = rpcplugin_config.plugin_auto_mtls
```

Configuration sources (in priority order):

1. **Environment variables** (highest priority)
1. **Configuration files** (YAML, JSON, TOML)
1. **Programmatic settings**
1. **Default values** (lowest priority)

## Error Handling

Structured exception hierarchy provides predictable error handling:

```python
from pyvider.rpcplugin.exception import (
    RPCPluginError,     # Base exception
    TransportError,     # Network/transport issues
    HandshakeError,     # Handshake failures
    SecurityError,      # Authentication/authorization
    ConfigError,        # Configuration problems
)
```

## Async/Await Integration

All APIs are async-first for maximum performance:

```python
# Server
async def main():
    server = plugin_server(protocol=MyProtocol(), handler=MyHandler())
    await server.serve()

# Client
async def main():
    async with plugin_client() as client:
        result = await client.call_method("my_method", param="value")
```

## What's Next?

Dive deeper into specific concepts:

<div class="grid cards" markdown>

-   :material-sitemap: **RPC Architecture & Handshake**

    ---

    Complete RPC architecture with secure handshake protocol

    [:octicons-arrow-right-24: Learn Architecture](architecture-and-handshake.md)

-   :material-swap-horizontal: **Transports**

    ---

    Understanding Unix sockets vs TCP and when to use each

    [:octicons-arrow-right-24: Explore Transports](transports.md)

-   :material-api: **Protocols**

    ---

    How to define and implement RPC protocols with gRPC

    [:octicons-arrow-right-24: Define Protocols](protocols.md)

-   :material-shield-check: **Security Model**

    ---

    Comprehensive security including mTLS, magic cookies, and isolation

    [:octicons-arrow-right-24: Secure Plugins](security.md)

</div>

Or jump to practical implementation:

- **[Server Development](../server/index.md)** - Build your first plugin server
- **[Client Development](../client/index.md)** - Connect to and manage plugins
