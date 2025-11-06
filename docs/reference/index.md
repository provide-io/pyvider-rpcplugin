# API Reference

This section contains the complete API reference for the `pyvider.rpcplugin` package, automatically generated from the source code docstrings.

## Package Organization

The `pyvider.rpcplugin` package is organized into the following main modules:

### Core Components

- **[pyvider.rpcplugin](pyvider/rpcplugin/index.md)** - Main package exports and initialization
- **[pyvider.rpcplugin.types](pyvider/rpcplugin/types.md)** - Type definitions and runtime-checkable protocols
- **[pyvider.rpcplugin.exception](pyvider/rpcplugin/exception.md)** - Exception hierarchy
- **[pyvider.rpcplugin.factories](pyvider/rpcplugin/factories.md)** - Factory functions for common patterns

### Client Components

- **[pyvider.rpcplugin.client](pyvider/rpcplugin/client/index.md)** - Client module
  - **[core](pyvider/rpcplugin/client/core.md)** - RPCPluginClient implementation
  - **[handshake](pyvider/rpcplugin/client/handshake.md)** - Client handshake mixin
  - **[process](pyvider/rpcplugin/client/process.md)** - Process management mixin
  - **[connection](pyvider/rpcplugin/client/connection.md)** - Connection wrapper

### Server Components

- **[pyvider.rpcplugin.server](pyvider/rpcplugin/server/index.md)** - Server module
  - **[core](pyvider/rpcplugin/server/core.md)** - RPCPluginServer and RateLimitingInterceptor
  - **[network](pyvider/rpcplugin/server/network.md)** - Server network mixin

### Transport Layer

- **[pyvider.rpcplugin.transport](pyvider/rpcplugin/transport/index.md)** - Transport implementations
  - **[base](pyvider/rpcplugin/transport/base.md)** - Abstract transport interface
  - **[tcp](pyvider/rpcplugin/transport/tcp.md)** - TCP socket transport
  - **[unix.transport](pyvider/rpcplugin/transport/unix/transport.md)** - Unix socket transport

### Protocol Layer

- **[pyvider.rpcplugin.protocol](pyvider/rpcplugin/protocol/index.md)** - Protocol implementations
  - **[base](pyvider/rpcplugin/protocol/base.md)** - Abstract protocol interface
  - **[service](pyvider/rpcplugin/protocol/service.md)** - gRPC service implementations

### Configuration

- **[pyvider.rpcplugin.config](pyvider/rpcplugin/config/index.md)** - Configuration management
  - **[runtime](pyvider/rpcplugin/config/runtime.md)** - RPCPluginConfig class
  - **[manager](pyvider/rpcplugin/config/manager.md)** - Multi-instance configuration
  - **[validators](pyvider/rpcplugin/config/validators.md)** - Configuration validators

### Handshake Protocol

- **[pyvider.rpcplugin.handshake](pyvider/rpcplugin/handshake/index.md)** - Handshake implementation
  - **[core](pyvider/rpcplugin/handshake/core.md)** - HandshakeConfig and validation
  - **[negotiation](pyvider/rpcplugin/handshake/negotiation.md)** - Protocol and transport negotiation

### Additional Components

- **[pyvider.rpcplugin.health_servicer](pyvider/rpcplugin/health_servicer.md)** - Health check service
- **[pyvider.rpcplugin.telemetry](pyvider/rpcplugin/telemetry.md)** - OpenTelemetry integration
- **[pyvider.rpcplugin.defaults](pyvider/rpcplugin/defaults.md)** - Default configuration values

## Using the API Reference

Each module page contains:

- **Module docstring** - Overview of the module's purpose
- **Classes** - Detailed documentation of all classes with:
  - Class docstring
  - Constructor parameters
  - Methods and their signatures
  - Return types and exceptions
- **Functions** - Standalone functions with complete documentation
- **Type definitions** - Type aliases and protocols
- **Constants** - Module-level constants and defaults

The documentation is generated directly from the source code, ensuring it stays up-to-date with the implementation.

## Quick Links

### Most Common Classes

- [RPCPluginClient](pyvider/rpcplugin/client/core.md#pyvider.rpcplugin.client.core.RPCPluginClient) - Main client class
- [RPCPluginServer](pyvider/rpcplugin/server/core.md#pyvider.rpcplugin.server.core.RPCPluginServer) - Main server class
- [RPCPluginConfig](pyvider/rpcplugin/config/runtime.md#pyvider.rpcplugin.config.runtime.RPCPluginConfig) - Configuration class
- [RPCPluginProtocol](pyvider/rpcplugin/protocol/base.md#pyvider.rpcplugin.protocol.base.RPCPluginProtocol) - Protocol base class

### Factory Functions

- [plugin_client()](pyvider/rpcplugin/factories.md#pyvider.rpcplugin.factories.plugin_client) - Create configured clients
- [plugin_server()](pyvider/rpcplugin/factories.md#pyvider.rpcplugin.factories.plugin_server) - Create configured servers
- [plugin_protocol()](pyvider/rpcplugin/factories.md#pyvider.rpcplugin.factories.plugin_protocol) - Create protocol instances

### Exceptions

- [RPCPluginError](pyvider/rpcplugin/exception.md#pyvider.rpcplugin.exception.RPCPluginError) - Base exception
- [HandshakeError](pyvider/rpcplugin/exception.md#pyvider.rpcplugin.exception.HandshakeError) - Handshake failures
- [TransportError](pyvider/rpcplugin/exception.md#pyvider.rpcplugin.exception.TransportError) - Transport issues
- [ProtocolError](pyvider/rpcplugin/exception.md#pyvider.rpcplugin.exception.ProtocolError) - Protocol violations