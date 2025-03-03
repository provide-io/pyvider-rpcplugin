---
title: Core Concepts
description: Foundational concepts of the Pyvider RPC Plugin system
---

# Core Concepts

Before diving into implementation details, it's important to understand the key concepts behind Pyvider RPC Plugin. This section provides an overview of the architecture, components, and workflows that make up the system.

## The Big Picture

Pyvider RPC Plugin is built around a simple but powerful idea: running plugins as separate processes and communicating with them through a well-defined RPC protocol. This approach provides several benefits:

- **Process Isolation**: Plugins can crash without taking down the host application
- **Resource Control**: Memory and CPU usage can be monitored and limited per plugin
- **Security**: Plugins run with restricted permissions
- **Language Agnosticism**: Plugins can be written in any language that supports gRPC

Think of it as embassies in a foreign country—technically on your soil, but operating under their own rules. And like diplomatic relations, everything happens through formal, well-documented protocols.

## Key Components

Pyvider RPC Plugin consists of several core components:

- [**Plugin Model**](plugin-model.md): The client-server architecture that defines how hosts and plugins interact
- [**Transport Layer**](transport.md): The communication channels (TCP, Unix sockets) between host and plugin
- [**Handshake Protocol**](handshake.md): The negotiation process that establishes the connection
- [**Security Model**](security.md): The authentication and encryption mechanisms that secure communications
- [**gRPC Interface**](grpc-interface.md): The service definitions that expose plugin functionality

## System Architecture

At a high level, the plugin system works as follows:

1. The host application (client) locates a plugin executable
2. The host launches the plugin as a separate process
3. The plugin starts up and performs a handshake with the host
4. The host and plugin establish a secure RPC channel
5. The host makes RPC calls to the plugin
6. The plugin processes requests and returns responses
7. When finished, the host terminates the plugin

This architecture is similar to how web browsers interact with web servers, except everything happens locally on the same machine. It's like having tiny web services running in your application—just without the latency of crossing the internet. Local travel for your data, if you will.

## Next Steps

- Learn about the [Plugin Model](plugin-model.md) to understand the client-server architecture
- Explore the [Transport Layer](transport.md) to understand how communication works
- Discover the [Handshake Protocol](handshake.md) to see how connections are established
- Understand the [Security Model](security.md) to see how communication is secured
- Review the [gRPC Interface](grpc-interface.md) to learn how services are defined
