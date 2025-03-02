---
title: Pyvider RPC Plugin
date: 2025-03-01
---

# Pyvider RPC Plugin

Welcome to the Pyvider RPC Plugin documentation. This library enables Python applications to communicate with plugins over RPC using the same protocol as HashiCorp's go-plugin system, enabling cross-language plugin architectures.

## What is Pyvider RPC Plugin?

Pyvider RPC Plugin is a Python implementation of HashiCorp's go-plugin system—but with more emoji logging and fewer pointer errors. It's a robust framework for creating plugin-based architectures that allows your application to:

- Load and communicate with plugins as separate processes
- Support plugins written in multiple languages
- Ensure secure, reliable communication between host and plugins
- Maintain compatibility with existing go-plugin ecosystems

At its core, Pyvider RPC Plugin provides a client-server architecture where:

- The **host application** (client) launches plugins and makes RPC calls
- The **plugin** (server) provides functionality via RPC interfaces

## Key Features

- **Process Isolation**: Plugins run in separate processes, preventing crashes from affecting the host
- **Language Agnostic**: Support for plugins written in various languages through gRPC
- **Secure Communication**: Mutual TLS authentication ensures connections are secure
- **Transport Flexibility**: Support for both TCP and Unix domain sockets
- **Protocol Versioning**: Negotiate compatible protocol versions between host and plugin
- **Graceful Error Handling**: Comprehensive exception hierarchy for detailed diagnostics
- **Structured Logging**: Emoji-based logging system for clear, visual debugging
- **Go Compatibility**: Full interoperability with HashiCorp's go-plugin ecosystem

## When to Use Pyvider RPC Plugin

Pyvider RPC Plugin is ideal for applications that:

- Need a stable, extensible plugin architecture
- Require process isolation for stability
- Want to enable third-party extensions
- Need cross-language plugin support
- Already use HashiCorp tools with go-plugin

## Getting Started

The fastest way to understand Pyvider is to see it in action:

```python
## Host application
client = RPCPluginClient(command=["python", "my_plugin.py"])
await client.start()
plugin_interface = await client.get_interface()
result = await plugin_interface.do_something()
