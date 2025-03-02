---
title: Pyvider RPC Plugin
description: A Python implementation of HashiCorp's go-plugin system
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

Think of it as microservices, but for your single application—where every plugin is a well-behaved citizen that can't crash your main program. It's like apartment living versus a commune; everyone gets their own space, but you can still borrow sugar when needed.

## Key Features

- **Process Isolation**: Plugins run in separate processes, preventing crashes from affecting the host. Because nobody wants one bad plugin to ruin the whole party.

- **Language Agnostic**: Support for plugins written in various languages through gRPC. Python, Go, or even JavaScript—we don't judge your life choices.

- **Secure Communication**: Mutual TLS authentication ensures connections are secure. Like a bouncer checking IDs at both doors.

- **Transport Flexibility**: Support for both TCP and Unix domain sockets. Choose your pipe, we'll carry the data.

- **Protocol Versioning**: Negotiate compatible protocol versions between host and plugin. We speak your language, even if it's an older dialect.

- **Graceful Error Handling**: Comprehensive exception hierarchy for detailed diagnostics. When things go wrong, at least you'll know why.

- **Structured Logging**: Emoji-based logging system for clear, visual debugging. Because in 2025, we communicate primarily in pictographs anyway.

- **Go Compatibility**: Full interoperability with HashiCorp's go-plugin ecosystem. Go ahead, mix your Pythons with your Gophers.

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
# Host application
client = RPCPluginClient(command=["python", "my_plugin.py"])
await client.start()
plugin_interface = await client.get_interface()
result = await plugin_interface.do_something()
```

Check out the [Quick Start Guide](guides/quick-start.md) for a complete example, or dive into the [Core Concepts](concepts/index.md) to understand the plugin model in depth.

Remember: With great plugin power comes great plugin responsibility.
