---
title: Plugin Model
description: Understanding the client-server architecture of Pyvider RPC Plugin
---

# Plugin Model (Client/Server)

The foundation of Pyvider RPC Plugin is a distributed client-server architecture where processes communicate over local IPC mechanisms. If you've ever worked with microservices, the concept is similar—except here, your services are plugins and your network is the loopback interface (which means your data packets get to take the scenic route of approximately 0.001 millimeters).

## Roles and Responsibilities

In the Pyvider RPC Plugin architecture, there are two primary actors:

### The Client (Host Application)

The client is the host application that loads and uses plugins. Its key responsibilities include:

- **Plugin Discovery**: Finding plugin executables in the file system
- **Plugin Execution**: Launching plugins as separate processes
- **Handshake Management**: Establishing initial connection and negotiating capabilities
- **Interface Usage**: Making RPC calls to plugin functionality
- **Lifecycle Management**: Monitoring and shutting down plugins when needed

Think of the client as the manager at a restaurant who hires specialized chefs (plugins), tells them what to cook (requests), and serves the resulting dishes (responses) to customers.

In code, this is represented by the `RPCPluginClient` class:

```python
client = RPCPluginClient(
    command=["python", "my_plugin.py"],
    config={
        "env": {
            "PLUGIN_MAGIC_COOKIE_KEY": "MY_PLUGIN",
            "PLUGIN_MAGIC_COOKIE": "supersecret",
        }
    }
)

# Launch the plugin
await client.start()

# Get the interface to make calls
plugin = await client.get_interface()

# Use the plugin
result = await plugin.do_something()

# Shut down when done
await client.close()
```

### The Server (Plugin)

The server is the plugin process that provides functionality to the host application. Its responsibilities include:

- **Protocol Compliance**: Implementing the handshake protocol
- **Service Provision**: Offering a gRPC service interface
- **Request Handling**: Processing RPC calls from the client
- **Resource Management**: Managing its own resources efficiently
- **Graceful Termination**: Shutting down cleanly when requested

The server is like a specialized chef who knows how to make one specific dish really well. The chef doesn't manage the restaurant; they just do their specific job when the manager asks.

In code, this is represented by the `RPCPluginServer` class:

```python
server = RPCPluginServer(
    protocol=MyProtocol(),
    handler=MyHandler()
)

# This handles everything: handshake, serving, shutdown
await server.serve()
```

## Communication Flow

The communication between client and server follows a specific pattern:

1. **Initialization**: The client launches the server process
2. **Handshake**: The server and client negotiate capabilities
3. **Connection**: A secure RPC channel is established
4. **Service**: The client makes RPC requests, the server responds
5. **Termination**: The client signals the server to shut down

This flow ensures that both sides understand each other's capabilities before attempting to communicate, much like how humans might establish a common language before having a conversation. Though in our case, it's less "Parlez-vous français?" and more "Do you support protocol version 5 over TCP socket transport?"

## Plugin Lifecycle

The lifecycle of a plugin server is straightforward:

1. **Launch**: The client starts the plugin process
2. **Configure**: Environment variables tell the plugin how to behave
3. **Handshake**: The plugin negotiates with the client
4. **Serve**: The plugin handles requests from the client
5. **Terminate**: The plugin shuts down when the client requests it

The client controls this lifecycle completely, which is different from traditional client-server models where servers often have independent lifecycles. Here, the plugin exists solely to serve the client that launched it—a truly codependent relationship.

## Plugin Versioning

Plugins and hosts must agree on a protocol version to communicate. This version determines the capabilities and message formats that they can exchange.

The system supports multiple protocol versions, allowing for backward compatibility as the protocol evolves. During the handshake process, the client advertises all versions it supports, and the server selects the highest version that both support.

It's like dating apps where both parties swipe right on protocol versions they like, and when there's a match, they can start communicating. Unlike dating apps, however, the rejection rate is significantly lower.

## Next Steps

Now that you understand the client-server model, learn about:

- [Transport Layer](transport.md) to see how client and server communicate
- [Handshake Protocol](handshake.md) to understand the negotiation process
- [Security Model](security.md) to explore the authentication mechanisms
