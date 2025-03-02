---
---

# Plugin Model (Client/Server)

The foundation of Pyvider RPC Plugin is a distributed client-server architecture where processes communicate over local IPC mechanisms. If you've ever worked with microservices, the concept is similar—except here, your services are plugins and your network is the loopback interface.

## Roles and Responsibilities

In the Pyvider RPC Plugin architecture, there are two primary actors:

### The Client (Host Application)

The client is the host application that loads and uses plugins. Its key responsibilities include:

- **Plugin Discovery**: Finding plugin executables in the file system
- **Plugin Execution**: Launching plugins as separate processes
- **Handshake Management**: Establishing initial connection and negotiating capabilities
- **Interface Usage**: Making RPC calls to plugin functionality
- **Lifecycle Management**: Monitoring and shutting down plugins when needed

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