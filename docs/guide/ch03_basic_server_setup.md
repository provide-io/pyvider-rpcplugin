# Chapter 3: Basic Server Setup

At the heart of a `pyvider.rpcplugin` server are three main components:

1.  **`RPCPluginServer`**: This is the main class that manages the plugin server's lifecycle. It handles:
    *   Performing the server-side of the handshake protocol (validating magic cookies, negotiating protocol versions and transports).
    *   Setting up the chosen transport (Unix socket or TCP).
    *   Starting and stopping the underlying gRPC server.
    *   Managing graceful shutdown.
    You typically create an instance of this using the `plugin_server` factory function.

2.  **`RPCPluginProtocol`**: This is an abstract base class that you implement to tell `RPCPluginServer` how to handle your specific gRPC service(s). Your implementation will:
    *   Provide the gRPC service descriptors (generated from your `.proto` file).
    *   Specify the name of your service.
    *   Define how to add your service implementation (your handler/servicer) to the gRPC server.
    The `plugin_protocol` factory can provide a basic implementation if you don't have custom gRPC services yet.

3.  **Handler (gRPC Servicer)**: This is the class where you write the actual logic for your RPC methods. It inherits from the gRPC-generated `YourServiceServicer` class (e.g., `EchoServiceServicer`). Each method in your handler corresponds to an RPC method defined in your `.proto` file.

## Example: Server Configuration (`examples/ch03_server_setup_concepts.py`)

The `ch03_server_setup_concepts.py` example illustrates how to configure an `RPCPluginServer` instance, though it doesn't run a fully operational server that waits for connections. Instead, it demonstrates the configuration options.

```python
#!/usr/bin/env python3
# examples/ch03_server_setup_concepts.py
import asyncio
from example_utils import configure_for_example, get_example_port

configure_for_example()

from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.telemetry import logger

class BasicProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self):
        return None, "BasicService"
    def get_method_type(self, method_name: str) -> str:
        return "unary_unary"
    async def add_to_server(self, server, handler):
        logger.info("🔌 Basic service registered")

class BasicHandler:
    pass

async def tcp_server_example():
    logger.info("🌐 TCP Server Configuration Example")
    server = plugin_server(
        protocol=BasicProtocol(),
        handler=BasicHandler(),
        transport="tcp",
        host="127.0.0.1",
        port=get_example_port(), # Uses a helper to find an available port
        config={"APP_MAX_WORKERS": 4}, # Example of app-specific config
    )
    logger.info(f"✅ TCP server configured: {server.transport.endpoint if server.transport else 'No transport'}")
    # Note: server.serve() is not called here, so it doesn't actually start listening.
    return server

async def unix_server_example():
    logger.info("🔌 Unix Socket Server Configuration Example")
    import os
    import tempfile
    socket_path = os.path.join(tempfile.gettempdir(), "pyvider_example.sock")
    server = plugin_server(
        protocol=BasicProtocol(),
        handler=BasicHandler(),
        transport="unix",
        transport_path=socket_path,
        config={"APP_MAX_WORKERS": 2},
    )
    logger.info(f"✅ Unix socket server configured: {server.transport.endpoint if server.transport else 'No transport'}")
    # Note: server.serve() is not called.
    return server

async def main():
    logger.info("🚀 Server Setup Examples")
    tcp_server = await tcp_server_example()
    unix_server = await unix_server_example()
    # To make these servers actually run, you would:
    # await tcp_server.serve()
    # or
    # await unix_server.serve()
    # And they would then print their handshake strings.
    logger.info("✅ All server setup examples completed (configuration demonstrated).")

if __name__ == "__main__":
    asyncio.run(main())
```

Key takeaways from `ch03_server_setup_concepts.py`:
*   The `plugin_server` factory function is used to instantiate `RPCPluginServer`.
*   You provide your `RPCPluginProtocol` implementation and your handler instance.
*   The `transport` parameter can be set to `"tcp"` or `"unix"`.
    *   For TCP, `host` and `port` can be specified. If `port` is 0 (or omitted), an ephemeral port is chosen.
    *   For Unix, `transport_path` specifies the socket file path.
*   An optional `config` dictionary can be passed.
    *   Keys in this dictionary that match `PLUGIN_` prefixed variables (e.g., `PLUGIN_LOG_LEVEL`) will override the global `pyvider.rpcplugin` configurations for this specific server instance.
    *   Other keys can be used for application-specific settings that your server might use, as demonstrated with `APP_MAX_WORKERS` in the example.
