# Chapter 2: Getting Started

This chapter will guide you through installing `pyvider.rpcplugin` and understanding its fundamental concepts, culminating in running your first plugin.

## Installation

You can install `pyvider.rpcplugin` using `uv` (recommended) or `pip`:

```bash
# With uv (recommended)
uv add pyvider-rpcplugin
```

```bash
# With pip
pip install pyvider-rpcplugin
```

This will install the core library and its dependencies, including `grpcio` for RPC communication and `attrs` for data classes.

## Core Concepts

Before diving into examples, let's briefly cover the main components of the `pyvider.rpcplugin` framework:

*   **Plugin**: An external executable or script that provides specific services. Plugins run in separate processes from the host application.
*   **Host Application (Client)**: The main application that launches, manages, and communicates with plugins. In `pyvider.rpcplugin` terms, this is often referred to as the "client" because it initiates the connection to the plugin server.
*   **Plugin Server**: The RPC server running within the plugin process. It listens for connections from the host application and serves RPC requests.
*   **Handshake**: A critical initial process where the client and server securely establish a connection. This involves:
    *   **Magic Cookie Authentication**: A shared secret passed via an environment variable to ensure the client is launching a trusted plugin.
    *   **Protocol Version Negotiation**: Client and server agree on a compatible version of the RPC protocol.
    *   **Transport Negotiation**: Client and server agree on the communication method (Unix domain sockets or TCP).
    *   **(Optional) mTLS Exchange**: If mTLS is enabled, certificates are exchanged and verified.
*   **Transport**: The underlying communication mechanism. `pyvider.rpcplugin` supports:
    *   **Unix Domain Sockets (UDS)**: For fast and secure Inter-Process Communication (IPC) on the same machine.
    *   **TCP Sockets**: For network-based communication, potentially between different machines.
*   **RPC (Remote Procedure Call)**: The mechanism allowing the client to invoke functions (procedures) in the plugin server as if they were local. `pyvider.rpcplugin` uses gRPC.
*   **Protocol Buffers (Protobufs)**: A language-neutral, platform-neutral, extensible mechanism for serializing structured data. Used with gRPC to define service interfaces and message structures.
*   **`RPCPluginClient`**: The primary class in `pyvider.rpcplugin` for the host application to manage and communicate with a plugin executable.
*   **`RPCPluginServer`**: The primary class for building the server-side logic within a plugin executable.
*   **`RPCPluginProtocol`**: An interface that defines how specific gRPC services are exposed and managed by the plugin server.
*   **Handler (Servicer)**: The actual implementation of your RPC service methods within the plugin.

## Example: Quick Start - Launching a Plugin

This example demonstrates the most common use case: a host application (client) launching a plugin server (which is a separate Python script acting as an executable) and establishing a connection.

**1. The Plugin Server Executable (`examples/ch02_dummy_server.py`)**

First, let's look at a minimal plugin server. This script (`ch02_dummy_server.py` in the `examples` directory) is designed to be run as an executable by our client. It starts an RPC server using a basic, built-in protocol and a simple handler that doesn't perform any specific actions. Its main role here is to participate in the handshake.

```python
#!/usr/bin/env python3
# examples/ch02_dummy_server.py
"""
A minimal RPC plugin server for use by other examples.
It uses the BasicRPCPluginProtocol and a no-op handler.
Prints its handshake string to stdout upon successful startup.
"""
import asyncio

# Import from examples.example_utils
from examples.example_utils import configure_for_example  # noqa: E402

# This should be called before other pyvider imports if this script is run directly.
# It sets up paths and default config (e.g., disabling mTLS for basic examples).
configure_for_example()

# from example_utils import configure_for_example  # noqa: E402 # Corrected import
# This line is now redundant

# Import the shared DummyHandler
from examples.example_utils import DummyHandler  # noqa: E402
from pyvider.rpcplugin import plugin_protocol, plugin_server  # noqa: E402
from pyvider.rpcplugin.server import RPCPluginServer  # noqa: E402
from pyvider.rpcplugin.types import (  # noqa: E402
    RPCPluginProtocol as TypesRPCPluginProtocol,
)
from pyvider.telemetry import logger  # noqa: E402


async def main() -> None:
    """Sets up and runs the dummy server for Chapter 2 Quick Start."""
    logger.info(
        "🚀 ch02_dummy_server.py (Quick Start version): "
        "Starting as an executable plugin..."
    )

    # `configure_for_example()` called at the module level sets up default
    # configurations, including a default magic cookie key/value and disabling
    # mTLS by default. The launching client (ch02_quick_start_client.py) is
    # expected to set the environment variable matching PLUGIN_MAGIC_COOKIE_KEY
    # with the value from PLUGIN_MAGIC_COOKIE_VALUE from its own configuration.

    protocol: TypesRPCPluginProtocol = plugin_protocol()  # Uses BasicRPCPluginProtocol
    handler = DummyHandler()  # Using the basic handler
    server: RPCPluginServer = plugin_server(protocol=protocol, handler=handler)

    try:
        logger.info("Dummy server attempting to start and serve (will print handshake)...")
        await server.serve()
        logger.info("Dummy server finished serving.")
    except KeyboardInterrupt: # pragma: no cover
        logger.info("Dummy server stopped by user.")
    except Exception as e: # pragma: no cover
        logger.error(f"Dummy server encountered an error: {e}", exc_info=True)
    finally:
        logger.info("Dummy server shutting down.")

if __name__ == "__main__":
    asyncio.run(main())
```

Key points about `ch02_dummy_server.py`:
*   It uses `configure_for_example()` to set up basic configurations suitable for examples (like disabling mTLS by default and setting a default magic cookie key/value).
*   It employs `plugin_protocol()` to get a basic protocol implementation and `plugin_server()` to create an `RPCPluginServer` instance.
*   The `server.serve()` call is crucial: it performs the server-side handshake (including printing the handshake string to its standard output) and then starts listening for RPC calls.

You typically don't run `ch02_dummy_server.py` directly in this scenario; it's launched as a subprocess by the client.

**2. The Client Application (`examples/ch02_quick_start_client.py`)**

Now, let's examine the client application (`ch02_quick_start_client.py`) that will launch and connect to our dummy server.

```python
#!/usr/bin/env python3
# examples/ch02_quick_start_client.py
"""
Quick Start Example - Client launching an executable plugin server.
"""
import asyncio
import sys
from pathlib import Path
from example_utils import configure_for_example

configure_for_example(clear_env=True) # Client context

from pyvider.rpcplugin import plugin_client
from pyvider.rpcplugin.client.base import RPCPluginClient # Retaining for clarity if user inspects client object
from pyvider.rpcplugin.exception import RPCPluginError
from pyvider.telemetry import logger

async def main():
    logger.info("🚀 Starting Quick Start Example (Client Launching Plugin)")
    example_dir = Path(__file__).resolve().parent
    dummy_server_executable = example_dir / "ch02_dummy_server.py"

    if not dummy_server_executable.exists(): # Good practice check
        logger.error(f"Dummy server executable not found at: {dummy_server_executable}")
        return

    dummy_server_command = [sys.executable, str(dummy_server_executable)]
    client: RPCPluginClient | None = None

    try:
        logger.info(f"Client launching plugin: {' '.join(dummy_server_command)}")
        client = plugin_client(command=dummy_server_command)

        logger.info("Starting client and connecting to plugin...")
        await client.start()

        logger.info("✅ Client connected to dummy_server plugin successfully!")
        logger.info("   The dummy_server uses a basic protocol with no custom RPC methods.")
        # If your plugin had defined services (e.g., via .proto files),
        # you would create a gRPC stub here using client.grpc_channel:
        # stub = YourServiceStub(client.grpc_channel)
        # response = await stub.YourMethod(YourRequest())
        await asyncio.sleep(2) # Keep connection alive for demonstration

    except RPCPluginError as e:
        logger.error(f"❌ Client RPCPluginError: {e.message}", exc_info=True)
        if e.hint:
            logger.error(f"   Hint: {e.hint}")
    except Exception as e:
        logger.error(f"❌ An unexpected error occurred: {e}", exc_info=True)
    finally:
        if client and client.is_started:
            logger.info("Shutting down client and plugin...")
            await client.close()
            logger.info("Client and plugin shut down.")
        elif client: # Handle case where client was instantiated but not started
            await client.close()
            logger.info("Client (not started) resources cleaned up.")

if __name__ == "__main__":
    asyncio.run(main())
```

Key points about `ch02_quick_start_client.py`:
*   It defines the command to execute the plugin server (`dummy_server_command`).
*   It uses the `plugin_client` factory function to create an `RPCPluginClient` instance. This factory is a convenient way to get a client that's pre-configured to launch an executable.
*   `client.start()` is the core method that:
    *   Launches the `ch02_dummy_server.py` script as a subprocess.
    *   Sets up necessary environment variables for the subprocess (like the magic cookie).
    *   Reads the handshake string from the server's stdout.
    *   Parses the handshake to determine how to connect (e.g., which Unix socket or TCP port).
    *   Establishes the gRPC channel.
*   After `client.start()` completes successfully, `client.grpc_channel` will be available for making RPC calls (though this dummy example doesn't make any specific calls).
*   `client.close()` gracefully shuts down the connection and terminates the plugin subprocess.

**To Run This Example:**

1.  **Installation**: Ensure you have `pyvider.rpcplugin` installed (see "Installation" section above).
2.  **Navigate to Project Root**: Open your terminal and navigate to the root directory of the `pyvider-rpcplugin` project (the directory containing the `examples/` and `src/` folders).
3.  **Run the Client**: Execute the client script using the following command:
    ```bash
    python examples/ch02_quick_start_client.py
    ```
    The `configure_for_example()` utility called within the scripts will handle `sys.path` adjustments to ensure modules are found correctly when run this way.

You should see log output from both the client and the server, indicating a successful connection and shutdown. This demonstrates the fundamental client-launches-plugin pattern.
