# Chapter 6: Basic Client Setup

This chapter introduces the client-side components of `pyvider.rpcplugin`, focusing on how a host application can launch and interact with a plugin.

The primary class for this purpose is `RPCPluginClient`. It encapsulates the logic for:

*   **Launching the Plugin Process**: It can take a command (e.g., `['python', 'my_plugin_server.py']`) and execute it as a subprocess.
*   **Performing the Handshake**:
    *   It sets up necessary environment variables for the plugin subprocess, including the magic cookie.
    *   It reads the handshake string printed by the plugin server to its standard output.
    *   It parses this string to determine the protocol version, transport type (Unix or TCP), and the network address for the gRPC connection.
    *   If mTLS is enabled, it also handles the server's certificate information from the handshake.
*   **Establishing the gRPC Channel**: Once the handshake is successful, `RPCPluginClient` creates a gRPC channel (`client.grpc_channel`) to the plugin server. This channel is then used with gRPC stubs to make RPC calls.
*   **Managing Lifecycle**: It provides `start()` and `close()` methods to manage the connection and the plugin subprocess. `close()` will also attempt to gracefully shut down the plugin server.

The `pyvider.rpcplugin.plugin_client` factory function is a convenient way to create an `RPCPluginClient` instance, especially when the client is responsible for launching the plugin executable.

## Example: Client Connection Concepts (`examples/ch06_client_setup_concepts.py`)

The `ch06_client_setup_concepts.py` script provides a conceptual outline of setting up a client and thinking about error handling. It doesn't connect to a live plugin but serves to illustrate the patterns.

```python
#!/usr/bin/env python3
# examples/ch06_client_setup_concepts.py
import asyncio
from example_utils import configure_for_example

configure_for_example()

from pyvider.rpcplugin.exception import HandshakeError, RPCPluginError, TransportError # noqa: E402
from pyvider.telemetry import logger # noqa: E402


async def basic_client_example() -> None:
    """Example: Basic client connection."""
    logger.info("🔗 Basic Client Connection Example")

    # Note: This is conceptual - real usage requires an executable plugin
    client_config = {"timeout": 10.0, "max_retries": 3}

    logger.info("💡 Client configuration prepared")
    logger.info(f"📋 Config: {client_config}")

    # In real usage:
    # from pyvider.rpcplugin import plugin_client
    # client = plugin_client(
    #     command=["./path/to/plugin/executable"],
    #     # The 'config' dict passed to plugin_client can include an 'env' sub-dictionary
    #     # to pass specific environment variables to the plugin subprocess.
    #     # It can also include other keys that RPCPluginClient might use directly.
    #     config={"env": {"MY_PLUGIN_VAR": "value"}, "timeout": 15.0}
    # )
    # await client.start() # This launches the plugin and connects
    # # After client.start() succeeds, client.grpc_channel is available
    # # ... make RPC calls using a stub ...
    # await client.close() # This stops the plugin and cleans up
    logger.info("✅ Basic client example completed (conceptual)")


async def error_handling_example() -> None:
    """Example: Client error handling patterns."""
    logger.info("⚠️  Client Error Handling Example")

    try:
        # Simulate client operations
        logger.info("🔄 Attempting client connection (simulated)...")

        # In a real scenario, client.start() might raise these:
        # raise TransportError("Simulated network issue during connection")
        # raise HandshakeError("Simulated authentication or handshake protocol failure")
        # raise RPCPluginError("A generic plugin system error during setup")
        logger.info("✅ Connection successful")

    except TransportError as e:
        logger.error(f"🚫 Transport error: {e}")
        # Handle transport-specific errors
    except HandshakeError as e:
        logger.error(f"🤝 Handshake error: {e}")
        # Handle authentication/handshake errors
    except RPCPluginError as e:  # Catching the base plugin error
        logger.error(f"🔌 RPC Plugin System Error: {e}")
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        # Handle other errors

    logger.info("✅ Error handling example completed")


async def main() -> None:
    """Run client connection examples."""
    logger.info("🚀 Client Connection Examples")

    await basic_client_example()
    await error_handling_example()

    logger.info("✅ All client examples completed")


if __name__ == "__main__":
    asyncio.run(main())
```

**Key takeaways from this conceptual example:**

*   **Client Creation**: An `RPCPluginClient` is typically created using `plugin_client(command=[...], config=...)`. The `command` specifies how to run your plugin executable. The `config` dictionary can be used to pass environment variables to the plugin (via `config={'env': {...}}`) or to set client-side behaviors if `RPCPluginClient` supported direct config options (currently, most config is global via `rpcplugin_config`).
*   **Starting the Client**: `await client.start()` is the crucial call that launches the plugin subprocess, executes the handshake, and establishes the gRPC channel.
*   **Error Handling**: It's important to wrap client operations, especially `start()`, in `try...except` blocks to catch potential errors like `TransportError` (e.g., plugin executable not found, network issues if using TCP), `HandshakeError` (e.g., magic cookie mismatch, mTLS failure), or other `RPCPluginError` subclasses.
*   **Cleanup**: A `finally` block should ensure `await client.close()` is called to properly terminate the plugin subprocess and release resources, even if errors occur.
