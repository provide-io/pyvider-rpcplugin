# Chapter 8: Direct Client Connections

While `RPCPluginClient` is designed for the common scenario where the host application launches and manages the plugin subprocess, there are situations where you might need to connect to a `pyvider.rpcplugin` server that is already running independently. This could be for:

*   **Debugging**: Connecting to a plugin server that you've started manually with specific debug flags.
*   **Testing**: Interacting with a standalone plugin server in a test environment.
*   **Alternative Deployment Models**: Scenarios where the plugin lifecycle is managed by a different system (e.g., a separate service, an orchestrator like Kubernetes that starts the plugin as a standalone pod).

In these cases, you bypass `RPCPluginClient` and use the underlying gRPC library (`grpc.aio`) directly to establish a connection. This requires you to know:

1.  **The server's transport address**:
    *   For Unix Domain Sockets: The file path of the socket (e.g., `/tmp/myplugin.sock`).
    *   For TCP: The host and port (e.g., `localhost:50051`).
2.  **Security configuration**:
    *   If the server is running insecurely (no mTLS).
    *   If the server is using mTLS, you'll need the client's certificate and private key, plus the CA certificate used to verify the server's certificate.

You will not go through the `pyvider.rpcplugin` handshake protocol (magic cookie, stdout-based handshake string) because that's handled by `RPCPluginClient` specifically when it launches the plugin. A direct connection assumes the server is already past that stage and is simply listening for gRPC connections on its configured transport.

## Example: Direct Client Connection (`examples/ch08_direct_client_connection.py`)

This example demonstrates how a Python script can connect directly to an already running `pyvider.rpcplugin` server, assuming it's listening on a known Unix domain socket and is *not* using mTLS for simplicity.

**To make this example work:**

1.  **Start a server manually**: Run `examples/ch02_dummy_server.py` in one terminal.
    *   The `ch02_dummy_server.py` (when run directly via `python examples/ch02_dummy_server.py`) is set up by `example_utils.configure_for_example()` to:
        *   Use a default magic cookie (e.g., "pyvider-example-cookie" with key "PYVIDER_PLUGIN_MAGIC_COOKIE").
        *   Disable mTLS (`PLUGIN_AUTO_MTLS=False`).
        *   Listen on a Unix socket (usually the default).
    *   Crucially, for this `ch08` example to find the socket, the `ch02_dummy_server.py` (after modifications in this plan) will write its active Unix socket path to a file named `dummy_server_socket.txt` in the project root. Note this down.

2.  **Run `ch08_direct_client_connection.py`**: In another terminal, run this script. It will attempt to read the socket path from `dummy_server_socket.txt` and connect.

```python
#!/usr/bin/env python3
# examples/ch08_direct_client_connection.py
import asyncio
import sys
from pathlib import Path
import grpc # For direct gRPC channel usage
from example_utils import clear_plugin_env_vars, configure_for_example
from pyvider.telemetry import logger

# Path to the file where ch02_dummy_server.py (when run standalone)
# is expected to write its socket path.
# This path assumes ch08_direct_client_connection.py is in examples/
# and dummy_server_socket.txt is in the project root (examples/../)
SOCKET_COMM_FILE = Path(__file__).resolve().parent.parent / "dummy_server_socket.txt"

async def run_direct_client():
    logger.info("🚀 pyvider-rpcplugin Direct Client Connection Example")
    socket_path_read = None
    try:
        # Read the socket path written by the standalone ch02_dummy_server.py
        socket_path_read = SOCKET_COMM_FILE.read_text().strip()
        if not socket_path_read:
            raise FileNotFoundError("Socket path in file is empty.")
        logger.info(f"Read socket path from {SOCKET_COMM_FILE}: {socket_path_read}")
    except FileNotFoundError:
        logger.error(
            f"Socket communication file not found: {SOCKET_COMM_FILE}. "
            "Ensure ch02_dummy_server.py ran successfully and wrote this file, "
            "or manually create it with the correct socket path."
        )
        return
    except Exception as e:
        logger.error(f"Error reading socket path file: {e}", exc_info=True)
        return

    # Target for grpc.aio.insecure_channel for Unix sockets is "unix:/path/to/socket"
    target = f"unix:{socket_path_read}"

    # Configure client-side aspects like logging.
    # No magic cookie env vars are needed by *this client script* for a direct connection,
    # as the handshake is bypassed. The server would have already validated it if launched by a host.
    clear_plugin_env_vars() # Clear any inherited PLUGIN_ vars
    configure_for_example(PLUGIN_LOG_LEVEL="DEBUG", PLUGIN_AUTO_MTLS=False)

    channel = None
    try:
        logger.info(f"Creating insecure gRPC channel directly to target: {target}...")
        # For an insecure connection (no mTLS)
        channel = grpc.aio.insecure_channel(target)

        # For an mTLS connection, you would use grpc.aio.secure_channel()
        # and provide client certificate, client key, and server's root CA cert:
        # client_cert_pem = Path("path/to/client.crt").read_text()
        # client_key_pem = Path("path/to/client.key").read_text()
        # server_ca_pem = Path("path/to/server_ca.crt").read_text()
        # credentials = grpc.ssl_channel_credentials(
        #     root_certificates=server_ca_pem.encode(),
        #     private_key=client_key_pem.encode(),
        #     certificate_chain=client_cert_pem.encode()
        # )
        # channel = grpc.aio.secure_channel(target, credentials)

        logger.info("Waiting for channel to be ready (timeout 5s)...")
        await asyncio.wait_for(channel.channel_ready(), timeout=5.0)
        logger.info(f"✅ Successfully connected to server at {target}")

        # At this point, you would use a gRPC stub generated from your .proto file
        # to make RPC calls. For the dummy server, there are no custom RPCs.
        # Example:
        # stub = your_pb2_grpc.YourServiceStub(channel)
        # response = await stub.YourMethod(your_pb2.YourRequest(data="..."))
        # logger.info(f"Received response: {response.message}")
        print("   (No RPC calls made in this basic direct connection example as dummy_server has no custom methods.)")
        await asyncio.sleep(1) # Keep connection for a moment

    except TimeoutError:
        logger.error(
            f"Timeout: Failed to connect to {target} within 5 seconds. "
            f"Is the server running and the socket path '{socket_path_read}' correct?"
        )
    except grpc.aio.AioRpcError as e:
        logger.error(
            f"gRPC Error during connection to {target}: {e.code()} - {e.details()}",
            exc_info=True,
        )
    except Exception as e:
        logger.error(f"An unexpected error occurred while connecting to {target}: {e}", exc_info=True)
    finally:
        if channel:
            logger.info(f"Closing gRPC channel to {target}.")
            await channel.close()
        logger.info("✅ Direct Client Connection Example Finished.")

if __name__ == "__main__":
    asyncio.run(run_direct_client())
```

**Key Points for Direct Connection:**

*   **No `RPCPluginClient`**: You interact directly with `grpc.aio.insecure_channel` or `grpc.aio.secure_channel`.
*   **Address is Key**: You must know the exact address (Unix socket path or TCP host:port) the server is listening on.
*   **Bypasses Handshake**: The `pyvider.rpcplugin` specific handshake (magic cookie, stdout parsing) is not performed. The server must already be running and past its own internal handshake validation (if it was launched by a compliant host previously or configured to allow direct connections).
*   **Security**: If the server is configured for mTLS, your direct client *must* also be configured with the correct client certificate, client key, and the CA certificate to trust the server. `grpc.aio.secure_channel` is used for this. If the server is not using mTLS, `grpc.aio.insecure_channel` is used.
*   **Use Cases**: This pattern is less common for typical plugin deployments managed by a host application but is invaluable for debugging, testing against a standalone server, or integrating with plugins managed by other systems.
