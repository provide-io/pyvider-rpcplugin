# Chapter 7: Client-Side of the Echo Demo

After successfully establishing a connection to a plugin server using `RPCPluginClient` (as shown in Chapter 6), your host application can start making Remote Procedure Calls (RPCs). This is done using **gRPC stubs**.

A gRPC stub is a client-side object, generated from your `.proto` file, that provides local methods corresponding to the RPC methods defined in your service. When you call a method on the stub, it handles the serialization of your request, sends it to the server over the established gRPC channel, receives the server's response, and deserializes it for you.

## Example: Echo Client Implementation (`examples/demo/echo_client.py`)

This client application is designed to interact with the `echo_server.py` (from Chapter 5). It demonstrates how to:
1.  Launch the `echo_server.py` plugin using `RPCPluginClient`.
2.  Create an `EchoServiceStub` using the `client.grpc_channel`.
3.  Call the `Echo` RPC method on the server.

```python
#!/usr/bin/env python3
# examples/demo/echo_client.py
import asyncio
import logging # Using standard logging for this example
import os
import sys
from pathlib import Path
from typing import Any
import grpc

# Path setup for pyvider.rpcplugin
# (Ensures 'src' and project root are in sys.path for imports)
project_root_path = Path(__file__).resolve().parent.parent.parent
src_path_abs = project_root_path / "src"
if src_path_abs.exists() and str(src_path_abs) not in sys.path:
    sys.path.insert(0, str(src_path_abs))
if str(project_root_path) not in sys.path: # For 'from examples.demo...'
    sys.path.insert(0, str(project_root_path))


from pyvider.rpcplugin.client import RPCPluginClient
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Import generated protobuf code for Echo service
try:
    # Assumes this script is run from a context where 'examples' is a package
    from examples.demo import echo_pb2, echo_pb2_grpc
except ImportError:
    # Fallback if run directly from examples/demo and '.' is in path
    import echo_pb2
    import echo_pb2_grpc

class EchoClient:
    server_script_path: str
    _client: RPCPluginClient | None = None
    _stub: echo_pb2_grpc.EchoServiceStub | None = None
    client_config: dict[str, Any]

    def __init__(self, server_script_path: str) -> None:
        self.server_script_path = server_script_path
        # Environment variables for the echo_server.py subprocess.
        # These must match what echo_server.py expects for its handshake.
        self.client_config = {"env": {
            "PLUGIN_MAGIC_COOKIE_KEY": "ECHO_PLUGIN_COOKIE_EXAMPLE", # Server looks for this key
            "PLUGIN_MAGIC_COOKIE_VALUE": "echo-super-secret-cookie", # Server expects this value
            "PLUGIN_MAGIC_COOKIE": "echo-super-secret-cookie", # Client sends this actual cookie
            # Other env vars like PLUGIN_AUTO_MTLS can be set here if needed by the server example
        }}

    async def start(self) -> bool:
        logger.info(f"Attempting to launch and connect to server: {self.server_script_path}")
        try:
            self._client = RPCPluginClient(
                command=[sys.executable, self.server_script_path],
                config=self.client_config, # Passes env vars to the server process
            )
            # Start client, launch server, perform handshake, establish gRPC channel
            await asyncio.wait_for(self._client.start(), timeout=15.0)

            if not self._client.grpc_channel:
                logger.error("gRPC channel not established after client start.")
                await self.close()
                return False

            # Create the gRPC stub using the established channel
            self._stub = echo_pb2_grpc.EchoServiceStub(self._client.grpc_channel)
            logger.info("Client started and connected successfully. Echo stub created.")
            return True
        except TimeoutError:
            logger.error("Timeout during client start (launching/connecting to server).")
            await self.close()
            return False
        except Exception as e:
            logger.error(f"Failed to start client: {e}", exc_info=True)
            await self.close()
            return False

    async def call_echo(self, message: str) -> str | None:
        if not self._stub or not self._client or not self._client.is_started:
            logger.error("Client not ready or stub not available for Echo call.")
            return None

        logger.info(f"Sending Echo request to server: '{message}'")
        try:
            # Create the request message object (from echo_pb2.py)
            request = echo_pb2.EchoRequest(message=message)
            # Make the RPC call using the stub
            response = await asyncio.wait_for(self._stub.Echo(request), timeout=5.0)
            logger.info(f"Received Echo reply from server: '{response.reply}'")
            return response.reply
        except TimeoutError:
            logger.error("RPC call to Echo method timed out.")
            return None
        except grpc.aio.AioRpcError as e: # Catch gRPC specific errors
            logger.error(f"gRPC Error during Echo call: {e.code()} - {e.details()}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during Echo call: {e}", exc_info=True)
            return None

    async def close(self) -> None:
        if self._client:
            logger.info("Closing client connection and terminating server process...")
            await self._client.close()
            self._client = None
            self._stub = None
            logger.info("Client resources cleaned up.")

async def run_client() -> None:
    client_dir = Path(__file__).parent
    server_script = client_dir / "echo_server.py" # Path to the server script

    client = EchoClient(str(server_script))

    if not await client.start():
        logger.error("Client initialization failed. Exiting.")
        return

    # Make an RPC call
    reply = await client.call_echo("Hello from pyvider client!")
    if reply:
        logger.info(f"Verification: Client received reply -> '{reply}'")
    else:
        logger.warning("Verification: Did not receive a valid reply for the first call.")

    # Example of calling again
    reply_again = await client.call_echo("Testing RPC call again!")
    if reply_again:
        logger.info(f"Verification: Second reply -> '{reply_again}'")
    else:
        logger.warning("Verification: Did not receive a valid reply for the second call.")

    await client.close()
    logger.info("Client example finished.")

if __name__ == "__main__":
    asyncio.run(run_client())
```

**Explanation:**

1.  **Import Generated Code**: The client imports `echo_pb2` (for message types like `EchoRequest`, `EchoResponse`) and `echo_pb2_grpc` (for the `EchoServiceStub`).
2.  **`EchoClient.__init__`**:
    *   Stores the path to the server script.
    *   Sets up `client_config` with an `env` dictionary. This dictionary contains environment variables that `RPCPluginClient` will pass to the `echo_server.py` subprocess when it's launched. Crucially, this includes the magic cookie key and value that the server expects for the handshake.
3.  **`EchoClient.start`**:
    *   Creates an `RPCPluginClient` instance, providing the command to run the server and the `client_config`.
    *   Calls `await self._client.start()`. This is where `pyvider.rpcplugin` launches the server, handles the handshake, and establishes the gRPC channel.
    *   If successful, `self._client.grpc_channel` becomes available.
    *   An `EchoServiceStub` is then created using this channel: `self._stub = echo_pb2_grpc.EchoServiceStub(self._client.grpc_channel)`.
4.  **`EchoClient.call_echo`**:
    *   Checks if the client is ready and the stub is available.
    *   Creates an `EchoRequest` message object: `request = echo_pb2.EchoRequest(message=message)`.
    *   Calls the `Echo` method on the stub: `response = await self._stub.Echo(request)`. This is the actual RPC call. It's an `async` call, so it's `await`ed.
    *   Processes the `EchoResponse` returned by the server.
5.  **`EchoClient.close`**:
    *   Calls `await self._client.close()` to shut down the connection and terminate the server subprocess.
6.  **`run_client`**: The main asynchronous function that orchestrates creating the `EchoClient`, starting it, making calls, and closing it.

This example demonstrates the typical workflow for a client application using `pyvider.rpcplugin` to interact with a plugin that it launches and manages.
