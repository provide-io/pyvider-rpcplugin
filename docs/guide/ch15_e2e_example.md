# Chapter 15: End-to-End Example Walkthrough

This chapter walks through the `examples/11_end_to_end.py` script. This example is somewhat unique as it demonstrates running both an `RPCPluginServer` and an `RPCPluginClient` (that launches a mock executable) within the *same Python process*. This setup is primarily for illustrative and testing purposes to show the components interacting without needing separate file executions.

In a typical production scenario, the plugin server and the host application (client) would be in separate processes, often launched as distinct executables.

## The `11_end_to_end.py` Example

The goal of this example is to:
1.  Define a simple gRPC-like service structure (though it doesn't use actual `.proto` compilation for this specific internal demo).
2.  Start an `RPCPluginServer` in the background, configured to listen on a Unix domain socket.
3.  Create a temporary "dummy executable" shell script. This script's role is to print a valid handshake string to its standard output, mimicking what a real plugin executable would do. The handshake string will point to the Unix socket our server is listening on.
4.  Create an `RPCPluginClient` configured to "launch" this dummy shell script.
5.  Have the client `start()`, which will execute the dummy script, read its handshake output, and connect to the server running in the same process.
6.  Simulate an RPC call to demonstrate the connection is live.
7.  Clean up all resources (client, server, dummy script, socket file).

```python
#!/usr/bin/env python3
# examples/11_end_to_end.py
"""
A complete, self-contained end-to-end example of a pyvider-rpcplugin server
and client running in the same process.
"""

import asyncio
import sys
from pathlib import Path
from typing import Any

from attrs import define, field

# Add src to path for examples
project_root = Path(__file__).resolve().parent.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Import pyvider.rpcplugin components
from pyvider.rpcplugin import (
    plugin_client,
    plugin_protocol, # Using the basic protocol factory
    plugin_server,
)
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.types import (
    RPCPluginProtocol as TypesRPCPluginProtocol,
)
from pyvider.telemetry import logger
from pyvider.rpcplugin.config import rpcplugin_config # For constructing handshake

# Define simple request/reply structures (like Protobuf messages)
@define(frozen=True, slots=True)
class GreetingRequest:
    name: str = field()

@define(frozen=True, slots=True)
class GreetingReply:
    message: str = field()

# Define a simple service handler
class GreeterServiceHandler:
    async def Greet(
        self, request: GreetingRequest, context: Any # Context is gRPC context, Any for this sim
    ) -> GreetingReply:
        logger.info(
            "Server (Handler): Received Greet request",
            client_name=request.name,
        )
        message = f"Hello, {request.name}! This is a live end-to-end call."
        return GreetingReply(message=message)

async def main() -> None:
    logger.info("🚀 pyvider-rpcplugin End-to-End In-Process Example")

    # 1. Define Protocol and Handler
    # Using the basic protocol provided by plugin_protocol() factory
    protocol_instance: TypesRPCPluginProtocol = plugin_protocol(service_name="E2EService")
    handler_instance = GreeterServiceHandler()

    # Define a Unix socket path for the server
    server_socket_path = Path("./e2e_server_demo.sock").resolve()

    # 2. Create and start the RPCPluginServer in a background task
    server_instance: RPCPluginServer = plugin_server(
        protocol=protocol_instance,
        handler=handler_instance,
        transport="unix",
        transport_path=str(server_socket_path),
    )

    logger.info(f"Server starting in background, listening on {server_socket_path}...")
    server_task = asyncio.create_task(server_instance.serve())

    try:
        # Wait for the server to be ready
        await server_instance.wait_for_server_ready(timeout=5.0)
        logger.info("Server is ready.")

        # 3. Construct the handshake string that the dummy executable will output.
        # This mimics what a real plugin server would print to stdout.
        core_v = rpcplugin_config.get("PLUGIN_CORE_VERSION")
        # Get actual protocol version negotiated by the server if possible, else default
        proto_v = getattr(server_instance, "_protocol_version", "1")
        # Get actual endpoint from the running server's transport
        server_transport_endpoint = getattr(getattr(server_instance, "_transport", None), "endpoint", None)

        if not server_transport_endpoint:
            raise RuntimeError("Server transport endpoint not available after server ready.")

        # Handshake: CORE_VER|PLUGIN_VER|NET_TYPE|NET_ADDR|PROTOCOL_NAME|CERT_BODY
        # For this example, PROTOCOL_NAME is 'grpc' (standard for go-plugin compatibility)
        # and CERT_BODY is empty as we are not using mTLS here.
        handshake_output_string = f"{core_v}|{proto_v}|unix|{server_transport_endpoint}|grpc|"
        logger.info(f"Dummy executable will output handshake: {handshake_output_string}")

        # Create the dummy executable shell script
        dummy_executable_file = Path("./dummy_e2e_handshaker.sh").resolve()
        with open(dummy_executable_file, "w") as f:
            f.write("#!/bin/sh\n")
            f.write(f"echo '{handshake_output_string}'\n") # Script just echoes the handshake
        dummy_executable_file.chmod(0o755) # Make it executable

        # 4. Create and start the RPCPluginClient
        client_instance = None
        try:
            logger.info(f"Client will launch dummy executable: {dummy_executable_file}")
            # The client is configured to run our dummy shell script.
            client_instance = plugin_client(command=[str(dummy_executable_file)])
            await client_instance.start() # Launches script, reads handshake, connects
            logger.info("Client connected to in-process server successfully via dummy executable.")

            # 5. Simulate an RPC call
            # Since BasicRPCPluginProtocol doesn't register a real gRPC service/stub,
            # we can't make a gRPC call through client.grpc_channel easily without one.
            # Instead, we'll directly call the handler method on the server instance
            # to prove the server is running and the concept works.
            if client_instance.is_started:
                logger.info("Client is connected. Simulating RPC call to server's handler...")
                request_obj = GreetingRequest(name="E2E Demo User")
                # Directly calling the handler method on the server instance
                reply_obj = await handler_instance.Greet(request_obj, None) # Context is None for this sim
                logger.info(f"Simulated RPC Reply from server: '{reply_obj.message}'")
                assert "E2E Demo User" in reply_obj.message
            else:
                logger.error("Client failed to connect as expected.")

        except Exception as client_err:
            logger.error(f"Error during client operations: {client_err}", exc_info=True)
        finally:
            if client_instance:
                await client_instance.close() # This also "terminates" the dummy script
                logger.info("Client closed.")
            if dummy_executable_file.exists():
                dummy_executable_file.unlink()
                logger.info("Dummy executable cleaned up.")

    except Exception as e:
        logger.error(f"An error occurred in the main E2E example: {e}", exc_info=True)
    finally:
        # Stop the server and wait for its task to complete
        logger.info("Stopping in-process server...")
        await server_instance.stop()
        if not server_task.done():
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                logger.info("Server task cancelled.")
        logger.info("Server stopped.")

        # Clean up the server's socket file
        if server_socket_path.exists():
            try:
                server_socket_path.unlink()
                logger.info("Server socket file cleaned up.")
            except OSError as e:
                logger.warning(f"Could not remove server socket file {server_socket_path}: {e}")

    logger.info("✅ End-to-end example finished.")

if __name__ == "__main__":
    # Configure for example runs (e.g. sets default magic cookie for server if not set by client)
    from example_utils import configure_for_example
    configure_for_example()
    asyncio.run(main())
```

**Breakdown of `11_end_to_end.py`:**

1.  **Service Definition (Conceptual)**:
    *   `GreetingRequest` and `GreetingReply` are `attrs` classes mimicking Protobuf messages.
    *   `GreeterServiceHandler` is a simple class with an `async def Greet` method, acting like a gRPC servicer.

2.  **Server Setup**:
    *   A `BasicRPCPluginProtocol` (via `plugin_protocol()`) and the `GreeterServiceHandler` are used to create an `RPCPluginServer`.
    *   The server is configured to use a Unix domain socket (`e2e_server.sock`).
    *   `server_instance.serve()` is run in a background `asyncio.task`.
    *   The script waits for the server to be ready using `await server_instance.wait_for_server_ready()`.

3.  **Dummy Executable Creation**:
    *   A crucial part of this example is creating a *fake* plugin executable (`dummy_e2e_handshaker.sh`).
    *   This shell script does only one thing: `echo` the exact handshake string that a real plugin (our `server_instance`) would produce.
    *   The handshake string is carefully constructed using the `RPCPluginServer`'s actual negotiated details (core version, protocol version, and its Unix socket endpoint).

4.  **Client Setup and Connection**:
    *   An `RPCPluginClient` is created, with its `command` set to execute the `dummy_e2e_handshaker.sh` script.
    *   When `await client_instance.start()` is called:
        *   The shell script runs.
        *   It prints the pre-calculated handshake string to its stdout.
        *   The `RPCPluginClient` reads this, parses it, and "connects" to the Unix socket where `server_instance` (running in the same process) is listening.

5.  **Simulated RPC Call**:
    *   Because `BasicRPCPluginProtocol` doesn't register any real gRPC services that the client could call via a stub, the example directly calls `handler_instance.Greet(...)`. This isn't a true RPC call over the established channel but demonstrates that the server-side logic is reachable and the conceptual flow is complete. A real end-to-end test with custom services would involve generating and using gRPC stubs.

6.  **Cleanup**:
    *   The client, dummy executable, server, and socket file are all cleaned up.

This example, while a bit artificial due to the in-process nature and the dummy executable, effectively tests and demonstrates the core handshake and connection mechanisms of `RPCPluginClient` and `RPCPluginServer` working together.
