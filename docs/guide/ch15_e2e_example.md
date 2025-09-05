# Chapter 15: End-to-End Example Walkthrough

This chapter walks through an end-to-end example that demonstrates a `RPCPluginClient` launching a separate `RPCPluginServer` process and making a real gRPC call.

The example consists of three main parts:
1.  A Protobuf definition for a simple `Greeter` service (`examples/proto/e2e_greeting.proto`).
2.  A plugin server script (`examples/ch15_e2e_server.py`) that implements this `Greeter` service.
3.  A client script (`examples/ch15_e2e_client.py`) that launches the server and calls its `Greet` method.

## 1. Protobuf Definition (`examples/proto/e2e_greeting.proto`)

This file defines the service interface using Protocol Buffers.

```protobuf
syntax = "proto3";

package examples.e2e_greeting;

option go_package = "github.com/provide-io/pyvider-rpcplugin/examples/proto/e2e_greeting"; // Example Go package

// The Greeter service definition.
service Greeter {
  // Sends a greeting
  rpc Greet (GreetingRequest) returns (GreetingReply) {}
}

// The request message containing the name to greet.
message GreetingRequest {
  string name = 1;
}

// The response message containing the greeting.
message GreetingReply {
  string message = 1;
}
```
This `.proto` file is compiled using `grpc_tools.protoc` to generate `e2e_greeting_pb2.py` (containing message classes) and `e2e_greeting_pb2_grpc.py` (containing client stubs and server base classes). These generated files are placed in `examples/proto/`.

## 2. The Plugin Server (`examples/ch15_e2e_server.py`)

This script implements the `Greeter` service and runs an `RPCPluginServer`.

```python
#!/usr/bin/env python3
# examples/ch15_e2e_server.py
"""
End-to-End Greeter Plugin Server.
"""
import asyncio
import os
from typing import Any, cast

import grpc

# Import pyvider components
from pyvider.rpcplugin.factories import plugin_server
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.types import RPCPluginProtocol as TypesRPCPluginProtocol
from provide.foundation import logger

# Import generated protobuf code for E2E Greeting service
from examples.proto import e2e_greeting_pb2
from examples.proto import e2e_greeting_pb2_grpc


# --- Implement the Handler (Servicer) ---
class GreeterServiceHandler(e2e_greeting_pb2_grpc.GreeterServicer):
    """
    Implements the Greeter service.
    """
    async def Greet(
        self, request: e2e_greeting_pb2.GreetingRequest, context: grpc.aio.ServicerContext
    ) -> e2e_greeting_pb2.GreetingReply:
        logger.info(
            "GreeterServiceHandler: Received Greet request",
            client_name=request.name,
        )
        message = f"Hello, {request.name}! This is a real end-to-end call from the E2E server."
        return e2e_greeting_pb2.GreetingReply(message=message)

# --- Implement the Protocol Wrapper ---
class E2EGreetingProtocol(RPCPluginProtocol):
    """
    RPCPluginProtocol implementation for the E2E Greeter service.
    """
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        # Return the generated _pb2_grpc module and the Service name string
        return e2e_greeting_pb2_grpc, "examples.e2e_greeting.Greeter"

    def get_method_type(self, method_name: str) -> str:
        if "Greet" in method_name:
            return "unary_unary"
        logger.warning(f"Unknown method {method_name} in E2EGreetingProtocol, defaulting to unary_unary.")
        return "unary_unary"

    async def add_to_server(self, server: Any, handler: Any) -> None:
        # Register the handler with the gRPC server
        e2e_greeting_pb2_grpc.add_GreeterServicer_to_server(
            cast(GreeterServiceHandler, handler), server
        )
        logger.info("GreeterService handler registered with gRPC server.")

# --- Main Server Logic ---
async def main() -> None:
    logger.info("Starting E2E Greeting Plugin Server (ch15_e2e_server.py)...")

    handler = GreeterServiceHandler()
    e2e_protocol_instance = cast(TypesRPCPluginProtocol, E2EGreetingProtocol())

    server: RPCPluginServer = plugin_server(
        protocol=e2e_protocol_instance,
        handler=handler,
    )

    try:
        await server.serve()
    except Exception as e:
        logger.error(f"E2E Greeting Server execution failed: {e}", exc_info=True)
    finally:
        logger.info("E2E Greeting Server (ch15_e2e_server.py) shutting down.")

if __name__ == "__main__":
    from examples.example_utils import configure_for_example
    configure_for_example()

    asyncio.run(main())
```
**Key points for the server:**
*   `GreeterServiceHandler` inherits from `e2e_greeting_pb2_grpc.GreeterServicer` and implements the `Greet` method using the generated protobuf message types.
*   `E2EGreetingProtocol` implements `RPCPluginProtocol` to provide descriptors from `e2e_greeting_pb2_grpc` and register the `GreeterServiceHandler`.
*   The `main` function sets up and runs the `RPCPluginServer`.

## 3. The Client Application (`examples/ch15_e2e_client.py`)

This script launches the `ch15_e2e_server.py` and makes an RPC call to it.

```python
#!/usr/bin/env python3
# examples/ch15_e2e_client.py
"""
End-to-End Greeter Plugin Client.
Launches the ch15_e2e_server.py and makes a gRPC call.
"""
import asyncio
import os
import sys
from pathlib import Path
# from typing import Any # Retain commented out or remove fully if not used

# Import pyvider components
from pyvider.rpcplugin.client import RPCPluginClient # noqa: E402
from pyvider.rpcplugin.exception import RPCPluginError # noqa: E402
from provide.foundation import logger # noqa: E402

# Import generated protobuf code for E2E Greeting service
from examples.proto import e2e_greeting_pb2, e2e_greeting_pb2_grpc # noqa: E402


async def main() -> None:
    logger.info("🚀 Starting E2E Greeting Client (ch15_e2e_client.py)")

    current_dir = Path(__file__).resolve().parent
    server_script_path = current_dir / "ch15_e2e_server.py"

    if not server_script_path.exists():
        logger.error(f"Could not find server script: {server_script_path}")
        return

    from pyvider.rpcplugin import rpcplugin_config # Import for reading client's config

    # Configure environment for the server subprocess
    client_config = {
        "env": {
            "PLUGIN_MAGIC_COOKIE_KEY": rpcplugin_config.magic_cookie_key(),
            "PLUGIN_MAGIC_COOKIE_VALUE": rpcplugin_config.magic_cookie_value(),
            "PLUGIN_LOG_LEVEL": rpcplugin_config.get("PLUGIN_LOG_LEVEL", "DEBUG"), # Use client's log level
            "PLUGIN_AUTO_MTLS": "False" # Explicitly disable mTLS for this example server
        }
    }

    client: RPCPluginClient | None = None
    try:
        logger.info(f"Client launching plugin server: {server_script_path}")
        client = RPCPluginClient(
            command=[sys.executable, str(server_script_path)],
            config=client_config
        )

        logger.info("Starting client and connecting to plugin server...")
        await client.start()

        if not client.grpc_channel:
            logger.error("Client connected but gRPC channel is not available.")
            return

        logger.info("✅ Client connected to E2E Greeting server successfully!")

        stub = e2e_greeting_pb2_grpc.GreeterStub(client.grpc_channel)
        request_pb = e2e_greeting_pb2.GreetingRequest(name="Real E2E User")

        logger.info(f"📞 Calling Greet method with name: '{request_pb.name}'...")
        response_pb = await stub.Greet(request_pb, timeout=10.0)

        logger.info(f"💬 Server replied: '{response_pb.message}'")
        assert "Real E2E User" in response_pb.message
        assert "from the E2E server" in response_pb.message

    except RPCPluginError as e:
        logger.error(f"❌ Client RPCPluginError: {e.message}", exc_info=True)
        if e.hint:
            logger.error(f"   Hint: {e.hint}")
    except Exception as e:
        logger.error(f"❌ An unexpected error occurred: {e}", exc_info=True)
    finally:
        if client:
            logger.info("Shutting down client and plugin server...")
            await client.close()
            logger.info("Client and plugin server shut down.")

if __name__ == "__main__":
    from examples.example_utils import configure_for_example
    configure_for_example()

    os.environ['PYTHONIOENCODING'] = 'UTF-8'
    asyncio.run(main())
```
**Key points for the client:**
*   It creates an `RPCPluginClient` instance, providing the command to run `ch15_e2e_server.py`.
*   After `await client.start()` successfully connects, it uses `client.grpc_channel` to create a `GreeterStub`.
*   It then makes a true RPC call: `await stub.Greet(request_pb)`.

This example accurately demonstrates the client-launches-server pattern with actual gRPC communication mediated by `pyvider.rpcplugin`.
To run this example:
1.  **Compile Protobufs**: First, ensure the gRPC Python stubs are generated from the `.proto` file. From the project root, run:
    ```bash
    (cd examples/proto && python -m grpc_tools.protoc -I. --python_out=. --pyi_out=. --grpc_python_out=. e2e_greeting.proto)
    ```
2.  **Set PYTHONPATH (if needed)**: The generated gRPC files import each other directly. To ensure Python can find them correctly when the example scripts are run from the project root, you might need to add the `examples/proto` directory to your `PYTHONPATH`. You can do this temporarily for the command:
    ```bash
    PYTHONPATH=${PYTHONPATH}:$(pwd)/examples/proto python examples/ch15_e2e_client.py
    ```
    Alternatively, you can export `PYTHONPATH` in your shell session before running:
    ```bash
    export PYTHONPATH=${PYTHONPATH}:$(pwd)/examples/proto
    python examples/ch15_e2e_client.py
    ```
3.  **Execute the client**: Once the above are handled, navigate to the project root and run the client.
    ```bash
    python examples/ch15_e2e_client.py
    ```
    (If you didn't export `PYTHONPATH` in step 2, use the combined command from that step.)

The client will launch the server, make the call, and then both will shut down.
