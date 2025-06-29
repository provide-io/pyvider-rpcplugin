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
from typing import Any

# Call configure_for_example() early to set up sys.path
# Import example_utils directly, as it's in the same directory.
import sys # Add sys import
from pathlib import Path # Add Path import

# Force project root onto sys.path immediately
project_root_for_client = str(Path(__file__).resolve().parent.parent)
if project_root_for_client not in sys.path:
    sys.path.insert(0, project_root_for_client)

import example_utils
example_utils.configure_for_example()

# Import pyvider components
from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.exception import RPCPluginError
from pyvider.telemetry import logger

# Import generated protobuf code for E2E Greeting service
# This needs to be done after example_utils.configure_for_example() has run.
# We will import them inside main() or where they are first needed.


async def main() -> None:
    logger.info("🚀 Starting E2E Greeting Client (ch15_e2e_client.py)")

    # Import proto modules here, after sys.path is configured
    import examples.proto # Import the package itself

    # Determine path to the server script
    current_dir = Path(__file__).resolve().parent
    server_script_path = current_dir / "ch15_e2e_server.py" # Updated name

    if not server_script_path.exists():
        logger.error(f"Could not find server script: {server_script_path}")
        return

    # The client's `example_utils.configure_for_example(clear_env=True)` sets up its
    # rpcplugin_config. `RPCPluginClient._launch_process` will use these
    # client-side config values (PLUGIN_MAGIC_COOKIE_KEY and PLUGIN_MAGIC_COOKIE_VALUE)
    # to set the correct environment variable for the server.
    # The server (`ch15_e2e_server.py`), also calling `configure_for_example(clear_env=False)`,
    # will have matching default expectations for these.
    from pyvider.rpcplugin import rpcplugin_config # Import for default log level
    client_config = {
        "env": {
            # Propagate the client's log level to the server for example consistency.
            "PLUGIN_LOG_LEVEL": rpcplugin_config.get("PLUGIN_LOG_LEVEL", "INFO")
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

        # Create a stub and make an RPC call
        stub = examples.proto.e2e_greeting_pb2_grpc.GreeterStub(client.grpc_channel)
        request_pb = examples.proto.e2e_greeting_pb2.GreetingRequest(name="Real E2E User")

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
    # Client context, clear its own env before specific example logic.
    configure_for_example(clear_env=True)

    # Ensure PYTHONIOENCODING is set for subprocesses, good practice
    os.environ['PYTHONIOENCODING'] = 'UTF-8'

    asyncio.run(main())
