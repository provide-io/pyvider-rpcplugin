#!/usr/bin/env python3
# examples/e2e_greeter_client.py
"""
End-to-End Greeter Plugin Client.
Launches the e2e_greeter_server.py and makes a gRPC call.
"""

import asyncio
import os
from pathlib import Path
import sys

import example_utils  # type: ignore[import-not-found]

example_utils.configure_for_example(clear_env=True)  # For client context

# Import pyvider components
# Import generated protobuf code for E2E Greeting service
from provide.foundation import logger  # noqa: E402

from examples.proto import e2e_greeting_pb2, e2e_greeting_pb2_grpc  # noqa: E402
from pyvider.rpcplugin.client import RPCPluginClient  # noqa: E402
from pyvider.rpcplugin.exception import RPCPluginError  # noqa: E402


async def main() -> None:
    logger.info("🚀 Starting E2E Greeting Client (e2e_greeter_client.py)")

    current_dir = Path(__file__).resolve().parent
    server_script_path = current_dir / "e2e_greeter_server.py"

    if not server_script_path.exists():
        logger.error(f"Could not find server script: {server_script_path}")
        return

    from pyvider.rpcplugin import rpcplugin_config  # Import for reading client's config

    # Configure environment for the server subprocess
    client_config = {
        "env": {
            "PLUGIN_MAGIC_COOKIE_KEY": rpcplugin_config.plugin_magic_cookie_key,
            "PLUGIN_MAGIC_COOKIE_VALUE": rpcplugin_config.plugin_magic_cookie_value,
            "PLUGIN_LOG_LEVEL": rpcplugin_config.plugin_log_level,  # Use client's log level
            # Explicitly disable mTLS for this example server
            "PLUGIN_AUTO_MTLS": "False",
        }
    }

    client: RPCPluginClient | None = None
    try:
        logger.info(f"Client launching plugin server: {server_script_path}")
        client = RPCPluginClient(command=[sys.executable, str(server_script_path)], config=client_config)

        logger.info("Starting client and connecting to plugin server...")
        await client.start()

        if not client.grpc_channel:
            logger.error("Client connected but gRPC channel is not available.")
            return

        logger.info("✅ Client connected to E2E Greeting server successfully!")

        # Create a stub and make an RPC call
        stub = e2e_greeting_pb2_grpc.GreeterStub(client.grpc_channel)
        request_pb = e2e_greeting_pb2.GreetingRequest(name="Real E2E User")

        logger.info(f"📞 Calling Greet method with name: '{request_pb.name}'...")
        response_pb = await stub.Greet(request_pb, timeout=10.0)

        logger.info(f"💬 Server replied: '{response_pb.message}'")
        assert "Real E2E User" in response_pb.message  # nosec B101
        assert "from the E2E server" in response_pb.message  # nosec B101

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
    os.environ["PYTHONIOENCODING"] = "UTF-8"

    asyncio.run(main())

# 🐍🔌🖥️🪄
