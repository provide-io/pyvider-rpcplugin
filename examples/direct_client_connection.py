#!/usr/bin/env python3
# examples/ch08_direct_client_connection.py
"""
Demonstrates a client connecting directly to an independently running
pyvider-rpcplugin server using a known transport path (e.g., Unix socket).

This contrasts with examples that use `plugin_client` to launch the server.
To run this example:
1. Start the `ch02_dummy_server.py` first, ensuring it's configured to
   write its socket path. From the project root, run:
   `export PYVIDER_WRITE_SOCKET_PATH="true"`
   `export PLUGIN_MAGIC_COOKIE="pyvider-example-cookie"`
   (if server expects it for standalone)
   `python examples/ch02_dummy_server.py`
   The `ch02_dummy_server.py` is adapted to write its socket path to
   `dummy_server_socket.txt` in the project root when `PYVIDER_WRITE_SOCKET_PATH`
   is true or when run as `__main__`. It also defaults to PLUGIN_AUTO_MTLS=False.
2. This script (`ch08_direct_client_connection.py`) will automatically read the
   socket path from `dummy_server_socket.txt`.
3. Run this script: `python examples/ch08_direct_client_connection.py`
"""

import asyncio
from pathlib import Path

# example_utils.configure_for_example() should handle path adjustments.
# Manual sys.path manipulation is generally discouraged if a utility handles it.
# example_dir = Path(__file__).resolve().parent
# project_root = example_dir.parent
# src_path = project_root / "src"
# if src_path.exists() and str(src_path) not in sys.path:
#     sys.path.insert(0, str(src_path))
from example_utils import (  # type: ignore[import-not-found]
    clear_plugin_env_vars,
    configure_for_example,
)
import grpc  # For direct gRPC channel usage
from provide.foundation import logger

# Define project_root for SOCKET_COMM_FILE path construction
project_root = Path(__file__).resolve().parent.parent
# Path to the file where ch02_dummy_server.py writes its socket path
SOCKET_COMM_FILE = project_root / "dummy_server_socket.txt"


async def run_direct_client() -> None:
    """Connects to an independently running server."""
    print("🚀 pyvider-rpcplugin Direct Client Connection Example")
    print("======================================================")

    socket_path_read = None  # Renamed to avoid conflict with global SOCKET_PATH if it were used
    try:
        socket_path_read = SOCKET_COMM_FILE.read_text().strip()
        logger.info(f"Read socket path from {SOCKET_COMM_FILE}: {socket_path_read}")
    except FileNotFoundError:
        logger.error(
            f"Socket communication file not found: {SOCKET_COMM_FILE}. Ensure "
            "ch08_dummy_server.py ran successfully and wrote this file."
        )
        print(f"❌ Socket path file not found: {SOCKET_COMM_FILE}. Start server first.")
        return
    except Exception as e:
        logger.error(f"Error reading socket path file: {e}", exc_info=True)
        print(f"❌ Error reading socket path from {SOCKET_COMM_FILE}: {e}")
        return

    if not socket_path_read:  # Check the renamed variable
        logger.error("Socket path is empty. Cannot connect.")
        print("❌ Socket path is empty in communication file.")
        return

    logger.info(f"Attempting to connect directly to server at Unix socket: {socket_path_read}")
    logger.warning(f"Ensure a server is running and listening on '{socket_path_read}'.")

    # Configure client-side aspects if necessary (e.g., logging)
    # No magic cookie env vars needed by this client as it's not launching the server.
    clear_plugin_env_vars()  # From example_utils
    configure_for_example()  # Call for basic path setup from example_utils

    from pyvider.rpcplugin import (
        configure as pyvider_core_configure,
    )  # Specific configure

    pyvider_core_configure(
        log_level="DEBUG", auto_mtls=False
    )  # Match typical dummy server config using pyvider's own configure

    # THIS IS THE LINE THAT HAD THE TYPO - USING socket_path_read (lowercase)
    target = f"unix:{socket_path_read}"
    channel = None
    try:
        # For a server script not launched by this client, connect directly
        # using grpc.aio.
        # This example assumes an insecure channel (no mTLS).
        # For mTLS, you would use grpc.aio.secure_channel() with credentials.
        logger.info(f"Creating insecure gRPC channel to {target}...")
        channel = grpc.aio.insecure_channel(target)

        logger.info("Waiting for channel to be ready (timeout 5s)...")
        await asyncio.wait_for(channel.channel_ready(), timeout=5.0)
        logger.info(f"Successfully connected to {target}")
        print(f"\n✅ Successfully connected to server at {target}")

        # At this point, you would typically use a gRPC stub generated
        # from your .proto file to make RPC calls. For example:
        # stub = YourServiceStub(channel)
        # response = await stub.YourMethod(YourRequest(data="hello from direct client"))
        # logger.info(f"Received response: {response.message}")
        print(
            "   (No RPC calls made in this basic direct connection example"
            " as dummy_server has no custom methods.)"
        )
        await asyncio.sleep(1)  # Keep connection for a moment

    except TimeoutError:
        logger.error(
            # Corrected to use socket_path_read in log message
            f"Timeout: Failed to connect to {target} within 5 seconds. "
            f"Is the server running and the socket path '{socket_path_read}' correct?"
        )
        # Corrected to use socket_path_read in print message
        print(f"❌ Timeout connecting to {target}. Check server status and socket path '{socket_path_read}'.")
    except grpc.aio.AioRpcError as e:
        logger.error(
            f"gRPC Error during connection: {e.code()} - {e.details()}",
            exc_info=True,
        )
        print(f"❌ gRPC error: {e.details()}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        print(f"❌ Unexpected error: {e}")
    finally:
        if channel:
            logger.info("Closing gRPC channel.")
            await channel.close(grace=None)
            print("   gRPC channel closed.")
        print("\n✅ Direct Client Connection Example Finished.")


if __name__ == "__main__":
    asyncio.run(run_direct_client())

# 🐍🔌🖥️🪄
