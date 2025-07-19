import asyncio
from pathlib import Path
from pyvider.rpcplugin import plugin_client, RPCPluginError # Assuming RPCPluginError is in rpcplugin
from pyvider.telemetry import logger # Assuming setup_logging might not be needed if config handles it

# This example demonstrates the async context manager.
# It uses a dummy server executable for the client to start.
async def manage_client_with_context():
    # Logging level will be set by PLUGIN_LOG_LEVEL environment variable

    # Determine path to dummy_server.sh
    # Corrected path logic to be more robust when script is run from /app
    base_path = Path('/app') # Running from /app
    dummy_server_path_abs = (base_path / "examples" / "dummy_server.sh").resolve()

    if not dummy_server_path_abs.exists():
        logger.error(f"dummy_server.sh not found at expected path: {dummy_server_path_abs}. "
                     "Ensure examples/dummy_server.sh exists in the project root.")
        print(f"Error: dummy_server.sh not found at {dummy_server_path_abs}")
        return

    logger.info(f"Using dummy_server.sh path: {dummy_server_path_abs}")

    # Configure client to use the dummy server
    # PLUGIN_AUTO_MTLS=False should be inherited if set for the subtask
    client = plugin_client(server_path=str(dummy_server_path_abs))
    try:
        async with client:
            # client.start() is automatically called by __aenter__
            logger.info(f"Client started. Handshake info: {client.handshake_info}")
            # The dummy_server.sh doesn't establish a real gRPC channel,
            # so client.grpc_channel would typically be None or unusable here.
            # We're primarily testing the context manager's start/close lifecycle.
            logger.info("Client is active within the 'async with' block.")
            await asyncio.sleep(0.1) # Simulate some work
        logger.info("Client has been closed automatically by __aexit__.")
    except FileNotFoundError:
        logger.error(f"dummy_server.sh not found at {dummy_server_path_abs}. "
                     "This check should have caught it earlier.")
    except RPCPluginError as e:
        logger.error(f"An RPCPluginError occurred: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(manage_client_with_context())
