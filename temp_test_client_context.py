import asyncio
from pathlib import Path
from pyvider.rpcplugin import plugin_client, RPCPluginError

# Dummy logger and setup_logging for this test
class DummyLogger:
    def info(self, msg):
        print(f"INFO: {msg}")
    def error(self, msg):
        print(f"ERROR: {msg}")
    def debug(self, msg):
        print(f"DEBUG: {msg}")

logger = DummyLogger()

def setup_logging(log_level):
    print(f"Logging setup with level: {log_level}")

# This example demonstrates the async context manager.
# It uses a dummy server executable for the client to start.
async def manage_client_with_context():
    # Setup basic logging for the example to run
    setup_logging(log_level="DEBUG")

    # Determine path to dummy_server.sh
    # Try path relative to current file first (e.g. if this script is in root/docs)
    dummy_server_path_rel_from_file = Path("../examples/dummy_server.sh")
    dummy_server_path_abs_from_file = (Path(__file__).parent / dummy_server_path_rel_from_file).resolve()

    # Fallback: try path relative to current working directory (e.g. if script is run from project root)
    dummy_server_path_rel_from_cwd = Path("examples/dummy_server.sh")
    dummy_server_path_abs_from_cwd = (Path.cwd() / dummy_server_path_rel_from_cwd).resolve()

    dummy_server_path_abs = None
    if dummy_server_path_abs_from_file.exists():
        dummy_server_path_abs = dummy_server_path_abs_from_file
    elif dummy_server_path_abs_from_cwd.exists():
        dummy_server_path_abs = dummy_server_path_abs_from_cwd


    if not dummy_server_path_abs or not dummy_server_path_abs.exists():
        logger.error(f"dummy_server.sh not found at expected paths. "
                     "Ensure examples/dummy_server.sh exists relative to project root or docs/ folder.")
        print(f"Error: dummy_server.sh not found. Searched: {dummy_server_path_abs_from_file} and {dummy_server_path_abs_from_cwd}")
        return

    # Use this path for the client command
    # Ensure PLUGIN_AUTO_MTLS is false for this dummy server which doesn't do mTLS
    os.environ["PLUGIN_AUTO_MTLS"] = "false"

    client = plugin_client(server_path=str(dummy_server_path_abs))
    try:
        async with client:
            # client.start() is automatically called by __aenter__
            # The dummy_server.sh outputs a basic handshake string.
            # We expect the client to start, read handshake, but not establish full gRPC.
            logger.info(f"Client started. Handshake successful: {client._handshake_complete_event.is_set()}")
            # Accessing client.handshake_info might be problematic if handshake didn't fully complete
            # to the point of populating that structure, or if it's not an attribute.
            # Let's check basic attributes set by _perform_handshake
            if client._address and client._transport_name:
                 logger.info(f"Handshake data: Address='{client._address}', Transport='{client._transport_name}'")
            else:
                 logger.info("Handshake data not fully populated (as expected with dummy server).")

            logger.info("Client is active within the 'async with' block.")
            await asyncio.sleep(0.1)
        logger.info("Client has been closed automatically by __aexit__.")
    except FileNotFoundError:
        logger.error(f"dummy_server.sh not found at {dummy_server_path_abs}. "
                     "Ensure path is correct for this example to run.")
    except RPCPluginError as e:
        logger.error(f"An RPCPluginError occurred: {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
   asyncio.run(manage_client_with_context())
