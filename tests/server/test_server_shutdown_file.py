import asyncio
import os
import tempfile
import uuid
from pathlib import Path

import pytest

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.types import HandlerT, ServerT # Assuming a base HandlerT
from pyvider.telemetry import logger

# A very basic handler and protocol for testing purposes
class DummyHandler:  # No need to inherit from HandlerT for this dummy
    async def Execute(self, request, context):
        logger.debug("DummyHandler Execute called")
        return request

class DummyProtocol(RPCPluginProtocol[ServerT, HandlerT]):
    async def get_grpc_descriptors(self) -> tuple[None, str]:
        logger.debug("DummyProtocol get_grpc_descriptors called")
        return None, "dummy_service_name"

    async def add_to_server(self, server: ServerT, handler: HandlerT) -> None:
        # Simplified registration for testing
        logger.debug(f"DummyProtocol add_to_server called with handler {handler} and server {server}")
        # In a real scenario, this would involve grpc.aio.Server methods
        pass

    # remove_from_server is not part of the base RPCPluginProtocol ABC
    # async def remove_from_server(self, server):
    #     logger.debug(f"DummyProtocol remove_from_server called with server {server}")
    #     pass


@pytest.fixture
def temp_shutdown_file():
    """Creates a temporary file path for the shutdown file."""
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        path = tmpfile.name
    # Ensure the file does not exist initially for most tests
    if os.path.exists(path):
        os.unlink(path)
    yield Path(path)
    # Clean up the file after the test if it was created
    if os.path.exists(path):
        os.unlink(path)

@pytest.fixture
def server_config_override(request):
    """Fixture to temporarily override rpcplugin_config settings."""
    original_values = {}

    if hasattr(request, "param"):
        for key, value in request.param.items():
            original_values[key] = rpcplugin_config.get(key)
            rpcplugin_config.set(key, value)
            logger.debug(f"Overriding config: {key} = {value}")

    yield

    for key, value in original_values.items():
        rpcplugin_config.set(key, value)
        logger.debug(f"Restoring config: {key} = {value}")


@pytest.mark.asyncio
async def test_server_shuts_down_on_file_creation(temp_shutdown_file, server_config_override):
    """Test that the server shuts down when the shutdown file is created."""
    shutdown_file_path_str = str(temp_shutdown_file)

    # Override config to set the shutdown file path
    request_param = {"PLUGIN_SHUTDOWN_FILE_PATH": shutdown_file_path_str}
    # Manually apply the config override logic since indirect parametrization is tricky here
    original_values = {}
    for key, value in request_param.items():
        original_values[key] = rpcplugin_config.get(key)
        rpcplugin_config.set(key, value)
        logger.debug(f"Overriding config for test: {key} = {value}")

    # Configure a basic server
    # Using dummy protocol and handler for simplicity
    protocol = DummyProtocol()
    handler = DummyHandler()

    server = RPCPluginServer(protocol=protocol, handler=handler)

    # Ensure the shutdown file does not exist at the start of this specific test part
    if os.path.exists(shutdown_file_path_str):
        os.unlink(shutdown_file_path_str)

    serve_task = None
    try:
        logger.info(f"Starting server for shutdown file test. Monitoring: {shutdown_file_path_str}")
        # Run the server in a background task
        serve_task = asyncio.create_task(server.serve())

        # Wait a brief moment for the server to start its watchers
        await asyncio.sleep(0.2)

        # Simulate server readiness for this test - in a real integration, you'd wait for handshake
        # For this unit test, we assume the file watcher starts quickly.
        assert server._shutdown_file_path == shutdown_file_path_str, "Shutdown file path not configured in server"
        assert server._shutdown_watcher_task is not None, "Shutdown watcher task not started"

        logger.info(f"Creating shutdown file: {shutdown_file_path_str}")
        # Create the shutdown file
        with open(shutdown_file_path_str, "w") as f:
            f.write("shutdown")

        assert os.path.exists(shutdown_file_path_str), "Test setup failed to create shutdown file"
        logger.info(f"Shutdown file {shutdown_file_path_str} created.")

        # Wait for the server to stop, with a timeout
        # The server's serve() method should exit, or stop() should complete
        await asyncio.wait_for(serve_task, timeout=5.0)

        logger.info("Server serve_task completed after shutdown file creation.")
        # Additional checks can be that the server.stop() was called if you can instrument it,
        # or that the _serving_future is done.
        assert server._serving_future.done(), "Server's serving future was not done after expected shutdown."

    except asyncio.TimeoutError:
        if serve_task and not serve_task.done():
            serve_task.cancel()
            await asyncio.sleep(0.1) # allow cancellation to process
        pytest.fail("Server did not shut down within the timeout period after file creation.")
    except Exception as e:
        if serve_task and not serve_task.done():
            serve_task.cancel()
            await asyncio.sleep(0.1)
        pytest.fail(f"An unexpected error occurred: {e}")
    finally:
        # Clean up config
        for key, value in original_values.items():
            rpcplugin_config.set(key, value)
            logger.debug(f"Restoring config post test: {key} = {value}")

        # Explicitly stop server if it hasn't stopped, to release resources
        # This is a safeguard; the test expects serve_task to complete.
        if hasattr(server, '_server') and server._server is not None: # if grpc server object exists
             logger.warning("Server might not have shut down cleanly, attempting explicit stop.")
             await server.stop()

        if os.path.exists(shutdown_file_path_str):
            try:
                os.unlink(shutdown_file_path_str)
            except Exception as e_unlink:
                logger.error(f"Error unlinking shutdown file in finally: {e_unlink}")
        logger.info(f"Test test_server_shuts_down_on_file_creation finished.")


@pytest.mark.asyncio
async def test_server_runs_if_file_not_created(temp_shutdown_file, server_config_override):
    """Test that the server continues running if the shutdown file is not created."""
    shutdown_file_path_str = str(temp_shutdown_file)

    original_values = {}
    request_param = {"PLUGIN_SHUTDOWN_FILE_PATH": shutdown_file_path_str}
    for key, value in request_param.items():
        original_values[key] = rpcplugin_config.get(key)
        rpcplugin_config.set(key, value)

    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    if os.path.exists(shutdown_file_path_str): # Ensure not present
        os.unlink(shutdown_file_path_str)

    serve_task = None
    try:
        logger.info(f"Starting server for 'no shutdown file' test. Monitoring: {shutdown_file_path_str}")
        serve_task = asyncio.create_task(server.serve())
        await asyncio.sleep(0.5) # Give server time to start and print handshake

        # Server should be running, and its serving_future should not be done.
        assert not server._serving_future.done(), "Server's serving_future was done prematurely."
        assert server._shutdown_watcher_task is not None and not server._shutdown_watcher_task.done(), "Shutdown watcher task not running or finished."

        logger.info("Server is running, no shutdown file created. Attempting normal stop.")
        await server.stop() # Explicitly stop the server

        # Wait for the serve_task to complete after stop()
        await asyncio.wait_for(serve_task, timeout=5.0)
        assert server._serving_future.done(), "Server's serving_future was not done after explicit stop."
        logger.info("Server stopped successfully after no file was created.")

    except asyncio.TimeoutError:
        if serve_task and not serve_task.done():
            serve_task.cancel()
        pytest.fail("Server task did not complete within timeout after explicit stop.")
    except Exception as e:
        if serve_task and not serve_task.done():
            serve_task.cancel()
        pytest.fail(f"An unexpected error occurred: {e}")
    finally:
        for key, value in original_values.items():
            rpcplugin_config.set(key, value)
        if hasattr(server, '_server') and server._server is not None:
             if not server._serving_future.done(): # If stop wasn't effective or test failed before
                logger.warning("Server might not have shut down cleanly in 'no file' test, attempting explicit stop.")
                await server.stop()
        if os.path.exists(shutdown_file_path_str):
            os.unlink(shutdown_file_path_str)
        logger.info("Test test_server_runs_if_file_not_created finished.")


@pytest.mark.asyncio
async def test_server_runs_if_no_shutdown_file_configured(server_config_override):
    """Test that the server runs normally if no shutdown file path is configured."""
    # Ensure PLUGIN_SHUTDOWN_FILE_PATH is None (its default)
    # The server_config_override fixture doesn't need params if we rely on default.
    # However, to be explicit, let's set it to None.
    original_values = {}
    request_param = {"PLUGIN_SHUTDOWN_FILE_PATH": None} # Explicitly ensure it's None
    for key, value in request_param.items():
        original_values[key] = rpcplugin_config.get(key)
        rpcplugin_config.set(key, value)

    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    serve_task = None
    try:
        logger.info("Starting server for 'no shutdown path configured' test.")
        serve_task = asyncio.create_task(server.serve())
        await asyncio.sleep(0.5) # Give server time to start

        assert server._shutdown_file_path is None, "Shutdown file path was configured when it should not have been."
        assert server._shutdown_watcher_task is None, "Shutdown watcher task was started when no path was configured."
        assert not server._serving_future.done(), "Server's serving_future was done prematurely."

        logger.info("Server is running with no shutdown path. Attempting normal stop.")
        await server.stop()
        await asyncio.wait_for(serve_task, timeout=5.0)
        assert server._serving_future.done(), "Server's serving_future was not done after explicit stop."
        logger.info("Server stopped successfully when no shutdown path was configured.")

    except asyncio.TimeoutError:
        if serve_task and not serve_task.done():
            serve_task.cancel()
        pytest.fail("Server task did not complete within timeout after explicit stop (no shutdown path).")
    except Exception as e:
        if serve_task and not serve_task.done():
            serve_task.cancel()
        pytest.fail(f"An unexpected error occurred (no shutdown path): {e}")
    finally:
        for key, value in original_values.items():
            rpcplugin_config.set(key, value)
        if hasattr(server, '_server') and server._server is not None:
            if not server._serving_future.done():
                logger.warning("Server might not have shut down cleanly in 'no path' test, attempting explicit stop.")
                await server.stop()
        logger.info("Test test_server_runs_if_no_shutdown_file_configured finished.")
