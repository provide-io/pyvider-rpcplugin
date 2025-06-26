# tests/fixtures/server.py

import pytest
import pytest_asyncio

import asyncio

from pyvider.telemetry import logger  # Added for logging in fixture
from pyvider.rpcplugin.server import RPCPluginServer


@pytest.fixture
def valid_server_env(monkeypatch) -> None:
    monkeypatch.setenv("PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE")
    monkeypatch.setenv(
        "PLUGIN_MAGIC_COOKIE",
        "hello",
    )
    monkeypatch.setenv("PLUGIN_PROTOCOL_VERSIONS", "1,2,3,4,5,6,7")
    monkeypatch.setenv("PLUGIN_TRANSPORTS", "tcp")


@pytest_asyncio.fixture(scope="module")
async def server_instance(
    mock_server_config,
    mock_server_protocol,
    mock_server_handler,
    mock_server_transport,
    client_cert,
):
    from pyvider.rpcplugin.config import rpcplugin_config

    try:
        # Set environment variables
        rpcplugin_config.set("PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE")
        rpcplugin_config.set(
            "PLUGIN_MAGIC_COOKIE",
            "d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2",
        )
        rpcplugin_config.set("PLUGIN_PROTOCOL_VERSIONS", "6")
        rpcplugin_config.set("PLUGIN_TRANSPORTS", "unix")
        rpcplugin_config.get("PLUGIN_CLIENT_CERT")

        # Start the server with mock handler
        server = RPCPluginServer(
            protocol=mock_server_protocol,
            handler=mock_server_handler,
            config=mock_server_config,
            transport=mock_server_transport,  # This transport's path is managed by managed_unix_socket_path
        )
        serve_task = asyncio.create_task(server.serve())

        # Wait for server readiness
        await asyncio.wait_for(server.wait_for_server_ready(), timeout=10)

        yield server
    finally:
        # Cleanup
        await server.stop()
        if serve_task and not serve_task.done():
            logger.debug("Attempting to await server.serve() task in fixture cleanup.")
            try:
                await asyncio.wait_for(serve_task, timeout=5.0)
                logger.debug(
                    "server.serve() task completed successfully in fixture cleanup."
                )
            except asyncio.TimeoutError:
                logger.error(
                    "Timeout waiting for server.serve() task to complete in fixture."
                )
                # Optionally, cancel the task if it timed out, though stop() should handle it.
                # serve_task.cancel()
                # try:
                #     await serve_task
                # except asyncio.CancelledError:
                #     logger.info("serve_task cancelled after timeout.")
            except asyncio.CancelledError:
                logger.info("Server.serve() task was cancelled during fixture cleanup.")
            except Exception as e:
                logger.error(
                    f"An unexpected error occurred while awaiting serve_task: {e}"
                )
        else:
            logger.debug(
                "serve_task was already done or not created in fixture cleanup."
            )
        # Socket cleanup is now fully handled by the managed_unix_socket_path fixture
        # which is used by the unix_transport fixture, which mock_server_transport might be.
        # No need to check transport_name or os.path.exists here.


### 🐍🏗🧪️
