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
        "PLUGIN_MAGIC_COOKIE",  # This is the env var name the client sets for the server.
        "hello",  # This is the value the client passes in that env var.
    )
    # For a server to validate this, its own PLUGIN_MAGIC_COOKIE_VALUE must be "hello".
    # The client's PLUGIN_MAGIC_COOKIE_KEY determines the name of the env var ("PLUGIN_MAGIC_COOKIE" here).
    monkeypatch.setenv("PLUGIN_MAGIC_COOKIE_VALUE", "hello")  # Server's expected value.
    monkeypatch.setenv("PLUGIN_PROTOCOL_VERSIONS", "1,2,3,4,5,6,7")
    monkeypatch.setenv(
        "PLUGIN_SERVER_TRANSPORTS", "tcp"
    )  # Corrected from PLUGIN_TRANSPORTS


@pytest_asyncio.fixture(scope="function")  # Changed scope to function
async def server_instance(
    rpc_plugin_server_manager,
    mock_server_protocol,
    mock_server_handler,
    mock_server_config_dict_fixture,
):
    """
    Provides a function-scoped, started RPCPluginServer instance using rpc_plugin_server_manager.
    This version uses a dictionary for config overrides.
    """
    # Determine transport type from mock_server_config or default to unix
    # This part needs careful handling as mock_server_config_dict_fixture provides a dict,
    # and rpc_plugin_server_manager expects transport_type string.
    # For simplicity, let's assume default 'unix' or allow parameterization if needed.

    # Example: Get preferred transport from config if available
    # For this refactor, we'll assume 'unix' is fine for the default server_instance,
    # or that specific tests will override if they need TCP.
    # The mock_server_config_dict_fixture already sets PLUGIN_SERVER_TRANSPORTS to ["unix"]
    # in tests/fixtures/mocks.py (via mock_server_config fixture)

    # Get config dictionary from the new fixture
    config_dict = mock_server_config_dict_fixture

    # We need to decide which transport the 'server_instance' should default to.
    # Let's use "unix" as it's often the default or preferred.
    # The rpc_plugin_server_manager will use managed_unix_socket_path for it.
    # If a test needs TCP for server_instance, it would be more complex with this specific fixture.
    # It might be better for tests to use rpc_plugin_server_manager directly if they need TCP.

    server, endpoint = await rpc_plugin_server_manager(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        transport_type="unix",  # Defaulting to unix for this fixture
        config_overrides=config_dict,  # Pass the config dictionary
        auto_start=True,
    )
    # The rpc_plugin_server_manager handles cleanup.
    # yield server # Just yield the server, endpoint might not always be needed by old tests

    # To maintain compatibility with tests that might expect server_instance to also provide endpoint info implicitly
    # (though it didn't before), we can attach it. Or tests should be updated.
    # For now, just yield the server.
    yield server


@pytest_asyncio.fixture(scope="function")
async def rpc_plugin_server_manager(
    managed_unix_socket_path, unused_tcp_port, mock_server_protocol, mock_server_handler
):
    """
    Manages the lifecycle of RPCPluginServer instances for tests.
    Yields a factory function to create and start servers.
    """
    servers_to_cleanup = []

    async def _create_server(
        protocol=None,
        handler=None,
        transport_type="unix",  # "unix" or "tcp"
        config_overrides=None,
        auto_start=True,
        custom_transport=None,
        server_cls=RPCPluginServer,  # Allow specifying server class for advanced tests
    ):
        nonlocal servers_to_cleanup
        from pyvider.rpcplugin.config import (
            rpcplugin_config,
        )  # Import here to use fresh instance
        from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport
        from tests.fixtures.mocks import MockProtocol, MockHandler  # Default mocks

        protocol_to_use = (
            protocol or mock_server_protocol
        )  # Use provided fixture as default
        handler_to_use = (
            handler or mock_server_handler
        )  # Use provided fixture as default

        # Start with a copy of the current global config, then apply overrides
        # This respects the per-test isolation from reset_rpcplugin_config_singleton
        current_config_dict = rpcplugin_config.config.copy()
        if config_overrides:
            for k, v in config_overrides.items():
                # Simulate rpcplugin_config.set() behavior for direct dict modification
                # This is simplified; direct .set() might do more type validation
                current_config_dict[k] = v

        if custom_transport:
            transport_instance = custom_transport
        elif transport_type == "unix":
            socket_path = managed_unix_socket_path  # Use the path from the fixture
            logger.debug(
                f"RPCPluginServerManager: Using Unix socket path: {socket_path}"
            )
            transport_instance = UnixSocketTransport(path=socket_path)
        elif transport_type == "tcp":
            port = unused_tcp_port  # Use the port from the fixture
            logger.debug(f"RPCPluginServerManager: Using TCP port: {port}")
            transport_instance = TCPSocketTransport(host="127.0.0.1", port=port)
        else:
            raise ValueError(f"Unsupported transport_type: {transport_type}")

        # Pass the config dictionary directly. RPCPluginServer will use it.
        server = server_cls(
            protocol=protocol_to_use,
            handler=handler_to_use,
            config=current_config_dict,  # Pass the dictionary
            transport=transport_instance,
        )
        servers_to_cleanup.append(server)

        endpoint = None
        if auto_start:
            logger.debug(
                f"RPCPluginServerManager: Auto-starting server ({transport_type})..."
            )
            # RPCPluginServer.serve() is blocking. Run it in a task.
            serve_task = asyncio.create_task(server.serve())
            await asyncio.sleep(0)  # Yield control to allow serve_task to start
            try:
                await server.wait_for_server_ready(timeout=10.0)  # Increased timeout
                # After server is ready, its transport should have the actual endpoint
                if server.transport and server.transport.endpoint:
                    endpoint = server.transport.endpoint
                    logger.debug(
                        f"RPCPluginServerManager: Server ready at {endpoint}. Serve task: {serve_task}"
                    )
                else:
                    logger.error(
                        "RPCPluginServerManager: Server reported ready, but transport endpoint is missing."
                    )
                    serve_task.cancel()  # Cancel if endpoint is missing
                    await asyncio.gather(serve_task, return_exceptions=True)
                    raise RuntimeError(
                        "Server transport endpoint not available after start."
                    )
            except Exception as e:
                logger.error(
                    f"RPCPluginServerManager: Error starting server or waiting for readiness: {e}"
                )
                serve_task.cancel()
                await asyncio.gather(serve_task, return_exceptions=True)
                raise

        return server, endpoint

    yield _create_server

    # Cleanup
    logger.debug(
        f"RPCPluginServerManager: Cleaning up {len(servers_to_cleanup)} server(s)."
    )
    for server_instance_to_clean in servers_to_cleanup:
        try:
            await server_instance_to_clean.stop()
            logger.debug(
                f"RPCPluginServerManager: Stopped server: {server_instance_to_clean}"
            )
        except Exception as e:
            logger.error(
                f"RPCPluginServerManager: Error stopping server {server_instance_to_clean}: {e}"
            )
    logger.debug("RPCPluginServerManager: Cleanup complete.")


### 🐍🏗🧪️
