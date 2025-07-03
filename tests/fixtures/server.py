# tests/fixtures/server.py

import asyncio
from collections.abc import AsyncGenerator, Callable  # Added Callable, AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
from pytest import MonkeyPatch  # Added MonkeyPatch

from pyvider.rpcplugin.protocol import RPCPluginProtocol  # Added RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.transport.base import RPCPluginTransport
from pyvider.telemetry import logger


@pytest.fixture
def valid_server_env(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setenv("PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE")
    monkeypatch.setenv(
        "PLUGIN_MAGIC_COOKIE",  # This is the env var name the client sets for the server.
        "hello",  # This is the value the client passes in that env var.
    )
    # For a server to validate this, its own PLUGIN_MAGIC_COOKIE_VALUE must be "hello".
    # The client's PLUGIN_MAGIC_COOKIE_KEY determines the name of the env var
    # ("PLUGIN_MAGIC_COOKIE" here).
    monkeypatch.setenv("PLUGIN_MAGIC_COOKIE_VALUE", "hello")  # Server's expected value.
    monkeypatch.setenv("PLUGIN_PROTOCOL_VERSIONS", "1,2,3,4,5,6,7")
    monkeypatch.setenv("PLUGIN_SERVER_TRANSPORTS", "tcp")


@pytest_asyncio.fixture(scope="function")
async def server_instance(
    rpc_plugin_server_manager: Callable[
        ..., asyncio.Future[tuple[RPCPluginServer, str | None]]
    ],
    mock_server_protocol: RPCPluginProtocol,
    mock_server_handler: Any,
    mock_server_config_dict_fixture: dict[str, Any],
) -> AsyncGenerator[RPCPluginServer]:
    """
    Provides a function-scoped, started RPCPluginServer instance using
    rpc_plugin_server_manager. This version uses a dictionary for config overrides.
    """
    config_dict = mock_server_config_dict_fixture

    server, _ = await rpc_plugin_server_manager(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        transport_type="unix",  # Defaulting to unix for this fixture
        config_overrides=config_dict,
        auto_start=True,
    )
    yield server


ServerFactoryType = Callable[..., asyncio.Future[tuple[RPCPluginServer, str | None]]]


@pytest_asyncio.fixture(scope="function")
async def rpc_plugin_server_manager(
    managed_unix_socket_path: str,
    unused_tcp_port: int,
    mock_server_protocol: RPCPluginProtocol,  # Default protocol
    mock_server_handler: Any,  # Default handler
) -> AsyncGenerator[ServerFactoryType]:
    """
    Manages the lifecycle of RPCPluginServer instances for tests.
    Yields a factory function to create and start servers.
    """
    servers_to_cleanup: list[RPCPluginServer] = []

    async def _create_server(
        protocol: RPCPluginProtocol | None = None,
        handler: Any | None = None,
        transport_type: str = "unix",
        config_overrides: dict[str, Any] | None = None,
        auto_start: bool = True,
        custom_transport: RPCPluginTransport | None = None,
        server_cls: type[RPCPluginServer] = RPCPluginServer,
    ) -> tuple[RPCPluginServer, str | None]:
        nonlocal servers_to_cleanup
        from pyvider.rpcplugin.config import rpcplugin_config
        from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport

        protocol_to_use = protocol or mock_server_protocol
        handler_to_use = handler or mock_server_handler

        current_config_dict = rpcplugin_config.config.copy()
        if config_overrides:
            for k, v in config_overrides.items():
                current_config_dict[k] = v

        transport_instance: RPCPluginTransport
        if custom_transport:
            transport_instance = custom_transport
        elif transport_type == "unix":
            socket_path = managed_unix_socket_path
            logger.debug(
                f"RPCPluginServerManager: Using Unix socket path: {socket_path}"
            )
            transport_instance = UnixSocketTransport(path=socket_path)
        elif transport_type == "tcp":
            port = unused_tcp_port
            logger.debug(f"RPCPluginServerManager: Using TCP port: {port}")
            transport_instance = TCPSocketTransport(host="127.0.0.1", port=port)
        else:
            raise ValueError(f"Unsupported transport_type: {transport_type}")

        server = server_cls(
            protocol=protocol_to_use,
            handler=handler_to_use,
            config=current_config_dict,
            transport=transport_instance,
        )
        servers_to_cleanup.append(server)

        endpoint: str | None = None
        if auto_start:
            logger.debug(
                f"RPCPluginServerManager: Auto-starting server ({transport_type})..."
            )
            serve_task = asyncio.create_task(server.serve())
            await asyncio.sleep(0)
            try:
                await server.wait_for_server_ready(timeout=10.0)
                if server.transport and server.transport.endpoint:
                    endpoint = server.transport.endpoint
                    logger.debug(
                        f"RPCPluginServerManager: Server ready at {endpoint}. "
                        f"Serve task: {serve_task}"
                    )
                else:
                    logger.error(
                        "RPCPluginServerManager: Server reported ready, but "
                        "transport endpoint is missing."
                    )
                    serve_task.cancel()
                    await asyncio.gather(serve_task, return_exceptions=True)
                    raise RuntimeError(
                        "Server transport endpoint not available after start."
                    )
            except Exception as e:
                logger.error(
                    f"RPCPluginServerManager: Error starting server or waiting for "
                    f"readiness: {e}"
                )
                serve_task.cancel()
                await asyncio.gather(serve_task, return_exceptions=True)
                raise
        return server, endpoint

    yield _create_server

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
                f"RPCPluginServerManager: Error stopping server "
                f"{server_instance_to_clean}: {e}"
            )
    logger.debug("RPCPluginServerManager: Cleanup complete.")


### 🐍🏗🧪️
