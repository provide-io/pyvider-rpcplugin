# tests/fixtures/mocks.py

import asyncio
import os
from collections.abc import AsyncGenerator
from contextlib import suppress
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from pytest_mock import MockerFixture

from pyvider.rpcplugin.config import (
    CONFIG_SCHEMA,
    rpcplugin_config,
)
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.transport import (
    TCPSocketTransport,
    UnixSocketTransport,
)
from pyvider.rpcplugin.transport.base import (
    RPCPluginTransport,
)
from pyvider.telemetry import logger


class MockProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(
        self,
    ) -> tuple[Any | None, str]:
        logger.debug("🔌🚀✅ MockProtocol.get_grpc_descriptors called.")
        return (None, "MockService")

    async def add_to_server(
        self, server: Any, handler: Any
    ) -> None:
        logger.debug(
            f"🔌🚀✅ MockProtocol.add_to_server called with server: {server}, "
            f"handler: {handler}."
        )
        pass

    def get_method_type(self, method_name: str) -> str:
        logger.debug("🔌🚀✅ MockProtocol.get_method_type called.")
        return "unary_unary"


class MockHandler:
    """Mock handler for testing the RPCPluginServer."""

    async def GetRequest(self, request: Any, context: Any) -> None:
        logger.debug("🔌🚀✅ MockHandler.GetRequest called.")
        return None

    async def GetResponse(self, request: Any, context: Any) -> None:
        logger.debug("🔌🚀✅ MockHandler.GetResponse called.")
        return None

    async def PutRequest(self, request: Any, context: Any) -> None:
        logger.debug("🔌🚀✅ MockHandler.PutRequest called.")
        return None

    async def Empty(self, request: Any, context: Any) -> None:
        logger.debug("🔌🚀✅ MockHandler.Empty called.")
        return None


class MockServicer:
    pass


class MockBytesIO:
    """Mock implementation of sys.stdout.buffer for testing."""

    def __init__(self, string_io: Any) -> None:
        self.string_io = string_io

    def write(self, data: bytes | str) -> int:
        if isinstance(data, bytes):
            self.string_io.write(data.decode("utf-8"))
        else:
            self.string_io.write(str(data))
        return len(data)

    def flush(self) -> None:
        self.string_io.flush()


@pytest_asyncio.fixture(scope="function", params=["tcp", "unix"])
async def mock_server_transport(
    request: Any, managed_unix_socket_path: str
) -> AsyncGenerator[RPCPluginTransport, None]:
    transport_name = request.param
    transport: RPCPluginTransport | None = None

    logger.debug(f"🧪🔌🐛 mock_server_transport called for transport: {transport_name}")

    if transport_name == "tcp":
        transport = TCPSocketTransport()
        logger.debug("🧪🔌🐛 Providing TCPSocketTransport")
        yield transport
    elif transport_name == "unix":
        logger.debug(
            f"🧪🔌🐛 Providing UnixSocketTransport with path: "
            f"{managed_unix_socket_path}"
        )
        transport = UnixSocketTransport(path=managed_unix_socket_path)
        yield transport
    else:
        raise ValueError(f"Unknown transport parameter: {transport_name}")

    if transport:
        endpoint_info = getattr(
            transport, "path", getattr(transport, "endpoint", "N/A")
        )
        logger.debug(
            f"🧪🔌🐛 Cleaning up transport {transport_name} for "
            f"path/endpoint: {endpoint_info}"
        )
        try:
            await transport.close()
        except Exception as e:
            logger.error(f"🧪🔌🐛 Error during transport.close(): {e}")
        await asyncio.sleep(0.1)
    else:
        logger.warning(
            f"🧪🔌🐛 Transport was None for {transport_name}, "
            f"no cleanup performed by mock_server_transport."
        )


@pytest_asyncio.fixture
async def mock_server_transport_tcp() -> AsyncGenerator[RPCPluginTransport, None]:
    transport = TCPSocketTransport()
    try:
        yield transport
    except Exception:
        raise ValueError(
            f"Could not open a TCP Socket Transport: {transport!r}"
        )
    finally:
        await transport.close()
        await asyncio.sleep(0.1)


@pytest_asyncio.fixture(scope="function")
async def mock_server_transport_unix(
    managed_unix_socket_path: str,
) -> AsyncGenerator[RPCPluginTransport, None]:
    """Fixture providing a properly configured Unix transport with unique path."""
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    try:
        await transport.listen()
        logger.debug(f"🧪✅ Unix transport initialized at {managed_unix_socket_path}")
        yield transport
    finally:
        try:
            await transport.close()
            logger.debug(f"🧪🧹 Transport closed for {managed_unix_socket_path}")
            if os.path.exists(managed_unix_socket_path):
                os.chmod(managed_unix_socket_path, 0o770)  # nosec B103
                os.unlink(managed_unix_socket_path)
                logger.debug(
                    f"🧪🧹 Manually removed socket file {managed_unix_socket_path}"
                )
        except Exception as e:
            logger.error(f"🧪❌ Error cleaning transport: {e}")


@pytest.fixture(scope="function")
def mock_server_handler() -> MockHandler:
    """Fixture to provide a mock handler instance."""
    return MockHandler()


@pytest_asyncio.fixture(scope="function")
async def mock_server_protocol() -> MockProtocol:
    """Fixture to provide a mock protocol class."""
    proto = MockProtocol()
    return proto


@pytest.fixture(scope="function")
def mock_server_config(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """
    Provides the global RPCPluginConfig instance, applying temporary test
    defaults.
    """
    _ = rpcplugin_config.instance()

    test_defaults = {
        "PLUGIN_MAGIC_COOKIE_KEY": "PLUGIN_MAGIC_COOKIE",
        "PLUGIN_MAGIC_COOKIE_VALUE": "hello-fixture-mock-TLS-v2",
        "PLUGIN_MAGIC_COOKIE": "hello-fixture-mock-TLS-v2",
        "PLUGIN_PROTOCOL_VERSIONS": [7],
        "PLUGIN_SERVER_TRANSPORTS": ["unix"],
        "PLUGIN_SERVER_ENDPOINT": None,
        "PLUGIN_SERVER_CERT": None,
        "PLUGIN_SERVER_KEY": None,
        "PLUGIN_CLIENT_CERT": None,
    }

    for key, value in test_defaults.items():
        if rpcplugin_config.config is not None:
            monkeypatch.setitem(rpcplugin_config.config, key, value)
        else: # Should not happen after instance() call
            logger.error(
                "CRITICAL: rpcplugin_config.config is None in "
                "mock_server_config fixture! This should not happen."
            )
            rpcplugin_config.config = {
                k: v_meta.get("default") for k, v_meta in CONFIG_SCHEMA.items()
            }

    return rpcplugin_config.config.copy()


@pytest_asyncio.fixture
async def server_with_mocks(
    mock_server_protocol: MockProtocol,
    mock_server_handler: MockHandler,
    mock_server_config: dict[str, Any],
    mock_server_transport: RPCPluginTransport,
) -> AsyncGenerator[RPCPluginServer, None]:
    """Fixture to provide a server instance with mocks."""
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport,
    )
    try:
        yield server
    finally:
        with suppress(Exception):
            if server:
                await server.stop()


@pytest.fixture(scope="function")
def mock_server_config_dict_fixture(
    mock_server_config: dict[str, Any]
) -> dict[str, Any]:
    """
    Provides the server configuration as a dictionary.
    Depends on mock_server_config to ensure config is populated.
    """
    return mock_server_config
