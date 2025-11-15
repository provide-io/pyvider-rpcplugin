# tests/fixtures/mocks.py


import asyncio
import os

from contextlib import suppress

import pytest
import pytest_asyncio


from pyvider.telemetry import logger
from pyvider.rpcplugin.protocol import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer

from pyvider.rpcplugin.transport import (
    TCPSocketTransport,
    UnixSocketTransport,
)

from pyvider.rpcplugin.types import TransportT, HandlerT, RPCPluginHandler # RPCPluginHandler is Any
from pyvider.rpcplugin.transport.base import RPCPluginTransport # Import base for type hint
from pyvider.rpcplugin.config import rpcplugin_config  # Import global instance

from typing import Tuple, Any, AsyncGenerator # Added Any, AsyncGenerator


class MockProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self) -> Tuple[Any, str]:
        # Mock descriptors for testing
        logger.debug("🔌🚀✅ MockProtocol.get_grpc_descriptors called.")
        return (None, "MockService") # Return a 2-tuple (descriptor, service_name)

    async def add_to_server(self, server, handler) -> None: # Corrected param order
        # Mock add_to_server for testing
        logger.debug("🔌🚀✅ MockProtocol.add_to_server called.")
        pass

    def get_method_type(self, method_name: str) -> str:
        logger.debug("🔌🚀✅ MockProtocol.get_method_type called.")
        return "unary_unary"  # Mock implementation


class MockHandler:
    """Mock handler for testing the RPCPluginServer."""

    async def GetRequest(self, request, context) -> None:
        logger.debug("🔌🚀✅ MockHandler.GetRequest called.")
        return None

    async def GetResponse(self, request, context) -> None:
        logger.debug("🔌🚀✅ MockHandler.GetResponse called.")
        return None

    async def PutRequest(self, request, context) -> None:
        logger.debug("🔌🚀✅ MockHandler.PutRequest called.")
        return None

    async def Empty(self, request, context) -> None:
        logger.debug("🔌🚀✅ MockHandler.Empty called.")
        return None


class MockServicer:
    pass


class MockBytesIO:
    """Mock implementation of sys.stdout.buffer for testing."""

    def __init__(self, string_io):
        self.string_io = string_io

    def write(self, data):
        if isinstance(data, bytes):
            # Convert bytes to string for StringIO
            self.string_io.write(data.decode("utf-8"))
        else:
            # Handle string content
            self.string_io.write(str(data))
        return len(data)

    def flush(self):
        self.string_io.flush()


@pytest_asyncio.fixture(scope="function", params=["tcp", "unix"])
async def mock_server_transport(
    request, managed_unix_socket_path: str
) -> AsyncGenerator[RPCPluginTransport, None]:
    transport_name = request.param
    transport: RPCPluginTransport | None = None # Initialize transport with broader type

    logger.debug(f"🧪🔌🐛 mock_server_transport called for transport: {transport_name}")

    if transport_name == "tcp":
        # For TCP, we don't use managed_unix_socket_path.
        # The original logic for TCP can remain.
        transport = TCPSocketTransport()
        logger.debug("🧪🔌🐛 Providing TCPSocketTransport")
        yield transport
    elif transport_name == "unix":
        # Use the path from managed_unix_socket_path fixture
        logger.debug(
            f"🧪🔌🐛 Providing UnixSocketTransport with path: {managed_unix_socket_path}"
        )
        transport = UnixSocketTransport(path=managed_unix_socket_path) # This is compatible with RPCPluginTransport
        yield transport
    else:
        # This case should ideally not be reached if params are correct
        raise ValueError(f"Unknown transport parameter: {transport_name}")

    # Cleanup is handled after yield returns for the specific yielded transport
    if transport: # transport is now RPCPluginTransport | None
        logger.debug(
            f"🧪🔌🐛 Cleaning up transport {transport_name} for path/endpoint: {getattr(transport, 'path', getattr(transport, 'endpoint', 'N/A'))}"
        )
        try:
            await transport.close()
        except Exception as e:
            logger.error(f"🧪🔌🐛 Error during transport.close(): {e}")
        # Short sleep to help ensure resources are released, especially sockets.
        await asyncio.sleep(0.1)
    else:
        logger.warning(
            f"🧪🔌🐛 Transport was None for {transport_name}, no cleanup performed by mock_server_transport."
        )


@pytest_asyncio.fixture
async def mock_server_transport_tcp() -> AsyncGenerator[RPCPluginTransport, None]:
    transport = TCPSocketTransport() # Define transport before try for finally block
    try:
        yield transport
    except Exception: # Consider more specific exception if possible
        # If transport instantiation itself failed, transport might not be fully initialized.
        # This specific structure might lead to issues if TCPSocketTransport() fails.
        # However, the original error was about the return type, not this logic.
        raise ValueError(f"Could not open a TCP Socket Transport: {transport!r}") # Use !r
    finally:
        # Clean up
        await transport.close()
        await asyncio.sleep(0.1)  # Allow time for resources to be released


# @pytest_asyncio.fixture
# async def mock_server_transport_unix() -> RPCPluginTransport: # Using RPCPluginTransport for consistency
#     with tempfile.NamedTemporaryFile(delete=True) as tmp:
#         socket_path = tmp.name
#     try:
#         transport = UnixSocketTransport(path=socket_path)
#
#     except Exception:
#         raise ValueError(f"Could not open a Unix : {transport!r}") # Use !r
#
#     return transport # This fixture style (return, not yield) is different


@pytest_asyncio.fixture(scope="function")
async def mock_server_transport_unix(managed_unix_socket_path) -> AsyncGenerator[RPCPluginTransport, None]:
    """Fixture providing a properly configured Unix transport with unique path."""
    transport = UnixSocketTransport(path=managed_unix_socket_path)

    try:
        # Early startup to verify it works
        await transport.listen()
        logger.debug(f"🧪✅ Unix transport initialized at {managed_unix_socket_path}")
        yield transport
    finally:
        # Ensure proper cleanup
        try:
            await transport.close()
            logger.debug(f"🧪🧹 Transport closed for {managed_unix_socket_path}")

            # Double-check for stale socket file
            if os.path.exists(managed_unix_socket_path):
                os.chmod(managed_unix_socket_path, 0o770) # Removed problematic comment
                os.unlink(managed_unix_socket_path)
                logger.debug(
                    f"🧪🧹 Manually removed socket file {managed_unix_socket_path}"
                )
        except Exception as e:
            logger.error(f"🧪❌ Error cleaning transport: {e}")


# @pytest_asyncio.fixture(scope="module", autouse=True)
@pytest.fixture(scope="function")
def mock_server_handler() -> MockHandler: # Changed to concrete MockHandler
    """Fixture to provide a mock hadler instance."""
    return MockHandler()


@pytest_asyncio.fixture(scope="function")
async def mock_server_protocol() -> MockProtocol:
    """Fixture to provide a mock protocol class."""
    proto = MockProtocol()
    return proto


@pytest.fixture(scope="function")
def mock_server_config(monkeypatch):
    """Provides the global RPCPluginConfig instance, applying temporary test defaults."""

    # Ensure the global rpcplugin_config.config dictionary is initialized
    _ = (
        rpcplugin_config.instance()
    )  # Ensures .config dictionary exists on the singleton

    test_defaults = {
        "PLUGIN_MAGIC_COOKIE_KEY": "PLUGIN_MAGIC_COOKIE",
        "PLUGIN_MAGIC_COOKIE_VALUE": "hello-fixture-mock-TLS-v2",  # Ensure distinct value
        "PLUGIN_MAGIC_COOKIE": "hello-fixture-mock-TLS-v2",
        "PLUGIN_PROTOCOL_VERSIONS": [7],  # Example distinct value
        "PLUGIN_SERVER_TRANSPORTS": ["unix"],  # Example distinct value
        "PLUGIN_SERVER_ENDPOINT": None,
        "PLUGIN_SERVER_CERT": None,
        "PLUGIN_SERVER_KEY": None,
        "PLUGIN_CLIENT_CERT": None,
    }

    for key, value in test_defaults.items():
        # rpcplugin_config.config should exist after .instance() call.
        # If it might not (e.g. very first test run and complex init), add defensive check.
        if rpcplugin_config.config is not None:
            monkeypatch.setitem(rpcplugin_config.config, key, value)
        else:
            # This state would be problematic for tests relying on this fixture.
            logger.error(
                "CRITICAL: rpcplugin_config.config is None in mock_server_config fixture! This should not happen."
            )

    yield rpcplugin_config
    # Monkeypatch automatically handles teardown/restoration of original values.


@pytest_asyncio.fixture
async def server_with_mocks(
    mock_server_protocol, mock_server_handler, mock_server_config, mock_server_transport
):
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
            await server.stop()
