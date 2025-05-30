# tests/fixtures/mocks.py
#
# Copyright (C) 2024 - All Rights Reserved
#
# This file is part of the PyVider RPCPlugin project.
#
# Any unauthorized use, reproduction, or distribution of this software
# is strictly prohibited without the express written permission of the copyright holder.
#

import asyncio # Added for asyncio.sleep
import os # Added for os.path and os.chmod/unlink in mock_server_transport_unix
import tempfile

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

from pyvider.rpcplugin.types import TransportT, HandlerT

from ..fixtures import * # This might be problematic if fixtures isn't structured as a package. Assuming it's fine.
from typing import Tuple


class MockProtocol(RPCPluginProtocol):
    def get_grpc_descriptors(self) -> Tuple[None, None, str]:
        # Mock descriptors for testing
        logger.debug("🔌🚀✅ MockProtocol.get_grpc_descriptors called.")
        return None, None, "MockService"

    async def add_to_server(self, handler, server) -> None:
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
            self.string_io.write(data.decode('utf-8'))
        else:
            # Handle string content
            self.string_io.write(str(data))
        return len(data)

    def flush(self):
        self.string_io.flush()

@pytest_asyncio.fixture(scope="function", params=["tcp", "unix"])
async def mock_server_transport(request) -> TransportT:
    transport_name = request.param
    transport = None # Initialize transport to None

    # tempfile.NamedTemporaryFile creates a file, which is good for UnixSocketTransport path
    # For TCP, it's not directly used but doesn't harm.
    # Ensure delete=False if UnixSocketTransport needs path after context, or manage path string.
    # For this fixture, path is only used if transport_name is "unix".
    # Let's refine socket_path logic for clarity if it's only for unix.
    socket_path = None
    if transport_name == "unix":
        with tempfile.NamedTemporaryFile(delete=False) as tmp: # delete=False, UnixSocketTransport will delete
            socket_path = tmp.name
    
    logger.debug(f"🧪🔌🐛 mock_server_transport called for transport: {transport_name}")
    if socket_path:
        logger.debug(f"🧪🔌🐛 socket_path for unix: {socket_path}")

    try:
        if transport_name == "tcp":
            transport = TCPSocketTransport() # OS picks a free port
        elif transport_name == "unix":
            if not socket_path: # Should have been created above
                 raise RuntimeError("Socket path not created for Unix transport")
            transport = UnixSocketTransport(path=socket_path)
        else:
            raise ValueError(f"Unknown transport: {transport_name}")
        
        yield transport

    except Exception as e:
        err_msg = f"Could not open {transport_name.upper()} Socket Transport"
        if transport:
            err_msg += f": {transport} (Error: {e})"
        elif socket_path and transport_name == "unix":
             err_msg += f" for path {socket_path} (Error: {e})"
        else:
            err_msg += f" (Instantiation failed: {e})"
        logger.error(err_msg)
        raise ValueError(err_msg) from e

    finally:
        if transport is not None:
            try:
                await transport.close()
                logger.debug(f"🧪🧹 Transport {transport_name} closed for {getattr(transport, 'path', '') or getattr(transport, 'endpoint', '')}")
            except Exception as close_exc:
                logger.error(f"🧪❌ Error during mock_server_transport ({transport_name}) cleanup: {close_exc}")
            await asyncio.sleep(0.1)  # Allow time for resources to be released
            
            # Specific cleanup for Unix socket file if it wasn't deleted by transport.close()
            if transport_name == "unix" and socket_path and os.path.exists(socket_path):
                try:
                    os.unlink(socket_path)
                    logger.debug(f"🧪🧹 Manually unlinked stale socket file: {socket_path}")
                except OSError as e:
                    logger.error(f"🧪❌ Error unlinking stale socket file {socket_path}: {e}")


@pytest_asyncio.fixture
async def mock_server_transport_tcp() -> TransportT:
    transport = None  # Initialize transport to None
    try:
        # TCPSocketTransport uses port=0 by default, so OS picks a free port.
        transport = TCPSocketTransport() 
        yield transport
    except Exception as e:
        err_msg = "Could not open a TCP Socket Transport"
        if transport: # Check if transport was instantiated
            err_msg += f": {transport} (Error: {e})"
        else:
            err_msg += f" (instantiation failed: {e})"
        # Consider raising a more specific error or just re-raising e
        logger.error(err_msg) # Log the error
        raise ValueError(err_msg) from e
    finally:
        if transport: # Only close if transport was successfully created and assigned
            try:
                await transport.close()
                logger.debug("🧪🧹 TCP Transport closed.")
            except Exception as close_exc:
                # Log or handle close error, but don't let it mask original exception
                logger.error(f"🧪❌ Error during mock_server_transport_tcp cleanup: {close_exc}")
            await asyncio.sleep(0.1)  # Allow time for resources to be released


@pytest_asyncio.fixture(scope="function")
async def mock_server_transport_unix(unique_socket_path) -> TransportT:
    """Fixture providing a properly configured Unix transport with unique path."""
    transport = UnixSocketTransport(path=unique_socket_path)
    try:
        # Early startup to verify it works
        # await transport.listen() # listen() is now part of test logic, not fixture setup for this one
        logger.debug(f"🧪✅ Unix transport initialized at {unique_socket_path}")
        yield transport
    except Exception as e:
        logger.error(f"🧪❌ Error initializing Unix transport at {unique_socket_path}: {e}")
        raise
    finally:
        # Ensure proper cleanup
        try:
            await transport.close()
            logger.debug(f"🧪🧹 Transport closed for {unique_socket_path}")

            # Double-check for stale socket file, even if transport.close() should handle it
            if os.path.exists(unique_socket_path):
                logger.warning(f"🧪⚠️ Stale socket file found after close: {unique_socket_path}. Attempting removal.")
                try:
                    current_mode = os.stat(unique_socket_path).st_mode
                    if not (current_mode & 0o200): # Check if write permission is missing for user
                        os.chmod(unique_socket_path, current_mode | 0o200) # Add user write permission
                    os.unlink(unique_socket_path)
                    logger.debug(f"🧪🧹 Manually removed stale socket file {unique_socket_path}")
                except OSError as unlink_e:
                     logger.error(f"🧪❌ Error removing stale socket file {unique_socket_path}: {unlink_e}")

        except Exception as e:
            logger.error(f"🧪❌ Error cleaning up Unix transport for {unique_socket_path}: {e}")
        await asyncio.sleep(0.1) # Allow time for resources to be released


@pytest.fixture(scope="function")
def mock_server_handler() -> HandlerT:
    """Fixture to provide a mock hadler instance."""
    return MockHandler()


@pytest_asyncio.fixture(scope="function")
async def mock_server_protocol() -> MockProtocol:
    """Fixture to provide a mock protocol class."""
    proto = MockProtocol()
    return proto


@pytest.fixture(scope="function")
def mock_server_config():
    """Provides actual RPCPluginConfig instance for testing."""
    from pyvider.rpcplugin.config import RPCPluginConfig

    # Create a fresh instance for each test
    config = RPCPluginConfig()

    # Set default test values
    config.set("PLUGIN_MAGIC_COOKIE_KEY", "PLUGIN_MAGIC_COOKIE")
    config.set("PLUGIN_MAGIC_COOKIE_VALUE", "hello")
    config.set("PLUGIN_MAGIC_COOKIE", "hello") # Duplicate of _VALUE, kept for compatibility if used elsewhere
    config.set("PLUGIN_PROTOCOL_VERSIONS", [1, 2, 3, 4, 5, 6, 7])
    config.set("PLUGIN_SERVER_TRANSPORTS", ["tcp", "unix"])

    return config


@pytest_asyncio.fixture
async def server_with_mocks(
    mock_server_protocol, mock_server_handler, mock_server_config, mock_server_transport # This now uses the parameterized one
):
    """Fixture to provide a server instance with mocks."""
    # Determine transport_name for logging/clarity if needed
    transport_name = "tcp" if isinstance(mock_server_transport, TCPSocketTransport) else "unix"
    logger.debug(f"🧪🔧 Creating server_with_mocks with {transport_name} transport.")

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=mock_server_config,
        transport=mock_server_transport, # Pass the actual transport instance from the fixture
    )
    try:
        yield server
    finally:
        logger.debug(f"🧪🧹 Stopping server_with_mocks ({transport_name} transport)...")
        with suppress(Exception): # Suppress errors during stop, as test might have failed earlier
            await server.stop()
        logger.debug(f"🧪🧹 Server_with_mocks ({transport_name} transport) stopped.")

# 🐍🏗️🔌
