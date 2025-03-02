# tests/fixtures/utils.py

import pytest
import pytest_asyncio

import asyncio
import os
import socket
import sys

import pytest
import pytest_asyncio

from cryptography.hazmat.primitives import serialization

# rom pyvider.rpcplugin.logger import logger
# from pyvider.rpcplugin.client import RPCPluginClient
# from pyvider.rpcplugin.protocol import RPCPluginProtocol
#
# # from pyvider.rpcplugin.security import (
# #     create_self_signed_x509_certificate,
# #     generate_keypair,
# #     Certificate,
# # )
# from pyvider.rpcplugin.server import RPCPluginServer
# from pyvider.rpcplugin.transport.types import TransportT
# from pyvider.rpcplugin.transport import (
#     RPCPluginTransport,
#     TCPSocketTransport,
#     UnixSocketTransport,
# )
#
# from pyvider.rpcplugin.types import ConfigT
#
# from tests.fixtures import *
#


@pytest_asyncio.fixture(scope="function")
def cleanup_temp_files():
    import shutil

    temp_dir = tempfile.mkdtemp()
    os.environ["TEMP_DIR"] = temp_dir  # Use as a base path for socket files
    logger.debug(f"Temporary directory is: {temp_dir}")

    yield temp_dir

    shutil.rmtree(temp_dir, ignore_errors=True)
    os.environ.pop("TEMP_DIR", None)  # Remove the environment variable
    logger.debug(f"Removed temporary directory at: {temp_dir}")


#@pytest_asyncio.fixture(scope="function", autouse=True)
async def cleanup_asyncio():
    """Ensure proper cleanup of asyncio resources after each test."""
    yield
    # Clean up any remaining tasks
    tasks = [
        t
        for t in asyncio.all_tasks()
        if t is not asyncio.current_task() and not t.done()
    ]

    if tasks:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    # Allow event loop to process any pending callbacks
    await asyncio.sleep(0)


@pytest_asyncio.fixture(scope="function", autouse=True)
async def ensure_asyncio_cleanup():
    yield
    pending_tasks = [
        task for task in asyncio.all_tasks() if task is not asyncio.current_task()
    ]
    for task in pending_tasks:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


################################################################################


@pytest.fixture(scope="function")
async def dummy_server(mock_server_protocol, mock_server_handler):
    """Provides a clean DummyGRPCServer instance per test"""
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
    )
    yield server
    # No async cleanup needed for dummy server


@pytest.fixture(scope="function")
async def clean_socket_dir(tmp_path):
    """Provides a clean temporary directory for socket files"""
    socket_dir = tmp_path / "sockets"
    socket_dir.mkdir()
    yield socket_dir
    # Cleanup any leftover socket files
    for sock_file in socket_dir.glob("*.sock"):
        try:
            os.unlink(sock_file)
        except OSError:
            pass

@pytest.fixture(scope="function")
def summarize_text(text: str, length: int = 32) -> str:
    """Helper to summarize text for logging."""
    if len(text) <= 2 * length:
        return text
    return f"{text[:length]} ... {text[-length:]}"

### 🐍🏗🧪️
