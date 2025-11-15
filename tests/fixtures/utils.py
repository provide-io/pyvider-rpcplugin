# tests/fixtures/utils.py

import pytest
import pytest_asyncio

import asyncio
import os
import tempfile
from pyvider.telemetry import logger
from pyvider.rpcplugin.server import RPCPluginServer


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


# @pytest_asyncio.fixture(scope="function", autouse=True)
# async def cleanup_asyncio():
#     """Ensure proper cleanup of asyncio resources after each test."""
#     yield
#     # Clean up any remaining tasks
#     tasks = [
#         t
#         for t in asyncio.all_tasks()
#         if t is not asyncio.current_task() and not t.done()
#     ]
#
#     if tasks:
#         for task in tasks:
#             task.cancel()
#         await asyncio.gather(*tasks, return_exceptions=True)
#
#     # Allow event loop to process any pending callbacks
#     await asyncio.sleep(0)


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


def summarize_text(text: str, length: int = 32) -> str:
    """Helper to summarize text for logging."""
    if len(text) <= 2 * length:
        return text
    return f"{text[:length]} ... {text[-length:]}"


### 🐍🏗🧪️
