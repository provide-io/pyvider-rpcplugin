# tests/fixtures/transport.py

import pytest
import pytest_asyncio

import asyncio

import os
import socket

from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.transport.types import TransportT

from pyvider.rpcplugin.transport import (
    RPCPluginTransport,
    TCPSocketTransport,
    UnixSocketTransport,
)

from ..fixtures import *


# is being used
@pytest_asyncio.fixture
async def unused_tcp_port() -> int:
    """Fixture to get an unused TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# Is being used.
@pytest_asyncio.fixture
async def unix_transport():
    logger.debug("unix_transport fixture invoked.")

    import tempfile

    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        sock_path = tmp.name

    logger.debug(f"Using socket at: {sock_path}")

    # sock_path=f"/tmp/pyvider_test_{os.getpid()}.sock"

    transport = UnixSocketTransport(path=sock_path)

    await transport.listen()
    logger.debug(
        f"DEBUG: Fixture initialized transport at {transport.path}, _server: {transport._server}"
    )
    # logger.debug(f"DEBUG: Initialized transport at {transport.path} of type {type(transport)}")

    logger.debug(f"DEBUG: Fixture setup complete: {transport.path}")
    try:
        yield transport
    finally:
        await transport.close()
        if os.path.exists(sock_path):
            logger.debug("DEBUG: removing sock_path")
            os.unlink(sock_path)
        logger.debug("DEBUG: Fixture cleanup complete")


@pytest.fixture(scope="function", autouse=True)
async def transport_cleanup():
    yield
    # Force cleanup of transport resources
    await asyncio.sleep(0.1)  # Allow any pending cleanups


@pytest_asyncio.fixture(scope="function")
async def unique_socket_path() -> str:
    import os, tempfile, uuid

    # Always keep it under ~100 bytes to be safe
    short_id = uuid.uuid4().hex[:8]
    return f"/tmp/pyv_{short_id}.sock"


################################################################################
