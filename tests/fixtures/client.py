# tests/fixtures/client.py

import pytest
import pytest_asyncio

import sys

from pyvider.rpcplugin.client import RPCPluginClient


@pytest_asyncio.fixture(scope="module")
async def client_command() -> list[str]:
    """Fixture for the client command (replace with your server launch command)."""
    # Example: Launching the server directly using python
    return [
        sys.executable,
        "-m",
        "pyvider.rpcplugin.server",
    ]


@pytest_asyncio.fixture(scope="module")
async def client_instance(client_command, server_instance, handshake_config):
    """
    Async fixture to create and start an RPCPluginClient instance.
    """
    client = RPCPluginClient(command=client_command)
    await client.start()

    # The handshake/connection can happen in your tests or here:
    # await client.connect()

    yield client

    # Now stop the client
    await client.stop()
