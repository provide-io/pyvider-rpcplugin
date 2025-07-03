# tests/client/conftest.py

import asyncio
import sys
from typing import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest_asyncio
from pytest_mock import MockerFixture
import grpc.aio

from pyvider.rpcplugin.client.base import RPCPluginClient
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.transport.base import RPCPluginTransport


@pytest_asyncio.fixture(scope="module")
async def client_command() -> list[str]:
    """Fixture for the client command."""
    return [
        sys.executable,
        "-m",
        "pyvider.rpcplugin.server",
    ]


@pytest_asyncio.fixture
async def client_instance(
    test_client_command: list[str],
) -> AsyncGenerator[RPCPluginClient, None]:
    """Base RPCPluginClient instance for testing with required attributes set."""
    with patch("subprocess.Popen"):
        client = RPCPluginClient(command=test_client_command)
        client._transport_name = "tcp"
        client._address = "127.0.0.1:8000"
        client._server_cert = None
        yield client


@pytest_asyncio.fixture
async def mock_process() -> MagicMock:
    """Mock subprocess.Popen instance for testing."""
    process = MagicMock()
    process.stdout = MagicMock()
    process.stderr = MagicMock()
    process.poll.return_value = None
    process.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:8000|grpc|\n"
    return process


@pytest_asyncio.fixture
async def mock_transport() -> AsyncMock:
    """Mock transport implementation for testing."""
    transport = AsyncMock(spec=TCPSocketTransport)
    transport.endpoint = "127.0.0.1:8000"
    transport.listen = AsyncMock(return_value="127.0.0.1:8000")
    transport.connect = AsyncMock()
    transport.close = AsyncMock()
    return transport


@pytest_asyncio.fixture
async def mock_unix_transport() -> AsyncMock:
    """Mock Unix socket transport for testing."""
    transport = AsyncMock(spec=UnixSocketTransport)
    transport.path = "/tmp/test.sock"  # nosec B108
    transport.endpoint = "/tmp/test.sock"  # nosec B108
    transport.listen = AsyncMock(return_value="/tmp/test.sock")  # nosec B108
    transport.connect = AsyncMock()
    transport.close = AsyncMock()
    return transport


@pytest_asyncio.fixture
async def mock_grpc_channel() -> AsyncMock:
    """Mock gRPC channel for testing."""
    channel = AsyncMock(spec=grpc.aio.Channel)
    channel.channel_ready = AsyncMock()
    channel.close = AsyncMock()
    return channel


@pytest_asyncio.fixture
async def test_client_command() -> list[str]:
    """Test command to launch the plugin process."""
    return ["python", "-m", "dummy_plugin"]


@pytest_asyncio.fixture
async def started_client_instance(
    client_instance: RPCPluginClient, mocker: MockerFixture
) -> RPCPluginClient:
    """Provides a client_instance that is mocked to appear as 'started'."""
    client_instance.is_started = True

    mock_proc = MagicMock()
    mock_proc.poll = MagicMock(return_value=None)
    mock_proc.terminate = MagicMock()
    mock_proc.wait = AsyncMock()
    client_instance._process = mock_proc

    client_instance._stdio_task = AsyncMock(spec=asyncio.Task)
    client_instance._stdio_task.done = MagicMock(return_value=True)
    client_instance._stdio_task.cancel = MagicMock()

    client_instance._broker_task = AsyncMock(spec=asyncio.Task)
    client_instance._broker_task.done = MagicMock(return_value=True)
    client_instance._broker_task.cancel = MagicMock()

    client_instance.grpc_channel = AsyncMock(spec=grpc.aio.Channel)
    client_instance.grpc_channel.close = AsyncMock()

    client_instance._transport = AsyncMock(spec=RPCPluginTransport)
    client_instance._transport.close = AsyncMock()

    client_instance._controller_stub = AsyncMock()
    client_instance._stdio_stub = AsyncMock()
    client_instance._broker_stub = AsyncMock()

    # Mock the shutdown_plugin method itself
    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)

    return client_instance


### 🐍🏗🧪️
