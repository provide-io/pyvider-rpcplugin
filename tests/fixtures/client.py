# tests/client/conftest.py

import pytest_asyncio
import sys
import asyncio # Import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from pyvider.rpcplugin.client.base import RPCPluginClient
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport


@pytest_asyncio.fixture(scope="module")
async def client_command() -> list[str]:
    """Fixture for the client command (replace with your server launch command)."""
    # Example: Launching the server directly using python
    return [
        sys.executable,
        "-m",
        "pyvider.rpcplugin.server",
    ]


@pytest_asyncio.fixture
async def client_instance(test_client_command):
    """Base RPCPluginClient instance for testing with required attributes set."""
    with patch("subprocess.Popen"):
        client = RPCPluginClient(command=test_client_command)
        # Set required attributes that tests expect
        client._transport_name = "tcp"  # Default to TCP for most tests
        client._address = "127.0.0.1:8000"
        client._server_cert = None

        yield client


@pytest_asyncio.fixture
async def mock_process():
    """Mock subprocess.Popen instance for testing."""
    process = MagicMock()
    process.stdout = MagicMock()
    process.stderr = MagicMock()
    process.poll.return_value = None  # Process is running

    # Set up stdout to return a valid handshake response
    process.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:8000|grpc|\n"

    return process


@pytest_asyncio.fixture
async def mock_transport():
    """Mock transport implementation for testing."""
    transport = AsyncMock(spec=TCPSocketTransport)
    transport.endpoint = "127.0.0.1:8000"
    transport.listen = AsyncMock(return_value="127.0.0.1:8000")
    transport.connect = AsyncMock()
    transport.close = AsyncMock()
    return transport


@pytest_asyncio.fixture
async def mock_unix_transport():
    """Mock Unix socket transport for testing."""
    transport = AsyncMock(spec=UnixSocketTransport)
    transport.path = "/tmp/test.sock"
    transport.endpoint = "/tmp/test.sock"
    transport.listen = AsyncMock(return_value="/tmp/test.sock")
    transport.connect = AsyncMock()
    transport.close = AsyncMock()
    return transport


@pytest_asyncio.fixture
async def mock_grpc_channel():
    """Mock gRPC channel for testing."""
    channel = AsyncMock()
    channel.channel_ready = AsyncMock()
    channel.close = AsyncMock()
    return channel


@pytest_asyncio.fixture
async def test_client_command():
    """Test command to launch the plugin process."""
    return ["python", "-m", "dummy_plugin"]


@pytest_asyncio.fixture
async def started_client_instance(client_instance, mocker):
    """Provides a client_instance that is mocked to appear as 'started'."""
    client_instance.is_started = True

    # Mock process
    mock_proc = MagicMock() # Removed spec
    mock_proc.poll = MagicMock(return_value=None)
    mock_proc.terminate = MagicMock()
    mock_proc.wait = AsyncMock()
    client_instance._process = mock_proc

    # Mock tasks (often checked if done or cancelled)
    client_instance._stdio_task = AsyncMock(spec=asyncio.Task)
    client_instance._stdio_task.done = MagicMock(return_value=True) # Default to done
    client_instance._stdio_task.cancel = MagicMock()

    client_instance._broker_task = AsyncMock(spec=asyncio.Task)
    client_instance._broker_task.done = MagicMock(return_value=True) # Default to done
    client_instance._broker_task.cancel = MagicMock()

    # Mock gRPC channel
    client_instance.grpc_channel = AsyncMock()
    client_instance.grpc_channel.close = AsyncMock()

    # Mock transport
    client_instance._transport = AsyncMock()
    client_instance._transport.close = AsyncMock()

    # Mock stubs (these are usually set in _init_stubs after channel creation)
    client_instance._controller_stub = AsyncMock()
    client_instance._stdio_stub = AsyncMock()
    client_instance._broker_stub = AsyncMock()

    # Mock the shutdown_plugin method itself, as tests often check its call or side effects
    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)

    return client_instance

### 🐍🏗🧪️
