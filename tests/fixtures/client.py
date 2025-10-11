# tests/client/conftest.py

import pytest_asyncio
import subprocess
import sys
from provide.testkit.mocking import AsyncMock, MagicMock, patch

from pyvider.rpcplugin.client.core import RPCPluginClient
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
    """Mock ManagedProcess wrapper for testing."""
    # Create the underlying Popen mock
    popen_mock = MagicMock(spec=subprocess.Popen)
    popen_mock.stdout = MagicMock()
    popen_mock.stderr = MagicMock()
    popen_mock.poll.return_value = None  # Process is running
    popen_mock.returncode = None

    # Set up stdout to return a valid handshake response
    popen_mock.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:8000|grpc|\n"

    # Create the ManagedProcess wrapper mock
    managed_process = MagicMock()
    managed_process.process = popen_mock
    managed_process.is_running.return_value = True
    managed_process.pid = 12345
    managed_process.returncode = None
    managed_process.terminate_gracefully.return_value = True
    managed_process.cleanup = MagicMock()

    return managed_process


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


### 🐍🏗🧪️

# 🐍🔌🖥️🪄
