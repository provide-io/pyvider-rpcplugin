# tests/client/test_client_handshake_perform.py
"""Tests for basic handshake execution functionality."""

import asyncio
import subprocess
from typing import Any

from provide.testkit.mocking import AsyncMock, MagicMock, patch
import pytest

from pyvider.rpcplugin.client.core import RPCPluginClient
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import HandshakeError, SecurityError, TransportError


@pytest.fixture
def client_instance_for_retry_tests(mocker: object) -> RPCPluginClient:
    client = RPCPluginClient(command=["dummy-plugin-cmd"])
    client.logger = mocker.MagicMock(spec=["info", "warning", "error", "debug"])

    # Create the underlying Popen mock (don't use spec to avoid Mock spec issues)
    popen_mock = MagicMock()
    popen_mock.poll.return_value = None
    popen_mock.returncode = None
    popen_mock.stderr = MagicMock()
    popen_mock.stdout = MagicMock()

    # Create the ManagedProcess wrapper mock
    managed_process = MagicMock()
    managed_process.process = popen_mock
    managed_process.is_running.return_value = True
    managed_process.pid = 12345
    managed_process.returncode = None
    managed_process.terminate_gracefully.return_value = True
    managed_process.cleanup = MagicMock()

    client._process = managed_process
    return client


@pytest.fixture
def minimal_client(mocker: object) -> RPCPluginClient:
    client = RPCPluginClient(command=["dummy"])
    client.logger = mocker.MagicMock(spec=["info", "warning", "error", "debug"])
    return client


@pytest.mark.asyncio
async def test_perform_handshake_success(client_instance: RPCPluginClient, mock_process: MagicMock) -> None:
    # Set up mock process with proper stderr that returns bytes
    mock_stderr = MagicMock()
    mock_stderr.readline = MagicMock(return_value=b"")
    mock_process.process.stderr = mock_stderr
    client_instance._process = None  # So _launch_process will actually launch

    with (
        patch("pyvider.rpcplugin.client.process.subprocess.Popen", return_value=mock_process.process),
        patch("pyvider.rpcplugin.transport.TCPSocketTransport") as mock_transport_class,
    ):
        mock_transport_instance = AsyncMock()
        mock_transport_class.return_value = mock_transport_instance
        mock_process.process.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:8000|grpc|\n"
        await client_instance._perform_handshake()
        # Should have created stderr relay task
        assert client_instance._stdio_task is not None
        assert client_instance._protocol_version == 1
        # Transport is not created during handshake, only transport metadata is stored
        assert client_instance._transport_name == "tcp"
        assert client_instance._address == "127.0.0.1:8000"
        assert client_instance._server_cert is None


@pytest.mark.asyncio
async def test_perform_handshake_with_cert(client_instance: RPCPluginClient, mock_process: MagicMock) -> None:
    # Set up mock process with proper stderr that returns bytes
    mock_stderr = MagicMock()
    mock_stderr.readline = MagicMock(return_value=b"")
    mock_process.process.stderr = mock_stderr
    client_instance._process = None  # So _launch_process will actually launch
    sample_cert = "dGVzdA=="

    with (
        patch("pyvider.rpcplugin.client.process.subprocess.Popen", return_value=mock_process.process),
        patch("pyvider.rpcplugin.transport.TCPSocketTransport") as mock_transport_class,
    ):
        mock_transport_instance = AsyncMock()
        mock_transport_class.return_value = mock_transport_instance
        mock_process.process.stdout.readline.return_value = f"1|1|tcp|127.0.0.1:8000|grpc|{sample_cert}\\n".encode()
        await client_instance._perform_handshake()
        # Should have created stderr relay task
        assert client_instance._stdio_task is not None
        assert client_instance._protocol_version == 1
        # Transport is not created during handshake, only transport metadata is stored
        assert client_instance._transport_name == "tcp"
        assert client_instance._address == "127.0.0.1:8000"
        assert client_instance._server_cert == sample_cert


@pytest.mark.asyncio
async def test_perform_handshake_with_unix_transport(
    client_instance: RPCPluginClient, mock_process: MagicMock
) -> None:
    # Set up mock process with proper stderr that returns bytes
    mock_stderr = MagicMock()
    mock_stderr.readline = MagicMock(return_value=b"")
    mock_process.process.stderr = mock_stderr
    client_instance._process = None  # So _launch_process will actually launch

    with (
        patch("pyvider.rpcplugin.client.process.subprocess.Popen", return_value=mock_process.process),
        patch("pyvider.rpcplugin.transport.UnixSocketTransport") as mock_transport_class,
    ):
        mock_transport_instance = AsyncMock()
        mock_transport_class.return_value = mock_transport_instance
        mock_process.process.stdout.readline.return_value = b"1|1|unix|/tmp/test.sock|grpc|\n"
        await client_instance._perform_handshake()
        # Should have created stderr relay task
        assert client_instance._stdio_task is not None
        assert client_instance._protocol_version == 1
        assert client_instance._transport_name == "unix"
        # Transport is not created during handshake, only transport metadata is stored
        assert client_instance._address == "/tmp/test.sock"


@pytest.mark.asyncio
async def test_perform_handshake_no_process(client_instance: RPCPluginClient) -> None:
    client_instance._process = None
    with pytest.raises(
        HandshakeError,
        match="Plugin process or stdout not available for handshake.",
    ):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_perform_handshake_process_exit(
    client_instance: RPCPluginClient, mock_process: MagicMock
) -> None:
    client_instance._process = mock_process
    mock_process.is_running.return_value = False  # Process has exited
    mock_process.returncode = 1
    mock_process.process.stderr.read.return_value = b"Error during startup"
    mock_process.process.stderr.readline.return_value = b""
    with pytest.raises(
        HandshakeError,
        match=r"\[HandshakeError\] Plugin process exited prematurely.*before completing handshake.*",
    ):
        await client_instance._perform_handshake()


@pytest.mark.asyncio
async def test_perform_handshake_invalid_format(
    client_instance: RPCPluginClient, mock_process: MagicMock, mocker: object
) -> None:
    client_instance._process = mock_process
    mock_process.process.stderr.read.return_value = b""

    # Mock _read_raw_handshake_line_from_stdout to directly return the problematic line
    # This bypasses the internal looping/timeout logic of _read_raw_handshake_line_from_stdout
    # and ensures that _perform_handshake proceeds to call parse_handshake_response with this line.
    mocker.patch(
        "pyvider.rpcplugin.client.core.RPCPluginClient._read_raw_handshake_line_from_stdout",
        new_callable=AsyncMock,
        return_value="invalid_handshake_format",
    )

    expected_error_match = r".*Failed to parse handshake response.*Invalid handshake format.*"
    with (
        patch(
            "pyvider.rpcplugin.client.core.RPCPluginClient._relay_stderr_background",
            new_callable=AsyncMock,
        ) as mock_relay,
        pytest.raises(HandshakeError, match=expected_error_match),
    ):
        await client_instance._perform_handshake()
        mock_relay.assert_called_once()  # This should be inside the with block if it depends on successful execution of the try part


@pytest.mark.asyncio
async def test_perform_handshake_parse_error(
    client_instance: RPCPluginClient, mock_process: MagicMock
) -> None:
    client_instance._process = mock_process
    mock_process.process.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:8000|grpc|\n"
    mock_process.process.stderr.read.return_value = b""
    with (
        patch.object(
            client_instance,
            "_relay_stderr_background",
            new_callable=AsyncMock,
        ),
        patch(
            "pyvider.rpcplugin.client.handshake.parse_handshake_response",
            side_effect=ValueError("Simulated parse error"),
        ) as mock_parse,
        pytest.raises(
            HandshakeError,
            match=r"Failed to process handshake response or establish transport connection: Simulated parse error",
        ),
    ):
        await client_instance._perform_handshake()
    mock_parse.assert_called_once()


@pytest.mark.asyncio
async def test_setup_client_certificates_existing_cert_failure(minimal_client: RPCPluginClient, mocker: object) -> None:
    mocker.patch.object(rpcplugin_config, "plugin_auto_mtls", False)
    mocker.patch.object(rpcplugin_config, "plugin_client_cert", "cert-path")
    mocker.patch.object(rpcplugin_config, "plugin_client_key", "key-path")

    mocker.patch(
        "pyvider.rpcplugin.client.handshake.Certificate.from_pem",
        side_effect=ValueError("broken cert")
    )

    with pytest.raises(SecurityError, match="Failed to load client certificate/key: broken cert"):
        await minimal_client._setup_client_certificates()


@pytest.mark.asyncio
async def test_setup_client_certificates_auto_mtls_failure(minimal_client: RPCPluginClient, mocker: object) -> None:
    mocker.patch.object(rpcplugin_config, "plugin_auto_mtls", True)
    mocker.patch.object(rpcplugin_config, "plugin_client_cert", None)
    mocker.patch.object(rpcplugin_config, "plugin_client_key", None)

    mocker.patch(
        "pyvider.rpcplugin.client.handshake.Certificate.create_self_signed_client_cert",
        side_effect=ValueError("auto failure"),
    )

    with pytest.raises(SecurityError, match="Failed to auto-generate client certificate: auto failure"):
        await minimal_client._setup_client_certificates()


def test_rebuild_x509_pem_empty(minimal_client: RPCPluginClient) -> None:
    assert minimal_client._rebuild_x509_pem("") == ""
    assert minimal_client._rebuild_x509_pem("   ") == ""


@pytest.mark.asyncio
async def test_perform_handshake_cleanup_warning(minimal_client: RPCPluginClient, mocker: object) -> None:
    client = minimal_client

    # Create ManagedProcess mock that raises exception during cleanup
    managed_process = MagicMock()
    managed_process.terminate_gracefully.side_effect = RuntimeError("terminate failure")
    managed_process.cleanup = MagicMock()
    managed_process.process = MagicMock()
    managed_process.process.stderr = MagicMock()
    managed_process.process.stderr.read.return_value = b""

    client._process = managed_process

    mocker.patch.object(client, "_launch_process", AsyncMock(return_value=None))
    mocker.patch.object(
        client,
        "_read_raw_handshake_line_from_stdout",
        AsyncMock(side_effect=RuntimeError("handshake boom")),
    )
    mocker.patch("pyvider.rpcplugin.client.handshake.asyncio.sleep", new_callable=AsyncMock)

    warning_spy = mocker.spy(client.logger, "warning")

    with pytest.raises(RuntimeError, match="handshake boom"):
        await client._perform_handshake()

    warning_spy.assert_called_once_with(
        "Error cleaning up process after handshake failure: terminate failure"
    )
    assert client._process is None


@pytest.mark.asyncio
async def test_perform_handshake_cleanup_kill(minimal_client: RPCPluginClient, mocker: object) -> None:
    client = minimal_client

    # Create ManagedProcess mock
    managed_process = MagicMock()
    managed_process.terminate_gracefully.return_value = True  # Succeeds
    managed_process.cleanup = MagicMock()
    managed_process.process = MagicMock()
    managed_process.process.stderr = MagicMock()
    managed_process.process.stderr.read.return_value = b""

    client._process = managed_process

    mocker.patch.object(client, "_launch_process", AsyncMock())
    mocker.patch.object(
        client,
        "_read_raw_handshake_line_from_stdout",
        AsyncMock(side_effect=RuntimeError("boom")),
    )
    mocker.patch("pyvider.rpcplugin.client.handshake.asyncio.sleep", new_callable=AsyncMock)

    with pytest.raises(RuntimeError, match="boom"):
        await client._perform_handshake()

    managed_process.terminate_gracefully.assert_called_once_with(timeout=1.0)
    managed_process.cleanup.assert_called_once()
    assert client._process is None


@pytest.mark.asyncio
async def test_complete_handshake_setup_with_stdio(minimal_client: RPCPluginClient, mocker: object) -> None:
    client = minimal_client
    client._address = "127.0.0.1"
    client._transport_name = "tcp"
    client._stdio_stub = AsyncMock()

    mocker.patch.object(client, "_setup_client_certificates", AsyncMock())
    mocker.patch.object(client, "_create_grpc_channel", AsyncMock())
    mocker.patch.object(client, "_read_stdio_logs", AsyncMock())

    scheduled: list[asyncio.Task[Any]] = []
    original_create_task = asyncio.create_task

    def track_task(coro: Any) -> asyncio.Task[Any]:
        task = original_create_task(coro)
        scheduled.append(task)
        return task

    create_task = mocker.patch("asyncio.create_task", side_effect=track_task)

    await client._complete_handshake_setup(attempt_num=2)

    create_task.assert_called_once()
    assert client._stdio_task is scheduled[0]
    assert client.is_started is True
    assert client._handshake_complete_event.is_set()

    for task in scheduled:
        await task


@pytest.mark.asyncio
async def test_complete_handshake_setup_missing_address(minimal_client: RPCPluginClient) -> None:
    with pytest.raises(HandshakeError):
        await minimal_client._complete_handshake_setup()


@pytest.mark.asyncio
async def test_handle_retry_cleanup_transport_close_warning(minimal_client: RPCPluginClient, mocker: object) -> None:
    client = minimal_client
    mock_transport = AsyncMock()
    mock_transport.close.side_effect = TransportError("close boom")
    client._transport = mock_transport

    mocker.patch("pyvider.rpcplugin.client.handshake.asyncio.sleep", new_callable=AsyncMock)
    warning_spy = mocker.spy(client.logger, "warning")

    await client._handle_retry_cleanup(50)

    mock_transport.close.assert_called_once()
    assert any("close boom" in str(call) for call in warning_spy.call_args_list)
    assert client._transport is None


@pytest.mark.asyncio
async def test_perform_handshake_invalid_network_type(
    client_instance: RPCPluginClient, mock_process: MagicMock
) -> None:
    client_instance._process = mock_process
    mock_process.process.stdout.readline.return_value = b"1|1|invalid_net|127.0.0.1:8000|grpc|\n"
    mock_process.process.stderr.read.return_value = b""
    with (
        patch.object(
            client_instance,
            "_relay_stderr_background",
            new_callable=AsyncMock,
        ),
        patch(
            "pyvider.rpcplugin.client.handshake.parse_handshake_response",
            side_effect=ValueError("Unsupported network type: invalid_net"),
        ) as mock_parse,
        pytest.raises(
            HandshakeError,
            match=r"Failed to process handshake response.*Unsupported network type: invalid_net",
        ),
    ):
        await client_instance._perform_handshake()
    mock_parse.assert_called_once()
