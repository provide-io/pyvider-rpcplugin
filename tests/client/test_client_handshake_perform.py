# tests/client/test_client_handshake_perform.py
"""Tests for basic handshake execution functionality."""

import subprocess

from provide.testkit.mocking import AsyncMock, MagicMock, patch
import pytest

from pyvider.rpcplugin.client.core import RPCPluginClient
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import HandshakeError, SecurityError


@pytest.fixture
def client_instance_for_retry_tests(mocker: object) -> RPCPluginClient:
    client = RPCPluginClient(command=["dummy-plugin-cmd"])
    client.logger = mocker.MagicMock(spec=["info", "warning", "error", "debug"])
    mock_process_obj = MagicMock(spec=subprocess.Popen)
    mock_process_obj.poll.return_value = None
    mock_process_obj.returncode = None
    mock_process_obj.stderr = MagicMock()
    mock_process_obj.stdout = MagicMock()
    client._process = mock_process_obj
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
    mock_process.stderr = mock_stderr
    client_instance._process = None  # So _launch_process will actually launch

    with (
        patch("pyvider.rpcplugin.client.process.subprocess.Popen", return_value=mock_process),
        patch("pyvider.rpcplugin.transport.TCPSocketTransport") as mock_transport_class,
    ):
        mock_transport_instance = AsyncMock()
        mock_transport_class.return_value = mock_transport_instance
        mock_process.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:8000|grpc|\n"
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
    mock_process.stderr = mock_stderr
    client_instance._process = None  # So _launch_process will actually launch
    sample_cert = "dGVzdA=="

    with (
        patch("pyvider.rpcplugin.client.process.subprocess.Popen", return_value=mock_process),
        patch("pyvider.rpcplugin.transport.TCPSocketTransport") as mock_transport_class,
    ):
        mock_transport_instance = AsyncMock()
        mock_transport_class.return_value = mock_transport_instance
        mock_process.stdout.readline.return_value = f"1|1|tcp|127.0.0.1:8000|grpc|{sample_cert}\\n".encode()
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
    mock_process.stderr = mock_stderr
    client_instance._process = None  # So _launch_process will actually launch

    with (
        patch("pyvider.rpcplugin.client.process.subprocess.Popen", return_value=mock_process),
        patch("pyvider.rpcplugin.transport.UnixSocketTransport") as mock_transport_class,
    ):
        mock_transport_instance = AsyncMock()
        mock_transport_class.return_value = mock_transport_instance
        mock_process.stdout.readline.return_value = b"1|1|unix|/tmp/test.sock|grpc|\n"
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
    mock_process.poll.return_value = 1
    mock_process.returncode = 1
    mock_process.stderr.read.return_value = b"Error during startup"
    mock_process.stderr.readline.return_value = b""
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
    mock_process.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:8000|grpc|\n"
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

    mock_certificate_cls = mocker.patch("pyvider.rpcplugin.client.handshake.Certificate")
    mock_certificate_cls.side_effect = ValueError("broken cert")

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

    mock_process = MagicMock(spec=subprocess.Popen)
    mock_process.poll.return_value = None
    mock_process.stderr = MagicMock()
    mock_process.stderr.read.return_value = b""
    mock_process.terminate.side_effect = RuntimeError("terminate failure")
    mock_process.kill = MagicMock()

    client._process = mock_process

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
async def test_perform_handshake_invalid_network_type(
    client_instance: RPCPluginClient, mock_process: MagicMock
) -> None:
    client_instance._process = mock_process
    mock_process.stdout.readline.return_value = b"1|1|invalid_net|127.0.0.1:8000|grpc|\n"
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
