import pytest
import subprocess  # Import subprocess
from unittest.mock import MagicMock, AsyncMock
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.client.base import RPCPluginClient


@pytest.fixture
async def client_instance_local(mocker):
    client = RPCPluginClient(command=["dummy-plugin-cmd"])
    client.logger = mocker.MagicMock(spec=["info", "warning", "error", "debug"])
    # Spec against subprocess.Popen for mock_process_obj
    mock_process_obj = MagicMock(spec=subprocess.Popen)
    mock_process_obj.poll.return_value = None
    mock_process_obj.returncode = None
    client._process = mock_process_obj
    return client


@pytest.mark.asyncio
async def test_connect_handshake_retry_success_after_failures(
    client_instance_local, mocker
):
    client_instance = client_instance_local

    mock_config_get = mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.get")
    config_values = {
        "PLUGIN_CLIENT_RETRY_ENABLED": "true",
        "PLUGIN_CLIENT_MAX_RETRIES": 3,
        "PLUGIN_CLIENT_INITIAL_BACKOFF_MS": 1,
        "PLUGIN_CLIENT_MAX_BACKOFF_MS": 5,
        "PLUGIN_CLIENT_RETRY_JITTER_MS": 1,
        "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": 10,
    }
    mock_config_get.side_effect = lambda key, default=None: config_values.get(
        key, default
    )

    mock_asyncio_sleep = mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.sleep", new_callable=AsyncMock
    )

    handshake_attempts = 0

    async def side_effect_perform_handshake_with_failures():
        nonlocal handshake_attempts
        handshake_attempts += 1
        if handshake_attempts < 3:
            if (
                client_instance._transport
                and hasattr(client_instance._transport, "close")
                and callable(client_instance._transport.close)
            ):
                await client_instance._transport.close()
            client_instance._transport = None
            raise HandshakeError(
                f"Simulated handshake failure attempt {handshake_attempts}"
            )

        client_instance._address = "mock_address_retry"
        client_instance._transport_name = "mock_transport_retry"
        client_instance._protocol_version = 1
        client_instance._server_cert = None
        client_instance._transport = AsyncMock()

    mock_perform_handshake_patcher = mocker.patch(
        "pyvider.rpcplugin.client.base.RPCPluginClient._perform_handshake",
        new_callable=AsyncMock,
    )
    mock_perform_handshake_patcher.side_effect = (
        side_effect_perform_handshake_with_failures
    )

    mock_create_grpc_channel_patcher = mocker.patch(
        "pyvider.rpcplugin.client.base.RPCPluginClient._create_grpc_channel",
        new_callable=AsyncMock,
    )

    async def side_effect_create_channel():
        client_instance.target_endpoint = "mock_target_endpoint_retry"
        client_instance.grpc_channel = AsyncMock()

    mock_create_grpc_channel_patcher.side_effect = side_effect_create_channel

    spied_logger_warning = mocker.spy(client_instance.logger, "warning")

    if not client_instance._process:
        m_proc = MagicMock(spec=subprocess.Popen)
        m_proc.poll.return_value = None
        client_instance._process = m_proc
    else:
        client_instance._process.poll.return_value = None

    client_instance.is_started = False
    client_instance._handshake_complete_event.clear()
    client_instance._handshake_failed_event.clear()
    client_instance.grpc_channel = None
    client_instance._transport = None

    await client_instance._connect_and_handshake_with_retry()

    assert mock_perform_handshake_patcher.call_count == 3
    mock_create_grpc_channel_patcher.assert_called_once()
    assert mock_asyncio_sleep.call_count == 2

    assert client_instance.is_started is True
    assert client_instance._handshake_complete_event.is_set() is True
    assert client_instance._handshake_failed_event.is_set() is False

    # Corrected assertion: Check the message content without the class name prefix.
    spied_logger_warning.assert_any_call(
        "Attempt 1 failed: Simulated handshake failure attempt 1"
    )
    spied_logger_warning.assert_any_call(
        "Attempt 2 failed: Simulated handshake failure attempt 2"
    )
