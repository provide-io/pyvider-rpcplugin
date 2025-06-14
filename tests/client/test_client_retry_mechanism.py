import pytest
import asyncio
import subprocess # Import subprocess
from unittest.mock import patch, MagicMock, AsyncMock
from pyvider.rpcplugin.exception import HandshakeError, TransportError
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
    # client.__attrs_post_init__() # Not typically needed if Attrs handles it

    try:
        yield client
    finally:
        await client.close()

@pytest.mark.asyncio
async def test_connect_handshake_retry_success_after_failures(client_instance_local, mocker):
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
    mock_config_get.side_effect = lambda key, default=None: config_values.get(key, default)

    mock_asyncio_sleep = mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep", new_callable=AsyncMock)

    handshake_attempts = 0
    async def side_effect_perform_handshake_with_failures():
        nonlocal handshake_attempts
        handshake_attempts += 1
        if handshake_attempts < 3:
            if client_instance._transport and hasattr(client_instance._transport, '"'"'close'"'"') and callable(client_instance._transport.close):
                await client_instance._transport.close()
            client_instance._transport = None
            raise HandshakeError(f"Simulated handshake failure attempt {handshake_attempts}")

        client_instance._address = "mock_address_retry"
        client_instance._transport_name = "mock_transport_retry"
        client_instance._protocol_version = 1
        client_instance._server_cert = None
        client_instance._transport = AsyncMock()

    mock_perform_handshake_patcher = mocker.patch("pyvider.rpcplugin.client.base.RPCPluginClient._perform_handshake", new_callable=AsyncMock)
    mock_perform_handshake_patcher.side_effect = side_effect_perform_handshake_with_failures

    mock_create_grpc_channel_patcher = mocker.patch("pyvider.rpcplugin.client.base.RPCPluginClient._create_grpc_channel", new_callable=AsyncMock)
    async def side_effect_create_channel():
        client_instance.target_endpoint = "mock_target_endpoint_retry"
        client_instance.grpc_channel = AsyncMock()
    mock_create_grpc_channel_patcher.side_effect = side_effect_create_channel

    spied_logger_info = mocker.spy(client_instance.logger, "info")
    spied_logger_warning = mocker.spy(client_instance.logger, "warning")

    # Ensure _process.poll can be set, using a Popen-specced mock if _process is not already set up
    # The fixture client_instance_local should already set _process correctly.
    # This block might be redundant if fixture guarantees _process is a suitable mock.
    # However, to be safe, ensure any mock for _process is correctly specced if it's redefined here.
    if not client_instance._process or not isinstance(client_instance._process, MagicMock) or not client_instance._process.mock_calls:
        # If _process is None, or not a mock, or an unconfigured mock, ensure it's a Popen-specced mock
        m_proc = MagicMock(spec=subprocess.Popen)
        m_proc.poll.return_value = None # This should now work
        client_instance._process = m_proc
    else:
        # If _process is already a mock (presumably from the fixture), ensure poll can be set.
        # This might not be necessary if the fixture's mock_process_obj is always used.
        # For safety, if we are to ensure poll.return_value is set, the object must support .poll
        # If client_instance._process is already the MagicMock(spec=subprocess.Popen) from the fixture, this is fine.
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

    spied_logger_warning.assert_any_call("Attempt 1 failed: [HandshakeError] Simulated handshake failure attempt 1")
    spied_logger_warning.assert_any_call("Attempt 2 failed: [HandshakeError] Simulated handshake failure attempt 2")

    found_retry_log = False
    for call in spied_logger_info.call_args_list:
        if "Retrying connection/handshake in " in call.args[0]:
            found_retry_log = True
            break
    assert found_retry_log, f"Expected retry log. Actual: {[c.args[0] for c in spied_logger_info.call_args_list]}"

    spied_logger_info.assert_any_call("Attempt 3 of 4 to connect and handshake...")
    spied_logger_info.assert_any_call("Handshake attempt 3 successful. Endpoint: mock_address_retry, Transport: mock_transport_retry")
    spied_logger_info.assert_any_call("Successfully connected to gRPC endpoint on attempt 3: mock_target_endpoint_retry")
    spied_logger_info.assert_any_call("Client connection and handshake successful on attempt 3.")

@pytest.mark.asyncio
async def test_connect_handshake_retry_exhausted(client_instance_local, mocker):
    # TODO: Implement this test case
    # Setup mocks for config (max_retries, etc.)
    # Mock _perform_handshake to always fail
    # Mock _create_grpc_channel (though it might not be reached)
    # Assert that the appropriate exception (e.g., HandshakeError or a custom retry error) is raised after retries are exhausted
    # Assert call counts for _perform_handshake and asyncio.sleep to match max_retries
    # Assert logger warnings for each failed attempt and a final error for exhaustion
    pass

@pytest.mark.asyncio
async def test_connect_handshake_total_retry_timeout_exceeded(client_instance_local, mocker):
    # TODO: Implement this test case
    # Setup mocks for config (total_retry_timeout_s, initial_backoff_ms, etc.)
    # Mock _perform_handshake to always fail
    # Mock asyncio.sleep to simulate time passing and exceeding the total timeout
    # Assert that the appropriate exception is raised when timeout is exceeded
    # Assert call counts and logger messages indicating attempts up to the timeout
    pass

@pytest.mark.asyncio
async def test_connect_handshake_retries_disabled(client_instance_local, mocker):
    # TODO: Implement this test case
    # Setup mocks for config (retry_enabled=false)
    # Mock _perform_handshake to fail once
    # Assert that _perform_handshake is called only once
    # Assert that the initial HandshakeError (or appropriate error) is raised directly without retry attempts
    # Assert no calls to asyncio.sleep for backoff
    # Assert logger messages reflect a single attempt
    pass

@pytest.mark.asyncio
async def test_connect_handshake_plugin_process_dies_during_retries(client_instance_local, mocker):
    # TODO: Implement this test case
    # Setup mocks for config (retry_enabled=true, max_retries, etc.)
    # Mock _perform_handshake to fail
    # Mock client._process.poll to return a non-None value (indicating process died) during one of the retry attempts
    # Assert that an appropriate error (e.g., RPCProcessError or similar) is raised
    # Assert that retries stop once the process death is detected
    # Assert logger messages indicating the failure and process termination
    pass
