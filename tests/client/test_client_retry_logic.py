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
    mock_process_obj.returncode = None # Ensure returncode is part of the spec if accessed
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

    spied_logger_warning.assert_any_call(
        "Attempt 1 failed: Simulated handshake failure attempt 1"
    )
    spied_logger_warning.assert_any_call(
        "Attempt 2 failed: Simulated handshake failure attempt 2"
    )


@pytest.mark.asyncio
async def test_connect_handshake_retry_process_exits(client_instance_local, mocker):
    """Test retry logic when the plugin process exits during a retry attempt."""
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

    mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep", new_callable=AsyncMock)

    mock_perform_handshake = mocker.patch(
        "pyvider.rpcplugin.client.base.RPCPluginClient._perform_handshake",
        new_callable=AsyncMock,
        side_effect=HandshakeError("Simulated first handshake failure")
    )

    if not client_instance._process:
        client_instance._process = MagicMock(spec=subprocess.Popen)
        client_instance._process.returncode = None

    original_poll = client_instance._process.poll
    if not isinstance(original_poll, MagicMock): # Ensure it's a mock we can control side_effect for
         client_instance._process.poll = MagicMock()

    poll_call_count = 0
    def mock_poll_side_effect(*args, **kwargs): # Added *args, **kwargs for robustness
        nonlocal poll_call_count
        poll_call_count += 1
        if poll_call_count <= 1:
            return None
        client_instance._process.returncode = 1
        return 1

    client_instance._process.poll.side_effect = mock_poll_side_effect

    mock_logger_error = mocker.spy(client_instance.logger, "error")

    # Corrected regex
    expected_error_msg = r"Plugin process exited \(code 1\) during retry sequence\."
    with pytest.raises(HandshakeError, match=expected_error_msg):
        await client_instance._connect_and_handshake_with_retry()

    mock_perform_handshake.assert_called_once()
    mock_logger_error.assert_any_call(
        "Plugin process exited with code 1 during retry attempt 2. Aborting retries."
    )
    assert client_instance._handshake_failed_event.is_set()


@pytest.mark.asyncio
async def test_connect_handshake_total_timeout_exceeded(client_instance_local, mocker):
    """Test retry logic when the total retry timeout is exceeded."""
    client_instance = client_instance_local

    total_timeout_s_config = 0.05 # Very short timeout for testing (50ms)
    mock_config_get = mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.get")
    config_values = {
        "PLUGIN_CLIENT_RETRY_ENABLED": "true",
        "PLUGIN_CLIENT_MAX_RETRIES": 10, # High enough to ensure timeout hits first
        "PLUGIN_CLIENT_INITIAL_BACKOFF_MS": 20, # 20ms
        "PLUGIN_CLIENT_MAX_BACKOFF_MS": 100,  # 100ms
        "PLUGIN_CLIENT_RETRY_JITTER_MS": 1,
        "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": total_timeout_s_config,
    }
    mock_config_get.side_effect = lambda key, default=None: config_values.get(key, default)

    # Mock asyncio.sleep to actually sleep, to allow time.monotonic() to advance
    # Patch time.monotonic to control its return value precisely around sleep
    mock_time_monotonic = mocker.patch("pyvider.rpcplugin.client.base.time.monotonic")

    # _perform_handshake will always fail
    simulated_error = HandshakeError("Simulated persistent handshake failure for timeout test")
    mock_perform_handshake = mocker.patch(
        "pyvider.rpcplugin.client.base.RPCPluginClient._perform_handshake",
        new_callable=AsyncMock,
        side_effect=simulated_error
    )

    # Ensure process appears to be running
    if not client_instance._process:
        client_instance._process = MagicMock(spec=subprocess.Popen)
    client_instance._process.poll.return_value = None
    client_instance._process.returncode = None

    mock_logger_error = mocker.spy(client_instance.logger, "error")
    mock_logger_warning = mocker.spy(client_instance.logger, "warning")

    # Control time.monotonic sequence
    # 1st call: overall_start_time
    # 2nd call: inside loop, before sleep (attempt 1)
    # (asyncio.sleep for initial_backoff_ms (20ms) would happen here)
    # 3rd call: inside loop, before sleep (attempt 2) - this should exceed total_timeout_s_config
    monotonic_return_values = [
        0.0,  # Initial overall_start_time
        0.01, # First check in loop (attempt 1)
        total_timeout_s_config + 0.01 # Second check in loop (attempt 2), now exceeds timeout
    ]
    mock_time_monotonic.side_effect = monotonic_return_values

    # We need actual sleep to allow monotonic time to be checked correctly if not fully mocked
    # For this test, fully mocking monotonic is better.
    # Let's mock asyncio.sleep to do nothing to speed up the test.
    mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep", new_callable=AsyncMock)


    # Expect HandshakeError due to total timeout
    # The error message comes from line 206 or 209
    expected_exception_message = "Retry sequence timed out." # If last_exception is None
    # If last_exception is set, it would be "Simulated persistent handshake failure for timeout test"
    # The code prioritizes last_exception if it exists.

    with pytest.raises(HandshakeError, match="Simulated persistent handshake failure for timeout test"):
        await client_instance._connect_and_handshake_with_retry()

    assert mock_perform_handshake.call_count >= 1 # It should make at least one attempt

    # Check logger calls
    mock_logger_error.assert_any_call(
        f"Client connection/handshake retry sequence timed out after {total_timeout_s_config}s. Last error: {simulated_error}"
    )
    assert client_instance._handshake_failed_event.is_set()

    # Restore original poll only if it was a mock and we changed its side_effect,
    # or if we explicitly replaced a non-mock.
    # This is mainly to ensure test isolation if the fixture is session/module scoped,
    # though client_instance_local is function-scoped.
    if hasattr(client_instance._process, 'poll'):
        if not isinstance(original_poll, MagicMock) and original_poll is not client_instance._process.poll:
             client_instance._process.poll = original_poll
        elif isinstance(original_poll, MagicMock) and original_poll.side_effect is not mock_poll_side_effect:
             client_instance._process.poll.side_effect = original_poll.side_effect


@pytest.mark.asyncio
async def test_connect_handshake_max_retries_reached(client_instance_local, mocker):
    """Test retry logic when max retries are reached."""
    client_instance = client_instance_local

    # Configure retry settings
    max_retries_config = 2 # Test with 2 max retries (so 3 attempts total)
    mock_config_get = mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.get")
    config_values = {
        "PLUGIN_CLIENT_RETRY_ENABLED": "true",
        "PLUGIN_CLIENT_MAX_RETRIES": max_retries_config,
        "PLUGIN_CLIENT_INITIAL_BACKOFF_MS": 1,
        "PLUGIN_CLIENT_MAX_BACKOFF_MS": 5,
        "PLUGIN_CLIENT_RETRY_JITTER_MS": 1,
        "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": 60, # Large enough to not interfere
    }
    mock_config_get.side_effect = lambda key, default=None: config_values.get(key, default)

    mock_sleep = mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep", new_callable=AsyncMock)

    # Mock _perform_handshake to always fail
    simulated_error = HandshakeError("Simulated persistent handshake failure")
    mock_perform_handshake = mocker.patch(
        "pyvider.rpcplugin.client.base.RPCPluginClient._perform_handshake",
        new_callable=AsyncMock,
        side_effect=simulated_error
    )

    # Ensure process appears to be running
    if not client_instance._process:
        client_instance._process = MagicMock(spec=subprocess.Popen)
    client_instance._process.poll.return_value = None # Process is running
    client_instance._process.returncode = None

    # Spy on logger.error
    mock_logger_error = mocker.spy(client_instance.logger, "error")
    mock_logger_warning = mocker.spy(client_instance.logger, "warning")

    # Expect the last HandshakeError after all retries
    with pytest.raises(HandshakeError, match="Simulated persistent handshake failure"):
        await client_instance._connect_and_handshake_with_retry()

    # Assertions
    # Total attempts = max_retries + 1
    assert mock_perform_handshake.call_count == max_retries_config + 1
    # Number of sleeps = max_retries
    assert mock_sleep.call_count == max_retries_config

    # Check logger calls
    for i in range(max_retries_config + 1):
        mock_logger_warning.assert_any_call(
            f"Attempt {i + 1} failed: Simulated persistent handshake failure"
        )

    mock_logger_error.assert_any_call(
        f"Maximum retry attempts ({max_retries_config + 1}) reached for connection/handshake. Last error: {simulated_error}"
    )
    assert client_instance._handshake_failed_event.is_set()
