import pytest
import subprocess  # Import subprocess
from unittest.mock import MagicMock, AsyncMock
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.client.base import RPCPluginClient


@pytest.fixture
def client_instance_local(mocker):
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
async def test_connect_handshake_total_timeout_immediately(client_instance_local, mocker):
    client_instance = client_instance_local
    mock_config_get = mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.get")
    config_values = {
        "PLUGIN_CLIENT_RETRY_ENABLED": "true",
        "PLUGIN_CLIENT_MAX_RETRIES": 3,
        "PLUGIN_CLIENT_INITIAL_BACKOFF_MS": 10,
        "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": 0.0, # Immediate timeout
    }
    mock_config_get.side_effect = lambda key, default=None: config_values.get(key, default)

    # Control time.monotonic sequence
    monotonic_values_sequence = [
        0.0,  # Initial overall_start_time for _connect_and_handshake_with_retry
        0.01, # First check in loop (for while condition), time() - overall_start_time = 0.01
              # total_timeout_s is 0.0. So 0.01 > 0.0 is true.
    ]
    monotonic_iterator = iter(monotonic_values_sequence)
    final_monotonic_value_after_timeout = 0.05

    def mock_monotonic_side_effect_func():
        nonlocal monotonic_iterator # Ensure we're using the one from the outer scope
        nonlocal final_monotonic_value_after_timeout
        try:
            val = next(monotonic_iterator)
            # client_instance.logger.debug(f"Mock time.monotonic returning: {val}") # Optional: for debugging test
            return val
        except StopIteration:
            # client_instance.logger.debug(f"Mock time.monotonic returning final value: {final_monotonic_value_after_timeout}")
            return final_monotonic_value_after_timeout

    mocker.patch("pyvider.rpcplugin.client.base.time.monotonic", side_effect=mock_monotonic_side_effect_func)
    mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep", new_callable=AsyncMock) # Prevent actual sleep

    if not client_instance._process:
        client_instance._process = MagicMock(spec=subprocess.Popen) # type: ignore[attr-defined]
    client_instance._process.poll.return_value = None # type: ignore[attr-defined]


    with pytest.raises(HandshakeError, match="Retry sequence timed out."):
        await client_instance._connect_and_handshake_with_retry()

    client_instance.logger.error.assert_any_call(
        "Client connection/handshake retry sequence timed out after 0.0s. Last error: N/A"
    )
    assert client_instance._handshake_failed_event.is_set()


@pytest.mark.asyncio
async def test_connect_handshake_retry_disabled_failure(client_instance_local, mocker):
    client_instance = client_instance_local
    mock_config_get = mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.get")
    # Ensure retry_enabled is false
    mock_config_get.side_effect = lambda key, default=None: "false" if key == "PLUGIN_CLIENT_RETRY_ENABLED" else default

    mocker.patch(
        "pyvider.rpcplugin.client.base.RPCPluginClient._perform_handshake",
        new_callable=AsyncMock,
        side_effect=HandshakeError("Simulated handshake failure, retries disabled")
    )
    # Ensure _process exists for the logger call in the except block
    if not client_instance._process:
        client_instance._process = MagicMock(spec=subprocess.Popen) # type: ignore[attr-defined]
        client_instance._process.pid = 1234 # type: ignore[attr-defined]

    with pytest.raises(HandshakeError, match="Simulated handshake failure, retries disabled"):
        await client_instance._connect_and_handshake_with_retry()

    assert client_instance._handshake_failed_event.is_set()
    # Verify error was logged (without checking exact message format due to error code additions)
    assert client_instance.logger.error.called
    # New assertion for the info log
    client_instance.logger.info.assert_any_call(
        "Client retries disabled. Attempting connection and handshake once."
    )


@pytest.mark.asyncio
async def test_connect_handshake_retry_transport_close_fails(client_instance_local, mocker):
    client_instance = client_instance_local
    mock_config_get = mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.get")
    config_values = { "PLUGIN_CLIENT_RETRY_ENABLED": "true", "PLUGIN_CLIENT_MAX_RETRIES": 1 }
    mock_config_get.side_effect = lambda key, default=None: config_values.get(key, default)

    mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep", new_callable=AsyncMock)

    # First attempt fails, triggering retry path
    mock_perform_handshake = mocker.patch(
        "pyvider.rpcplugin.client.base.RPCPluginClient._perform_handshake",
        new_callable=AsyncMock,
        side_effect=HandshakeError("Simulated first failure")
    )

    # Mock transport that will be set during the (failed) handshake attempt
    mock_transport_instance = AsyncMock()
    mock_transport_instance.close = AsyncMock(side_effect=Exception("Transport close failed"))

    # Ensure _perform_handshake sets up a transport that will then fail to close
    async def perform_handshake_sets_transport_then_fails():
        client_instance._transport = mock_transport_instance # Assign the mock transport
        raise HandshakeError("Simulated first failure")
    mock_perform_handshake.side_effect = perform_handshake_sets_transport_then_fails

    if not client_instance._process:
        client_instance._process = MagicMock(spec=subprocess.Popen) # type: ignore[attr-defined]
    client_instance._process.poll.return_value = None # type: ignore[attr-defined]


    with pytest.raises(HandshakeError, match="Simulated first failure"): # Expect the final error
        await client_instance._connect_and_handshake_with_retry()

    # Verify that transport.close() was called and the exception was swallowed
    mock_transport_instance.close.assert_called_once()


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
    monotonic_values_sequence = [
        0.0,  # Initial overall_start_time
        0.01, # First check in loop (attempt 1)
        # Value for the time check that leads to timeout:
        total_timeout_s_config + 0.01 # Ensures time.monotonic() - overall_start_time > total_timeout_s
    ]
    monotonic_iterator = iter(monotonic_values_sequence)
    # After the sequence, keep returning a value that maintains the timeout condition
    final_monotonic_value_after_timeout = total_timeout_s_config + 0.05

    def mock_monotonic_side_effect_func():
        try:
            val = next(monotonic_iterator)
            client_instance.logger.debug(f"Mock time.monotonic returning: {val}")
            return val
        except StopIteration:
            client_instance.logger.debug(f"Mock time.monotonic returning final value: {final_monotonic_value_after_timeout}")
            return final_monotonic_value_after_timeout

    mock_time_monotonic.side_effect = mock_monotonic_side_effect_func

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
    # This path is taken when the current attempt has failed, and scheduling the *next* sleep
    # would push the total time over the limit.
    mock_logger_error.assert_any_call(
        f"Next retry would exceed total timeout. Aborting. Last error: {simulated_error}"
    )
    assert client_instance._handshake_failed_event.is_set()

    # Cleanup of original_poll is not needed here as it's not modified in this test
    # and client_instance_local is function-scoped.


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


# 🐍🔌🧪🪄
