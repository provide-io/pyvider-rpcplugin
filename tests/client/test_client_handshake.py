# tests/client/test_client_handshake.py

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import subprocess  # Added for spec=subprocess.Popen

from pyvider.rpcplugin.exception import (
    HandshakeError,
)  # Added ProtocolError, SecurityError
from pyvider.rpcplugin.client.base import RPCPluginClient


@pytest.fixture
async def client_instance_for_retry_tests(mocker):
    client = RPCPluginClient(command=["dummy-plugin-cmd"])
    client.logger = mocker.MagicMock(spec=["info", "warning", "error", "debug"])
    mock_process_obj = MagicMock(spec=subprocess.Popen)
    mock_process_obj.poll.return_value = None
    mock_process_obj.returncode = None
    mock_process_obj.stderr = MagicMock()
    mock_process_obj.stdout = MagicMock()
    client._process = mock_process_obj
    return client


@pytest.mark.asyncio
async def test_relay_stderr_background(client_instance, mock_process):
    client_instance._process = mock_process
    with patch("threading.Thread") as mock_thread:
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance
        await client_instance._relay_stderr_background()
        mock_thread.assert_called_once()
        mock_thread_instance.start.assert_called_once()


@pytest.mark.asyncio
async def test_perform_handshake_success(client_instance, mock_process):
    client_instance._process = mock_process
    with (
        patch(
            "pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background",
            new_callable=AsyncMock,
        ) as mock_relay,
        patch(
            "pyvider.rpcplugin.client.base.TCPSocketTransport"
        ) as mock_transport_class,
    ):
        mock_transport_instance = AsyncMock()
        mock_transport_class.return_value = mock_transport_instance
        mock_process.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:8000|grpc|\n"
        await client_instance._perform_handshake()
        mock_relay.assert_called_once()
        assert client_instance._protocol_version == 1
        assert client_instance._transport is mock_transport_instance
        assert client_instance._server_cert is None


@pytest.mark.asyncio
async def test_perform_handshake_with_cert(client_instance, mock_process):
    client_instance._process = mock_process
    sample_cert = "dGVzdA=="
    with (
        patch(
            "pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background",
            new_callable=AsyncMock,
        ) as mock_relay,
        patch(
            "pyvider.rpcplugin.client.base.TCPSocketTransport"
        ) as mock_transport_class,
    ):
        mock_transport_instance = AsyncMock()
        mock_transport_class.return_value = mock_transport_instance
        mock_process.stdout.readline.return_value = (
            "1|1|tcp|127.0.0.1:8000|grpc|{}\\n".format(sample_cert).encode()
        )
        await client_instance._perform_handshake()
        mock_relay.assert_called_once()
        assert client_instance._protocol_version == 1
        assert client_instance._transport is mock_transport_instance
        assert client_instance._server_cert == sample_cert


@pytest.mark.asyncio
async def test_perform_handshake_with_unix_transport(client_instance, mock_process):
    client_instance._process = mock_process
    with (
        patch(
            "pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background",
            new_callable=AsyncMock,
        ) as mock_relay,
        patch(
            "pyvider.rpcplugin.client.base.UnixSocketTransport"
        ) as mock_transport_class,
    ):
        mock_transport_instance = AsyncMock()
        mock_transport_class.return_value = mock_transport_instance
        mock_process.stdout.readline.return_value = b"1|1|unix|/tmp/test.sock|grpc|\n"
        await client_instance._perform_handshake()
        mock_relay.assert_called_once()
        assert client_instance._protocol_version == 1
        assert client_instance._transport_name == "unix"
        assert client_instance._transport is mock_transport_instance
        mock_transport_instance.connect.assert_called_once_with("/tmp/test.sock")


@pytest.mark.asyncio
async def test_perform_handshake_no_process(client_instance):
    client_instance._process = None
    with pytest.raises(
        HandshakeError,
        match="Plugin process or its stdout stream is not available for handshake.",
    ):
        await client_instance._perform_handshake()


@pytest.mark.asyncio
async def test_perform_handshake_process_exit(client_instance, mock_process):
    client_instance._process = mock_process
    mock_process.poll.return_value = 1
    mock_process.returncode = 1
    mock_process.stderr.read.return_value = b"Error during startup"
    mock_process.stderr.readline.return_value = b""
    with pytest.raises(
        HandshakeError,
        match=r"Plugin process exited prematurely \(code 1\) before handshake.",
    ):
        await client_instance._perform_handshake()


@pytest.mark.asyncio
async def test_perform_handshake_invalid_format(
    client_instance, mock_process, mocker
):  # Added mocker
    client_instance._process = mock_process

    # Mock _read_raw_handshake_line_from_stdout to directly return the problematic line
    # This bypasses the internal looping/timeout logic of _read_raw_handshake_line_from_stdout
    # and ensures that _perform_handshake proceeds to call parse_handshake_response with this line.
    mocker.patch(
        "pyvider.rpcplugin.client.base.RPCPluginClient._read_raw_handshake_line_from_stdout",
        new_callable=AsyncMock,
        return_value="invalid_handshake_format",
    )

    expected_error_match = r"\[HandshakeError\] Failed to parse handshake response: \[HandshakeError\] Invalid handshake format. Expected 6 pipe-separated parts, got 1: 'invalid_handshake_format...' \(Hint: Ensure the plugin's handshake output matches 'CORE_VER\|PLUGIN_VER\|NET\|ADDR\|PROTO\|CERT'.\)"
    with (
        patch(
            "pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background",
            new_callable=AsyncMock,
        ) as mock_relay,
        pytest.raises(HandshakeError, match=expected_error_match),
    ):
        await client_instance._perform_handshake()
        mock_relay.assert_called_once()  # This should be inside the with block if it depends on successful execution of the try part


@pytest.mark.asyncio
async def test_perform_handshake_parse_error(client_instance, mock_process):
    client_instance._process = mock_process
    mock_process.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:8000|grpc|\n"
    with (
        patch(
            "pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background",
            new_callable=AsyncMock,
        ),
        patch(
            "pyvider.rpcplugin.client.base.parse_handshake_response",
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
async def test_perform_handshake_invalid_network_type(client_instance, mock_process):
    client_instance._process = mock_process
    mock_process.stdout.readline.return_value = (
        b"1|1|invalid_net|127.0.0.1:8000|grpc|\n"
    )
    with (
        patch(
            "pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background",
            new_callable=AsyncMock,
        ),
        pytest.raises(
            HandshakeError,
            match=r"\[HandshakeError\] Invalid network type 'invalid_net' in handshake.*Hint: Network type must be 'tcp' or 'unix'\..*",
        ),
    ):
        await client_instance._perform_handshake()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_process_exits_with_stderr(
    client_instance_for_retry_tests, mocker
):
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.poll.return_value = 1
    mock_process.returncode = 1
    mock_process.stderr.read.return_value = b"critical error in plugin"
    mocker.patch.object(asyncio, "sleep")
    with pytest.raises(
        HandshakeError,
        match=r"Plugin process exited prematurely \(code 1\) before handshake.",
    ):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_process_stdout_becomes_none(
    client_instance_for_retry_tests, mocker
):
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.poll.return_value = None
    original_stdout = mock_process.stdout
    original_stdout.readline.return_value = b""
    sleep_call_count = 0
    original_asyncio_sleep = asyncio.sleep

    async def sleep_side_effect(delay):
        nonlocal sleep_call_count
        sleep_call_count += 1
        if mock_process.stdout is not None and sleep_call_count > 2:
            mock_process.stdout = None
        await original_asyncio_sleep(0.0001)

    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.sleep", side_effect=sleep_side_effect
    )
    mock_loop_instance = MagicMock()
    time_values = [
        i * 0.1 for i in range(105)
    ]  # Ensure enough time for multiple attempts
    mock_loop_instance.time.side_effect = time_values

    async def set_future_empty_result(fut):
        await asyncio.sleep(0)
        if not fut.done():
            fut.set_result(b"")

    def run_in_executor_empty_readline(loop, func):
        fut = asyncio.Future()
        asyncio.create_task(set_future_empty_result(fut))
        return fut

    mock_loop_instance.run_in_executor.side_effect = run_in_executor_empty_readline
    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    with pytest.raises(
        HandshakeError, match=r"Timed out waiting for handshake line from plugin."
    ):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_outer_timeout_with_stderr(
    client_instance_for_retry_tests, mocker
):
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.poll.return_value = None
    mock_process.stdout.readline.return_value = b""
    mock_process.stdout.read.return_value = b""
    mock_process.stderr.read.return_value = b"stderr messages on timeout"
    mock_loop_instance = MagicMock()
    mock_loop_instance.time.side_effect = [i * 1.0 for i in range(12)]

    async def set_future_result_empty(fut):
        await asyncio.sleep(0)
        if not fut.done():
            fut.set_result(b"")

    def run_in_executor_side_effect(loop, func):
        fut = asyncio.Future()
        asyncio.create_task(set_future_result_empty(fut))
        return fut

    mock_loop_instance.run_in_executor.side_effect = run_in_executor_side_effect
    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep")

    expected_msg_regex = r"\[HandshakeError\] Timed out waiting for handshake line from plugin\. \(Hint: Ensure the plugin command '\['dummy-plugin-cmd'\]' starts correctly and outputs the handshake string to stdout within 10\.0 seconds\..*Stderr: 'stderr messages on timeout'\)"
    with pytest.raises(HandshakeError, match=expected_msg_regex):
        await client_instance._read_raw_handshake_line_from_stdout()
    # client_instance.logger.error.assert_any_call("🤝 Handshake timed out. Stderr output: stderr messages on timeout") # Commented out


@pytest.mark.asyncio
async def test_read_raw_handshake_line_outer_timeout_no_stderr(
    client_instance_for_retry_tests, mocker
):
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.poll.return_value = None
    mock_process.stdout.readline.return_value = b""
    mock_process.stdout.read.return_value = b""
    mock_process.stderr = None
    mock_loop_instance = MagicMock()
    mock_loop_instance.time.side_effect = [i * 1.0 for i in range(12)]

    async def set_future_result_empty(fut):
        await asyncio.sleep(0)
        if not fut.done():
            fut.set_result(b"")

    def run_in_executor_side_effect(loop, func):
        fut = asyncio.Future()
        asyncio.create_task(set_future_result_empty(fut))
        return fut

    mock_loop_instance.run_in_executor.side_effect = run_in_executor_side_effect
    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep")
    expected_msg_regex = r"\[HandshakeError\] Timed out waiting for handshake line from plugin\. \(Hint: Ensure the plugin command '\['dummy-plugin-cmd'\]' starts correctly and outputs the handshake string to stdout within 10\.0 seconds\..*Stderr: ''\)"
    with pytest.raises(HandshakeError, match=expected_msg_regex):
        await client_instance._read_raw_handshake_line_from_stdout()
    # client_instance.logger.error.assert_any_call("🤝 Handshake timed out. Stderr output: ") # Commented out


@pytest.mark.asyncio
async def test_perform_handshake_transport_not_initialized(
    client_instance, mock_process, mocker
):
    client_instance._process = mock_process
    if not hasattr(mock_process, "stdout") or not hasattr(
        mock_process.stdout, "readline"
    ):
        mock_process.stdout = MagicMock()
    mock_process.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:1234|grpc|\n"
    mocker.patch(
        "pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background",
        new_callable=AsyncMock,
    )
    mocker.patch(
        "pyvider.rpcplugin.client.base.parse_handshake_response",
        return_value=(1, 1, "tcp", "127.0.0.1:1234", "grpc", None),
    )
    mocker.patch("pyvider.rpcplugin.client.base.TCPSocketTransport", return_value=None)
    mocker.patch("pyvider.rpcplugin.client.base.UnixSocketTransport", return_value=None)
    with pytest.raises(
        HandshakeError,
        match=r"Internal error: Transport was not initialized before attempting to connect.",
    ):
        await client_instance._perform_handshake()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_byte_by_byte_success(
    client_instance_for_retry_tests, mocker
):
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.poll.return_value = None
    handshake_str = "1|1|unix|/tmp/test.sock|grpc|"
    handshake_bytes_list = [bytes([b]) for b in handshake_str.encode("utf-8")]
    mock_process.stdout.readline.return_value = b""

    # Define this helper function inside the test method or ensure it's properly scoped
    read_call_idx = 0
    # The list of byte strings to return, ending with a persistent EOF signal (b"")
    bytes_to_return_sequence = handshake_bytes_list + [b""]

    def robust_read_side_effect(*args, **kwargs):
        nonlocal read_call_idx
        if read_call_idx < len(bytes_to_return_sequence):
            val = bytes_to_return_sequence[read_call_idx]
            read_call_idx += 1
            return val
        return b""  # Persistently return EOF after sequence is exhausted

    mock_process.stdout.read.side_effect = robust_read_side_effect
    executor_call_count = 0

    async def set_future_result(fut, result_value):
        await asyncio.sleep(0)
        if not fut.done():
            fut.set_result(result_value)

    def custom_run_in_executor(loop, func_to_run):
        nonlocal executor_call_count
        f = asyncio.Future()
        executor_call_count += 1
        result_val = b""
        if executor_call_count == 1:  # Simulates initial readline() call
            result_val = mock_process.stdout.readline()
        else:  # Simulates subsequent read(1) calls
            try:
                result_val = func_to_run()  # This is mock_process.stdout.read(1)
            except StopIteration:  # This is the key!
                result_val = b""
        asyncio.create_task(set_future_result(f, result_val))
        return f

    mock_loop_instance = MagicMock()
    # Generous time_values to prevent exhaustion by loop.time() calls from wait_for
    time_values = [i * 0.01 for i in range(2000)]
    mock_loop_instance.time.side_effect = time_values
    mock_loop_instance.run_in_executor.side_effect = custom_run_in_executor
    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep")
    line = await client_instance._read_raw_handshake_line_from_stdout()
    assert line.strip() == handshake_str


@pytest.mark.asyncio
async def test_read_raw_handshake_line_byte_by_byte_stdout_none(
    client_instance_for_retry_tests, mocker
):
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.poll.return_value = None
    mock_process.stdout.readline.return_value = b""
    initial_byte_reads = [b"a", b"b"]
    read_call_count_for_stdout_none = 0

    def complex_read_side_effect(*args):
        nonlocal read_call_count_for_stdout_none
        read_call_count_for_stdout_none += 1
        if read_call_count_for_stdout_none <= len(initial_byte_reads):
            return initial_byte_reads[read_call_count_for_stdout_none - 1]
        else:
            mock_process.stdout = None
            return b""

    mock_process.stdout.read.side_effect = complex_read_side_effect
    mock_loop_instance = MagicMock()
    time_values = [i * 0.1 for i in range(105)]
    mock_loop_instance.time.side_effect = time_values
    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep")

    def run_in_executor_wrapper(loop, func_to_run):
        f = asyncio.Future()
        try:
            if client_instance._process.stdout:
                result = func_to_run()
            else:
                result = b""
            f.set_result(result)
        except Exception as e:
            f.set_exception(e)
        return f

    mock_loop_instance.run_in_executor.side_effect = run_in_executor_wrapper
    with pytest.raises(HandshakeError, match=r"Timed out waiting for handshake line"):
        await client_instance._read_raw_handshake_line_from_stdout()


# LONG_RUNNING_TEST - This test takes approximately 3 minutes to run due to byte-by-byte processing and timeouts.
# long-running
@pytest.mark.asyncio
# long-running test
async def test_read_raw_handshake_line_byte_by_byte_read_timeout(
    client_instance_for_retry_tests, mocker
):
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.poll.return_value = None
    mock_process.stdout.readline.return_value = b""
    original_asyncio_wait_for = asyncio.wait_for
    wait_for_call_count = 0

    async def custom_wait_for(awaitable, timeout):
        nonlocal wait_for_call_count
        wait_for_call_count += 1
        if wait_for_call_count > 1 and timeout == 1.0:
            raise asyncio.TimeoutError("Simulated inner timeout for read(1)")
        return await original_asyncio_wait_for(awaitable, timeout)

    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.wait_for", side_effect=custom_wait_for
    )

    def run_in_executor_for_inner_timeout(loop, func):
        f = asyncio.Future()
        is_readline_call = "readline" in getattr(func, "__qualname__", "")
        if is_readline_call:
            f.set_result(b"")
        else:
            pass  # For read(1) calls, let custom_wait_for handle the timeout
        return f

    mock_loop_instance = MagicMock()
    # Define time_values to correctly simulate passing the 10s timeout
    # The timeout in _read_raw_handshake_line_from_stdout is 10.0 seconds.
    simulated_timeout_duration = 10.0
    time_step = 0.1  # Advance time by 0.1s per call to loop.time()
    # Add enough steps to go past the timeout plus a small buffer
    num_steps = int(simulated_timeout_duration / time_step) + 5
    time_values = [i * time_step for i in range(num_steps)]
    mock_loop_instance.time.side_effect = time_values
    mock_loop_instance.run_in_executor.side_effect = run_in_executor_for_inner_timeout
    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep")
    with pytest.raises(
        HandshakeError, match=r"Timed out waiting for handshake line from plugin."
    ):  # General timeout
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_process_exits_no_stderr(
    client_instance_for_retry_tests, mocker
):
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.poll.return_value = 1
    mock_process.returncode = 1
    mock_process.stderr = None
    mocker.patch.object(asyncio, "sleep")
    with pytest.raises(
        HandshakeError,
        match=r"Plugin process exited prematurely \(code 1\) before handshake.",
    ):
        await client_instance._read_raw_handshake_line_from_stdout()


# Test Case 1 for retry logic (using client_instance_for_retry_tests fixture)
@pytest.mark.asyncio
async def test_connect_handshake_retry_success_first_attempt(
    client_instance_for_retry_tests, mocker
):
    client_instance = client_instance_for_retry_tests
    mock_config_get = mocker.patch("pyvider.rpcplugin.config.rpcplugin_config.get")
    config_values = {
        "PLUGIN_CLIENT_RETRY_ENABLED": "true",
        "PLUGIN_CLIENT_MAX_RETRIES": 3,
        "PLUGIN_CLIENT_INITIAL_BACKOFF_MS": 10,
        "PLUGIN_CLIENT_MAX_BACKOFF_MS": 100,
        "PLUGIN_CLIENT_RETRY_JITTER_MS": 5,
        "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": 5,
    }
    mock_config_get.side_effect = lambda key, default=None: config_values.get(
        key, default
    )

    mock_perform_handshake = mocker.patch(
        "pyvider.rpcplugin.client.base.RPCPluginClient._perform_handshake",
        new_callable=AsyncMock,
    )
    mock_create_grpc_channel = mocker.patch(
        "pyvider.rpcplugin.client.base.RPCPluginClient._create_grpc_channel",
        new_callable=AsyncMock,
    )

    async def side_effect_perform_handshake():
        client_instance._address = "mock_address"
        client_instance._transport_name = "mock_transport"
        client_instance._protocol_version = 1
        client_instance._server_cert = None
        client_instance._transport = AsyncMock()

    mock_perform_handshake.side_effect = side_effect_perform_handshake

    async def side_effect_create_channel():
        client_instance.target_endpoint = "mock_target_endpoint"
        client_instance.grpc_channel = AsyncMock()

    mock_create_grpc_channel.side_effect = side_effect_create_channel

    logger_mock = client_instance.logger

    client_instance.is_started = False
    client_instance._handshake_complete_event.clear()
    client_instance._handshake_failed_event.clear()
    client_instance.grpc_channel = None
    client_instance._transport = None

    await client_instance._connect_and_handshake_with_retry()

    mock_perform_handshake.assert_called_once()
    mock_create_grpc_channel.assert_called_once()
    assert client_instance.is_started is True
    assert client_instance._handshake_complete_event.is_set() is True
    assert client_instance._handshake_failed_event.is_set() is False
    for call_args in logger_mock.warning.call_args_list:
        assert "failed:" not in call_args[0][0].lower()
    logger_mock.info.assert_any_call("Attempt 1 of 4 to connect and handshake...")
    logger_mock.info.assert_any_call(
        "Handshake attempt 1 successful. Endpoint: mock_address, Transport: mock_transport"
    )
    logger_mock.info.assert_any_call(
        "Successfully connected to gRPC endpoint on attempt 1: mock_target_endpoint"
    )
    logger_mock.info.assert_any_call(
        "Client connection and handshake successful on attempt 1."
    )
    assert any(
        "Starting connection/handshake sequence with retries enabled" in call.args[0]
        for call in logger_mock.info.call_args_list
    )
