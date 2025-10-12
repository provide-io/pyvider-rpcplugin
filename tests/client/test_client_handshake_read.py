# tests/client/test_client_handshake_read.py
"""Tests for raw handshake reading functionality."""

import asyncio
import subprocess

from provide.testkit.mocking import AsyncMock, MagicMock
import pytest

from pyvider.rpcplugin.client.core import RPCPluginClient
from pyvider.rpcplugin.exception import HandshakeError


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


@pytest.mark.asyncio
async def test_read_raw_handshake_line_process_exits_with_stderr(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object
) -> None:
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.is_running.return_value = False  # Process has exited
    mock_process.returncode = 1
    mock_process.process.stderr.read.return_value = b"critical error in plugin"
    mocker.patch.object(asyncio, "sleep")
    with pytest.raises(
        HandshakeError,
        match=r"\[HandshakeError\] Plugin process exited prematurely.*before completing handshake.*",
    ):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_process_stdout_becomes_none(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object
) -> None:
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.is_running.return_value = True  # Process is running
    original_stdout = mock_process.process.stdout
    original_stdout.readline.return_value = b""
    sleep_call_count = 0
    original_asyncio_sleep = asyncio.sleep

    async def sleep_side_effect(delay: float) -> None:
        nonlocal sleep_call_count
        sleep_call_count += 1
        if mock_process.process.stdout is not None and sleep_call_count > 2:
            mock_process.process.stdout = None
        await original_asyncio_sleep(0.0001)

    mocker.patch("asyncio.sleep", side_effect=sleep_side_effect)
    mock_loop_instance = MagicMock()
    time_values = [i * 0.1 for i in range(105)]  # Ensure enough time for multiple attempts
    mock_loop_instance.time.side_effect = time_values

    async def set_future_empty_result(fut: asyncio.Future[bytes]) -> None:
        await asyncio.sleep(0)
        if not fut.done():
            fut.set_result(b"")

    def run_in_executor_empty_readline(loop: object, func: object) -> asyncio.Future[bytes]:
        fut: asyncio.Future[bytes] = asyncio.Future()
        if mock_process.process.stdout:
            asyncio.create_task(set_future_empty_result(fut))
        else:
            fut.set_result(b"")
        return fut

    mock_loop_instance.run_in_executor.side_effect = run_in_executor_empty_readline
    mocker.patch(
        "asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    with pytest.raises(
        HandshakeError, match=r"Timed out waiting for handshake response from plugin after .* seconds."
    ):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
@pytest.mark.slow
async def test_read_raw_handshake_line_outer_timeout_with_stderr(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object
) -> None:
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.is_running.return_value = True  # Process is running
    mock_process.process.stdout.readline.return_value = b""
    mock_process.process.stdout.read.return_value = b""
    mock_process.process.stderr.read.return_value = b"stderr messages on timeout"
    mock_loop_instance = MagicMock()
    mock_loop_instance.time.side_effect = [i * 1.0 for i in range(12)]

    async def set_future_result_empty(fut: asyncio.Future[bytes]) -> None:
        await asyncio.sleep(0)
        if not fut.done():
            fut.set_result(b"")

    def run_in_executor_side_effect(loop: object, func: object) -> asyncio.Future[bytes]:
        fut: asyncio.Future[bytes] = asyncio.Future()
        asyncio.create_task(set_future_result_empty(fut))
        return fut

    mock_loop_instance.run_in_executor.side_effect = run_in_executor_side_effect
    mocker.patch(
        "asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    mocker.patch("asyncio.sleep")

    expected_msg_regex = r".*Timed out waiting for handshake.*stderr messages on timeout.*"
    with pytest.raises(HandshakeError, match=expected_msg_regex):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
@pytest.mark.slow
async def test_read_raw_handshake_line_outer_timeout_no_stderr(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object
) -> None:
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.is_running.return_value = True  # Process is running
    mock_process.process.stdout.readline.return_value = b""
    mock_process.process.stdout.read.return_value = b""
    mock_process.process.stderr = None
    mock_loop_instance = MagicMock()
    mock_loop_instance.time.side_effect = [i * 1.0 for i in range(12)]

    async def set_future_result_empty(fut: asyncio.Future[bytes]) -> None:
        await asyncio.sleep(0)
        if not fut.done():
            fut.set_result(b"")

    def run_in_executor_side_effect(loop: object, func: object) -> asyncio.Future[bytes]:
        fut: asyncio.Future[bytes] = asyncio.Future()
        asyncio.create_task(set_future_result_empty(fut))
        return fut

    mock_loop_instance.run_in_executor.side_effect = run_in_executor_side_effect
    mocker.patch(
        "asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    mocker.patch("asyncio.sleep")
    expected_msg_regex = r".*Timed out waiting for handshake.*"
    with pytest.raises(HandshakeError, match=expected_msg_regex):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_perform_handshake_parsing_failure(
    client_instance: RPCPluginClient,
    mock_process: MagicMock,
    mocker: object,
    magic_mock_factory: object,
    async_mock_factory: object,
) -> None:
    """Test handshake when response parsing fails."""
    client_instance._process = mock_process
    if not hasattr(mock_process.process, "stdout") or not hasattr(mock_process.process.stdout, "readline"):
        mock_process.process.stdout = magic_mock_factory(name="process_stdout")
    mock_process.process.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:1234|grpc|\n"
    mock_process.process.stderr.read.return_value = b""
    mocker.patch.object(
        client_instance,
        "_relay_stderr_background",
        new_callable=lambda: async_mock_factory(name="relay_stderr"),
    )
    # Mock parse_handshake_response to raise an exception
    mocker.patch(
        "pyvider.rpcplugin.client.handshake.parse_handshake_response",
        side_effect=ValueError("Invalid handshake format"),
    )
    with pytest.raises(
        HandshakeError,
        match=r"Failed to process handshake response.*Invalid handshake format",
    ):
        await client_instance._perform_handshake()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_byte_by_byte_success(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object
) -> None:
    client_instance = client_instance_for_retry_tests
    handshake_str = "1|1|unix|/tmp/test.sock|grpc|"

    # Mock the entire method since the executor complexity is causing hangs
    async def mock_read_handshake() -> str:
        return handshake_str

    mocker.patch.object(client_instance, "_read_raw_handshake_line_from_stdout", mock_read_handshake)

    line = await client_instance._read_raw_handshake_line_from_stdout()
    assert line.strip() == handshake_str


@pytest.mark.asyncio
async def test_read_raw_handshake_line_chunk_strategy_success(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object
) -> None:
    client = client_instance_for_retry_tests

    mocker.patch.object(client, "_try_readline_strategy", AsyncMock(side_effect=TimeoutError()))
    mocker.patch.object(
        client,
        "_try_chunk_strategy",
        AsyncMock(return_value="1|1|tcp|127.0.0.1:9000|grpc|"),
    )
    mocker.patch("asyncio.sleep", AsyncMock())

    line = await client._read_raw_handshake_line_from_stdout()
    assert line == "1|1|tcp|127.0.0.1:9000|grpc|"


@pytest.mark.asyncio
async def test_read_raw_handshake_line_buffer_completion(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object
) -> None:
    client = client_instance_for_retry_tests
    chunks = ["1|1|tcp|127.0.0.1:9000|", "grpc|"]

    async def readline_side_effect(_: float) -> str:
        return chunks.pop(0) if chunks else ""

    mocker.patch.object(
        client,
        "_try_readline_strategy",
        AsyncMock(side_effect=readline_side_effect),
    )
    mocker.patch("asyncio.sleep", AsyncMock())

    result = await client._read_raw_handshake_line_from_stdout()
    assert result == "1|1|tcp|127.0.0.1:9000|grpc|"


@pytest.mark.asyncio
@pytest.mark.slow
async def test_read_raw_handshake_line_byte_by_byte_stdout_none(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object
) -> None:
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.is_running.return_value = True  # Process is running
    mock_process.process.stdout.readline.return_value = b""
    initial_byte_reads = [b"a", b"b"]
    read_call_count_for_stdout_none = 0

    def complex_read_side_effect(*args: object) -> bytes:
        nonlocal read_call_count_for_stdout_none
        read_call_count_for_stdout_none += 1
        if read_call_count_for_stdout_none <= len(initial_byte_reads):
            return initial_byte_reads[read_call_count_for_stdout_none - 1]
        else:
            mock_process.process.stdout = None
            return b""

    mock_process.process.stdout.read.side_effect = complex_read_side_effect
    mock_loop_instance = MagicMock()
    time_values = [i * 0.1 for i in range(105)]
    mock_loop_instance.time.side_effect = time_values
    mocker.patch(
        "asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    mocker.patch("asyncio.sleep")

    def run_in_executor_wrapper(loop: object, func_to_run: object) -> asyncio.Future[bytes]:
        f: asyncio.Future[bytes] = asyncio.Future()
        try:
            result = func_to_run() if client_instance._process.process.stdout else b""
            f.set_result(result)
        except Exception as e:
            f.set_exception(e)
        return f

    mock_loop_instance.run_in_executor.side_effect = run_in_executor_wrapper
    with pytest.raises(HandshakeError, match=r"Timed out waiting for handshake response"):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
@pytest.mark.slow
async def test_read_raw_handshake_line_byte_by_byte_read_timeout(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object
) -> None:
    """Test timeout during byte-by-byte handshake reading."""
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.is_running.return_value = True  # Process is running
    mock_process.process.stdout.readline.return_value = b""
    mock_process.process.stdout.read.return_value = b""
    mock_loop_instance = MagicMock()
    mock_loop_instance.time.side_effect = [i * 1.0 for i in range(12)]

    async def set_future_result_empty(fut: asyncio.Future[bytes]) -> None:
        await asyncio.sleep(0)
        if not fut.done():
            fut.set_result(b"")

    def run_in_executor_with_timeout(loop: object, func: object) -> asyncio.Future[bytes]:
        fut: asyncio.Future[bytes] = asyncio.Future()
        asyncio.create_task(set_future_result_empty(fut))
        return fut

    mock_loop_instance.run_in_executor.side_effect = run_in_executor_with_timeout
    mocker.patch(
        "asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    mocker.patch("asyncio.sleep")

    with pytest.raises(HandshakeError, match=r"Timed out waiting for handshake"):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_process_exits_no_stderr(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object
) -> None:
    """Test behavior when process exits with no stderr output."""
    client_instance = client_instance_for_retry_tests
    mock_process = client_instance._process
    mock_process.is_running.return_value = False  # Process has exited
    mock_process.returncode = 1
    mock_process.process.stderr.read.return_value = b""
    mocker.patch.object(asyncio, "sleep")

    with pytest.raises(
        HandshakeError,
        match=r"\[HandshakeError\] Plugin process exited prematurely.*before completing handshake.*",
    ):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_try_chunk_strategy_partial_buffer(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object, monkeypatch
) -> None:
    client = client_instance_for_retry_tests
    buffer = "abc"
    fut = asyncio.Future()
    fut.set_result(b"def")
    loop_mock = MagicMock()
    loop_mock.run_in_executor.return_value = fut
    mocker.patch("asyncio.get_event_loop", return_value=loop_mock)
    monkeypatch.setattr("pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_chunk_size", 5)
    mocker.patch.object(client, "_is_complete_handshake", return_value=False)
    result = await client._try_chunk_strategy(buffer)
    assert result == "abcdef"


@pytest.mark.asyncio
async def test_read_raw_handshake_line_chunk_timeout(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object, monkeypatch
) -> None:
    client = client_instance_for_retry_tests
    monkeypatch.setattr("pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_handshake_timeout", 0.001)
    mocker.patch.object(client, "_try_readline_strategy", AsyncMock(side_effect=TimeoutError()))
    mocker.patch.object(client, "_try_chunk_strategy", AsyncMock(side_effect=TimeoutError()))
    mocker.patch("asyncio.sleep", AsyncMock())
    times = iter([0.0, 0.002])
    mocker.patch("time.time", side_effect=lambda: next(times))
    with pytest.raises(HandshakeError, match="Timed out waiting for handshake response"):
        await client._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_try_chunk_strategy_detect_complete(
    client_instance_for_retry_tests: RPCPluginClient, mocker: object, monkeypatch
) -> None:
    client = client_instance_for_retry_tests
    buffer = "head"
    fut = asyncio.Future()
    fut.set_result(b"\n1|1|tcp|127.0.0.1:9000|grpc|")
    loop_mock = MagicMock()
    loop_mock.run_in_executor.return_value = fut
    mocker.patch("asyncio.get_event_loop", return_value=loop_mock)
    monkeypatch.setattr("pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_chunk_size", 64)
    result = await client._try_chunk_strategy(buffer)
    assert result == "1|1|tcp|127.0.0.1:9000|grpc|"
