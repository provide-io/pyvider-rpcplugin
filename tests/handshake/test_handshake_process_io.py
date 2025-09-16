# tests/handshake/test_handshake_process_io.py
import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import subprocess  # For Popen spec
import re  # For escaping regex if needed

from pyvider.rpcplugin.handshake import (
    read_handshake_response,
    parse_handshake_response, # Changed import
    create_stderr_relay,
)
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.config import rpcplugin_config  # Import the config object


# Mock Popen object for testing
class MockProcess:
    def __init__(self, stdout_content=None, stderr_content=None, exit_code=None):
        self.stdout = MagicMock()
        self.stderr = MagicMock()
        self.returncode = exit_code

        if stdout_content is not None:
            # Make readline return content then empty bytes (EOF)
            self.stdout.readline.side_effect = [stdout_content.encode(), b""]
            # Make read return content then empty bytes (EOF)
            self.stdout.read.side_effect = [stdout_content.encode(), b""]
        else:
            self.stdout.readline.return_value = b""
            self.stdout.read.return_value = b""

        if stderr_content is not None:
            self.stderr.read.return_value = stderr_content.encode()
        else:
            self.stderr.read.return_value = b""

        # If stderr is None, ensure read access raises appropriate error or returns None
        if stderr_content is None:
            # Make stderr itself None to simulate no stderr pipe
            self.stderr = None

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is not None:
            return self.returncode
        if timeout:
            # Simulate timeout if process hasn't "exited"
            raise subprocess.TimeoutExpired(cmd="test", timeout=timeout)
        return None  # Should not be reached if timeout is always provided in tests

    def terminate(self):
        self.returncode = -15  # Simulate termination

    def kill(self):
        self.returncode = -9  # Simulate kill


# --- Test Cases ---


@pytest.mark.asyncio
async def test_read_handshake_response_complete_line(mocker):
    """Test reading a complete handshake line successfully."""
    process = MockProcess(stdout_content="1|1|tcp|127.0.0.1:1234|grpc|\n")
    mocker.patch("time.time", side_effect=[0, 0.1])  # Ensure loop runs once

    line = await read_handshake_response(process)
    assert line == "1|1|tcp|127.0.0.1:1234|grpc|"


@pytest.mark.asyncio
@pytest.mark.slow
async def test_read_handshake_response_multiple_attempts(mocker):
    """Test reading handshake that requires multiple read attempts (chunked)."""
    process = MockProcess()
    # Simulate chunked reading
    process.stdout.readline.side_effect = asyncio.TimeoutError(
        "Simulated readline timeout to force chunk strategy"
    )
    process.stdout.read.side_effect = [b"1|1|tcp|", b"127.0.0.1:1234", b"|grpc|\n", b""]

    # Mock time to control loop iterations
    time_values = [i * 0.1 for i in range(200)]  # Simulate up to 20 seconds
    mocker.patch("time.time", side_effect=time_values)
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)  # Mock sleep to run fast

    line = await read_handshake_response(process)
    assert line == "1|1|tcp|127.0.0.1:1234|grpc|"


@pytest.mark.asyncio
async def test_read_handshake_response_process_exit_stderr_read_error(mocker):
    """Test error when process exits and reading its stderr also fails."""
    process = MockProcess(stdout_content="", exit_code=1)
    process.stderr = mocker.MagicMock()
    process.stderr.read.side_effect = OSError("Failed to read stderr")

    mock_logger_error = mocker.patch("pyvider.rpcplugin.handshake.negotiation.logger.error")

    expected_regex = r".*Plugin process exited prematurely.*"
    with pytest.raises(HandshakeError, match=expected_regex):
        await read_handshake_response(process)

    mock_logger_error.assert_called_once_with(
        "🤝📥❌ Plugin process exited with code 1 before handshake"
    )


@pytest.mark.asyncio
async def test_read_handshake_response_timeout(mocker):
    """Test timeout while waiting for handshake response."""
    process = MockProcess()
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)
    mocker.patch(
        "time.time", side_effect=[i * 2.0 for i in range(100)]  # Provide enough values
    )

    mock_logger_error = mocker.patch("pyvider.rpcplugin.handshake.negotiation.logger.error")

    with pytest.raises(
        HandshakeError,
        match=r"Timed out waiting for handshake response from plugin after 10.0 seconds.",
    ):
        await read_handshake_response(process)

    for call_args in mock_logger_error.call_args_list:
        args, _ = call_args
        if (
            "Timed out waiting for handshake response from plugin after 10.0 seconds."
            in args[0]
        ):
            break


@pytest.mark.asyncio
async def test_read_handshake_response_timeout_stderr_read_error(mocker):
    """Test timeout while waiting for handshake, and stderr read also fails."""
    process = MockProcess()
    process.stderr = mocker.MagicMock()
    process.stderr.read.side_effect = OSError("Failed to read stderr on timeout")

    mocker.patch("pyvider.rpcplugin.handshake.negotiation.asyncio.sleep", new_callable=AsyncMock)
    mocker.patch(
        "pyvider.rpcplugin.handshake.negotiation.time.time", side_effect=[i * 2.0 for i in range(100)]  # Provide enough values
    )

    expected_regex = r".*Timed out waiting for handshake response.*"
    with pytest.raises(HandshakeError, match=expected_regex):
        await read_handshake_response(process)


@pytest.mark.asyncio
async def test_read_handshake_response_process_exit(mocker):
    """Test when process exits cleanly before handshake."""
    process = MockProcess(exit_code=0, stderr_content="Exited normally.")
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)
    mocker.patch("time.time", side_effect=[0, 0.1, 0.2])

    with pytest.raises(
        HandshakeError, match=r"Plugin process exited prematurely with code 0"
    ):
        await read_handshake_response(process)


@pytest.mark.asyncio
async def test_create_stderr_relay(mocker):
    """Test creation and functionality of the stderr relay task."""
    mock_process = MagicMock(spec=subprocess.Popen)
    mock_process.stderr = MagicMock()
    mock_process.stderr.readline.side_effect = [b"line1\n", b"line2\n", b"", b""]
    mock_process.poll.side_effect = [None, None, None, 0]

    relay_task = await create_stderr_relay(mock_process)
    assert relay_task is not None
    assert isinstance(relay_task, asyncio.Task)

    try:
        await asyncio.wait_for(relay_task, timeout=2.0)
    except asyncio.TimeoutError:
        relay_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await relay_task
        pytest.fail("stderr relay task timed out")
    except Exception as e:
        pytest.fail(f"stderr relay task failed with an unexpected exception: {e}")


@pytest.mark.asyncio
async def test_create_stderr_relay_exception_in_reader(mocker):
    """Test stderr relay handles exceptions during stderr read."""
    mock_process = MagicMock(spec=subprocess.Popen)
    mock_process.stderr = MagicMock()
    mock_process.stderr.readline = MagicMock()
    # Poll should return None (process running) a few times, then return 0 (process ended)
    mock_process.poll.side_effect = [None, None, None, 0]
    mock_logger_error = mocker.patch("pyvider.rpcplugin.handshake.negotiation.logger.error")
    
    # Mock readline to raise exception on second call
    mock_process.stderr.readline.side_effect = [
        b"line1\n",
        Exception("stderr read error"),
        b"",
    ]
    
    # Create and run the relay task
    relay_task = await create_stderr_relay(mock_process)
    assert relay_task is not None
    
    # Wait for the task to complete (it should exit on exception)
    try:
        await asyncio.wait_for(relay_task, timeout=1.0)
    except asyncio.TimeoutError:
        relay_task.cancel()
        try:
            await relay_task
        except asyncio.CancelledError:
            pass

    # Verify the error was logged with permissive matching
    found_log = False
    for call_arg in mock_logger_error.call_args_list:
        if len(call_arg[0]) > 0:
            log_message = str(call_arg[0][0]).lower()
            # Check for key terms: error, stderr, relay
            if "error" in log_message and "stderr" in log_message and "relay" in log_message:
                found_log = True
                break
    assert found_log, f"stderr read error was not logged by relay. Logs: {mock_logger_error.call_args_list}"


@pytest.mark.parametrize(
    "handshake_line, expected",
    [
        ("1|6|tcp|127.0.0.1:8000|grpc|", (1, 6, "tcp", "127.0.0.1:8000", "grpc", None)),
        (
            "1|7|unix|/tmp/socket.sock|grpc|abc123",
            (1, 7, "unix", "/tmp/socket.sock", "grpc", "abc123=="),
        ),
        ("2|7|unix|/tmp/socket.sock|grpc|abc123", "Unsupported handshake version: 2 (expected: 1)"),
    ],
)
def test_parse_handshake_response_valid_and_core_version_mismatch(handshake_line, expected, mocker):
    """Test parsing valid handshake lines and core version mismatch."""
    mocker.patch.object(rpcplugin_config, 'plugin_core_version', 1)

    if isinstance(expected, tuple):
        result = parse_handshake_response(handshake_line)
        assert result == expected
    else:
        with pytest.raises(HandshakeError, match=re.escape(expected)):
            parse_handshake_response(handshake_line)


@pytest.mark.parametrize(
    "handshake_line, error_message_core",
    [
        ("", "Invalid handshake format. Expected 6 pipe-separated parts, got 1: '...'"), # Added ...
        ("1|2|3", "Invalid handshake format. Expected 6 pipe-separated parts, got 3: '1|2|3...'"), # Added ...
        ("1|2|invalid|127.0.0.1:8000|grpc|", "Invalid network type 'invalid' in handshake."),
        (
            "1|2|tcp||grpc|",
            "Empty address received in handshake string for TCP transport.",
        ),
        ("abc|1|tcp|host:port|grpc|", "Invalid handshake format. Expected 6 pipe-separated parts, got 6: 'abc|1|tcp|host:port|grpc|...'"),
        ("1|xyz|tcp|host:port|grpc|", "Invalid handshake format. Expected 6 pipe-separated parts, got 6: '1|xyz|tcp|host:port|grpc|...'"),
    ],
)
def test_parse_handshake_response_invalid(handshake_line, error_message_core, mocker):
    """Test parsing handshake with invalid inputs."""
    mocker.patch.object(rpcplugin_config, 'plugin_core_version', 1)
    # Adjusted regex to match the wrapped error message
    flexible_pattern = rf"\[HandshakeError\] Failed to parse handshake response: \[HandshakeError\] {re.escape(error_message_core)}"
    with pytest.raises(HandshakeError, match=flexible_pattern):
        parse_handshake_response(handshake_line)


@pytest.mark.asyncio
async def test_create_stderr_relay_process_stderr_is_none_initially(mocker):
    mock_process = MagicMock(spec=subprocess.Popen)
    mock_process.stderr = None
    mock_logger_debug = mocker.patch("pyvider.rpcplugin.handshake.negotiation.logger.debug")
    task = await create_stderr_relay(mock_process)
    assert task is None
    mock_logger_debug.assert_any_call("🤝📤⚠️ No process or stderr stream available for relay")

@pytest.mark.asyncio
async def test_read_handshake_stdout_becomes_none(mocker):
    mock_process = MagicMock(spec=subprocess.Popen)
    readline_calls = 0
    def readline_side_effect():
        nonlocal readline_calls
        readline_calls += 1
        if readline_calls == 1:
            return b"partial_line|"
        elif readline_calls == 2:
            mock_process.stdout = None
            raise asyncio.TimeoutError("Simulated timeout after stdout becomes None for readline")
        elif mock_process.stdout is None:
             raise AttributeError("'NoneType' object has no attribute 'readline'")
        return b""

    mock_stdout_stream = MagicMock()
    mock_stdout_stream.readline = MagicMock(side_effect=readline_side_effect)

    def read_side_effect(size):
        if mock_process.stdout is None:
            raise AttributeError("'NoneType' object has no attribute 'read'")
        raise asyncio.TimeoutError("Simulated timeout for read")

    mock_stdout_stream.read = MagicMock(side_effect=read_side_effect)
    mock_process.stdout = mock_stdout_stream
    mock_process.poll.return_value = None
    mock_process.stderr = MagicMock()
    mock_process.stderr.read.return_value = b"no specific error on stderr"
    mocker.patch("pyvider.rpcplugin.handshake.negotiation.asyncio.sleep", new_callable=AsyncMock)
    time_side_effects = [i * 0.05 for i in range(400)]
    mocker.patch("pyvider.rpcplugin.handshake.negotiation.time.time", side_effect=time_side_effects)

    with pytest.raises(HandshakeError, match=r"Timed out waiting for handshake response from plugin after \d+\.\d+ seconds"):
        await read_handshake_response(mock_process)
    assert mock_process.stdout is None

# 🐍🏗️🤝


# 🐍🔌🧪🪄
