# tests/handshake/test_handshake_process_io.py
import pytest
import asyncio
import time
import os
import stat
from unittest.mock import patch, MagicMock, AsyncMock, call
import subprocess # For Popen spec
import re # For escaping regex if needed

from pyvider.rpcplugin.handshake import (
    read_handshake_response,
    parse_and_validate_handshake,
    create_stderr_relay,
)
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.config import rpcplugin_config # Import the config object


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
        return None # Should not be reached if timeout is always provided in tests

    def terminate(self):
        self.returncode = -15 # Simulate termination

    def kill(self):
        self.returncode = -9 # Simulate kill

# --- Test Cases ---

@pytest.mark.asyncio
async def test_read_handshake_response_complete_line(mocker):
    """Test reading a complete handshake line successfully."""
    process = MockProcess(stdout_content="1|1|tcp|127.0.0.1:1234|grpc|\n")
    mocker.patch("time.time", side_effect=[0, 0.1]) # Ensure loop runs once

    line = await read_handshake_response(process)
    assert line == "1|1|tcp|127.0.0.1:1234|grpc|"

@pytest.mark.asyncio
async def test_read_handshake_response_multiple_attempts(mocker):
    """Test reading handshake that requires multiple read attempts (chunked)."""
    process = MockProcess()
    # Simulate chunked reading
    process.stdout.readline.side_effect = None # Disable readline for this test
    process.stdout.read.side_effect = [b"1|1|tcp|", b"127.0.0.1:1234", b"|grpc|\n", b""]

    # Mock time to control loop iterations
    # Needs enough time for initial readline attempt + multiple chunk reads + sleeps
    time_values = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
    mocker.patch("time.time", side_effect=time_values)
    mocker.patch("asyncio.sleep", new_callable=AsyncMock) # Mock sleep to run fast

    line = await read_handshake_response(process)
    assert line == "1|1|tcp|127.0.0.1:1234|grpc|"


@pytest.mark.asyncio
async def test_read_handshake_response_process_exit_stderr_read_error(mocker):
    """Test error when process exits and reading its stderr also fails."""
    process = MockProcess(stdout_content="", exit_code=1)
    process.stderr = mocker.MagicMock()
    process.stderr.read.side_effect = OSError("Failed to read stderr")

    mock_logger_error = mocker.patch("pyvider.rpcplugin.handshake.logger.error")

    expected_regex = r"\[HandshakeError\] Plugin process exited prematurely with code \d+ before completing handshake\. \(Code: \d+\) \(Hint: Check plugin logs or stderr for details\. Stderr captured: 'Error reading stderr: Failed to read stderr'\)"
    with pytest.raises(HandshakeError, match=expected_regex):
        await read_handshake_response(process)

    mock_logger_error.assert_called_once_with(
        "🤝📥❌ Plugin process exited with code 1 before handshake"
    )


@pytest.mark.asyncio
async def test_read_handshake_response_timeout(mocker):
    """Test timeout while waiting for handshake response."""
    process = MockProcess() # stdout.readline will return b"" by default
    # Patch time.time and asyncio.sleep to make the test run faster and ensure timeout
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)
    mocker.patch("time.time", side_effect=[i * 2.0 for i in range(10)]) # Simulate time passing to exceed 10s timeout

    mock_logger_error = mocker.patch("pyvider.rpcplugin.handshake.logger.error")

    with pytest.raises(HandshakeError, match=r"Timed out waiting for handshake response from plugin after 10.0 seconds."):
        await read_handshake_response(process)

    found_log = False
    for call_args in mock_logger_error.call_args_list:
        args, _ = call_args
        if "Timed out waiting for handshake response from plugin after 10.0 seconds." in args[0]:
            found_log = True
            break
    # assert found_log, "Expected log for handshake timeout not found."


@pytest.mark.asyncio
async def test_read_handshake_response_timeout_stderr_read_error(mocker):
    """Test timeout while waiting for handshake, and stderr read also fails."""
    process = MockProcess()  # stdout.readline will return b"" by default

    process.stderr = mocker.MagicMock()
    process.stderr.read.side_effect = OSError("Failed to read stderr on timeout")

    mocker.patch("pyvider.rpcplugin.handshake.asyncio.sleep", new_callable=AsyncMock)
    mocker.patch(
        "pyvider.rpcplugin.handshake.time.time", side_effect=[0, 2, 4, 6, 8, 10, 12]
    )  # Exceed the 10s timeout

    expected_regex = r"\[HandshakeError\] Timed out waiting for handshake response from plugin after \d+\.\d+ seconds\. \(Hint: Ensure the plugin starts and prints its handshake string to stdout promptly\. Last buffer: ''\. Stderr: 'Error reading stderr: Fai.*\)"
    with pytest.raises(HandshakeError, match=expected_regex):
        await read_handshake_response(process)

@pytest.mark.asyncio
async def test_read_handshake_response_process_exit(mocker):
    """Test when process exits cleanly before handshake."""
    process = MockProcess(exit_code=0, stderr_content="Exited normally.")
    mocker.patch("asyncio.sleep", new_callable=AsyncMock)
    mocker.patch("time.time", side_effect=[0, 0.1, 0.2])

    with pytest.raises(HandshakeError, match=r"Plugin process exited prematurely with code 0"):
        await read_handshake_response(process)


@pytest.mark.asyncio
async def test_create_stderr_relay(mocker):
    """Test creation and functionality of the stderr relay task."""
    mock_process = MagicMock(spec=subprocess.Popen)
    mock_process.stderr = MagicMock()
    mock_process.stderr.readline.side_effect = [b"line1\n", b"line2\n", b""]
    mock_process.poll.return_value = None

    created_task_coro = None
    def mock_create_task(coro):
        nonlocal created_task_coro
        created_task_coro = coro
        mock_task = asyncio.Future()
        mock_task.set_result(None)
        return mock_task

    mocker.patch("asyncio.create_task", side_effect=mock_create_task)
    mocker.patch("asyncio.get_event_loop").run_in_executor = AsyncMock(return_value=b"line1\n")

    relay_task_obj = await create_stderr_relay(mock_process)
    assert relay_task_obj is not None
    assert created_task_coro is not None


@pytest.mark.asyncio
async def test_create_stderr_relay_exception_in_reader(mocker):
    """Test stderr relay handles exceptions during stderr read."""
    mock_process = MagicMock(spec=subprocess.Popen)
    mock_process.stderr = MagicMock()
    mock_process.stderr.readline.side_effect = [b"line1\n", Exception("stderr read error"), b""]
    mock_process.poll.return_value = None

    mock_logger_error = mocker.patch("pyvider.rpcplugin.handshake.logger.error")

    async def run_coro_immediately(coro):
        try:
            await coro
        except Exception:
            pass
        return MagicMock()

    mocker.patch("asyncio.create_task", side_effect=run_coro_immediately)

    async def mock_run_in_executor(*args, **kwargs):
        effect = mock_process.stderr.readline.side_effect.pop(0)
        if isinstance(effect, Exception):
            raise effect
        return effect
    mocker.patch("asyncio.get_event_loop").run_in_executor = mock_run_in_executor


    await create_stderr_relay(mock_process)

    found_log = False
    for call_arg in mock_logger_error.call_args_list:
        if "Error in stderr relay: stderr read error" in call_arg[0][0]:
            found_log = True
            break
    assert found_log, "stderr read error was not logged by relay"


@pytest.mark.parametrize(
    "handshake_line, expected",
    [
        ("1|6|tcp|127.0.0.1:8000|grpc|", (1, 6, "tcp", "127.0.0.1:8000", "grpc", None)),
        ("1|7|unix|/tmp/socket.sock|grpc|abc123", (1, 7, "unix", "/tmp/socket.sock", "grpc", "abc123==")),
    ],
)
@pytest.mark.asyncio
async def test_parse_and_validate_handshake_valid(handshake_line, expected):
    """Test parsing and validating valid handshake lines."""
    with patch.object(rpcplugin_config, 'get') as mock_get:
        mock_get.side_effect = lambda key, default=None: 1 if key == "PLUGIN_CORE_VERSION" else default
        result = await parse_and_validate_handshake(handshake_line)
        assert result == expected

@pytest.mark.parametrize(
    "handshake_line, error_message_core",
    [
        ("", "Failed to parse handshake"),
        ("1|2|3", "Invalid handshake format"),
        ("1|2|invalid|127.0.0.1:8000|grpc|", "Invalid network type"),
        ("1|2|tcp||grpc|", "Empty address received in handshake string."), # Corrected line
        ("1|2|tcp|127.0.0.1:8000|invalid|", "Unsupported protocol"),
    ],
)
@pytest.mark.asyncio
async def test_parse_and_validate_handshake_invalid(handshake_line, error_message_core):
    """Test parsing and validating handshake with invalid inputs."""
    flexible_pattern = rf".*\[HandshakeError\] {re.escape(error_message_core)}.*"
    with pytest.raises(HandshakeError, match=flexible_pattern):
        await parse_and_validate_handshake(handshake_line)

# 🐍🏗️🤝
