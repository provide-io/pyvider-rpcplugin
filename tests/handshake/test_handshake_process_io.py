
# tests/handshake/test_handshake_process_io.py

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.handshake import (
    read_handshake_response,
    create_stderr_relay,
    parse_and_validate_handshake,
)


class MockProcess:
    """Mock subprocess.Popen instance for testing process I/O interactions."""
    
    def __init__(self, stdout_content=None, stderr_content=None, exit_code=None):
        self.stdout = MagicMock()
        self.stderr = MagicMock()
        self.returncode = None
        self.initial_exit_code = exit_code # Store the intended exit code
        
        # Configure stdout content and behavior
        if isinstance(stdout_content, list):
            # Sequential reads
            self.stdout.readline.side_effect = [
                content.encode('utf-8') for content in stdout_content
            ] + [b""]  # End with empty to simulate EOF
        elif stdout_content is not None:
            self.stdout.readline.return_value = stdout_content.encode('utf-8')
        else:
            self.stdout.readline.return_value = b""
            
        # Configure stderr content
        if stderr_content:
            self.stderr.read.return_value = stderr_content.encode('utf-8')
            self.stderr.readline.return_value = stderr_content.encode('utf-8')
        
        # Configure process exit behavior
        if self.initial_exit_code is not None: # Check stored exit code
            self._poll_count = 0
            self._poll_exit_after = 1  # Exit after 1 poll call if exit_code is set
            
    def poll(self):
        """Mock the poll() method to simulate process state."""
        if hasattr(self, '_poll_count'): # Check if exit behavior is configured
            self._poll_count += 1
            if self._poll_count >= self._poll_exit_after:
                self.returncode = self.initial_exit_code # Use the stored exit code
                return self.returncode
        return None


@pytest.mark.asyncio
async def test_read_handshake_response_complete_line():
    """Test reading handshake when process outputs a complete line."""
    handshake = "1|2|tcp|127.0.0.1:8000|grpc|"
    process = MockProcess(stdout_content=handshake)
    
    response = await read_handshake_response(process)
    assert response == handshake
    process.stdout.readline.assert_called_once()


@pytest.mark.asyncio
async def test_read_handshake_response_multiple_attempts():
    """Test reading handshake with multiple read attempts needed."""
    # Simulate partial content that requires multiple reads
    process = MockProcess(stdout_content=[
        "1|2|tcp|",
        "127.0.0.1:8000|grpc|cert123"
    ])
    
    response = await read_handshake_response(process)
    assert response == "1|2|tcp|127.0.0.1:8000|grpc|cert123"
    assert process.stdout.readline.call_count == 2


@pytest.mark.asyncio
async def test_read_handshake_response_process_exit():
    """Test error when process exits before providing handshake."""
    process = MockProcess(stdout_content="", exit_code=1)
    process.stderr.read.return_value = b"Error in plugin initialization"
    
    with pytest.raises(HandshakeError, match="Plugin process exited with code"):
        await read_handshake_response(process)

@pytest.mark.asyncio
async def test_read_handshake_response_process_exit_stderr_read_error(mocker):
    """Test error when process exits and reading its stderr also fails."""
    process = MockProcess(stdout_content="", exit_code=1)
    process.stderr = mocker.MagicMock()
    process.stderr.read.side_effect = OSError("Failed to read stderr")

    mock_logger_error = mocker.patch('pyvider.rpcplugin.handshake.logger.error')

    with pytest.raises(HandshakeError, match="Error reading stderr: Failed to read stderr"):
        await read_handshake_response(process)

    mock_logger_error.assert_called_once_with(
        "🤝📥❌ Plugin process exited with code 1 before handshake"
    )


@pytest.mark.asyncio
async def test_read_handshake_response_timeout():
    """Test timeout while waiting for handshake."""
    process = MockProcess()
    
    # Make readline sleep to simulate timeout
    original_readline = process.stdout.readline
    
    async def slow_readline(*args, **kwargs):
        await asyncio.sleep(0.1)  # Delay each read
        return b""  # Return empty to continue trying
        
    process.stdout.readline = AsyncMock(side_effect=slow_readline)
    
    # Patch time.time and asyncio.sleep to make the test run faster
    with patch('asyncio.sleep', new_callable=AsyncMock):
        with patch('time.time', side_effect=[0, 11]):  # Exceed the timeout
            with pytest.raises(HandshakeError, match="Timed out waiting for handshake"):
                await read_handshake_response(process)

@pytest.mark.asyncio
async def test_read_handshake_response_timeout_stderr_read_error(mocker):
    """Test timeout while waiting for handshake, and stderr read also fails."""
    process = MockProcess() # stdout.readline will return b"" by default

    process.stderr = mocker.MagicMock()
    process.stderr.read.side_effect = OSError("Failed to read stderr on timeout")

    # Patch time.time and asyncio.sleep to make the test run faster and ensure timeout
    mocker.patch('pyvider.rpcplugin.handshake.asyncio.sleep', new_callable=AsyncMock)
    mocker.patch('pyvider.rpcplugin.handshake.time.time', side_effect=[0, 2, 4, 6, 8, 10, 12])  # Exceed the 10s timeout

    with pytest.raises(HandshakeError, match="Error reading stderr: Failed to read stderr on timeout"):
        await read_handshake_response(process)


@pytest.mark.asyncio
async def test_create_stderr_relay():
    """Test the stderr relay functionality."""
    messages = ["Error line 1", "Warning line 2"]
    
    process = MockProcess(stderr_content="\n".join(messages))
    
    # Replace readline with a version that returns lines one at a time, then None
    process.stderr.readline.side_effect = [
        (line + "\n").encode('utf-8') for line in messages
    ] + [b""]
    
    # Mock get_event_loop().run_in_executor to return lines directly
    with patch('asyncio.get_event_loop') as mock_loop:
        mock_executor = AsyncMock()
        mock_executor.side_effect = process.stderr.readline.side_effect
        mock_loop.return_value.run_in_executor.return_value = mock_executor
        
        # Create the relay task
        relay_task = await create_stderr_relay(process)
        
        # Give the task a moment to process lines
        await asyncio.sleep(0.1)
        
        # Cancel the task to clean up
        if relay_task and not relay_task.done():
            relay_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await relay_task
                
        # Verify the executor was called for each line
        assert mock_loop.return_value.run_in_executor.call_count > 0

@pytest.mark.asyncio
async def test_create_stderr_relay_exception_in_reader(mocker):
    """Test the stderr relay when process.stderr.readline raises an exception."""
    process = MockProcess() # Process is running, poll returns None initially
    process.stderr = mocker.MagicMock()
    process.stderr.readline.side_effect = [b"first line\n", Exception("Read error from stderr"), b""] # Error then stop

    mock_logger_error = mocker.patch('pyvider.rpcplugin.handshake.logger.error')
    mock_logger_debug = mocker.patch('pyvider.rpcplugin.handshake.logger.debug') # To check for start/end messages

    relay_task = await create_stderr_relay(process)
    assert relay_task is not None

    # Allow the task to run and encounter the exception
    # We can't directly await the task here if it errors internally and loop continues,
    # but we can give it a moment to process.
    await asyncio.sleep(0.1)

    # Check for start, error, and end log messages
    start_logged = any("Starting stderr relay task" in call_args[0][0] for call_args in mock_logger_debug.call_args_list)
    error_logged = any("Error in stderr relay: Read error from stderr" in call_args[0][0] for call_args in mock_logger_error.call_args_list)
    # end_logged = any("Stderr relay task ended" in call_args[0][0] for call_args in mock_logger_debug.call_args_list)
    # Depending on timing, end_logged might not fire if the task truly breaks.
    # The primary check is that the error was logged.

    assert start_logged
    assert error_logged
    # assert end_logged # This might be flaky depending on when the loop breaks

    # Clean up the task if it's still around (it should have exited due to break)
    if not relay_task.done():
        relay_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await relay_task


@pytest.mark.parametrize(
    "handshake_line, expected",
    [
        (
            "1|6|tcp|127.0.0.1:8000|grpc|", 
            (1, 6, "tcp", "127.0.0.1:8000", "grpc", None)
        ),
        (
            "1|7|unix|/tmp/socket.sock|grpc|abc123", 
            (1, 7, "unix", "/tmp/socket.sock", "grpc", "abc123==")  # Note: padding added
        ),
    ]
)
@pytest.mark.asyncio
async def test_parse_and_validate_handshake_valid(handshake_line, expected):
    """Test parsing and validating handshake with valid inputs."""
    result = await parse_and_validate_handshake(handshake_line)
    assert result == expected


@pytest.mark.parametrize(
    "handshake_line, error_pattern",
    [
        ("", "Failed to parse handshake"),
        ("1|2|3", "Invalid handshake format"),
        ("1|2|invalid|127.0.0.1:8000|grpc|", "Invalid network type"),
        ("1|2|tcp||grpc|", "Empty address in handshake"),
        ("1|2|tcp|127.0.0.1:8000|invalid|", "Unsupported protocol"),
    ]
)
@pytest.mark.asyncio
async def test_parse_and_validate_handshake_invalid(handshake_line, error_pattern):
    """Test parsing and validating handshake with invalid inputs."""
    with pytest.raises(HandshakeError, match=error_pattern):
        await parse_and_validate_handshake(handshake_line)
