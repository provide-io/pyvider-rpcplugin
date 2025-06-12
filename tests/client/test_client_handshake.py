# tests/client/test_client_handshake.py

import pytest
import asyncio  # Added
from unittest.mock import patch, MagicMock, AsyncMock

from pyvider.rpcplugin.exception import HandshakeError


@pytest.mark.asyncio
async def test_relay_stderr_background(client_instance, mock_process):
    """Test the background stderr relay functionality."""
    client_instance._process = mock_process

    # Mock threading.Thread to capture what it's called with
    with patch("threading.Thread") as mock_thread:
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        await client_instance._relay_stderr_background()

        # A thread should be created and started
        mock_thread.assert_called_once()
        mock_thread_instance.start.assert_called_once()


@pytest.mark.asyncio
async def test_perform_handshake_success(client_instance, mock_process):
    """Test successful handshake with plugin."""
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

        # Configure process.stdout to return a valid handshake response
        mock_process.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:8000|grpc|\n"

        await client_instance._perform_handshake()

        # Verify handshake components were set correctly
        mock_relay.assert_called_once()
        assert client_instance._protocol_version == 1
        assert client_instance._transport is mock_transport_instance
        assert client_instance._server_cert is None


@pytest.mark.asyncio
async def test_perform_handshake_with_cert(client_instance, mock_process):
    """Test handshake with server certificate included."""
    client_instance._process = mock_process

    # Use a known padded Base64 string
    sample_cert = "dGVzdA=="  # "test"

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

        # Configure process.stdout to return a handshake with cert
        mock_process.stdout.readline.return_value = (
            f"1|1|tcp|127.0.0.1:8000|grpc|{sample_cert}\n".encode()
        )

        await client_instance._perform_handshake()

        # Certificate should be captured
        mock_relay.assert_called_once()
        assert client_instance._protocol_version == 1
        assert client_instance._transport is mock_transport_instance
        assert client_instance._server_cert == sample_cert


@pytest.mark.asyncio
async def test_perform_handshake_with_unix_transport(client_instance, mock_process):
    """Test handshake with Unix socket transport."""
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

        # Configure process.stdout to return a Unix socket handshake
        mock_process.stdout.readline.return_value = b"1|1|unix|/tmp/test.sock|grpc|\n"

        await client_instance._perform_handshake()

        # Transport type should be unix
        mock_relay.assert_called_once()
        assert client_instance._protocol_version == 1
        assert client_instance._transport_name == "unix"
        assert client_instance._transport is mock_transport_instance
        mock_transport_instance.connect.assert_called_once_with("/tmp/test.sock")


@pytest.mark.asyncio
async def test_perform_handshake_no_process(client_instance):
    """Test handshake when no process is available."""
    client_instance._process = None

    with pytest.raises(
        HandshakeError, match="No server process or no stdout available"
    ):
        await client_instance._perform_handshake()


@pytest.mark.asyncio
async def test_perform_handshake_process_exit(client_instance, mock_process):
    """Test handshake when process exits prematurely."""
    client_instance._process = mock_process

    # Configure process to indicate it has exited
    mock_process.poll.return_value = 1  # Indicates process has exited
    mock_process.returncode = 1  # Set the actual integer returncode
    mock_process.stderr.read.return_value = b"Error during startup"
    mock_process.stderr.readline.return_value = b""  # For _relay_stderr_background

    # This test does NOT mock _relay_stderr_background, so the real one runs.
    # It also does not mock _perform_handshake itself.
    with pytest.raises(HandshakeError, match="Plugin process exited with code 1"):
        await client_instance._perform_handshake()


@pytest.mark.asyncio
async def test_perform_handshake_invalid_format(client_instance, mock_process):
    """Test handshake with invalid response format."""
    client_instance._process = mock_process

    # Configure process.stdout to return an invalid handshake
    mock_process.stdout.readline.return_value = b"invalid_handshake_format\n"

    with (
        patch(
            "pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background",
            new_callable=AsyncMock,
        ) as mock_relay,
        pytest.raises(HandshakeError),
    ):
        await client_instance._perform_handshake()

    # Assert relay was called because handshake starts before parsing fails
    mock_relay.assert_called_once()


@pytest.mark.asyncio
async def test_perform_handshake_parse_error(client_instance, mock_process):
    """Test handshake when parse_handshake_response raises an error."""
    client_instance._process = mock_process

    # Configure process.stdout to return a seemingly valid handshake line
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
            HandshakeError, match="Handshake parse/connect error: Simulated parse error"
        ),
    ):
        await client_instance._perform_handshake()
        mock_parse.assert_called_once()  # Ensure our mock was actually called


@pytest.mark.asyncio
async def test_perform_handshake_invalid_network_type(client_instance, mock_process):
    """Test handshake with an invalid network type returned by parser."""
    client_instance._process = mock_process

    # This line will be parsed by the mocked parse_handshake_response
    mock_process.stdout.readline.return_value = (
        b"1|1|invalid_net|127.0.0.1:8000|grpc|\n"
    )

    parsed_response_with_invalid_net = (
        1,
        1,
        "invalid_net",
        "127.0.0.1:8000",
        "grpc",
        None,
    )

    with (
        patch(
            "pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background",
            new_callable=AsyncMock,
        ),
        patch(
            "pyvider.rpcplugin.client.base.parse_handshake_response",
            return_value=parsed_response_with_invalid_net,
        ) as mock_parse,
        pytest.raises(HandshakeError, match="Unsupported transport: invalid_net"),
    ):
        await client_instance._perform_handshake()
        mock_parse.assert_called_once()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_process_exits_with_stderr(
    client_instance, mocker
):
    """Test _read_raw_handshake_line when process exits early with stderr."""
    mock_process = mocker.MagicMock()  # Removed spec
    mock_process.poll.return_value = 1  # Process has exited
    mock_process.returncode = 1
    mock_process.stderr = mocker.MagicMock()
    mock_process.stderr.read.return_value = b"critical error in plugin"
    client_instance._process = mock_process

    mocker.patch.object(asyncio, "sleep")  # To speed up the loop if it tries to sleep

    with pytest.raises(
        HandshakeError, match="Plugin process exited with code 1 before handshake."
    ):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_process_stdout_becomes_none(
    client_instance, mocker
):
    """Test _read_raw_handshake_line when process.stdout becomes None during readline loop."""
    mock_process = mocker.MagicMock()  # Removed spec
    mock_process.poll.return_value = None  # Process is running

    # Simulate stdout becoming None after the first asyncio.sleep(0.1) in the readline attempt part
    # The readline itself will be mocked to not return a full line, forcing multiple iterations.
    original_stdout = mocker.MagicMock()
    original_stdout.readline.return_value = b""  # Simulate not getting a full line

    mock_process.stdout = original_stdout
    client_instance._process = mock_process

    async def sleep_side_effect(delay):
        sleep_side_effect.call_count += 1  # Increment call count
        if mock_process.stdout is not None:  # On first few calls to sleep
            # After some attempts, make stdout None to trigger the else branch
            if sleep_side_effect.call_count > 2:
                mock_process.stdout = None
        await original_asyncio_sleep(0.0001)  # actual sleep for a tiny bit

    sleep_side_effect.call_count = 0

    original_asyncio_sleep = asyncio.sleep  # Store original sleep

    # Need to mock the actual asyncio.sleep if it's directly called in the loop being tested
    # The code is: await asyncio.sleep(0.1)
    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.sleep", side_effect=sleep_side_effect
    )  # Target where it's used

    # Correctly mock loop.time()
    mock_loop_instance = mocker.MagicMock()
    time_values = [i * 0.1 for i in range(105)]
    mock_loop_instance.time.side_effect = time_values

    # Mock run_in_executor on the loop instance to return an awaitable (AsyncMock)
    # This AsyncMock will simulate the future returned by run_in_executor
    mock_executor_future = AsyncMock()
    # For this test, readline is returning b"", so the future resolves to that.
    # If it's called multiple times (it will be), it should keep returning b""
    mock_executor_future.side_effect = (
        lambda: asyncio.Future()
    )  # Return a new future each time

    async def set_future_result_empty(fut):  # Helper to resolve future
        await asyncio.sleep(0)  # Let other things run
        if not fut.done():
            fut.set_result(b"")

    def run_in_executor_side_effect(loop, func):
        # func is lambda: self._process.stdout.readline() or read(1)
        # it should return bytes
        fut = asyncio.Future()
        # We need to handle both readline and read(1) cases if they differ
        # For this specific test, original_stdout.readline.return_value = b""
        # and read(1) is not expected to be called if readline keeps returning empty
        # and then stdout becomes None.
        # Let's assume the future resolves with what the underlying sync call returns.
        # Here, readline returns b"".
        asyncio.create_task(set_future_result_empty(fut))
        return fut

    mock_loop_instance.run_in_executor.side_effect = run_in_executor_side_effect
    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )

    with pytest.raises(TimeoutError, match="Timed out waiting for handshake line"):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_outer_timeout_with_stderr(
    client_instance, mocker
):
    """Test outer timeout in _read_raw_handshake_line_from_stdout with stderr."""
    mock_process = mocker.MagicMock()  # Removed spec
    mock_process.poll.return_value = None  # Process is running
    mock_stdout = mocker.MagicMock()
    mock_stdout.readline.return_value = b""  # Never returns a line
    mock_stdout.read.return_value = b""  # Byte-by-byte also returns nothing
    mock_process.stdout = mock_stdout

    mock_stderr = mocker.MagicMock()
    mock_stderr.read.return_value = b"stderr messages on timeout"
    mock_process.stderr = mock_stderr
    client_instance._process = mock_process

    # Mock time to ensure the 10-second outer timeout is triggered
    mock_loop_instance = mocker.MagicMock()
    mock_loop_instance.time.side_effect = [
        i * 1.0 for i in range(12)
    ]  # Enough to cause timeout

    # Mock run_in_executor to return a future that resolves to b"" (empty read)
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
    mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep")  # Avoid actual sleep

    mock_logger_error = mocker.patch("pyvider.rpcplugin.client.base.logger.error")

    with pytest.raises(TimeoutError, match="Timed out waiting for handshake line"):
        await client_instance._read_raw_handshake_line_from_stdout()

    # Check that logger.error was called with stderr content
    mock_logger_error.assert_any_call(
        "🤝 Handshake timed out. Stderr output: stderr messages on timeout"
    )


@pytest.mark.asyncio
async def test_read_raw_handshake_line_outer_timeout_no_stderr(client_instance, mocker):
    """Test outer timeout in _read_raw_handshake_line_from_stdout when stderr is None."""
    mock_process = mocker.MagicMock()  # Removed spec
    mock_process.poll.return_value = None  # Process is running
    mock_stdout = mocker.MagicMock()
    mock_stdout.readline.return_value = b""  # Never returns a line
    mock_stdout.read.return_value = b""  # Byte-by-byte also returns nothing
    mock_process.stdout = mock_stdout
    mock_process.stderr = None  # stderr is None
    client_instance._process = mock_process

    mock_loop_instance = mocker.MagicMock()
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

    mock_logger_error = mocker.patch("pyvider.rpcplugin.client.base.logger.error")

    with pytest.raises(TimeoutError, match="Timed out waiting for handshake line"):
        await client_instance._read_raw_handshake_line_from_stdout()

    mock_logger_error.assert_any_call("🤝 Handshake timed out. Stderr output: ")


@pytest.mark.asyncio
async def test_perform_handshake_transport_not_initialized(
    client_instance, mock_process, mocker
):
    """Test _perform_handshake raises error if transport is not set before connect."""
    client_instance._process = mock_process
    mock_process.stdout.readline.return_value = (
        b"1|1|tcp|127.0.0.1:1234|grpc|\n"  # Valid handshake line
    )

    # Mock parse_handshake_response to simulate that transport selection somehow failed
    # or _transport was reset to None before connect.
    # We can achieve this by patching the transport classes (TCPSocketTransport, UnixSocketTransport)
    # so that they don't get assigned to self._transport, or by directly setting self._transport to None
    # after parse_handshake_response has run but before self._transport.connect is called.
    # A more direct way is to mock self._transport to be None right before the connect call.

    mocker.patch(
        "pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background",
        new_callable=AsyncMock,
    )

    # Let initial parsing happen
    original_parse_handshake_response = client_instance._perform_handshake.__globals__[
        "parse_handshake_response"
    ]

    async def perform_handshake_and_clear_transport():
        # Let the original _perform_handshake run up to the point it sets _transport
        # then we'll clear it to simulate the error condition.
        # This is a bit tricky as we need to intercept execution flow.

        # Instead, let's mock what happens after parse_handshake_response
        # Assume parse_handshake_response worked and set _transport_name, _address etc.
        client_instance._protocol_version = 1
        client_instance._server_cert = None
        client_instance._transport_name = "tcp"  # Assume TCP was parsed
        client_instance._address = "127.0.0.1:1234"

        # Crucially, force _transport to be None to trigger the error
        client_instance._transport = None

        # Now, the original code would try to call self._transport.connect(address)
        # which should fail if self._transport is None.
        # The actual error we are testing for is `raise HandshakeError("Transport not initialized before connect call.")`
        # which happens if self._transport is None within the _perform_handshake method
        # right before the `await self._transport.connect(address)` line.

    mocker.patch(
        "pyvider.rpcplugin.client.base.parse_handshake_response",
        return_value=(1, 1, "tcp", "127.0.0.1:1234", "grpc", None),
    )

    # To ensure the specific check `if self._transport is not None:` fails:
    # We'll allow the normal parsing to happen, then mock `_transport` to become None.
    # This is tricky because the check and call happen in the same function.
    # A simpler way: mock the transport classes themselves to return None or not set _transport.

    mocker.patch("pyvider.rpcplugin.client.base.TCPSocketTransport", return_value=None)
    mocker.patch("pyvider.rpcplugin.client.base.UnixSocketTransport", return_value=None)

    with pytest.raises(
        HandshakeError, match="Transport not initialized before connect call."
    ):
        await client_instance._perform_handshake()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_byte_by_byte_success(client_instance, mocker):
    """Test successful handshake line construction via byte-by-byte reading."""
    mock_process = mocker.MagicMock()  # Removed spec
    mock_process.poll.return_value = None  # Process is running

    handshake_str = "1|1|unix|/tmp/test.sock|grpc|"
    handshake_bytes = list(handshake_str.encode("utf-8"))  # List of byte integers

    mock_stdout = mocker.MagicMock()
    # First readline returns empty to trigger byte-by-byte
    mock_stdout.readline.return_value = b""
    # Subsequent read(1) calls return one byte at a time
    read_side_effect_list = [bytes([b]) for b in handshake_bytes] + [
        b""
    ]  # Store the list
    mock_stdout.read.side_effect = read_side_effect_list

    mock_process.stdout = mock_stdout
    client_instance._process = mock_process

    # Mock loop.run_in_executor to return a Future that resolves with the byte
    # This will be used for both readline and read(1) calls from within _read_raw_handshake_line_from_stdout

    # We need to control what the Future resolves to based on whether it's readline or read(1)
    # The mock_stdout.read.side_effect already has the sequence of bytes for read(1)
    # The mock_stdout.readline.return_value is b""

    async def set_future_result(fut, result_value):
        await asyncio.sleep(0)  # yield control briefly
        if not fut.done():
            fut.set_result(result_value)

    # Keep track of calls to the mocked read(1)
    read_call_idx = 0

    def custom_run_in_executor(loop, func_to_run):
        nonlocal read_call_idx
        f = asyncio.Future()
        # Determine if func_to_run is trying to do readline or read(1)
        # by counting calls to the executor.
        nonlocal executor_call_count  # Need to modify this counter
        executor_call_count += 1

        if executor_call_count == 1:  # First call to executor is for readline
            asyncio.create_task(
                set_future_result(f, mock_stdout.readline.return_value)
            )  # b""
        else:  # Subsequent calls are for read(1)
            # Use the length of the original list for boundary check
            if read_call_idx < len(read_side_effect_list):  # Use stored list here
                byte_to_return = read_side_effect_list[
                    read_call_idx
                ]  # Access original list
                asyncio.create_task(set_future_result(f, byte_to_return))
                read_call_idx += 1
            else:  # Should not happen if side_effect list is correctly sized
                asyncio.create_task(set_future_result(f, b"ERROR_READ_IDX_OOB"))
        return f

    # Keep track of calls to the mocked read(1) for its side_effect list
    # read_call_idx is already defined above
    # Keep track of calls to the executor itself
    executor_call_count = 0

    # Patch run_in_executor on the mocked loop instance
    mock_loop_instance = mocker.MagicMock()
    time_values = [i * 0.01 for i in range(60)]  # Extended time values
    mock_loop_instance.time.side_effect = time_values
    mock_loop_instance.run_in_executor.side_effect = custom_run_in_executor

    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    # Do NOT mock asyncio.wait_for generally, let it use the real one with mocked time/futures
    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.sleep"
    )  # Still mock sleep to prevent real delays

    line = await client_instance._read_raw_handshake_line_from_stdout()
    assert line.strip() == handshake_str  # Strip potential newline if any


@pytest.mark.asyncio
async def test_read_raw_handshake_line_byte_by_byte_stdout_none(
    client_instance, mocker
):
    """Test byte-by-byte read when process.stdout becomes None."""
    mock_process = mocker.MagicMock()  # Removed spec
    mock_process.poll.return_value = None

    mock_stdout = mocker.MagicMock()
    mock_stdout.readline.return_value = b""  # Empty line to trigger byte-by-byte

    # Simulate stdout becoming None after a few byte reads
    read_count = 0

    def read_side_effect(*args):
        nonlocal read_count
        read_count += 1
        if read_count > 2:
            mock_process.stdout = None
            return b""  # Simulate EOF or error
        return b"a"  # Return some data initially

    mock_stdout.read.side_effect = read_side_effect

    mock_process.stdout = mock_stdout
    client_instance._process = mock_process

    mocker.patch("asyncio.get_event_loop").run_in_executor.side_effect = (
        lambda _, func: func()
    )
    mocker.patch("asyncio.wait_for", side_effect=lambda coro, timeout: coro)
    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.sleep"
    )  # Mock sleep to avoid delays

    mock_loop_instance = mocker.MagicMock()
    time_values = [i * 0.1 for i in range(105)]
    mock_loop_instance.time.side_effect = time_values
    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )

    with pytest.raises(TimeoutError, match="Timed out waiting for handshake line"):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_byte_by_byte_read_timeout(
    client_instance, mocker
):
    """Test byte-by-byte read when read(1) itself times out."""
    mock_process = mocker.MagicMock()  # Removed spec
    mock_process.poll.return_value = None
    mock_stdout = mocker.MagicMock()
    mock_stdout.readline.return_value = b""  # Trigger byte-by-byte
    mock_process.stdout = mock_stdout
    client_instance._process = mock_process

    # Mock run_in_executor for the loop instance.
    # For readline, it should return a future resolving to b"".
    # For read(1), it should return a future that results in a timeout for the wait_for.

    async def set_future_result(fut, result_val, delay=0):
        if delay > 0:
            await asyncio.sleep(delay)
        if not fut.done():
            fut.set_result(result_val)

    async def set_future_exception(fut, exc, delay=0):
        if delay > 0:
            await asyncio.sleep(delay)
        if not fut.done():
            fut.set_exception(exc)

    # Store the original asyncio.wait_for
    original_asyncio_wait_for = asyncio.wait_for

    def run_in_executor_side_effect_for_timeout(loop, func):
        fut = asyncio.Future()
        qualname = getattr(func, "__qualname__", "")

        if "readline" in qualname:  # Mock readline part
            asyncio.create_task(
                set_future_result(fut, b"")
            )  # readline returns empty to trigger byte-by-byte
        elif "read" in qualname:  # Mock read(1) part to simulate timeout via wait_for
            # This future itself won't resolve to TimeoutError.
            # Instead, we'll make asyncio.wait_for(this_future) timeout.
            # So, this future just needs to never resolve, or resolve late.
            # For simplicity, let it be a future that never resolves in this test's context.
            pass  # Let this future hang, wait_for will handle the timeout
        else:  # Should not happen
            asyncio.create_task(set_future_result(fut, b"unexpected_call"))
        return fut

    async def wait_for_side_effect_for_read_timeout(coro_or_future, timeout):
        # If this wait_for is wrapping our specific hanging future from read(1), raise TimeoutError
        # This simulates asyncio.wait_for(executor_future_for_read, timeout=1.0) timing out.
        # We need to identify if 'coro_or_future' is the one from the 'read(1)' call.
        # This is tricky. A simpler way is to make the future itself raise the timeout if awaited.
        # However, run_in_executor returns a future; wait_for awaits it.
        # Let's assume the default wait_for behavior is what we want to test,
        # and the future from run_in_executor for read(1) will just hang.
        # The `except asyncio.TimeoutError: pass` in SUT should catch it.
        # The test is for the *outer* timeout.
        # The test name is `...byte_by_byte_read_timeout` implying the *inner* read(1) times out.
        # SUT has `except asyncio.TimeoutError: pass` for the inner `wait_for` on `read(1)`.
        # So, if `read(1)` `wait_for` times out, the SUT continues, and then the outer loop should timeout.

        # For this test, we want the `wait_for` around `read(1)` to timeout.
        # So, the future returned by `run_in_executor` for `read(1)` should hang.
        # And `asyncio.wait_for` wrapping it should raise `TimeoutError`.

        # If the coro_or_future is the one from read(1), make it timeout.
        # This requires identifying the future.
        # Let's assume the default `original_asyncio_wait_for` will correctly timeout
        # if the future from `run_in_executor` (for read(1)) never resolves.
        # The `run_in_executor_side_effect_for_timeout` already ensures the future for read(1) hangs.
        return await original_asyncio_wait_for(coro_or_future, timeout)

    mock_loop_instance = mocker.MagicMock()
    time_values = [i * 0.1 for i in range(105)]
    mock_loop_instance.time.side_effect = time_values
    mock_loop_instance.run_in_executor.side_effect = (
        run_in_executor_side_effect_for_timeout
    )

    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.get_event_loop",
        return_value=mock_loop_instance,
    )
    mocker.patch(
        "pyvider.rpcplugin.client.base.asyncio.wait_for",
        side_effect=wait_for_side_effect_for_read_timeout,
    )
    mocker.patch("pyvider.rpcplugin.client.base.asyncio.sleep")  # Speed up loops

    with pytest.raises(TimeoutError, match="Timed out waiting for handshake line"):
        await client_instance._read_raw_handshake_line_from_stdout()


@pytest.mark.asyncio
async def test_read_raw_handshake_line_process_exits_no_stderr(client_instance, mocker):
    """Test _read_raw_handshake_line when process exits early and stderr is None."""
    mock_process = mocker.MagicMock()  # Removed spec
    mock_process.poll.return_value = 1  # Process has exited
    mock_process.returncode = 1
    mock_process.stderr = None  # stderr is None
    client_instance._process = mock_process

    mocker.patch.object(asyncio, "sleep")

    with pytest.raises(
        HandshakeError, match="Plugin process exited with code 1 before handshake."
    ):
        await client_instance._read_raw_handshake_line_from_stdout()
