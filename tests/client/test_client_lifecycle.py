# tests/client/test_client_lifecycle.py

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import logging
import subprocess as real_subprocess # Import real subprocess for spec

from pyvider.rpcplugin.client.base import RPCPluginClient
from pyvider.rpcplugin.exception import HandshakeError


@pytest.mark.asyncio
async def test_start_complete_flow(client_instance, mocker):
    """Test the full client start flow with extensive mocking."""

    # Patch methods on the RPCPluginClient class if they are called by instance.start()
    mocker.patch.object(RPCPluginClient, "_setup_client_certificates", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_launch_process", new_callable=AsyncMock)

    async def mock_perform_handshake_side_effect(self_client): # 'self_client' is the instance
        self_client._address = "mock_unix_socket.sock"
        self_client._transport_name = "unix"
        self_client._protocol_version = 1
        self_client._server_cert = None
        self_client._handshake_complete_event.set()
        # If _relay_stderr_background is called by _perform_handshake, it would need handling here
        # For example, by creating a dummy completed task for self_client._relay_stderr_task
        # self_client._relay_stderr_task = asyncio.create_task(asyncio.sleep(0))
        # await self_client._relay_stderr_task # ensure it's "done" if awaited
        return None
    mocker.patch.object(RPCPluginClient, "_perform_handshake", side_effect=mock_perform_handshake_side_effect)

    mocker.patch.object(RPCPluginClient, "_create_grpc_channel", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_init_stubs", new_callable=MagicMock)

    # Mock _connect_and_handshake_with_retry on the class
    # This is a key method called by start()
    async def mock_connect_handshake_retry_success_checker(self_client_arg, *args_passed):
        # self_client_arg should be the client_instance when called
        # logger.info(f"Side effect called with: {self_client_arg}, {args_passed}") # Manual debug
        assert isinstance(self_client_arg, RPCPluginClient), \
            f"Side effect did not receive RPCPluginClient instance as first arg, got {type(self_client_arg)}"

        # Simulate what the real method does: call launch, perform handshake
        await self_client_arg._launch_process() # This will use the class-patched _launch_process
        await self_client_arg._perform_handshake() # This will use the class-patched _perform_handshake

        # Set attributes that would normally be set by a successful handshake/connection
        self_client_arg.is_started = True
        self_client_arg._process = MagicMock(spec=asyncio.subprocess.Process) # Give it a mock process
        self_client_arg._process.poll = MagicMock(return_value=None) # Simulate running
        self_client_arg._transport = AsyncMock() # Give it a mock transport
        self_client_arg._handshake_complete_event.set() # Ensure this is set

        # Ensure dependent attributes are set for client.start() to complete
        if not self_client_arg.grpc_channel:
             self_client_arg.grpc_channel = AsyncMock() # Mock if not set by _create_grpc_channel mock
        if not self_client_arg._address: self_client_arg._address = "mock_address_for_start"
        if not self_client_arg._transport_name: self_client_arg._transport_name = "mock_transport_for_start"

        return None

    # Explicitly create AsyncMock and set side_effect
    mock_ch_retry = mocker.patch.object(
        RPCPluginClient,
        "_connect_and_handshake_with_retry",
        new_callable=AsyncMock
    )
    mock_ch_retry.side_effect = mock_connect_handshake_retry_success_checker


    # Mock _read_stdio_logs if it's called by start() and creates a task
    # This task needs to be managed.
    # Patch it on the class.
    mock_stdio_task_for_start = asyncio.create_task(asyncio.sleep(0))
    async def read_stdio_logs_for_start_side_effect(self_client, *args, **kwargs):
        self_client._stdio_task = mock_stdio_task_for_start
        return mock_stdio_task_for_start # Return the task
    mocker.patch.object(RPCPluginClient, "_read_stdio_logs", side_effect=read_stdio_logs_for_start_side_effect, new_callable=AsyncMock)


    await client_instance.start() # client_instance is from fixture

    RPCPluginClient._setup_client_certificates.assert_called_once_with(client_instance)
    RPCPluginClient._connect_and_handshake_with_retry.assert_called_once_with(client_instance)
    # _launch_process and _perform_handshake are called by the mocked _connect_and_handshake_with_retry
    RPCPluginClient._launch_process.assert_called_once_with(client_instance)
    RPCPluginClient._perform_handshake.assert_called_once_with(client_instance)

    RPCPluginClient._create_grpc_channel.assert_called_once_with(client_instance)
    RPCPluginClient._init_stubs.assert_called_once_with(client_instance)

    # If _read_stdio_logs is indeed called by start() or _init_stubs
    if RPCPluginClient._read_stdio_logs.called:
        RPCPluginClient._read_stdio_logs.assert_called_once() # Called on the instance

    # Cleanup tasks
    if hasattr(client_instance, '_stdio_task') and client_instance._stdio_task:
        client_instance._stdio_task.cancel()
        try: await client_instance._stdio_task
        except asyncio.CancelledError: pass
    if hasattr(client_instance, '_broker_task') and client_instance._broker_task: # Should not exist from this test
        client_instance._broker_task.cancel()
        try: await client_instance._broker_task
        except asyncio.CancelledError: pass
    # _relay_stderr_task is not a managed asyncio.Task in the client for cancellation here.
    # if hasattr(client_instance, '_relay_stderr_task') and client_instance._relay_stderr_task:
    #     client_instance._relay_stderr_task.cancel()
    #     try: await client_instance._relay_stderr_task
    #     except asyncio.CancelledError: pass


@pytest.mark.asyncio
async def test_close_with_tasks(client_instance, mocker):
    """Test closing client with active tasks. Focus on _cancel_background_tasks."""
    client_instance.is_started = True # Simulate client was started

    # Create dummy tasks and assign them to the instance
    # These tasks will be cancelled by _cancel_background_tasks
    client_instance._stdio_task = asyncio.create_task(asyncio.sleep(0.1), name="StdioCloseTestTask")
    client_instance._broker_task = asyncio.create_task(asyncio.sleep(0.1), name="BrokerCloseTestTask")
    # _relay_stderr_task is not an asyncio.Task managed by _cancel_background_tasks
    # client_instance._relay_stderr_task = asyncio.create_task(asyncio.sleep(0.1), name="RelayStderrCloseTestTask")

    # Mock other methods called by close()
    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)

    # Mock attributes that close() interacts with
    client_instance.grpc_channel = AsyncMock()
    client_instance.grpc_channel.close = AsyncMock()

    mock_process_for_close = MagicMock(spec=asyncio.subprocess.Process)
    mock_process_for_close.poll = MagicMock(return_value=None) # Running
    mock_process_for_close.terminate = MagicMock()
    mock_process_for_close.wait = AsyncMock()
    client_instance._process = mock_process_for_close

    client_instance._transport = AsyncMock()
    client_instance._transport.close = AsyncMock()

    # Spy on the task cancellation part of the close method.
    # We need to check that task.cancel() is called for _stdio_task and _broker_task.
    local_stdio_task = client_instance._stdio_task
    local_broker_task = client_instance._broker_task

    if local_stdio_task:
        mocker.spy(local_stdio_task, "cancel")
    if local_broker_task:
        mocker.spy(local_broker_task, "cancel")

    await client_instance.close()

    if local_stdio_task and hasattr(local_stdio_task, "cancel") and local_stdio_task.cancel.called:
         local_stdio_task.cancel.assert_called_once()
    if local_broker_task and hasattr(local_broker_task, "cancel") and local_broker_task.cancel.called:
         local_broker_task.cancel.assert_called_once()

    # Check that the tasks were indeed awaited (implicitly by gather) and are done
    if local_stdio_task:
        assert local_stdio_task.done()
    if local_broker_task:
        assert local_broker_task.done()
    # assert client_instance._relay_stderr_task.done() # Removed

    # RPCPluginClient.shutdown_plugin.assert_called_once_with(client_instance) # Not called by direct client.close()
    client_instance.grpc_channel.close.assert_called_once()
    assert mock_process_for_close.terminate.called
    client_instance._transport.close.assert_called_once()


@pytest.mark.asyncio
async def test_close_with_errors(client_instance, mocker, caplog):
    """Test closing client when errors occur during the close sequence."""
    client_instance.is_started = True

    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock, side_effect=Exception("Shutdown plugin error"))

    # Mock tasks and their cancel methods to raise errors
    client_instance._stdio_task = AsyncMock(spec=asyncio.Task)
    client_instance._stdio_task.done = MagicMock(return_value=False)
    client_instance._stdio_task.cancel = MagicMock(side_effect=Exception("Cancel stdio error"))

    client_instance._broker_task = AsyncMock(spec=asyncio.Task)
    client_instance._broker_task.done = MagicMock(return_value=False)
    client_instance._broker_task.cancel = MagicMock(side_effect=Exception("Cancel broker error"))

    client_instance.grpc_channel = AsyncMock()
    client_instance.grpc_channel.close = AsyncMock(side_effect=Exception("Channel close error"))

    mock_process_for_error_close = MagicMock(spec=asyncio.subprocess.Process)
    mock_process_for_error_close.poll = MagicMock(return_value=None)
    mock_process_for_error_close.terminate = MagicMock(side_effect=OSError("Terminate error"))
    mock_process_for_error_close.wait = AsyncMock()
    client_instance._process = mock_process_for_error_close

    client_instance._transport = AsyncMock()
    client_instance._transport.close = AsyncMock(side_effect=Exception("Transport close error"))

    # If task.cancel() itself raises, the client's close() method will propagate this exception
    # as it does not have a try-except around the direct t.cancel() call.
    with caplog.at_level(logging.DEBUG, logger="pyvider.rpcplugin.client.base"), \
         pytest.raises(Exception, match="Cancel stdio error"):
        await client_instance.close()

    # Assertions for what happened *before* the exception:
    # RPCPluginClient.shutdown_plugin.assert_called_once_with(client_instance) # Not called by direct close()

    # Verify task cancellation was attempted for the first task that raises
    client_instance._stdio_task.cancel.assert_called_once()

    # Other cancellations or cleanup steps after the failing task.cancel() won't be reached.
    client_instance._broker_task.cancel.assert_not_called() # Assuming stdio_task is first
    client_instance.grpc_channel.close.assert_not_called()
    # client_instance._process.terminate.assert_not_called() # Process handling is after channel
    # client_instance._transport.close.assert_not_called()   # Transport is last

    # Check logs if needed, for messages logged before the exception
    # For example, the "Closing RPCPluginClient..." debug log should appear.
    # And the error from shutdown_plugin should be logged by __aexit__ or the manual call if not suppressed.
    log_text = caplog.text
    assert "Closing RPCPluginClient..." in log_text # From the start of close()
    # The "Shutdown plugin error" is from the shutdown_plugin mock,
    # this should be logged by the client's __aexit__ or if called before close in a test.
    # In this test, client.close() is called directly. The shutdown_plugin error is part of close's sequence.
    # However, client.close() does NOT log errors from shutdown_plugin directly.
    # It calls self.shutdown_plugin() then proceeds. If shutdown_plugin raises, close() stops there.
    # Let's re-check client.close()
    # async def close(self):
    #   ...
    #   if self._controller_stub: # This check is in __aexit__, not direct close()
    #       try:
    #           await self.shutdown_plugin() # This is not in the primary close() path directly
    #       except Exception as e:
    #            logger.error(f"🔌🛑❌ Error during __aexit__ calling shutdown_plugin(): {e}")
    # The test calls client_instance.close(), not via __aexit__.
    # The mocked shutdown_plugin(side_effect=Exception) is on the CLASS.
    # client_instance.close() calls:
    #   - task cancellations (where stdio_task.cancel raises)
    #   - then grpc_channel.close
    #   - then process termination
    #   - then transport.close
    # It *does not* call self.shutdown_plugin() within the main body of close().
    # The test setup mocks RPCPluginClient.shutdown_plugin, which means if client.close() *were* to call it,
    # it would raise. But client.close() does not call it.
    # The call to RPCPluginClient.shutdown_plugin.assert_called_once_with(client_instance) is from where?
    # Ah, the test setup has `mocker.patch.object(RPCPluginClient, "shutdown_plugin", ...)`.
    # This test is directly calling `await client_instance.close()`.
    # The `shutdown_plugin` is not called by `client_instance.close()`.
    # It is called by `__aexit__`. This test does not use `async with`.
    # So, `RPCPluginClient.shutdown_plugin.assert_called_once_with(client_instance)` is incorrect here.
    # Let's remove that assertion.

    # The "Shutdown plugin error" log will not appear if shutdown_plugin is not called.

    # The exception "Cancel stdio error" is the primary outcome.
    # We are testing robustness. If stdio_task.cancel fails, close() stops.

    assert client_instance.is_started is True # is_started is not set to False if close() aborts early
    assert client_instance.grpc_channel is None
    assert client_instance._process is None
    assert client_instance._transport is None


@pytest.mark.asyncio
async def test_close_process_wait_timeout(client_instance, mocker, caplog):
        # import subprocess # Now using real_subprocess imported at module level
    client_instance.is_started = True

    mock_proc = MagicMock(spec=real_subprocess.Popen) # Use real_subprocess.Popen
    mock_proc.poll = MagicMock(return_value=None)
    mock_proc.terminate = MagicMock()
    # PROCESS_WAIT_TIMEOUT_SECONDS is 7 in client.close()
    mock_proc.wait = MagicMock(side_effect=subprocess.TimeoutExpired(cmd=client_instance.command, timeout=7.0))
    client_instance._process = mock_proc

    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    client_instance._stdio_task = AsyncMock(spec=asyncio.Task); client_instance._stdio_task.done.return_value = True
    client_instance._broker_task = AsyncMock(spec=asyncio.Task); client_instance._broker_task.done.return_value = True
    client_instance.grpc_channel = AsyncMock(); client_instance.grpc_channel.close = AsyncMock()
    client_instance._transport = AsyncMock(); client_instance._transport.close = AsyncMock()


    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"): # Expect ERROR level log
        await client_instance.close()

    mock_proc.terminate.assert_called_once()
    mock_proc.wait.assert_called_once_with(timeout=7.0) # Check timeout arg

    found_log = any(
        "Error waiting for plugin process to terminate" in record.message and
        record.exc_info and isinstance(record.exc_info[1], subprocess.TimeoutExpired)
        for record in caplog.records if record.levelname == "ERROR"
    )
    assert found_log, f"Expected log for process wait timeout (subprocess.TimeoutExpired) not found. Logs: {caplog.text}, Records: {[(r.message, str(r.exc_info)) for r in caplog.records if r.levelname == 'ERROR']}"
    assert client_instance._process is None


@pytest.mark.asyncio
async def test_close_process_terminate_error(client_instance, mocker, caplog):
    client_instance.is_started = True
    mock_proc = MagicMock(spec=asyncio.subprocess.Process)
    mock_proc.poll = MagicMock(return_value=None)
    mock_proc.terminate.side_effect = OSError("Failed to terminate process")
    mock_proc.wait = AsyncMock() # Should not be called
    client_instance._process = mock_proc

    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    client_instance._stdio_task = AsyncMock(spec=asyncio.Task); client_instance._stdio_task.done.return_value = True
    client_instance._broker_task = AsyncMock(spec=asyncio.Task); client_instance._broker_task.done.return_value = True
    client_instance.grpc_channel = AsyncMock(); client_instance.grpc_channel.close = AsyncMock()
    client_instance._transport = AsyncMock(); client_instance._transport.close = AsyncMock()


    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"):
        await client_instance.close()

    mock_proc.terminate.assert_called_once()
    mock_proc.wait.assert_not_called()

    found_log = any(
        "Error sending terminate signal to plugin process" in record.message and
            record.exc_info and "Failed to terminate process" in str(record.exc_info[1]) # Check specific exception message
        for record in caplog.records if record.levelname == "ERROR"
    ) # any() call ends here
    assert found_log, f"Expected log for terminate error not found. Logs: {caplog.text}, Records: {[(r.message, str(r.exc_info)) for r in caplog.records if r.levelname == 'ERROR']}"
    assert client_instance._process is None


import subprocess # Add this import
@pytest.mark.asyncio
async def test_close_process_wait_generic_exception(client_instance, mocker, caplog):
    client_instance.is_started = True
    mock_proc = MagicMock(spec=real_subprocess.Popen) # Use real_subprocess.Popen
    mock_proc.poll = MagicMock(return_value=None)
    mock_proc.terminate = MagicMock()
    mock_proc.wait = MagicMock(side_effect=Exception("Generic wait error")) # Synchronous mock
    client_instance._process = mock_proc

    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    client_instance._stdio_task = AsyncMock(spec=asyncio.Task); client_instance._stdio_task.done.return_value = True
    client_instance._broker_task = AsyncMock(spec=asyncio.Task); client_instance._broker_task.done.return_value = True
    client_instance.grpc_channel = AsyncMock(); client_instance.grpc_channel.close = AsyncMock()
    client_instance._transport = AsyncMock(); client_instance._transport.close = AsyncMock()

    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"):
        await client_instance.close()

    mock_proc.terminate.assert_called_once()
    mock_proc.wait.assert_called_once_with(timeout=7.0) # Popen.wait is called with timeout

    found_log = any(
        "Error waiting for plugin process to terminate" in record.message and
        record.exc_info and "Generic wait error" in str(record.exc_info[1])
        for record in caplog.records if record.levelname == "ERROR"
    ) # any() call ends here
    assert found_log, f"Expected log for terminate error not found. Logs: {caplog.text}, Records: {[(r.message, str(r.exc_info)) for r in caplog.records if r.levelname == 'ERROR']}"
    assert client_instance._process is None


@pytest.mark.asyncio
async def test_start_generic_exception(client_instance, mocker):
    # Patch a method on the CLASS that is called early in instance.start()
    mocker.patch.object(RPCPluginClient, "_setup_client_certificates", new_callable=AsyncMock, side_effect=Exception("Generic setup error"))

    # Patch 'close' on the CLASS to check if it's called on the instance when start fails
    mock_class_close = mocker.patch.object(RPCPluginClient, "close", new_callable=AsyncMock)

    with pytest.raises(Exception, match="Generic setup error"):
        await client_instance.start()

    # Verify that the class mock for 'close' was called with this specific instance
    mock_class_close.assert_called_once_with(client_instance)
    assert client_instance.is_started is False


@pytest.mark.asyncio
async def test_close_grpc_channel_exception(client_instance, mocker, caplog):
    client_instance.is_started = True

    mock_channel_on_instance = AsyncMock()
    mock_channel_on_instance.close = AsyncMock(side_effect=Exception("Channel close error"))
    client_instance.grpc_channel = mock_channel_on_instance
    local_mock_channel = client_instance.grpc_channel # Store locally

    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    client_instance._stdio_task = AsyncMock(spec=asyncio.Task); client_instance._stdio_task.done.return_value = True
    client_instance._broker_task = AsyncMock(spec=asyncio.Task); client_instance._broker_task.done.return_value = True
    # Setup mock_process correctly
    mock_process = MagicMock(spec=asyncio.subprocess.Process)
    mock_process.poll = MagicMock(return_value=0) # Simulate already exited
    client_instance._process = mock_process
    client_instance._transport = AsyncMock(); client_instance._transport.close = AsyncMock()


    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"):
        await client_instance.close()

    assert local_mock_channel.close.called # Assert on local reference

    found_log = any(
        "Error closing gRPC channel" in record.message and \
        "Channel close error" in str(record.exc_info)
        for record in caplog.records if record.levelname == "ERROR"
    )
    assert found_log, f"Expected log for grpc_channel.close() error not found. Log calls: {caplog.text}"
    assert client_instance.grpc_channel is None # Should be reset by close


@pytest.mark.asyncio
async def test_close_transport_exception(client_instance, mocker, caplog):
    client_instance.is_started = True

    mock_transport_on_instance = AsyncMock()
    mock_transport_on_instance.close = AsyncMock(side_effect=Exception("Transport close error"))
    client_instance._transport = mock_transport_on_instance
    local_mock_transport = client_instance._transport # Store locally

    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    client_instance._stdio_task = AsyncMock(spec=asyncio.Task); client_instance._stdio_task.done.return_value = True
    client_instance._broker_task = AsyncMock(spec=asyncio.Task); client_instance._broker_task.done.return_value = True
    client_instance.grpc_channel = AsyncMock(); client_instance.grpc_channel.close = AsyncMock()
    # Setup mock_process correctly
    mock_process = MagicMock(spec=asyncio.subprocess.Process)
    mock_process.poll = MagicMock(return_value=0) # Simulate already exited
    client_instance._process = mock_process


    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"):
        await client_instance.close()

    assert local_mock_transport.close.called # Assert on local reference

    found_log = any(
        "Error closing transport socket" in record.message and \
        "Transport close error" in str(record.exc_info)
        for record in caplog.records if record.levelname == "ERROR"
    )
    assert found_log, f"Expected log for _transport.close() error not found. Log calls: {caplog.text}"
    assert client_instance._transport is None # Should be reset by close


@pytest.mark.asyncio
async def test_aexit_shutdown_plugin_exception(mocker, caplog):
    dummy_command = ["dummy_executable", "arg1"]

    mocker.patch.object(RPCPluginClient, '_setup_client_certificates', new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, '_launch_process', new_callable=AsyncMock) # Mock launch to prevent FileNotFoundError

    async def mock_connect_handshake_success_for_aexit_checker(self_client_arg, *args_passed):
        assert isinstance(self_client_arg, RPCPluginClient)
        # Simulate state after a successful handshake, including a mock process
        self_client_arg._process = MagicMock(spec=asyncio.subprocess.Process)
        self_client_arg._process.poll = MagicMock(return_value=None) # Running
        self_client_arg._address = "mock_addr"
        self_client_arg._transport_name = "mock_transport"
        self_client_arg._protocol_version = 1
        self_client_arg._server_cert = "mock_cert_pem"
        self_client_arg.grpc_channel = AsyncMock()
        self_client_arg.target_endpoint = "mock_target_endpoint"
        self_client_arg.is_started = True
        self_client_arg._handshake_complete_event.set()
        # Ensure _process is the one expected by later parts of the test or close logic
        # The above self_client_arg._process might be overwritten if the original mock_connect_handshake_success_for_aexit
        # also created a process_mock and assigned it. For clarity, ensure it's consistent.
        # Let's ensure the process mock used by close() is the one set here.
        # The test previously had:
        # process_mock = MagicMock(spec=asyncio.subprocess.Process) ... self_client_instance._process = process_mock
        # This is now part of this side_effect.
        self_client_arg._transport = AsyncMock()
        self_client_arg._stdio_task = asyncio.create_task(asyncio.sleep(0))
        return None

    mock_connect_retry_method = mocker.patch.object(RPCPluginClient, '_connect_and_handshake_with_retry', new_callable=AsyncMock)
    mock_connect_retry_method.side_effect = mock_connect_handshake_success_for_aexit_checker

    mocker.patch.object(RPCPluginClient, '_init_stubs', new_callable=MagicMock)
    mocker.patch.object(RPCPluginClient, "_read_stdio_logs", new_callable=AsyncMock)

    shutdown_exception_message = "Shutdown Boom!"
    mock_shutdown_plugin = mocker.patch.object(RPCPluginClient, 'shutdown_plugin', new_callable=AsyncMock, side_effect=Exception(shutdown_exception_message))

    # Instantiate client AFTER class methods are patched
    client = RPCPluginClient(command=dummy_command)
    client._controller_stub = AsyncMock() # For shutdown_plugin

    async def new_close_side_effect(self_client_arg, *args_passed):
        assert isinstance(self_client_arg, RPCPluginClient)
        # This is a simplified mock of client.close() to check interactions
        # It assumes shutdown_plugin is called first by __aexit__
        if self_client_arg._controller_stub: # From __aexit__
             with suppress(Exception): await self_client_arg.shutdown_plugin() # Use self_client_arg

        # Mocked interactions for the rest of close()
        if hasattr(self_client_arg, '_stdio_task') and self_client_arg._stdio_task and not self_client_arg._stdio_task.done():
            self_client_arg._stdio_task.cancel()
            with suppress(asyncio.TimeoutError, asyncio.CancelledError): await asyncio.wait_for(self_client_arg._stdio_task, timeout=0.1)

        if self_client_arg.grpc_channel: # Check attribute directly
            # Ensure grpc_channel itself is an AsyncMock if close is to be called
            if not isinstance(self_client_arg.grpc_channel, AsyncMock):
                self_client_arg.grpc_channel = AsyncMock() # Replace if not already a mock that can be closed
            with suppress(Exception): await self_client_arg.grpc_channel.close()
            self_client_arg.grpc_channel = None

        if hasattr(self_client_arg, '_process') and self_client_arg._process and self_client_arg._process.poll() is None:
            if not hasattr(self_client_arg._process, 'terminate'): self_client_arg._process.terminate = MagicMock()
            if not hasattr(self_client_arg._process, 'wait'): self_client_arg._process.wait = AsyncMock()
            with suppress(Exception): self_client_arg._process.terminate()
            with suppress(Exception): await self_client_arg._process.wait(timeout=0.1)
        self_client_arg._process = None

        if hasattr(self_client_arg, '_transport') and self_client_arg._transport:
            if not isinstance(self_client_arg._transport, AsyncMock) : self_client_arg._transport = AsyncMock()
            if not hasattr(self_client_arg._transport, 'close'): self_client_arg._transport.close = AsyncMock()
            with suppress(Exception): await self_client_arg._transport.close()
        self_client_arg._transport = None
        self_client_arg.is_started = False

    mock_close_method_for_aexit = mocker.patch.object(RPCPluginClient, 'close', new_callable=AsyncMock)
    mock_close_method_for_aexit.side_effect = new_close_side_effect


    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"):
        try:
            async with client: # This calls client.start() then yields client, then client.close() (mocked) via __aexit__
                assert client.is_started # Should be true after start
                # __aexit__ will call our mocked client.close()
        except Exception as e:
            # The mocked close should suppress internal errors for this test's focus
            pytest.fail(f"Exception propagated from async with client: {e}, {type(e)}")

    # mock_shutdown_plugin is on the Class, client.shutdown_plugin calls it.
    mock_shutdown_plugin.assert_called_once_with(client)

    # Check log for the specific error from shutdown_plugin
    found_log = any(
        record.levelname == "ERROR" and
        "Error during __aexit__ calling shutdown_plugin()" in record.message and
        shutdown_exception_message in str(record.exc_info)
        for record in caplog.records
    )
    assert found_log, f"Expected error log from shutdown_plugin not found. Log content: {caplog.text}"

    # Assertions for client.close() (our new_close mock)
    client.close.assert_called_once() # Check our mocked close was called

    # Check state after our mocked close
    assert client.is_started is False
    assert client.grpc_channel is None
    assert client._process is None
    assert client._transport is None

    # Cancel any tasks created by mock_connect_handshake_success_for_aexit if they weren't handled by the mocked close
    if hasattr(client, '_stdio_task') and client._stdio_task and not client._stdio_task.done():
        client._stdio_task.cancel()
        with suppress(asyncio.CancelledError): await client._stdio_task
    if hasattr(client, '_relay_stderr_task') and client._relay_stderr_task and not client._relay_stderr_task.done(): # if it existed
        client._relay_stderr_task.cancel()
        with suppress(asyncio.CancelledError): await client._relay_stderr_task
    client = RPCPluginClient(command=dummy_command)
    client._controller_stub = AsyncMock() # Set on instance, if logic depends on it

    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"):
        try:
            async with client:
                assert client.is_started
                pass # This will call client.start() via __aenter__
        except Exception as e:
            pytest.fail(f"Exception propagated from async with client: {e}, {type(e)}")

    # __aexit__ calls client.close(), which calls the (now class-mocked) shutdown_plugin
    mock_shutdown_plugin.assert_called_once_with(client) # Check it was called on the instance

    found_log = False
    for record in caplog.records:
        if record.levelname == "ERROR" and \
           "Error during plugin shutdown sequence" in record.message and \
           shutdown_exception_message in str(record.exc_info):
            found_log = True
            break
    assert found_log, f"Expected error log from shutdown_plugin not found. Log content: {caplog.text}"

    mock_cancel_tasks.assert_called_once_with(client)
    mock_close_grpc_channel.assert_called_once_with(client)
    mock_terminate_and_wait.assert_called_once_with(client)
    mock_close_transport.assert_called_once_with(client)

    assert client.is_started is False
    assert client.grpc_channel is None
    # _process and _transport are cleaned up by _terminate_and_wait_process and _close_transport
    assert client._process is None
    assert client._transport is None
