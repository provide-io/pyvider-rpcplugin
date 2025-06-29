# tests/client/test_client_lifecycle.py

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import logging

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
    async def mock_connect_handshake_retry_success(self_client):
        # Simulate what the real method does: call launch, perform handshake
        await self_client._launch_process() # This will use the class-patched _launch_process
        await self_client._perform_handshake() # This will use the class-patched _perform_handshake

        # Set attributes that would normally be set by a successful handshake/connection
        self_client.is_started = True
        self_client._process = MagicMock(spec=asyncio.subprocess.Process) # Give it a mock process
        self_client._process.poll = MagicMock(return_value=None) # Simulate running
        self_client._transport = AsyncMock() # Give it a mock transport
        self_client._handshake_complete_event.set() # Ensure this is set
        return None

    mocker.patch.object(RPCPluginClient, "_connect_and_handshake_with_retry", side_effect=mock_connect_handshake_retry_success)

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
    if hasattr(client_instance, '_relay_stderr_task') and client_instance._relay_stderr_task: # May exist if perform_handshake created it
        client_instance._relay_stderr_task.cancel()
        try: await client_instance._relay_stderr_task
        except asyncio.CancelledError: pass


@pytest.mark.asyncio
async def test_close_with_tasks(client_instance, mocker):
    """Test closing client with active tasks. Focus on _cancel_background_tasks."""
    client_instance.is_started = True # Simulate client was started

    # Create dummy tasks and assign them to the instance
    # These tasks will be cancelled by _cancel_background_tasks
    client_instance._stdio_task = asyncio.create_task(asyncio.sleep(0.1), name="StdioCloseTestTask")
    client_instance._broker_task = asyncio.create_task(asyncio.sleep(0.1), name="BrokerCloseTestTask")
    # Ensure _relay_stderr_task is also handled if it can exist
    client_instance._relay_stderr_task = asyncio.create_task(asyncio.sleep(0.1), name="RelayStderrCloseTestTask")


    # Mock other methods called by close() to isolate _cancel_background_tasks
    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_close_grpc_channel", new_callable=AsyncMock)

    # Mock _terminate_and_wait_process carefully
    mock_process_for_close = MagicMock(spec=asyncio.subprocess.Process)
    mock_process_for_close.poll = MagicMock(return_value=None) # Running
    mock_process_for_close.terminate = MagicMock()
    mock_process_for_close.wait = AsyncMock()
    client_instance._process = mock_process_for_close # Assign to instance

    mocker.patch.object(RPCPluginClient, "_close_transport", new_callable=AsyncMock)

    # Spy on the actual _cancel_background_tasks to ensure it's called
    # but let the original logic run to cancel the dummy tasks.
    original_cancel_method = client_instance._cancel_background_tasks
    async def cancel_spy_wrapper(*args, **kwargs):
        return await original_cancel_method(*args, **kwargs)
    spy_cancel_tasks = mocker.patch.object(client_instance, "_cancel_background_tasks", side_effect=cancel_spy_wrapper, new_callable=AsyncMock)

    await client_instance.close()

    spy_cancel_tasks.assert_called_once() # Check our spy was called

    # Check that the tasks were indeed cancelled and are done
    assert client_instance._stdio_task.done()
    assert client_instance._broker_task.done()
    assert client_instance._relay_stderr_task.done()
    # To be more precise, check they were cancelled (if they didn't finish naturally before cancel)
    # This requires tasks to handle CancelledError appropriately or for test to run long enough for sleep(0.1)
    # For this test, done() is sufficient if we assume cancel works.

    RPCPluginClient.shutdown_plugin.assert_called_once_with(client_instance)
    RPCPluginClient._close_grpc_channel.assert_called_once_with(client_instance)
    assert mock_process_for_close.terminate.called # Check terminate on the assigned mock
    RPCPluginClient._close_transport.assert_called_once_with(client_instance)


@pytest.mark.asyncio
async def test_close_with_errors(client_instance, mocker, caplog):
    """Test closing client when errors occur during the close sequence. Attributes are on instance."""
    client_instance.is_started = True

    # Mock methods on the CLASS so they affect the instance when called
    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock, side_effect=Exception("Shutdown plugin error"))
    mocker.patch.object(RPCPluginClient, "_cancel_background_tasks", new_callable=AsyncMock, side_effect=Exception("Cancel tasks error"))
    mocker.patch.object(RPCPluginClient, "_close_grpc_channel", new_callable=AsyncMock, side_effect=Exception("Channel close error"))

    # For _terminate_and_wait_process, we need to control the instance's _process attribute
    mock_process_for_error_close = MagicMock(spec=asyncio.subprocess.Process)
    mock_process_for_error_close.poll = MagicMock(return_value=None)
    mock_process_for_error_close.terminate = MagicMock(side_effect=OSError("Terminate error"))
    mock_process_for_error_close.wait = AsyncMock() # Should not be called due to terminate error
    client_instance._process = mock_process_for_error_close # Assign to client_instance

    mocker.patch.object(RPCPluginClient, "_close_transport", new_callable=AsyncMock, side_effect=Exception("Transport close error"))

    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"):
        await client_instance.close()

    RPCPluginClient.shutdown_plugin.assert_called_once_with(client_instance)
    RPCPluginClient._cancel_background_tasks.assert_called_once_with(client_instance)
    RPCPluginClient._close_grpc_channel.assert_called_once_with(client_instance)
    assert client_instance._process.terminate.called # Check on the instance's mock
    RPCPluginClient._close_transport.assert_called_once_with(client_instance)

    log_text = caplog.text
    assert "Error during plugin shutdown sequence" in log_text
    assert "Shutdown plugin error" in log_text
    assert "Error cancelling background tasks" in log_text
    assert "Error closing gRPC channel" in log_text
    assert "Error sending terminate signal to plugin process" in log_text
    assert "Terminate error" in log_text
    assert "Error closing transport socket" in log_text

    assert client_instance.is_started is False
    assert client_instance.grpc_channel is None
    assert client_instance._process is None # _terminate_and_wait_process should nullify it
    assert client_instance._transport is None


@pytest.mark.asyncio
async def test_close_process_wait_timeout(client_instance, mocker, caplog):
    import subprocess
    client_instance.is_started = True

    mock_proc = MagicMock(spec=asyncio.subprocess.Process)
    mock_proc.poll = MagicMock(return_value=None)
    mock_proc.terminate = MagicMock()
    mock_proc.wait = AsyncMock(side_effect=subprocess.TimeoutExpired(cmd="test_cmd", timeout=0.1))
    client_instance._process = mock_proc # Assign to the instance

    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_cancel_background_tasks", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_close_grpc_channel", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_close_transport", new_callable=AsyncMock)

    with caplog.at_level(logging.WARNING, logger="pyvider.rpcplugin.client.base"):
        await client_instance.close()

    mock_proc.terminate.assert_called_once()
    mock_proc.wait.assert_called_once_with(timeout=client_instance.PROCESS_WAIT_TIMEOUT_SECONDS)

    found_log = any(
        "Error waiting for plugin process to terminate" in record.message and
        "TimeoutExpired" in str(record.exc_info)
        for record in caplog.records if record.levelname == "WARNING"
    )
    assert found_log, f"Expected log for process wait timeout not found. Logs: {caplog.text}"
    assert client_instance._process is None


@pytest.mark.asyncio
async def test_close_process_terminate_error(client_instance, mocker, caplog):
    client_instance.is_started = True
    mock_proc = MagicMock(spec=asyncio.subprocess.Process)
    mock_proc.poll = MagicMock(return_value=None)
    mock_proc.terminate.side_effect = OSError("Failed to terminate process")
    mock_proc.wait = AsyncMock()
    client_instance._process = mock_proc

    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_cancel_background_tasks", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_close_grpc_channel", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_close_transport", new_callable=AsyncMock)

    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"):
        await client_instance.close()

    mock_proc.terminate.assert_called_once()
    mock_proc.wait.assert_not_called()

    found_log = any(
        "Error sending terminate signal to plugin process" in record.message and
        "Failed to terminate process" in str(record.exc_info)
        for record in caplog.records if record.levelname == "ERROR"
    )
    assert found_log, f"Expected log for terminate error not found. Logs: {caplog.text}"
    assert client_instance._process is None


@pytest.mark.asyncio
async def test_close_process_wait_generic_exception(client_instance, mocker, caplog):
    client_instance.is_started = True
    mock_proc = MagicMock(spec=asyncio.subprocess.Process)
    mock_proc.poll = MagicMock(return_value=None)
    mock_proc.terminate = MagicMock()
    mock_proc.wait = AsyncMock(side_effect=Exception("Generic wait error"))
    client_instance._process = mock_proc

    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_cancel_background_tasks", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_close_grpc_channel", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_close_transport", new_callable=AsyncMock)

    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"):
        await client_instance.close()

    mock_proc.terminate.assert_called_once()
    mock_proc.wait.assert_called_once_with(timeout=client_instance.PROCESS_WAIT_TIMEOUT_SECONDS)

    found_log = any(
        "Error waiting for plugin process to terminate" in record.message and \
        "Generic wait error" in str(record.exc_info)
        for record in caplog.records if record.levelname == "ERROR"
    )
    assert found_log, f"Expected log for generic wait error not found. Log calls: {caplog.text}"
    assert client_instance._process is None


@pytest.mark.asyncio
async def test_start_generic_exception(client_instance, mocker):
    # Patch a method on the CLASS that is called early in instance.start()
    mocker.patch.object(RPCPluginClient, "_setup_client_certificates", new_callable=AsyncMock, side_effect=Exception("Generic setup error"))

    # Spy on the close method of the specific instance by patching it on the instance
    # This is okay if client_instance is function-scoped and not re-used by other tests in a way that this patch interferes.
    mock_close_on_instance = mocker.patch.object(client_instance, "close", new_callable=AsyncMock)

    with pytest.raises(Exception, match="Generic setup error"):
        await client_instance.start()

    mock_close_on_instance.assert_called_once()
    assert client_instance.is_started is False


@pytest.mark.asyncio
async def test_close_grpc_channel_exception(client_instance, mocker, caplog):
    client_instance.is_started = True

    mock_channel_on_instance = AsyncMock()
    mock_channel_on_instance.close = AsyncMock(side_effect=Exception("Channel close error"))
    client_instance.grpc_channel = mock_channel_on_instance

    # Patch other methods on the CLASS, assuming client_instance.close() will call them via self.method()
    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_cancel_background_tasks", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_terminate_and_wait_process", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_close_transport", new_callable=AsyncMock)

    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"):
        await client_instance.close()

    assert client_instance.grpc_channel.close.called

    found_log = any(
        "Error closing gRPC channel" in record.message and \
        "Channel close error" in str(record.exc_info)
        for record in caplog.records if record.levelname == "ERROR"
    )
    assert found_log, f"Expected log for grpc_channel.close() error not found. Log calls: {caplog.text}"
    assert client_instance.grpc_channel is None


@pytest.mark.asyncio
async def test_close_transport_exception(client_instance, mocker, caplog):
    client_instance.is_started = True

    mock_transport_on_instance = AsyncMock()
    mock_transport_on_instance.close = AsyncMock(side_effect=Exception("Transport close error"))
    client_instance._transport = mock_transport_on_instance

    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_cancel_background_tasks", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_close_grpc_channel", new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, "_terminate_and_wait_process", new_callable=AsyncMock)

    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"):
        await client_instance.close()

    assert client_instance._transport.close.called

    found_log = any(
        "Error closing transport socket" in record.message and \
        "Transport close error" in str(record.exc_info)
        for record in caplog.records if record.levelname == "ERROR"
    )
    assert found_log, f"Expected log for _transport.close() error not found. Log calls: {caplog.text}"
    assert client_instance._transport is None


@pytest.mark.asyncio
async def test_aexit_shutdown_plugin_exception(mocker, caplog):
    dummy_command = ["dummy_executable", "arg1"]
    # Create a fresh client instance for this specific test
    # Patch its class's methods BEFORE instance calls them in start() or close()

    mocker.patch.object(RPCPluginClient, '_setup_client_certificates', new_callable=AsyncMock)

    async def mock_connect_handshake_success_for_aexit(self_client_instance): # self_client_instance is the client
        self_client_instance._address = "mock_addr"
        self_client_instance._transport_name = "mock_transport"
        self_client_instance._protocol_version = 1
        self_client_instance._server_cert = "mock_cert_pem"
        self_client_instance.grpc_channel = AsyncMock()
        self_client_instance.target_endpoint = "mock_target_endpoint"
        self_client_instance.is_started = True
        self_client_instance._handshake_complete_event.set()

        # Setup _process mock on the instance
        process_mock = MagicMock(spec=asyncio.subprocess.Process)
        process_mock.poll = MagicMock(return_value=None)
        process_mock.terminate = MagicMock()
        process_mock.wait = AsyncMock()
        self_client_instance._process = process_mock

        self_client_instance._transport = AsyncMock()
        self_client_instance._stdio_task = asyncio.create_task(asyncio.sleep(0))
        self_client_instance._relay_stderr_task = asyncio.create_task(asyncio.sleep(0))
        return None

    mocker.patch.object(RPCPluginClient, '_connect_and_handshake_with_retry', side_effect=mock_connect_handshake_success_for_aexit)
    mocker.patch.object(RPCPluginClient, '_init_stubs', new_callable=MagicMock)
    mocker.patch.object(RPCPluginClient, "_read_stdio_logs", new_callable=AsyncMock) # Ensure this is also mocked if start calls it

    # Mock shutdown_plugin on the class to raise an exception
    shutdown_exception_message = "Shutdown Boom!"
    mock_shutdown_plugin = mocker.patch.object(RPCPluginClient, 'shutdown_plugin', new_callable=AsyncMock, side_effect=Exception(shutdown_exception_message))

    # Mock other parts of 'close' on the CLASS
    mock_close_grpc_channel = mocker.patch.object(RPCPluginClient, '_close_grpc_channel', new_callable=AsyncMock)
    mock_terminate_and_wait = mocker.patch.object(RPCPluginClient, '_terminate_and_wait_process', new_callable=AsyncMock)
    mock_close_transport = mocker.patch.object(RPCPluginClient, '_close_transport', new_callable=AsyncMock)
    mock_cancel_tasks = mocker.patch.object(RPCPluginClient, '_cancel_background_tasks', new_callable=AsyncMock)

    # Instantiate client AFTER class methods are patched
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
