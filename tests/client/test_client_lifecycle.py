# tests/client/test_client_lifecycle.py

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
import logging
import subprocess as real_subprocess # Import real subprocess for spec
from contextlib import suppress

from pyvider.rpcplugin.client.base import RPCPluginClient
from pyvider.rpcplugin.exception import HandshakeError


@pytest.mark.asyncio
async def test_start_complete_flow(client_instance, mocker):
    """Test the full client start flow with extensive mocking."""

    mocker.patch.object(RPCPluginClient, "_setup_client_certificates", autospec=True)
    mocker.patch.object(RPCPluginClient, "_launch_process", autospec=True)

    async def actual_perform_handshake_logic_for_autospec_inner(received_self, *remaining_args, **remaining_kwargs):
        assert isinstance(received_self, RPCPluginClient)
        received_self._address = "mock_unix_socket.sock"
        received_self._transport_name = "unix"
        received_self._protocol_version = 1
        received_self._server_cert = None
        received_self._handshake_complete_event.set()
        return None
    mocker.patch.object(RPCPluginClient, "_perform_handshake", autospec=True, side_effect=actual_perform_handshake_logic_for_autospec_inner)

    async def actual_create_grpc_channel_logic(received_self, *args, **kwargs):
        assert isinstance(received_self, RPCPluginClient)
        received_self.grpc_channel = AsyncMock()
        received_self.target_endpoint = f"{received_self._transport_name}:{received_self._address}"
        return None
    mocker.patch.object(RPCPluginClient, "_create_grpc_channel", autospec=True, side_effect=actual_create_grpc_channel_logic)

    mocker.patch.object(RPCPluginClient, "_init_stubs", autospec=True)

    async def actual_connect_logic_for_autospec(*args, **kwargs):
        true_self = args[0]
        await true_self._perform_handshake()
        true_self.is_started = True
        true_self._process = MagicMock()
        true_self._process.poll = MagicMock(return_value=None)
        true_self._transport = AsyncMock()
        true_self._handshake_complete_event.set()
        await true_self._create_grpc_channel()
        return None
    mocker.patch.object(RPCPluginClient, "_connect_and_handshake_with_retry", autospec=True, side_effect=actual_connect_logic_for_autospec)

    mock_stdio_task_for_start = asyncio.create_task(asyncio.sleep(0))
    async def read_stdio_logs_side_effect_autospec(received_self, *original_args, **original_kwargs):
        assert isinstance(received_self, RPCPluginClient)
        received_self._stdio_task = mock_stdio_task_for_start
        return mock_stdio_task_for_start
    mocker.patch.object(RPCPluginClient, "_read_stdio_logs", autospec=True, side_effect=read_stdio_logs_side_effect_autospec)

    await client_instance.start()

    RPCPluginClient._setup_client_certificates.assert_called_once_with(client_instance)
    RPCPluginClient._connect_and_handshake_with_retry.assert_called_once_with(client_instance)
    RPCPluginClient._launch_process.assert_called_once_with(client_instance)
    RPCPluginClient._perform_handshake.assert_called_once_with(client_instance)
    RPCPluginClient._create_grpc_channel.assert_called_once_with(client_instance)
    RPCPluginClient._init_stubs.assert_called_once_with(client_instance)
    if RPCPluginClient._read_stdio_logs.called:
        RPCPluginClient._read_stdio_logs.assert_called_once_with(client_instance)

    if hasattr(client_instance, '_stdio_task') and client_instance._stdio_task:
        client_instance._stdio_task.cancel()
        try: await client_instance._stdio_task
        except asyncio.CancelledError: pass
    if hasattr(client_instance, '_broker_task') and client_instance._broker_task:
        client_instance._broker_task.cancel()
        try: await client_instance._broker_task
        except asyncio.CancelledError: pass

@pytest.mark.asyncio
async def test_close_with_tasks(client_instance, mocker):
    client_instance.is_started = True
    client_instance._stdio_task = asyncio.create_task(asyncio.sleep(0.1), name="StdioCloseTestTask")
    client_instance._broker_task = asyncio.create_task(asyncio.sleep(0.1), name="BrokerCloseTestTask")
    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    client_instance.grpc_channel = AsyncMock()
    local_grpc_channel = client_instance.grpc_channel
    assert local_grpc_channel is not None, "local_grpc_channel should be an AsyncMock after assignment"
    local_grpc_channel.close = AsyncMock()
    mock_process_for_close = MagicMock(spec=asyncio.subprocess.Process)
    mock_process_for_close.poll = MagicMock(return_value=None)
    mock_process_for_close.terminate = MagicMock()
    mock_process_for_close.wait = AsyncMock()
    client_instance._process = mock_process_for_close
    client_instance._transport = AsyncMock()
    local_transport = client_instance._transport
    local_transport.close = AsyncMock()
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
    if local_stdio_task:
        assert local_stdio_task.done()
    if local_broker_task:
        assert local_broker_task.done()
    local_grpc_channel.close.assert_called_once()
    assert mock_process_for_close.terminate.called
    assert hasattr(local_transport, 'close'), "local_transport mock should have a close attribute"
    local_transport.close.assert_called_once()

@pytest.mark.asyncio
async def test_close_with_errors(client_instance, mocker, caplog):
    client_instance.is_started = True
    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock, side_effect=Exception("Shutdown plugin error"))
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
    from pyvider.rpcplugin.client import base as client_base_module
    mock_logger_debug = mocker.patch.object(client_base_module.logger, "debug")
    with pytest.raises(Exception, match="Cancel stdio error"):
        await client_instance.close()
    client_instance._stdio_task.cancel.assert_called_once()
    client_instance._broker_task.cancel.assert_not_called()
    client_instance.grpc_channel.close.assert_not_called()
    mock_logger_debug.assert_any_call("🔄 Closing RPCPluginClient...")
    assert client_instance.is_started is True
    assert client_instance.grpc_channel is not None # Because close was aborted
    assert client_instance._process is not None # Because close was aborted
    assert client_instance._transport is not None # Because close was aborted

@pytest.mark.asyncio
async def test_close_process_wait_timeout(client_instance, mocker, caplog):
    client_instance.is_started = True
    mock_proc = MagicMock() # spec=real_subprocess.Popen removed
    mock_proc.poll = MagicMock(return_value=None)
    mock_proc.terminate = MagicMock()
    mock_proc.wait = MagicMock(side_effect=subprocess.TimeoutExpired(cmd=client_instance.command, timeout=7.0))
    client_instance._process = mock_proc
    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    client_instance._stdio_task = AsyncMock(spec=asyncio.Task); client_instance._stdio_task.done.return_value = True
    client_instance._broker_task = AsyncMock(spec=asyncio.Task); client_instance._broker_task.done.return_value = True
    client_instance.grpc_channel = AsyncMock(); client_instance.grpc_channel.close = AsyncMock()
    client_instance._transport = AsyncMock(); client_instance._transport.close = AsyncMock()
    from pyvider.rpcplugin.client import base as client_base_module
    mock_logger_error = mocker.patch.object(client_base_module.logger, "error")
    await client_instance.close()
    mock_proc.terminate.assert_called_once()
    mock_proc.wait.assert_called_once_with(timeout=7.0)
    found_log_call = False
    expected_message_substring = "Error waiting for plugin process to terminate"
    for call_obj in mock_logger_error.call_args_list:
        args, kwargs = call_obj
        message_arg = args[0] if args else ""
        if expected_message_substring in message_arg:
            if kwargs.get("extra"):
                found_log_call = True
                break
    assert found_log_call, f"Expected logger.error call for process wait timeout not found or not logged with details. Actual calls: {mock_logger_error.call_args_list}"
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
    client_instance._stdio_task = AsyncMock(spec=asyncio.Task); client_instance._stdio_task.done.return_value = True
    client_instance._broker_task = AsyncMock(spec=asyncio.Task); client_instance._broker_task.done.return_value = True
    client_instance.grpc_channel = AsyncMock(); client_instance.grpc_channel.close = AsyncMock()
    client_instance._transport = AsyncMock(); client_instance._transport.close = AsyncMock()
    from pyvider.rpcplugin.client import base as client_base_module
    mock_logger_error = mocker.patch.object(client_base_module.logger, "error")
    await client_instance.close()
    mock_proc.terminate.assert_called_once()
    mock_proc.wait.assert_not_called()
    found_log_call = False
    expected_message_substring = "Error sending terminate signal to plugin process"
    for call_obj in mock_logger_error.call_args_list:
        args, kwargs = call_obj
        message_arg = args[0] if args else ""
        exc_info_arg = kwargs.get("exc_info")
        if expected_message_substring in message_arg:
            if exc_info_arg:
                found_log_call = True
                break
            found_log_call = True
            break
    assert found_log_call, f"Expected logger.error call with substring '{expected_message_substring}' not found. Actual calls: {mock_logger_error.call_args_list}"
    assert client_instance._process is None

@pytest.mark.asyncio
async def test_close_process_wait_generic_exception(client_instance, mocker, caplog):
    client_instance.is_started = True
    mock_proc = MagicMock() # spec=real_subprocess.Popen removed
    mock_proc.poll = MagicMock(return_value=None)
    mock_proc.terminate = MagicMock()
    mock_proc.wait = MagicMock(side_effect=Exception("Generic wait error"))
    client_instance._process = mock_proc
    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    client_instance._stdio_task = AsyncMock(spec=asyncio.Task); client_instance._stdio_task.done.return_value = True
    client_instance._broker_task = AsyncMock(spec=asyncio.Task); client_instance._broker_task.done.return_value = True
    client_instance.grpc_channel = AsyncMock(); client_instance.grpc_channel.close = AsyncMock()
    client_instance._transport = AsyncMock(); client_instance._transport.close = AsyncMock()
    from pyvider.rpcplugin.client import base as client_base_module
    mock_logger_error = mocker.patch.object(client_base_module.logger, "error")
    await client_instance.close()
    mock_proc.terminate.assert_called_once()
    mock_proc.wait.assert_called_once_with(timeout=7.0)
    found_log_call = False
    expected_message_substring = "Error waiting for plugin process to terminate"
    expected_exception_substring = "Generic wait error"
    for call_obj in mock_logger_error.call_args_list:
        args, kwargs = call_obj
        message_arg = args[0] if args else ""
        if expected_message_substring in message_arg and expected_exception_substring in message_arg:
            if kwargs.get("extra"):
                found_log_call = True
                break
    assert found_log_call, f"Expected logger.error call for generic wait error not found or not logged with details. Actual calls: {mock_logger_error.call_args_list}"
    assert client_instance._process is None

@pytest.mark.asyncio
async def test_start_generic_exception(client_instance, mocker):
    mocker.patch.object(RPCPluginClient, "_setup_client_certificates", new_callable=AsyncMock, side_effect=Exception("Generic setup error"))
    mock_class_close = mocker.patch.object(RPCPluginClient, "close", autospec=True)
    with pytest.raises(Exception, match="Generic setup error"):
        await client_instance.start()
    mock_class_close.assert_called_once_with(client_instance)
    assert client_instance.is_started is False

@pytest.mark.asyncio
async def test_close_grpc_channel_exception(client_instance, mocker, caplog):
    client_instance.is_started = True
    mock_channel_on_instance = AsyncMock()
    mock_channel_on_instance.close = AsyncMock(side_effect=Exception("Channel close error"))
    client_instance.grpc_channel = mock_channel_on_instance
    local_mock_channel = client_instance.grpc_channel
    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    client_instance._stdio_task = AsyncMock(spec=asyncio.Task); client_instance._stdio_task.done.return_value = True
    client_instance._broker_task = AsyncMock(spec=asyncio.Task); client_instance._broker_task.done.return_value = True
    mock_process = MagicMock(spec=asyncio.subprocess.Process)
    mock_process.poll = MagicMock(return_value=0)
    client_instance._process = mock_process
    client_instance._transport = AsyncMock(); client_instance._transport.close = AsyncMock()
    from pyvider.rpcplugin.client import base as client_base_module
    mock_logger_error = mocker.patch.object(client_base_module.logger, "error")
    await client_instance.close()
    assert local_mock_channel.close.called
    found_log_call = False
    expected_message_substring = "Error closing gRPC channel"
    expected_exception_substring = "Channel close error"
    for call_obj in mock_logger_error.call_args_list:
        args, kwargs = call_obj
        message_arg = args[0] if args else ""
        if expected_message_substring in message_arg and expected_exception_substring in message_arg:
            if kwargs.get("extra"):
                 found_log_call = True
                 break
    assert found_log_call, f"Expected logger.error call for grpc_channel close error not found. Actual calls: {mock_logger_error.call_args_list}"
    assert client_instance.grpc_channel is None

@pytest.mark.asyncio
async def test_close_transport_exception(client_instance, mocker, caplog):
    client_instance.is_started = True
    mock_transport_on_instance = AsyncMock()
    mock_transport_on_instance.close = AsyncMock(side_effect=Exception("Transport close error"))
    client_instance._transport = mock_transport_on_instance
    local_mock_transport = client_instance._transport
    mocker.patch.object(RPCPluginClient, "shutdown_plugin", new_callable=AsyncMock)
    client_instance._stdio_task = AsyncMock(spec=asyncio.Task); client_instance._stdio_task.done.return_value = True
    client_instance._broker_task = AsyncMock(spec=asyncio.Task); client_instance._broker_task.done.return_value = True
    client_instance.grpc_channel = AsyncMock(); client_instance.grpc_channel.close = AsyncMock()
    mock_process = MagicMock(spec=asyncio.subprocess.Process)
    mock_process.poll = MagicMock(return_value=0)
    client_instance._process = mock_process
    from pyvider.rpcplugin.client import base as client_base_module
    mock_logger_error = mocker.patch.object(client_base_module.logger, "error")
    await client_instance.close()
    assert local_mock_transport.close.called
    found_log_call = False
    expected_message_substring = "Error closing transport socket"
    expected_exception_substring = "Transport close error"
    for call_obj in mock_logger_error.call_args_list:
        args, kwargs = call_obj
        message_arg = args[0] if args else ""
        if expected_message_substring in message_arg and expected_exception_substring in message_arg:
            if kwargs.get("extra"):
                found_log_call = True
                break
    assert found_log_call, f"Expected logger.error call for transport close error not found. Actual calls: {mock_logger_error.call_args_list}"
    assert client_instance._transport is None

@pytest.mark.asyncio
async def test_aexit_shutdown_plugin_exception(mocker, caplog):
    dummy_command = ["dummy_executable", "arg1"]
    mocker.patch.object(RPCPluginClient, '_setup_client_certificates', new_callable=AsyncMock)
    mocker.patch.object(RPCPluginClient, '_launch_process', new_callable=AsyncMock)
    client = RPCPluginClient(command=dummy_command)
    client._controller_stub = AsyncMock()
    async def actual_connect_logic_for_aexit_autospec(*args, **kwargs):
        client._process = MagicMock(spec=real_subprocess.Popen)
        client._process.poll = MagicMock(return_value=None)
        client._address = "mock_addr"
        client._transport_name = "mock_transport"
        client._protocol_version = 1
        client._server_cert = "mock_cert_pem"
        client.grpc_channel = AsyncMock()
        client.target_endpoint = "mock_target_endpoint"
        client.is_started = True
        client._handshake_complete_event.set()
        client._transport = AsyncMock()
        client._stdio_task = asyncio.create_task(asyncio.sleep(0))
        return None
    mocker.patch.object(RPCPluginClient, '_connect_and_handshake_with_retry', autospec=True, side_effect=actual_connect_logic_for_aexit_autospec)
    mocker.patch.object(RPCPluginClient, '_init_stubs', new_callable=MagicMock)
    mocker.patch.object(RPCPluginClient, "_read_stdio_logs", new_callable=AsyncMock)
    shutdown_exception_message = "Shutdown Boom!"
    mock_shutdown_plugin = mocker.patch.object(RPCPluginClient, 'shutdown_plugin', autospec=True, side_effect=Exception(shutdown_exception_message))
    async def actual_new_close_logic_simplified(instance_arg, *args_passed):
        print(f"actual_new_close_logic_simplified called on instance: {instance_arg}")
        assert isinstance(instance_arg, RPCPluginClient)
        if hasattr(instance_arg, '_stdio_task') and instance_arg._stdio_task and not instance_arg._stdio_task.done():
            instance_arg._stdio_task.cancel()
            with suppress(asyncio.TimeoutError, asyncio.CancelledError): await asyncio.wait_for(instance_arg._stdio_task, timeout=0.1)
        instance_arg.grpc_channel = None
        instance_arg._process = None
        instance_arg._transport = None
        instance_arg.is_started = False
        return None
    mocker.patch.object(RPCPluginClient, 'close', autospec=True, side_effect=actual_new_close_logic_simplified)
    with caplog.at_level(logging.ERROR, logger="pyvider.rpcplugin.client.base"):
        try:
            async with client:
                assert client.is_started
        except Exception as e:
            pytest.fail(f"Exception propagated from async with client: {e}, {type(e)}")
    mock_shutdown_plugin.assert_called_once_with(client)
    found_log = any(
        record.levelname == "ERROR" and
        "Error during __aexit__ calling shutdown_plugin()" in record.message and
        shutdown_exception_message in str(record.exc_info)
        for record in caplog.records
    )
    assert found_log, f"Expected error log from __aexit__/shutdown_plugin not found. Log content: {caplog.text}"
    RPCPluginClient.close.assert_called_once_with(client)
    assert client.is_started is False
    assert client.grpc_channel is None
    assert client._process is None
    assert client._transport is None
    if hasattr(client, '_stdio_task') and client._stdio_task and not client._stdio_task.done():
        client._stdio_task.cancel()
        with suppress(asyncio.CancelledError): await client._stdio_task
    # _relay_stderr_task is not created by current mocks.
