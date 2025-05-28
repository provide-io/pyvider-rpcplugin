# tests/client/test_client_lifecycle.py

import pytest
import asyncio # Make sure asyncio is imported
from unittest.mock import patch, MagicMock, AsyncMock


@pytest.mark.asyncio
async def test_start_complete_flow(client_instance): # client_instance fixture still provides the instance
    """Test the full client start flow."""
    with patch('pyvider.rpcplugin.client.base.RPCPluginClient._setup_client_certificates', new_callable=AsyncMock) as mock_setup_certs, \
         patch('pyvider.rpcplugin.client.base.RPCPluginClient._launch_process', new_callable=AsyncMock) as mock_launch, \
         patch('pyvider.rpcplugin.client.base.RPCPluginClient._perform_handshake', new_callable=AsyncMock) as mock_handshake, \
         patch('pyvider.rpcplugin.client.base.RPCPluginClient._create_grpc_channel', new_callable=AsyncMock) as mock_create_channel, \
         patch('pyvider.rpcplugin.client.base.RPCPluginClient._init_stubs', new_callable=MagicMock) as mock_init_stubs, \
         patch('pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background', new_callable=AsyncMock) as mock_relay_stderr, \
         patch('pyvider.rpcplugin.client.base.RPCPluginClient._read_stdio_logs', new_callable=AsyncMock) as mock_read_stdio_logs, \
         patch('asyncio.create_task') as mock_create_task:
        
        await client_instance.start() # Call start on the instance
        
        # Assertions remain the same
        mock_setup_certs.assert_called_once()
        mock_launch.assert_called_once()
        mock_handshake.assert_called_once()
        mock_create_channel.assert_called_once()
        mock_init_stubs.assert_called_once()
        # Check that asyncio.create_task was called.
        # The argument to create_task is the coroutine returned by mock_read_stdio_logs().
        mock_create_task.assert_called_once()
        mock_read_stdio_logs.assert_called_once() # The method itself is called
        # mock_relay_stderr.assert_not_called() # Or called, depending on expectations

@pytest.mark.asyncio
async def test_close_with_tasks(client_instance):
    """Test closing client with active tasks."""
    
    async def dummy_task_coro():
        try:
            await asyncio.sleep(5) # Simulate some work
        except asyncio.CancelledError:
            # print("Dummy task cancelled") # Optional: for debugging test execution
            raise

    # Create real asyncio.Task instances
    stdio_task_actual = asyncio.create_task(dummy_task_coro())
    broker_task_actual = asyncio.create_task(dummy_task_coro())

    # Mock their methods for assertions and control
    # Mock 'done' to control the condition in client.close()
    # The real .done() would also work but this gives explicit control.
    stdio_task_actual.done = MagicMock(return_value=False, name="StdioTask.done")
    # Mock 'cancel' to assert it's called. The real .cancel() will be called by client.close().
    # We are replacing it with a mock to check the call.
    # If we needed the task to actually be cancelled for subsequent logic, we'd use side_effect.
    # For this test, just checking it's called is enough.
    stdio_task_actual.cancel = MagicMock(name="StdioTask.cancel_mock")

    broker_task_actual.done = MagicMock(return_value=False, name="BrokerTask.done")
    broker_task_actual.cancel = MagicMock(name="BrokerTask.cancel_mock")

    client_instance._stdio_task = stdio_task_actual
    client_instance._broker_task = broker_task_actual
    
    local_mock_channel = AsyncMock(name="Channel")
    local_mock_channel.close = AsyncMock(name="Channel.close_method")
    client_instance._channel = local_mock_channel
    
    local_mock_process = MagicMock(name="Process")
    local_mock_process.terminate = MagicMock(name="Process.terminate_method")
    local_mock_process.wait = MagicMock(name="Process.wait_method")
    client_instance._process = local_mock_process
    
    local_mock_transport = AsyncMock(name="Transport")
    local_mock_transport.close = AsyncMock(name="Transport.close_method")
    client_instance._transport = local_mock_transport
    
    await client_instance.close() # This will now await actual (though mocked) tasks
    
    stdio_task_actual.cancel.assert_called_once()
    broker_task_actual.cancel.assert_called_once()
    
    local_mock_channel.close.assert_called_once()
    local_mock_process.terminate.assert_called_once()
    local_mock_transport.close.assert_called_once()

    # Clean up tasks to prevent them from interfering with other tests if they weren't fully cancelled
    # (though client.close() should handle awaiting them after cancellation)
    # For safety in testing, explicitly ensure tasks are finished if not already.
    if not stdio_task_actual.done():
        # stdio_task_actual.cancel() # This is the MagicMock, not the real cancel.
                                  # The client.close() called this MagicMock.
                                  # To actually cancel the task for cleanup, we need to call the real cancel.
        asyncio.Task.cancel(stdio_task_actual) # Call the static method to ensure actual cancellation
        with pytest.raises(asyncio.CancelledError): # Expect cancellation
             await stdio_task_actual
             
    if not broker_task_actual.done():
        # broker_task_actual.cancel() # This is the MagicMock.
        asyncio.Task.cancel(broker_task_actual) # Call the static method to ensure actual cancellation
        with pytest.raises(asyncio.CancelledError): # Expect cancellation
             await broker_task_actual

@pytest.mark.asyncio
async def test_close_with_errors(client_instance):
    """Test closing client when errors occur."""
    # Store mocks locally
    mock_channel = AsyncMock()
    mock_channel.close.side_effect = Exception("Channel close error")
    client_instance._channel = mock_channel
    
    mock_process = MagicMock()
    mock_process.terminate.side_effect = Exception("Process terminate error")
    # For process.wait(), ensure it can be called if terminate succeeds in a real scenario
    # but here terminate itself is erroring. If terminate didn't error, wait might.
    mock_process.wait = MagicMock() 
    client_instance._process = mock_process
    
    mock_transport = AsyncMock()
    mock_transport.close.side_effect = Exception("Transport close error")
    client_instance._transport = mock_transport
    
    # Close should handle errors gracefully
    await client_instance.close()
    
    # All close methods should be called despite errors
    mock_channel.close.assert_called_once()
    mock_process.terminate.assert_called_once()
    # mock_process.wait will not be called if terminate() errors, which it does here.
    # If terminate() didn't error, then wait() would be called.
    # So, we don't assert wait() here as terminate is designed to fail.
    mock_transport.close.assert_called_once()
    
    # Resources should be nullified on the instance
    assert client_instance._channel is None
    assert client_instance._process is None
    assert client_instance._transport is None
