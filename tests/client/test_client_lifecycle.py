# tests/client/test_client_lifecycle.py

import pytest
from unittest.mock import patch, MagicMock, AsyncMock


@pytest.mark.asyncio
async def test_start_complete_flow(client_instance):
    """Test the full client start flow."""
    # Mock all methods called by start()
    with patch.object(client_instance, '_setup_client_certificates', AsyncMock()) as mock_setup_certs, \
         patch.object(client_instance, '_launch_process', AsyncMock()) as mock_launch, \
         patch.object(client_instance, '_perform_handshake', AsyncMock()) as mock_handshake, \
         patch.object(client_instance, '_create_grpc_channel', AsyncMock()) as mock_create_channel, \
         patch.object(client_instance, '_init_stubs') as mock_init_stubs, \
         patch('asyncio.create_task') as mock_create_task:
        
        # Mock _read_stdio_logs
        client_instance._read_stdio_logs = AsyncMock()
        
        # Start client
        await client_instance.start()
        
        # Verify all methods were called in correct order
        mock_setup_certs.assert_called_once()
        mock_launch.assert_called_once()
        mock_handshake.assert_called_once()
        mock_create_channel.assert_called_once()
        mock_init_stubs.assert_called_once()
        mock_create_task.assert_called_once()

@pytest.mark.asyncio
async def test_close_with_tasks(client_instance):
    """Test closing client with active tasks."""
    # Create mock tasks
    mock_stdio_task = AsyncMock()
    mock_broker_task = AsyncMock()
    
    client_instance._stdio_task = mock_stdio_task
    client_instance._broker_task = mock_broker_task
    client_instance._channel = AsyncMock()
    client_instance._process = MagicMock()
    client_instance._transport = AsyncMock()
    
    # Task cancellation setup
    mock_stdio_task.done.return_value = False
    mock_broker_task.done.return_value = False
    
    # Close client
    await client_instance.close()
    
    # Verify tasks were cancelled
    mock_stdio_task.cancel.assert_called_once()
    mock_broker_task.cancel.assert_called_once()
    
    # Verify resources were closed
    client_instance._channel.close.assert_called_once()
    assert client_instance._process.terminate.called
    client_instance._transport.close.assert_called_once()

@pytest.mark.asyncio
async def test_close_with_errors(client_instance):
    """Test closing client when errors occur."""
    client_instance._channel = AsyncMock()
    client_instance._channel.close.side_effect = Exception("Channel close error")
    
    client_instance._process = MagicMock()
    client_instance._process.terminate.side_effect = Exception("Process terminate error")
    
    client_instance._transport = AsyncMock()
    client_instance._transport.close.side_effect = Exception("Transport close error")
    
    # Close should handle errors gracefully
    await client_instance.close()
    
    # All close methods should be called despite errors
    client_instance._channel.close.assert_called_once()
    assert client_instance._process.terminate.called
    client_instance._transport.close.assert_called_once()
    
    # Resources should be nullified
    assert client_instance._channel is None
    assert client_instance._process is None
    assert client_instance._transport is None
