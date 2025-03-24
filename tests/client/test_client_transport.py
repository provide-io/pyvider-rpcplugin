# tests/client/test_client_transport.py

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

from pyvider.rpcplugin.client.base import RPCPluginClient
from pyvider.rpcplugin.exception import TransportError

@pytest.mark.asyncio
async def test_launch_process(client_instance):
    """Test the _launch_process method."""
    with patch('subprocess.Popen') as mock_popen:
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        
        await client_instance._launch_process()
        
        # Popen should be called with the correct command
        mock_popen.assert_called_once()
        assert client_instance._process == mock_process
        
        # Environment variables should be set correctly
        call_kwargs = mock_popen.call_args[1]
        assert 'env' in call_kwargs
        assert 'PYTHONUNBUFFERED' in call_kwargs['env']
        assert call_kwargs['env']['PYTHONUNBUFFERED'] == '1'

@pytest.mark.asyncio
async def test_launch_process_with_client_cert(client_instance):
    """Test process launch with client cert in environment."""
    client_instance.client_cert = "test-cert"
    
    with patch('subprocess.Popen') as mock_popen:
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        
        await client_instance._launch_process()
        
        # Client cert should be passed in environment
        call_kwargs = mock_popen.call_args[1]
        assert 'env' in call_kwargs
        assert 'PLUGIN_CLIENT_CERT' in call_kwargs['env']
        assert call_kwargs['env']['PLUGIN_CLIENT_CERT'] == 'test-cert'

@pytest.mark.asyncio
async def test_launch_process_already_running(client_instance):
    """Test _launch_process when process already exists."""
    client_instance._process = MagicMock()  # Process already exists
    
    with patch('subprocess.Popen') as mock_popen:
        await client_instance._launch_process()
        
        # Popen should not be called
        mock_popen.assert_not_called()

@pytest.mark.asyncio
async def test_launch_process_error(client_instance):
    """Test _launch_process handling errors."""
    with patch('subprocess.Popen') as mock_popen:
        mock_popen.side_effect = OSError("Failed to launch")
        
        with pytest.raises(OSError, match="Failed to launch"):
            await client_instance._launch_process()

@pytest.mark.asyncio
async def test_connect_tcp_transport(client_instance, mock_transport):
    """Test connecting to a TCP transport."""
    client_instance._transport_name = "tcp"
    client_instance._transport = mock_transport
    
    await client_instance._transport.connect("127.0.0.1:8000")
    
    mock_transport.connect.assert_called_once_with("127.0.0.1:8000")

@pytest.mark.asyncio
async def test_connect_unix_transport(client_instance, mock_unix_transport):
    """Test connecting to a Unix socket transport."""
    client_instance._transport_name = "unix"
    client_instance._transport = mock_unix_transport
    
    await client_instance._transport.connect("/tmp/test.sock")
    
    mock_unix_transport.connect.assert_called_once_with("/tmp/test.sock")
