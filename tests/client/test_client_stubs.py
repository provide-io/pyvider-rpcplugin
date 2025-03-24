# tests/client/test_client_stubs.py

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock, ANY

from pyvider.rpcplugin.client.base import RPCPluginClient
from google.protobuf import empty_pb2

@pytest.mark.asyncio
async def test_init_stubs(client_instance):
    """Test initialization of gRPC stubs."""
    # Setup
    client_instance._channel = MagicMock()
    
    # Mock all stub classes
    with patch('pyvider.rpcplugin.client.base.GRPCStdioStub') as mock_stdio_stub_class, \
         patch('pyvider.rpcplugin.client.base.GRPCBrokerStub') as mock_broker_stub_class, \
         patch('pyvider.rpcplugin.client.base.GRPCControllerStub') as mock_controller_stub_class:
        
        mock_stdio_stub = MagicMock()
        mock_broker_stub = MagicMock()
        mock_controller_stub = MagicMock()
        
        mock_stdio_stub_class.return_value = mock_stdio_stub
        mock_broker_stub_class.return_value = mock_broker_stub
        mock_controller_stub_class.return_value = mock_controller_stub
        
        # Initialize stubs
        client_instance._init_stubs()
        
        # Verify stubs were initialized with the channel
        mock_stdio_stub_class.assert_called_once_with(client_instance._channel)
        mock_broker_stub_class.assert_called_once_with(client_instance._channel)
        mock_controller_stub_class.assert_called_once_with(client_instance._channel)
        
        # Verify stubs were assigned
        assert client_instance._stdio_stub == mock_stdio_stub
        assert client_instance._broker_stub == mock_broker_stub
        assert client_instance._controller_stub == mock_controller_stub

@pytest.mark.asyncio
async def test_init_stubs_no_channel(client_instance):
    """Test _init_stubs with no channel available."""
    client_instance._channel = None
    
    with pytest.raises(RuntimeError, match="Cannot init stubs"):
        client_instance._init_stubs()

@pytest.mark.asyncio
async def test_read_stdio_logs(client_instance):
    """Test reading logs from stdio stub."""
    # Setup
    mock_stdio_stub = MagicMock()
    client_instance._stdio_stub = mock_stdio_stub
    
    # Mock StreamStdio as async generator
    async def mock_stream_stdio(_):
        yield MagicMock(channel=1, data=b"stdout log message")
        yield MagicMock(channel=2, data=b"stderr log message")
        raise asyncio.CancelledError()  # Simulate cancellation
    
    mock_stdio_stub.StreamStdio = mock_stream_stdio
    
    # Test
    with pytest.raises(asyncio.CancelledError):
        await client_instance._read_stdio_logs()

@pytest.mark.asyncio
async def test_read_stdio_logs_no_stub(client_instance):
    """Test _read_stdio_logs with no stub available."""
    client_instance._stdio_stub = None
    
    # Should return without error
    await client_instance._read_stdio_logs()

@pytest.mark.asyncio
async def test_open_broker_subchannel(client_instance):
    """Test opening a broker subchannel."""
    # Setup
    mock_broker_stub = MagicMock()
    client_instance._broker_stub = mock_broker_stub
    
    # Mock StartStream call
    mock_call = AsyncMock()
    mock_broker_stub.StartStream.return_value = mock_call
    
    # Test response generator
    async def mock_response_gen():
        yield MagicMock(
            service_id=123,
            knock=MagicMock(ack=True, error="")
        )
    
    # Mock call's aiter method
    mock_call.__aiter__.return_value = mock_response_gen()
    
    # Open subchannel
    await client_instance.open_broker_subchannel(123, "127.0.0.1:8001")
    
    # Verify call was made correctly
    assert client_instance._broker_task is not None
    mock_broker_stub.StartStream.assert_called_once()
    mock_call.write.assert_called_once()
    mock_call.done_writing.assert_called_once()

@pytest.mark.asyncio
async def test_shutdown_plugin(client_instance):
    """Test shutting down the plugin via controller stub."""
    # Setup
    mock_controller_stub = MagicMock()
    client_instance._controller_stub = mock_controller_stub
    
    # Mock Shutdown
    mock_controller_stub.Shutdown = AsyncMock()
    
    # Shutdown plugin
    await client_instance.shutdown_plugin()
    
    # Verify controller stub was used
    mock_controller_stub.Shutdown.assert_called_once_with(ANY)
