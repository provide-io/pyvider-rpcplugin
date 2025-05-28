# tests/client/test_client_handshake.py

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from pyvider.rpcplugin.exception import HandshakeError

@pytest.mark.asyncio
async def test_relay_stderr_background(client_instance, mock_process):
    """Test the background stderr relay functionality."""
    client_instance._process = mock_process
    
    # Mock threading.Thread to capture what it's called with
    with patch('threading.Thread') as mock_thread:
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
    
    with patch('pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background', new_callable=AsyncMock) as mock_relay, \
         patch('pyvider.rpcplugin.client.base.TCPSocketTransport') as mock_transport_class:
        
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
    sample_cert = "dGVzdA==" # "test"
    
    with patch('pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background', new_callable=AsyncMock) as mock_relay, \
         patch('pyvider.rpcplugin.client.base.TCPSocketTransport') as mock_transport_class:
        
        mock_transport_instance = AsyncMock()
        mock_transport_class.return_value = mock_transport_instance
        
        # Configure process.stdout to return a handshake with cert
        mock_process.stdout.readline.return_value = f"1|1|tcp|127.0.0.1:8000|grpc|{sample_cert}\n".encode()
        
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
    
    with patch('pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background', new_callable=AsyncMock) as mock_relay, \
         patch('pyvider.rpcplugin.client.base.UnixSocketTransport') as mock_transport_class:
        
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
    
    with pytest.raises(HandshakeError, match="No server process or no stdout available"):
        await client_instance._perform_handshake()

@pytest.mark.asyncio
async def test_perform_handshake_process_exit(client_instance, mock_process):
    """Test handshake when process exits prematurely."""
    client_instance._process = mock_process
    
    # Configure process to indicate it has exited
    mock_process.poll.return_value = 1  # Indicates process has exited
    mock_process.returncode = 1         # Set the actual integer returncode
    mock_process.stderr.read.return_value = b"Error during startup"
    mock_process.stderr.readline.return_value = b"" # For _relay_stderr_background
    
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
    
    with patch('pyvider.rpcplugin.client.base.RPCPluginClient._relay_stderr_background', new_callable=AsyncMock) as mock_relay, \
         pytest.raises(HandshakeError): 
        
        await client_instance._perform_handshake()
    
    # Assert relay was called because handshake starts before parsing fails
    mock_relay.assert_called_once()
