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
    
    # Mock the relay method to avoid threading complexity
    with patch.object(client_instance, '_relay_stderr_background', AsyncMock()) as mock_relay:
        # Mock connecting to the transport
        with patch('pyvider.rpcplugin.client.base.TCPSocketTransport') as mock_transport_class:
            mock_transport = AsyncMock()
            mock_transport_class.return_value = mock_transport
            
            # Configure process.stdout to return a valid handshake response
            mock_process.stdout.readline.return_value = b"1|1|tcp|127.0.0.1:8000|grpc|\n"
            
            await client_instance._perform_handshake()
            
            # Verify handshake components were set correctly
            mock_relay.assert_called_once()
            assert client_instance._protocol_version == 1
            assert client_instance._transport is not None
            assert client_instance._server_cert is None

@pytest.mark.asyncio
async def test_perform_handshake_with_cert(client_instance, mock_process):
    """Test handshake with server certificate included."""
    client_instance._process = mock_process
    
    # Sample base64-encoded cert
    sample_cert = "MIIEpAIBADANBgkqhkiG9w0BAQEFAASCBJYwggSSAgEAAoIBAQDBj08sp"
    
    # Mock the relay method
    with patch.object(client_instance, '_relay_stderr_background', AsyncMock()):
        # Mock connecting to the transport
        with patch('pyvider.rpcplugin.client.base.TCPSocketTransport') as mock_transport_class:
            mock_transport = AsyncMock()
            mock_transport_class.return_value = mock_transport
            
            # Configure process.stdout to return a handshake with cert
            mock_process.stdout.readline.return_value = f"1|1|tcp|127.0.0.1:8000|grpc|{sample_cert}\n".encode()
            
            await client_instance._perform_handshake()
            
            # Certificate should be captured
            assert client_instance._protocol_version == 1
            assert client_instance._transport is not None
            assert client_instance._server_cert == sample_cert

@pytest.mark.asyncio
async def test_perform_handshake_with_unix_transport(client_instance, mock_process):
    """Test handshake with Unix socket transport."""
    client_instance._process = mock_process
    
    # Mock the relay method
    with patch.object(client_instance, '_relay_stderr_background', AsyncMock()):
        # Mock UnixSocketTransport
        with patch('pyvider.rpcplugin.client.base.UnixSocketTransport') as mock_transport_class:
            mock_transport = AsyncMock()
            mock_transport_class.return_value = mock_transport
            
            # Configure process.stdout to return a Unix socket handshake
            mock_process.stdout.readline.return_value = b"1|1|unix|/tmp/test.sock|grpc|\n"
            
            await client_instance._perform_handshake()
            
            # Transport type should be unix
            assert client_instance._protocol_version == 1
            assert client_instance._transport_name == "unix"
            mock_transport.connect.assert_called_once_with("/tmp/test.sock")

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
    mock_process.poll.return_value = 1
    mock_process.stderr.read.return_value = b"Error during startup"
    
    with pytest.raises(HandshakeError, match="Plugin process exited with code 1"):
        await client_instance._perform_handshake()

@pytest.mark.asyncio
async def test_perform_handshake_invalid_format(client_instance, mock_process):
    """Test handshake with invalid response format."""
    client_instance._process = mock_process
    
    # Configure process.stdout to return an invalid handshake
    mock_process.stdout.readline.return_value = b"invalid_handshake_format\n"
    
    with patch.object(client_instance, '_relay_stderr_background', AsyncMock()):
        with pytest.raises(HandshakeError):
            await client_instance._perform_handshake()
