# tests/client/test_client_grpc.py

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock, ANY

from pyvider.rpcplugin.client.base import RPCPluginClient

@pytest.mark.asyncio
async def test_rebuild_x509_pem(client_instance):
    """Test rebuilding X.509 certificate to PEM format."""
    # Test with raw base64 data (no headers)
    raw_cert = "MIIEpAIBADANBgkqhkiG9w0BAQEFAASCBJYwggSSAgEAAoIBAQDBj08sp"
    result = client_instance._rebuild_x509_pem(raw_cert)
    
    # PEM headers should be added
    assert result.startswith("-----BEGIN CERTIFICATE-----")
    assert result.endswith("-----END CERTIFICATE-----\n")
    assert raw_cert in result
    
    # Test with already formatted PEM
    pem_cert = "-----BEGIN CERTIFICATE-----\nMIIEpAIBADANBgkqhkiG9w0BAQEFAASCBJYwggSSAgEAAoIBAQDBj08sp\n-----END CERTIFICATE-----"
    result = client_instance._rebuild_x509_pem(pem_cert)
    
    # Should be unchanged
    assert result == pem_cert

@pytest.mark.asyncio
async def test_create_grpc_channel_with_tls(client_instance):
    """Test creating a gRPC channel with TLS."""
    # Setup
    client_instance._transport = MagicMock()
    client_instance._transport_name = "tcp"
    client_instance._address = "127.0.0.1:8000"
    client_instance._server_cert = "MIIEpAIBADANBgkqhkiG9w0BAQEFAASCBJYwggSSAgEAAoIBAQDBj08sp"
    
    # Mock SSL credentials
    with patch('pyvider.rpcplugin.client.base.grpc.ssl_channel_credentials') as mock_ssl_creds:
        mock_creds = MagicMock()
        mock_ssl_creds.return_value = mock_creds
        
        # Mock secure channel
        with patch('pyvider.rpcplugin.client.base.grpc.aio.secure_channel') as mock_secure_channel:
            mock_channel = AsyncMock()
            mock_secure_channel.return_value = mock_channel
            
            # Mock channel_ready() to return immediately
            mock_channel.channel_ready = AsyncMock()
            
            await client_instance._create_grpc_channel()
            
            # Verify secure_channel was called correctly
            mock_ssl_creds.assert_called_once()
            mock_secure_channel.assert_called_once()
            assert client_instance._channel == mock_channel

@pytest.mark.asyncio
async def test_create_grpc_channel_with_mtls(client_instance):
    """Test creating a gRPC channel with mutual TLS."""
    # Setup
    client_instance._transport = MagicMock()
    client_instance._transport_name = "tcp"
    client_instance._address = "127.0.0.1:8000"
    client_instance._server_cert = "MIIEpAIBADANBgkqhkiG9w0BAQEFAASCBJYwggSSAgEAAoIBAQDBj08sp"
    client_instance.client_cert = "client-cert"
    client_instance.client_key_pem = "client-key"
    
    # Mock SSL credentials
    with patch('pyvider.rpcplugin.client.base.grpc.ssl_channel_credentials') as mock_ssl_creds:
        mock_creds = MagicMock()
        mock_ssl_creds.return_value = mock_creds
        
        # Mock secure channel
        with patch('pyvider.rpcplugin.client.base.grpc.aio.secure_channel') as mock_secure_channel:
            mock_channel = AsyncMock()
            mock_secure_channel.return_value = mock_channel
            
            # Mock channel_ready() to return immediately
            mock_channel.channel_ready = AsyncMock()
            
            await client_instance._create_grpc_channel()
            
            # Verify mTLS credentials were used
            mock_ssl_creds.assert_called_once_with(
                root_certificates=ANY, 
                private_key=ANY, 
                certificate_chain=ANY
            )
            mock_secure_channel.assert_called_once()

@pytest.mark.asyncio
async def test_create_grpc_channel_insecure(client_instance):
    """Test creating an insecure gRPC channel."""
    # Setup
    client_instance._transport = MagicMock()
    client_instance._transport_name = "tcp"
    client_instance._address = "127.0.0.1:8000"
    client_instance._server_cert = None  # No server cert = insecure channel
    
    # Mock insecure_channel
    with patch('pyvider.rpcplugin.client.base.grpc.aio.insecure_channel') as mock_insecure_channel:
        mock_channel = AsyncMock()
        mock_insecure_channel.return_value = mock_channel
        
        # Mock channel_ready() to return immediately
        mock_channel.channel_ready = AsyncMock()
        
        await client_instance._create_grpc_channel()
        
        # Verify insecure_channel was called
        mock_insecure_channel.assert_called_once()
        assert client_instance._channel == mock_channel

@pytest.mark.asyncio
async def test_create_grpc_channel_unix_socket(client_instance):
    """Test creating a gRPC channel for Unix socket transport."""
    # Setup
    client_instance._transport = MagicMock()
    client_instance._transport_name = "unix"
    client_instance._address = "/tmp/test.sock"
    client_instance._server_cert = None
    
    # Mock insecure_channel
    with patch('pyvider.rpcplugin.client.base.grpc.aio.insecure_channel') as mock_insecure_channel:
        mock_channel = AsyncMock()
        mock_insecure_channel.return_value = mock_channel
        
        # Mock channel_ready() to return immediately
        mock_channel.channel_ready = AsyncMock()
        
        await client_instance._create_grpc_channel()
        
        # Verify unix prefix was used
        mock_insecure_channel.assert_called_once_with("unix:/tmp/test.sock", ANY)
