# tests/client/test_client_init.py

import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

from pyvider.rpcplugin.client.base import RPCPluginClient

def test_client_initialization(test_client_command):
    """Test basic initialization of the RPCPluginClient class."""
    client = RPCPluginClient(command=test_client_command)
    
    # Check initialization of important attributes
    assert client.command == test_client_command
    assert client.config is None
    assert client._process is None
    assert client._transport is None
    assert client._address is None
    assert client._protocol_version is None
    assert client._server_cert is None
    assert client._channel is None
    assert client.client_cert is None
    assert client.client_key_pem is None

def test_client_initialization_with_config(test_client_command):
    """Test initialization with a configuration dictionary."""
    config = {"key": "value", "env": {"ENV_VAR": "value"}}
    client = RPCPluginClient(command=test_client_command, config=config)
    
    assert client.config == config

@pytest.mark.asyncio
async def test_setup_client_certificates_with_auto_mtls(client_instance):
    """Test client certificate setup with auto-mTLS enabled."""
    # Mock the config to enable auto-mTLS
    with patch('pyvider.rpcplugin.client.base.rpcplugin_config.get') as mock_get:
        mock_get.side_effect = lambda key, default=None: "true" if key == "PLUGIN_AUTO_MTLS" else None
        
        # Mock Certificate to return a test certificate
        with patch('pyvider.rpcplugin.client.base.Certificate') as mock_cert_class:
            mock_cert = MagicMock()
            mock_cert.cert = "test-cert"
            mock_cert.key = "test-key"
            mock_cert_class.return_value = mock_cert
            
            await client_instance._setup_client_certificates()
            
            # Check if the certificate was created
            mock_cert_class.assert_called_once()
            assert client_instance.client_cert == "test-cert"
            assert client_instance.client_key_pem == "test-key"

@pytest.mark.asyncio
async def test_setup_client_certificates_with_existing_certs(client_instance):
    """Test using pre-existing certificates from config."""
    # Mock the config to enable auto-mTLS and provide existing certificates
    with patch('pyvider.rpcplugin.client.base.rpcplugin_config.get') as mock_get:
        mock_get.side_effect = lambda key, default=None: {
            "PLUGIN_AUTO_MTLS": "true",
            "PLUGIN_CLIENT_CERT": "existing-cert",
            "PLUGIN_CLIENT_KEY": "existing-key"
        }.get(key, None)
        
        await client_instance._setup_client_certificates()
        
        # Certificates should be loaded from config
        assert client_instance.client_cert == "existing-cert"
        assert client_instance.client_key_pem == "existing-key"

@pytest.mark.asyncio
async def test_setup_client_certificates_without_mtls(client_instance):
    """Test client certificate setup with mTLS disabled."""
    # Mock the config to disable auto-mTLS
    with patch('pyvider.rpcplugin.client.base.rpcplugin_config.get') as mock_get:
        mock_get.side_effect = lambda key, default=None: "false" if key == "PLUGIN_AUTO_MTLS" else None
        
        await client_instance._setup_client_certificates()
        
        # No certificates should be set
        assert client_instance.client_cert is None
        assert client_instance.client_key_pem is None
