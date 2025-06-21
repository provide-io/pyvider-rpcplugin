# pyvider/rpcplugin/tests/server/test_server_tls.py

import pytest
from unittest import mock

from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import SecurityError

from tests.conftest import (
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
)

@pytest.mark.asyncio
async def test_read_client_cert_logic(monkeypatch, mock_server_protocol, mock_server_handler, mock_server_transport):
    """Tests the logic of _read_client_cert for instance vs. global config."""
    
    # Scenario 1: Cert is in instance config
    instance_config = {"PLUGIN_CLIENT_CERT": "instance_cert"}
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_CLIENT_CERT", "global_cert")
    server1 = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler, config=instance_config, transport=mock_server_transport)
    assert server1._read_client_cert() == "instance_cert"

    # Scenario 2: Cert is not in instance config, fallback to global
    instance_config_empty = {}
    server2 = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler, config=instance_config_empty, transport=mock_server_transport)
    assert server2._read_client_cert() == "global_cert"
    
    # Scenario 3: Not in instance or global config
    monkeypatch.delitem(rpcplugin_config.config, "PLUGIN_CLIENT_CERT", raising=False)
    server3 = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler, config=instance_config_empty, transport=mock_server_transport)
    assert server3._read_client_cert() is None

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "config_setup",
    [
        # Secure mode with provided certs
        {
            "PLUGIN_SERVER_CERT": "dummy_cert_pem",
            "PLUGIN_SERVER_KEY": "dummy_key_pem",
            "PLUGIN_AUTO_MTLS": True,
            "PLUGIN_CLIENT_ROOT_CERTS": "dummy_ca_pem",
            "expected_require_auth": True
        },
        # Server-only TLS (mTLS disabled, but certs provided)
        {
            "PLUGIN_SERVER_CERT": "dummy_cert_pem",
            "PLUGIN_SERVER_KEY": "dummy_key_pem",
            "PLUGIN_AUTO_MTLS": False,
            "PLUGIN_CLIENT_ROOT_CERTS": None,
            "expected_require_auth": False
        },
        # Auto mTLS with auto-generated server cert (no client CA)
        {
            "PLUGIN_SERVER_CERT": None,
            "PLUGIN_SERVER_KEY": None,
            "PLUGIN_AUTO_MTLS": True,
            "PLUGIN_CLIENT_ROOT_CERTS": None,
            "expected_require_auth": False
        }
    ],
    ids=["mTLS-ProvidedCerts", "ServerTLS-Only", "Auto-mTLS-GeneratedCert"]
)
async def test_generate_server_credentials_scenarios(
    config_setup, monkeypatch, mock_server_protocol, mock_server_handler
):
    """Consolidated test for various credential generation scenarios."""
    
    # Apply config from parameters
    for key, value in config_setup.items():
        if "expected" not in key:
            monkeypatch.setitem(rpcplugin_config.config, key, value)

    # Ensure other necessary defaults for server initialization are present
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_PROTOCOL_VERSIONS", ["1"])
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_SERVER_TRANSPORTS", ["tcp"])

    server = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler, config=None)

    with mock.patch("pyvider.rpcplugin.server.Certificate") as mock_certificate_class, \
         mock.patch("pyvider.rpcplugin.server.grpc.ssl_server_credentials") as mock_grpc_creds:
        
        mock_cert_instance = mock.MagicMock(spec=Certificate)
        mock_cert_instance.cert = "dummy_cert_pem_content"
        mock_cert_instance.key = "dummy_key_pem_content"
        
        # Make the Certificate class return our mock instance
        mock_certificate_class.return_value = mock_cert_instance
        # Also mock the class methods used for auto-generation
        mock_certificate_class.create_self_signed_server_cert.return_value = mock_cert_instance

        # Call the method
        server._generate_server_credentials()

        # Verify grpc.ssl_server_credentials was called with the correct require_client_auth
        mock_grpc_creds.assert_called_once()
        call_kwargs = mock_grpc_creds.call_args.kwargs
        assert call_kwargs.get('require_client_auth') == config_setup["expected_require_auth"]

@pytest.mark.asyncio
async def test_generate_server_credentials_failures(
    monkeypatch, mock_server_protocol, mock_server_handler
):
    """Test various failure paths in credential generation."""
    
    # Scenario 1: Failed to load provided cert/key
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_SERVER_CERT", "path/to/cert")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_SERVER_KEY", "path/to/key")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_AUTO_MTLS", False)
    
    with mock.patch("pyvider.rpcplugin.server.Certificate", side_effect=Exception("Load fail")):
        server = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler)
        with pytest.raises(SecurityError, match="Failed to load server certificate/key"):
            server._generate_server_credentials()

    # Scenario 2: Failed to auto-generate cert
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_SERVER_CERT", None)
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_SERVER_KEY", None)
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_AUTO_MTLS", True)
    
    with mock.patch("pyvider.rpcplugin.server.Certificate.create_self_signed_server_cert", side_effect=Exception("Generate fail")):
        server = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler)
        with pytest.raises(SecurityError, match="Failed to auto-generate self-signed server certificate"):
            server._generate_server_credentials()

    # Scenario 3: Cert object is invalid (e.g., key is None)
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_SERVER_CERT", "path/to/cert")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_SERVER_KEY", "path/to/key")
    monkeypatch.setitem(rpcplugin_config.config, "PLUGIN_AUTO_MTLS", False)
    
    with mock.patch("pyvider.rpcplugin.server.Certificate") as mock_cert_class:
        mock_instance = mock.MagicMock(spec=Certificate)
        mock_instance.cert = "dummy_cert"
        mock_instance.key = None # Key is missing
        mock_cert_class.return_value = mock_instance
        
        server = RPCPluginServer(protocol=mock_server_protocol, handler=mock_server_handler)
        with pytest.raises(SecurityError, match="Server certificate object is invalid or missing PEM data"):
            server._generate_server_credentials()
