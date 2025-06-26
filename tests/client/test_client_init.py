# tests/client/test_client_init.py

import pytest
from unittest.mock import patch, MagicMock

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
    assert client.grpc_channel is None
    assert client.client_cert is None
    assert client.client_key_pem is None


def test_client_initialization_with_config(test_client_command):
    """Test initialization with a configuration dictionary."""
    config = {"key": "value", "env": {"ENV_VAR": "value"}}
    client = RPCPluginClient(command=test_client_command, config=config)

    assert client.config == config


@pytest.mark.asyncio
async def test_setup_client_certificates_with_auto_mtls(client_instance):
    """Test client certificate setup with auto-mTLS enabled and no pre-existing certs."""
    with (
        patch(
            "pyvider.rpcplugin.client.base.rpcplugin_config.auto_mtls_enabled",
            return_value=True,
        ) as mock_auto_mtls_enabled,
        patch(
            "pyvider.rpcplugin.client.base.rpcplugin_config.get"
        ) as mock_get_for_certs,
        patch("pyvider.rpcplugin.client.base.Certificate") as mock_cert_class,
    ):

        def side_effect_for_certs(key, default=None):
            if key == "PLUGIN_CLIENT_CERT":
                return None  # Simulate no pre-existing cert
            elif key == "PLUGIN_CLIENT_KEY":
                return None  # Simulate no pre-existing key
            return default

        mock_get_for_certs.side_effect = side_effect_for_certs

        mock_cert_instance = MagicMock()
        mock_cert_instance.cert = "test-cert"
        mock_cert_instance.key = "test-key"
        mock_cert_class.return_value = mock_cert_instance

        await client_instance._setup_client_certificates()

        mock_auto_mtls_enabled.assert_called_once()
        # Check that get was called for PLUGIN_CLIENT_CERT and PLUGIN_CLIENT_KEY
        mock_get_for_certs.assert_any_call("PLUGIN_CLIENT_CERT")
        mock_get_for_certs.assert_any_call("PLUGIN_CLIENT_KEY")

        mock_cert_class.assert_called_once()  # New cert should be generated
        assert client_instance.client_cert == "test-cert"
        assert client_instance.client_key_pem == "test-key"


@pytest.mark.asyncio
async def test_setup_client_certificates_with_existing_certs(client_instance):
    """Test client certificate setup with auto-mTLS enabled and pre-existing certs."""
    with (
        patch(
            "pyvider.rpcplugin.client.base.rpcplugin_config.auto_mtls_enabled",
            return_value=True,
        ) as mock_auto_mtls_enabled,
        patch(
            "pyvider.rpcplugin.client.base.rpcplugin_config.get"
        ) as mock_get_for_certs,
        patch("pyvider.rpcplugin.client.base.Certificate") as mock_cert_class,
    ):  # Still need to mock Certificate to prevent actual creation

        def side_effect_for_existing_certs(key, default=None):
            if key == "PLUGIN_CLIENT_CERT":
                return "existing-cert"
            elif key == "PLUGIN_CLIENT_KEY":
                return "existing-key"
            return default

        mock_get_for_certs.side_effect = side_effect_for_existing_certs

        await client_instance._setup_client_certificates()

        mock_auto_mtls_enabled.assert_called_once()
        # Check that get was called for PLUGIN_CLIENT_CERT and PLUGIN_CLIENT_KEY
        mock_get_for_certs.assert_any_call("PLUGIN_CLIENT_CERT")
        mock_get_for_certs.assert_any_call("PLUGIN_CLIENT_KEY")

        mock_cert_class.assert_not_called()  # New cert should NOT be generated
        assert client_instance.client_cert == "existing-cert"
        assert client_instance.client_key_pem == "existing-key"


@pytest.mark.asyncio
async def test_setup_client_certificates_without_mtls(client_instance):
    """Test client certificate setup with mTLS disabled."""
    # Mock auto_mtls_enabled directly to return False
    with patch(
        "pyvider.rpcplugin.client.base.rpcplugin_config.auto_mtls_enabled",
        return_value=False,
    ) as mock_auto_mtls_disabled:
        await client_instance._setup_client_certificates()

        # Ensure the mock was called (optional but good practice)
        mock_auto_mtls_disabled.assert_called_once()

        # No certificates should be set
        assert client_instance.client_cert is None
        assert client_instance.client_key_pem is None
