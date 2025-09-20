# tests/client/test_client_init.py

import pytest
from unittest.mock import patch, MagicMock

from pyvider.rpcplugin.client.core import RPCPluginClient
from provide.foundation.crypto import Certificate


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
            "pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_auto_mtls",
            True,
        ) as mock_plugin_auto_mtls,
        patch(
            "pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_client_cert",
            None,
        ) as mock_client_cert,
        patch(
            "pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_client_key",
            None,
        ) as mock_client_key,
        patch("pyvider.rpcplugin.client.handshake.Certificate") as mock_cert_class,
    ):

        mock_cert_instance = MagicMock()
        mock_cert_instance.cert = "test-cert"
        mock_cert_instance.key = "test-key"
        mock_cert_class.create_self_signed_client_cert.return_value = mock_cert_instance

        await client_instance._setup_client_certificates()

        # Attributes were accessed via patches

        assert client_instance.client_cert == "test-cert"
        assert client_instance.client_key_pem == "test-key"


@pytest.mark.asyncio
async def test_setup_client_certificates_with_existing_certs(client_instance):
    """Test client certificate setup with auto-mTLS enabled and pre-existing certs."""
    with (
        patch(
            "pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_auto_mtls",
            True,
        ) as mock_plugin_auto_mtls,
        patch(
            "pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_client_cert",
            "existing-cert",
        ) as mock_client_cert,
        patch(
            "pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_client_key",
            "existing-key",
        ) as mock_client_key,
        patch("pyvider.rpcplugin.client.handshake.Certificate") as mock_cert_class,
    ):
        # Set up mock to return the expected cert and key values
        mock_cert_instance = MagicMock()
        mock_cert_instance.cert = "existing-cert"
        mock_cert_instance.key = "existing-key"
        mock_cert_class.return_value = mock_cert_instance

        await client_instance._setup_client_certificates()

        # Attributes were accessed via patches

        mock_cert_class.assert_called_once_with(cert_pem_or_uri="existing-cert", key_pem_or_uri="existing-key")  # Existing cert should be loaded
        assert client_instance.client_cert == "existing-cert"
        assert client_instance.client_key_pem == "existing-key"


@pytest.mark.asyncio
async def test_setup_client_certificates_without_mtls(client_instance):
    """Test client certificate setup with mTLS disabled."""
    # Mock plugin_auto_mtls directly to return False
    with patch(
        "pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_auto_mtls",
        False,
    ) as mock_auto_mtls_disabled:
        await client_instance._setup_client_certificates()

        # Ensure the mock was called (optional but good practice)

        # No certificates should be set
        assert client_instance.client_cert is None
        assert client_instance.client_key_pem is None


@pytest.mark.asyncio
async def test_setup_client_certificates_mtls_missing_key(client_instance, mocker):
    """Test mTLS enabled, cert provided, but key is missing -> should generate."""
    mocker.patch("pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_auto_mtls", True)

    # Mock the Foundation attributes directly
    mocker.patch("pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_client_cert", "dummy-cert-pem")
    mocker.patch("pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_client_key", None)

    # We need to mock the Certificate class from the correct module
    mock_cert_generated_instance = MagicMock(spec=Certificate)
    mock_cert_generated_instance.cert = "generated-cert"
    mock_cert_generated_instance.key = "generated-key"

    # Ensure this path matches where Certificate is imported in client/handshake.py
    mock_certificate_class = mocker.patch("pyvider.rpcplugin.client.handshake.Certificate")
    mock_certificate_class.create_self_signed_client_cert.return_value = mock_cert_generated_instance

    # Mock the logger on the client_instance if it's used internally and part of RPCPluginClient
    # Assuming client_instance.logger is already a mock from a fixture or setup
    if not hasattr(client_instance, 'logger') or not isinstance(client_instance.logger, MagicMock):
         # If logger is not already a mock, patch it for this test
        client_instance.logger = MagicMock()

    # Patch the logger at the module level where it's used
    mock_logger_info = mocker.patch("pyvider.rpcplugin.client.core.logger.debug")

    await client_instance._setup_client_certificates()

    mock_certificate_class.create_self_signed_client_cert.assert_called_once_with(
        common_name="pyvider.rpcplugin.autogen.client",
        organization_name="Pyvider AutoGenerated",
        validity_days=365
    )
    assert client_instance.client_cert == "generated-cert"
    assert client_instance.client_key_pem == "generated-key"
    # Note: The actual message is a debug call, not info, so we need to check the right logger level


# 🐍🔌🧪🪄
