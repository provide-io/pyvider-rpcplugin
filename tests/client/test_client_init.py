# tests/client/test_client_init.py
import logging
import pytest
from unittest.mock import patch, MagicMock, AsyncMock, call # Ensure call is imported

from pyvider.rpcplugin.client.base import RPCPluginClient
from pyvider.rpcplugin.crypto.certificate import Certificate
# Import the module itself to patch its logger instance's methods
from pyvider.rpcplugin.client import base as client_base_module


def test_client_initialization(test_client_command):
    """Test basic initialization of the RPCPluginClient class."""
    client = RPCPluginClient(command=test_client_command)

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
@patch.object(client_base_module.logger, 'info')
async def test_setup_client_certificates_with_auto_mtls(mock_logger_info, client_instance, mocker):
    mocker.patch.object(client_base_module.rpcplugin_config, "auto_mtls_enabled", return_value=True)

    mock_get_for_certs = mocker.patch.object(client_base_module.rpcplugin_config, "get")
    def side_effect_for_certs(key, default=None):
        if key == "PLUGIN_CLIENT_CERT": return None
        if key == "PLUGIN_CLIENT_KEY": return None
        return default
    mock_get_for_certs.side_effect = side_effect_for_certs

    mock_cert_instance = MagicMock(spec=Certificate)
    mock_cert_instance.cert = "test-cert"
    mock_cert_instance.key = "test-key"

    mock_cert_class = mocker.patch("pyvider.rpcplugin.client.base.Certificate", return_value=mock_cert_instance)

    await client_instance._setup_client_certificates()

    client_base_module.rpcplugin_config.auto_mtls_enabled.assert_called_once()

    # Robust check for calls to rpcplugin_config.get
    expected_get_calls = [
        call("PLUGIN_CLIENT_CERT", None),
        call("PLUGIN_CLIENT_KEY", None)
    ]
    # Check if each expected call is in the actual call list
    for expected_call in expected_get_calls:
        assert expected_call in mock_get_for_certs.call_args_list, \
            f"Expected call {expected_call} not found in {mock_get_for_certs.call_args_list}"


    mock_cert_class.assert_called_once_with(generate_keypair=True, key_type="ecdsa")
    assert client_instance.client_cert == "test-cert"
    assert client_instance.client_key_pem == "test-key"

    mock_logger_info.assert_any_call("🔐 Generating ephemeral self-signed client certificate.")


@pytest.mark.asyncio
@patch.object(client_base_module.logger, 'info')
async def test_setup_client_certificates_with_existing_certs(mock_logger_info, client_instance, mocker):
    mocker.patch.object(client_base_module.rpcplugin_config, "auto_mtls_enabled", return_value=True)

    mock_get_for_certs = mocker.patch.object(client_base_module.rpcplugin_config, "get")
    def side_effect_for_existing_certs(key, default=None):
        if key == "PLUGIN_CLIENT_CERT": return "existing-cert"
        if key == "PLUGIN_CLIENT_KEY": return "existing-key"
        return default
    mock_get_for_certs.side_effect = side_effect_for_existing_certs

    mock_cert_class = mocker.patch("pyvider.rpcplugin.client.base.Certificate")

    await client_instance._setup_client_certificates()

    client_base_module.rpcplugin_config.auto_mtls_enabled.assert_called_once()

    expected_get_calls = [
        call("PLUGIN_CLIENT_CERT", None),
        call("PLUGIN_CLIENT_KEY", None)
    ]
    for expected_call in expected_get_calls:
        assert expected_call in mock_get_for_certs.call_args_list, \
            f"Expected call {expected_call} not found in {mock_get_for_certs.call_args_list}"

    mock_cert_class.assert_not_called()

    assert client_instance.client_cert == "existing-cert"
    assert client_instance.client_key_pem == "existing-key"

    mock_logger_info.assert_any_call("🔐 Using existing client cert/key from config.")


@pytest.mark.asyncio
@patch.object(client_base_module.logger, 'debug')
@patch.object(client_base_module.logger, 'info')
@patch.object(client_base_module.logger, 'isEnabledFor')
async def test_setup_client_certificates_without_mtls(mock_is_enabled_for, mock_logger_info, mock_logger_debug, client_instance, mocker):
    # Ensure isEnabledFor(logging.DEBUG) returns True for this test
    mock_is_enabled_for.return_value = True

    mocker.patch.object(client_base_module.rpcplugin_config, "auto_mtls_enabled", return_value=False)
    mock_cert_class = mocker.patch("pyvider.rpcplugin.client.base.Certificate")

    await client_instance._setup_client_certificates()

    client_base_module.rpcplugin_config.auto_mtls_enabled.assert_called_once()
    mock_cert_class.assert_not_called()

    assert client_instance.client_cert is None
    assert client_instance.client_key_pem is None

    mock_logger_info.assert_any_call("🔐 mTLS not enabled; operating in insecure mode.")
    mock_logger_debug.assert_any_call("🔐 mTLS is disabled, skipping client certificate setup.")
    mock_is_enabled_for.assert_any_call(logging.DEBUG) # Check that isEnabledFor was actually queried


@pytest.mark.asyncio
@patch.object(client_base_module.logger, 'info')
async def test_setup_client_certificates_mtls_missing_key(mock_logger_info, client_instance, mocker):
    mocker.patch.object(client_base_module.rpcplugin_config, "auto_mtls_enabled", return_value=True)

    mock_get_config = mocker.patch.object(client_base_module.rpcplugin_config, "get")
    def config_side_effect(key, default=None):
        if key == "PLUGIN_CLIENT_CERT": return "dummy-cert-pem"
        if key == "PLUGIN_CLIENT_KEY": return None
        return default
    mock_get_config.side_effect = config_side_effect

    mock_cert_generated_instance = MagicMock(spec=Certificate)
    mock_cert_generated_instance.cert = "generated-cert"
    mock_cert_generated_instance.key = "generated-key"
    mock_certificate_class = mocker.patch("pyvider.rpcplugin.client.base.Certificate", return_value=mock_cert_generated_instance)

    await client_instance._setup_client_certificates()

    mock_certificate_class.assert_called_once_with(generate_keypair=True, key_type="ecdsa")
    assert client_instance.client_cert == "generated-cert"
    assert client_instance.client_key_pem == "generated-key"

    mock_logger_info.assert_any_call("🔐 Generating ephemeral self-signed client certificate.")
