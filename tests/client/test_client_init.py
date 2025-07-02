# tests/client/test_client_init.py
from typing import Any
from unittest.mock import MagicMock, call, patch

import pytest

# Import the module itself to patch its logger instance's methods
from pyvider.rpcplugin.client import base as client_base_module
from pyvider.rpcplugin.client.base import RPCPluginClient
from pyvider.rpcplugin.crypto.certificate import Certificate


def test_client_initialization(test_client_command: list[str]) -> None:
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


def test_client_initialization_with_config(test_client_command: list[str]) -> None:
    """Test initialization with a configuration dictionary."""
    config = {"key": "value", "env": {"ENV_VAR": "value"}}
    client = RPCPluginClient(command=test_client_command, config=config)

    assert client.config == config


@pytest.mark.asyncio
@patch.object(client_base_module.logger, "info")
async def test_setup_client_certificates_with_auto_mtls(
    mock_logger_info: MagicMock, client_instance: RPCPluginClient, mocker: Any
) -> None:
    mocker.patch.object(
        client_base_module.rpcplugin_config, "auto_mtls_enabled", return_value=True
    )

    mock_get_for_certs = mocker.patch.object(client_base_module.rpcplugin_config, "get")

    def side_effect_for_certs(key: str, default: Any = None) -> Any:
        if key == "PLUGIN_CLIENT_CERT":
            return None
        if key == "PLUGIN_CLIENT_KEY":
            return None
        return default

    mock_get_for_certs.side_effect = side_effect_for_certs

    mock_cert_instance = MagicMock(spec=Certificate)
    mock_cert_instance.cert = "test-cert"
    mock_cert_instance.key = "test-key"

    mock_cert_class = mocker.patch(
        "pyvider.rpcplugin.client.base.Certificate", return_value=mock_cert_instance
    )

    await client_instance._setup_client_certificates()

    client_base_module.rpcplugin_config.auto_mtls_enabled.assert_called_once()

    # Robust check for calls to rpcplugin_config.get
    expected_get_calls = [
        call(
            "PLUGIN_CLIENT_CERT"
        ),  # Default arg is not used in actual code for these keys
        call(
            "PLUGIN_CLIENT_KEY"
        ),  # Default arg is not used in actual code for these keys
    ]
    # Check if each expected call is in the actual call list
    # We need to check the .args attribute of each call object
    actual_calls_args = [c.args for c in mock_get_for_certs.call_args_list]
    for expected_call_args in [ec.args for ec in expected_get_calls]:
        assert expected_call_args in actual_calls_args, (
            f"Expected call args {expected_call_args} not found in {actual_calls_args}"
        )

    mock_cert_class.assert_called_once_with(generate_keypair=True, key_type="ecdsa")
    assert client_instance.client_cert == "test-cert"
    assert client_instance.client_key_pem == "test-key"

    mock_logger_info.assert_any_call(
        "🔐 Generating ephemeral self-signed client certificate."
    )


@pytest.mark.asyncio
@patch.object(client_base_module.logger, "info")
async def test_setup_client_certificates_with_existing_certs(
    mock_logger_info: MagicMock, client_instance: RPCPluginClient, mocker: Any
) -> None:
    mocker.patch.object(
        client_base_module.rpcplugin_config, "auto_mtls_enabled", return_value=True
    )

    mock_get_for_certs = mocker.patch.object(client_base_module.rpcplugin_config, "get")

    def side_effect_for_existing_certs(key: str, default: Any = None) -> Any:
        if key == "PLUGIN_CLIENT_CERT":
            return "existing-cert"
        if key == "PLUGIN_CLIENT_KEY":
            return "existing-key"
        return default

    mock_get_for_certs.side_effect = side_effect_for_existing_certs

    mock_cert_class = mocker.patch("pyvider.rpcplugin.client.base.Certificate")

    await client_instance._setup_client_certificates()

    client_base_module.rpcplugin_config.auto_mtls_enabled.assert_called_once()

    expected_get_calls = [
        call("PLUGIN_CLIENT_CERT"),  # Default arg is not used in actual code
        call("PLUGIN_CLIENT_KEY"),  # Default arg is not used in actual code
    ]
    actual_calls_args = [c.args for c in mock_get_for_certs.call_args_list]
    for expected_call_args in [ec.args for ec in expected_get_calls]:
        assert expected_call_args in actual_calls_args, (
            f"Expected call args {expected_call_args} not found in {actual_calls_args}"
        )

    mock_cert_class.assert_not_called()

    assert client_instance.client_cert == "existing-cert"
    assert client_instance.client_key_pem == "existing-key"

    mock_logger_info.assert_any_call("🔐 Using existing client cert/key from config.")


@pytest.mark.asyncio
@patch.object(client_base_module.logger, "debug")
@patch.object(client_base_module.logger, "info")
# @patch.object(client_base_module.logger, 'isEnabledFor') # Removed: isEnabledFor is not called by the tested code path # noqa: E501
async def test_setup_client_certificates_without_mtls(
    mock_logger_info: MagicMock,
    mock_logger_debug: MagicMock,
    client_instance: RPCPluginClient,
    mocker: Any,
) -> None:  # Removed mock_is_enabled_for
    # Ensure isEnabledFor(logging.DEBUG) returns True for this test - Not needed if not called # noqa: E501
    # mock_is_enabled_for.return_value = True

    mocker.patch.object(
        client_base_module.rpcplugin_config,
        "auto_mtls_enabled",
        side_effect=lambda: False,
    )  # Use side_effect
    mock_cert_class = mocker.patch("pyvider.rpcplugin.client.base.Certificate")

    await client_instance._setup_client_certificates()

    client_base_module.rpcplugin_config.auto_mtls_enabled.assert_called_once()
    mock_cert_class.assert_not_called()

    assert client_instance.client_cert is None
    assert client_instance.client_key_pem is None

    mock_logger_info.assert_any_call("🔐 mTLS not enabled; operating in insecure mode.")
    # The actual first debug log message when mTLS is not explicitly enabled.
    mock_logger_debug.assert_any_call("🔐 Checking if auto-mTLS is enabled for client.")
    # mock_is_enabled_for.assert_any_call(logging.DEBUG) # This line was causing issues as isEnabledFor is not always called # noqa: E501


@pytest.mark.asyncio
@patch.object(client_base_module.logger, "info")
async def test_setup_client_certificates_mtls_missing_key(
    mock_logger_info: MagicMock, client_instance: RPCPluginClient, mocker: Any
) -> None:
    mocker.patch.object(
        client_base_module.rpcplugin_config, "auto_mtls_enabled", return_value=True
    )

    mock_get_config = mocker.patch.object(client_base_module.rpcplugin_config, "get")

    def config_side_effect(key: str, default: Any = None) -> Any:
        if key == "PLUGIN_CLIENT_CERT":
            return "dummy-cert-pem"
        if key == "PLUGIN_CLIENT_KEY":
            return None
        return default

    mock_get_config.side_effect = config_side_effect

    mock_cert_generated_instance = MagicMock(spec=Certificate)
    mock_cert_generated_instance.cert = "generated-cert"
    mock_cert_generated_instance.key = "generated-key"
    mock_certificate_class = mocker.patch(
        "pyvider.rpcplugin.client.base.Certificate",
        return_value=mock_cert_generated_instance,
    )

    await client_instance._setup_client_certificates()

    mock_certificate_class.assert_called_once_with(
        generate_keypair=True, key_type="ecdsa"
    )
    assert client_instance.client_cert == "generated-cert"
    assert client_instance.client_key_pem == "generated-key"

    mock_logger_info.assert_any_call(
        "🔐 Generating ephemeral self-signed client certificate."
    )
