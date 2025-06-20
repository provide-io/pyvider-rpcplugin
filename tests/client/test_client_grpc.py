# tests/client/test_client_grpc.py

import pytest
import asyncio  # Added
from unittest.mock import patch, MagicMock, AsyncMock, ANY  # ANY added back
from pyvider.rpcplugin.transport import (
    UnixSocketTransport,
    TCPSocketTransport,
)  # Import added
from pyvider.rpcplugin.exception import TransportError  # Added import


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
    client_instance._server_cert = (
        "MIIEpAIBADANBgkqhkiG9w0BAQEFAASCBJYwggSSAgEAAoIBAQDBj08sp"
    )

    # Mock SSL credentials
    with patch(
        "pyvider.rpcplugin.client.base.grpc.ssl_channel_credentials"
    ) as mock_ssl_creds:
        mock_creds = MagicMock()
        mock_ssl_creds.return_value = mock_creds

        # Mock secure channel
        with patch(
            "pyvider.rpcplugin.client.base.grpc.aio.secure_channel"
        ) as mock_secure_channel:
            mock_channel = AsyncMock()
            mock_secure_channel.return_value = mock_channel

            # Mock channel_ready() to return immediately
            mock_channel.channel_ready = AsyncMock()

            await client_instance._create_grpc_channel()

            # Verify TLS-only credentials were used (only root_certificates)
            mock_ssl_creds.assert_called_once_with(root_certificates=ANY)
            mock_secure_channel.assert_called_once()
            assert client_instance.grpc_channel == mock_channel



@pytest.mark.asyncio
async def test_create_grpc_channel_with_mtls(client_instance, mocker):
    """Test creating a gRPC channel with mutual TLS."""
    # Setup instance attributes that _setup_client_certificates would normally set
    # based on config, or that are set before _create_grpc_channel is called.
    dummy_client_cert_pem = "DUMMY_CLIENT_CERT_PEM_STRING"
    dummy_client_key_pem = "DUMMY_CLIENT_KEY_PEM_STRING"
    dummy_server_root_pem = "DUMMY_SERVER_ROOT_PEM_STRING"

    client_instance.client_cert = dummy_client_cert_pem
    client_instance.client_key_pem = dummy_client_key_pem
    client_instance._server_cert = dummy_server_root_pem # Used if PLUGIN_SERVER_ROOT_CERTS is not primary

    # Mock rpcplugin_config.get
    def mock_config_get_side_effect(key, default=None):
        if key == "PLUGIN_AUTO_MTLS":
            return True # Enable mTLS path
        elif key == "PLUGIN_CLIENT_CERT":
            return dummy_client_cert_pem # Explicit client cert configured
        elif key == "PLUGIN_CLIENT_KEY":
            return dummy_client_key_pem   # Explicit client key configured
        elif key == "PLUGIN_SERVER_ROOT_CERTS":
            return dummy_server_root_pem # Explicit server root CAs
        # Default for other config values if any are checked by the method implicitly
        return default

    mocker.patch("pyvider.rpcplugin.client.base.rpcplugin_config.get", side_effect=mock_config_get_side_effect)

    client_instance._transport = MagicMock()
    client_instance._transport_name = "tcp"
    client_instance._address = "127.0.0.1:8000"

    # Mock SSL credentials
    with patch(
        "pyvider.rpcplugin.client.base.grpc.ssl_channel_credentials"
    ) as mock_ssl_creds:
        mock_creds = MagicMock()
        mock_ssl_creds.return_value = mock_creds

        # Mock secure channel
        with patch(
            "pyvider.rpcplugin.client.base.grpc.aio.secure_channel"
        ) as mock_secure_channel:
            mock_channel = AsyncMock()
            mock_secure_channel.return_value = mock_channel

            # Mock channel_ready() to return immediately
            mock_channel.channel_ready = AsyncMock()

            await client_instance._create_grpc_channel()

            # Verify mTLS credentials were used
            expected_root_certs_pem = client_instance._rebuild_x509_pem(dummy_server_root_pem)
            mock_ssl_creds.assert_called_once_with(
                root_certificates=expected_root_certs_pem.encode(),
                private_key=dummy_client_key_pem.encode(),
                certificate_chain=dummy_client_cert_pem.encode()
            )
            mock_secure_channel.assert_called_once()
            assert client_instance.grpc_channel == mock_channel


@pytest.mark.asyncio
async def test_create_grpc_channel_insecure(client_instance):
    """Test creating an insecure gRPC channel."""
    # Setup
    client_instance._transport = MagicMock()
    client_instance._transport_name = "tcp"
    client_instance._address = "127.0.0.1:8000"
    client_instance._server_cert = None  # No server cert = insecure channel

    # Mock insecure_channel
    with patch(
        "pyvider.rpcplugin.client.base.grpc.aio.insecure_channel"
    ) as mock_insecure_channel:
        mock_channel = AsyncMock()
        mock_insecure_channel.return_value = mock_channel

        # Mock channel_ready() to return immediately
        mock_channel.channel_ready = AsyncMock()

        await client_instance._create_grpc_channel()

        # Verify insecure_channel was called
        mock_insecure_channel.assert_called_once()
        assert client_instance.grpc_channel == mock_channel


@pytest.mark.asyncio
async def test_create_grpc_channel_unix_socket(client_instance):
    """Test creating a gRPC channel for Unix socket transport."""
    # Setup
    client_instance._transport = AsyncMock(
        spec=UnixSocketTransport
    )  # Changed to use spec
    client_instance._transport_name = "unix"  # This is correct for the logic path
    client_instance._address = "/tmp/test.sock"  # This is the raw path
    client_instance._server_cert = None  # To ensure insecure_channel is called

    with patch(
        "pyvider.rpcplugin.client.base.grpc.aio.insecure_channel"
    ) as mock_insecure_channel:
        mock_channel = AsyncMock()
        mock_insecure_channel.return_value = mock_channel
        mock_channel.channel_ready = AsyncMock()  # Mock channel_ready

        await client_instance._create_grpc_channel()

        # Verify unix prefix was used and no extra args
        mock_insecure_channel.assert_called_once_with(
            "unix:/tmp/test.sock"
        )  # Corrected assertion


@pytest.mark.asyncio
async def test_create_grpc_channel_ready_timeout_unix(client_instance, mocker):
    """Test channel ready timeout for Unix socket."""
    client_instance._transport = mocker.MagicMock(spec=UnixSocketTransport)
    client_instance._transport_name = "unix"
    client_instance._address = "/tmp/test_timeout.sock"  # Actual path used by transport
    client_instance._server_cert = None  # Insecure channel

    mock_channel = AsyncMock()
    mock_channel.channel_ready = AsyncMock(
        side_effect=asyncio.TimeoutError("Channel timed out")
    )

    mocker.patch(
        "pyvider.rpcplugin.client.base.grpc.aio.insecure_channel",
        return_value=mock_channel,
    )
    mocker.patch(
        "os.path.exists", return_value=True
    )  # Assume socket file exists for the diagnostic log
    mock_logger_error = mocker.patch("pyvider.rpcplugin.client.base.logger.error")

    with pytest.raises(
        TransportError,
        match=r"\[TransportError\] Failed to establish gRPC channel to plugin: timeout.*Hint: Check network connectivity to unix:/tmp/test_timeout.sock.*",
    ):
        await client_instance._create_grpc_channel()

    mock_logger_error.assert_any_call(
        "🚢❌ gRPC channel failed to become ready (timeout)"
    )
    mock_logger_error.assert_any_call(
        "🚢❌ Socket diagnostics: path=/tmp/test_timeout.sock, exists=True"
    )


@pytest.mark.asyncio
async def test_create_grpc_channel_ready_timeout_tcp(client_instance, mocker):
    """Test channel ready timeout for TCP socket."""
    client_instance._transport = mocker.MagicMock(
        spec=TCPSocketTransport
    )  # Mock TCP transport
    client_instance._transport_name = "tcp"
    client_instance._address = "127.0.0.1:12345"
    client_instance._server_cert = None  # Insecure channel

    mock_channel = AsyncMock()
    mock_channel.channel_ready = AsyncMock(
        side_effect=asyncio.TimeoutError("Channel timed out")
    )

    mocker.patch(
        "pyvider.rpcplugin.client.base.grpc.aio.insecure_channel",
        return_value=mock_channel,
    )
    mock_logger_error = mocker.patch("pyvider.rpcplugin.client.base.logger.error")

    with pytest.raises(
        TransportError,
        match=r"\[TransportError\] Failed to establish gRPC channel to plugin: timeout.*Hint: Check network connectivity to 127.0.0.1:12345.*",
    ):
        await client_instance._create_grpc_channel()

    # Ensure the primary timeout log is there, but not the Unix-specific socket diagnostic
    mock_logger_error.assert_any_call(
        "🚢❌ gRPC channel failed to become ready (timeout)"
    )
    # Check that the Unix-specific diagnostic was NOT called
    for call in mock_logger_error.call_args_list:
        assert "Socket diagnostics" not in call.args[0]


@pytest.mark.asyncio
async def test_create_grpc_channel_ready_generic_exception(client_instance, mocker):
    """Test generic exception during channel_ready."""
    client_instance._transport = mocker.MagicMock(spec=TCPSocketTransport)
    client_instance._transport_name = "tcp"
    client_instance._address = "127.0.0.1:12345"
    client_instance._server_cert = None

    mock_channel = AsyncMock()
    mock_channel.channel_ready = AsyncMock(
        side_effect=RuntimeError("Other connection issue")
    )

    mocker.patch(
        "pyvider.rpcplugin.client.base.grpc.aio.insecure_channel",
        return_value=mock_channel,
    )
    mock_logger_error = mocker.patch("pyvider.rpcplugin.client.base.logger.error")

    with pytest.raises(
        TransportError,
        match=r"\[TransportError\] Failed to establish gRPC channel to plugin at 127.0.0.1:12345: Other connection issue.*Hint: Verify plugin server is running.*",
    ):
        await client_instance._create_grpc_channel()

    mock_logger_error.assert_any_call(
        "🚢❌ gRPC channel creation failed: Other connection issue"
    )  # <--- Ensure this is the new assertion
