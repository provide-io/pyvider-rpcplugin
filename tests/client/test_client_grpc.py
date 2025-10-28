#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""TODO: Add module docstring."""

from provide.testkit.mocking import ANY, AsyncMock, MagicMock, patch
import pytest

from pyvider.rpcplugin.exception import TransportError  # Added import
from pyvider.rpcplugin.transport import (
    TCPSocketTransport,
    UnixSocketTransport,
)  # Import added


@pytest.mark.asyncio
async def test_rebuild_x509_pem(client_instance) -> None:
    """Test rebuilding X.509 certificate to PEM format."""
    # Test with raw base64 data (no headers)
    raw_cert = "MIIEpAIBADANBgkqhkiG9w0BAQEFAASCBJYwggSSAgEAAoIBAQDBj08sp"
    result = client_instance._rebuild_x509_pem(raw_cert)

    # PEM headers should be added
    assert result.startswith("-----BEGIN CERTIFICATE-----")
    assert result.endswith("-----END CERTIFICATE-----")
    assert raw_cert in result

    # Test with already formatted PEM
    pem_cert = "-----BEGIN CERTIFICATE-----\nMIIEpAIBADANBgkqhkiG9w0BAQEFAASCBJYwggSSAgEAAoIBAQDBj08sp\n-----END CERTIFICATE-----"
    result = client_instance._rebuild_x509_pem(pem_cert)

    # Should be unchanged
    assert result == pem_cert


@pytest.mark.asyncio
async def test_create_grpc_channel_with_tls(client_instance) -> None:
    """Test creating a gRPC channel with TLS."""
    # Setup
    client_instance._transport = MagicMock()
    client_instance._transport_name = "tcp"
    client_instance._address = "127.0.0.1:8000"
    client_instance._server_cert = "MIIEpAIBADANBgkqhkiG9w0BAQEFAASCBJYwggSSAgEAAoIBAQDBj08sp"

    # Mock SSL credentials
    with patch("pyvider.rpcplugin.client.core.grpc.ssl_channel_credentials") as mock_ssl_creds:
        mock_creds = MagicMock()
        mock_ssl_creds.return_value = mock_creds

        # Mock secure channel
        with patch("pyvider.rpcplugin.client.core.grpc.aio.secure_channel") as mock_secure_channel:
            mock_channel = MagicMock()
            mock_secure_channel.return_value = mock_channel

            # Mock channel_ready() to return immediately
            mock_channel.channel_ready = AsyncMock()

            await client_instance._create_grpc_channel()

            # Verify TLS-only credentials were used (root_certificates with None for client certs)
            mock_ssl_creds.assert_called_once_with(
                root_certificates=ANY, private_key=None, certificate_chain=None
            )
            mock_secure_channel.assert_called_once()
            assert client_instance.grpc_channel == mock_channel


@pytest.mark.asyncio
async def test_create_grpc_channel_with_mtls(client_instance, mocker) -> None:
    """Test creating a gRPC channel with mutual TLS."""
    # Setup instance attributes that _setup_client_certificates would normally set
    # based on config, or that are set before _create_grpc_channel is called.
    dummy_client_cert_pem = "DUMMY_CLIENT_CERT_PEM_STRING"
    dummy_client_key_pem = "DUMMY_CLIENT_KEY_PEM_STRING"
    dummy_server_root_pem = "DUMMY_SERVER_ROOT_PEM_STRING"

    client_instance.client_cert = dummy_client_cert_pem
    client_instance.client_key_pem = dummy_client_key_pem
    client_instance._server_cert = dummy_server_root_pem  # Used if PLUGIN_SERVER_ROOT_CERTS is not primary

    # Mock rpcplugin_config using Foundation patterns
    mocker.patch("pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_auto_mtls", True)
    mocker.patch(
        "pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_client_cert", dummy_client_cert_pem
    )
    mocker.patch("pyvider.rpcplugin.client.handshake.rpcplugin_config.plugin_client_key", dummy_client_key_pem)
    mocker.patch(
        "pyvider.rpcplugin.client.process.rpcplugin_config.plugin_server_root_certs", dummy_server_root_pem
    )

    client_instance._transport = MagicMock()
    client_instance._transport_name = "tcp"
    client_instance._address = "127.0.0.1:8000"

    # Mock SSL credentials
    with patch("pyvider.rpcplugin.client.core.grpc.ssl_channel_credentials") as mock_ssl_creds:
        mock_creds = MagicMock()
        mock_ssl_creds.return_value = mock_creds

        # Mock secure channel
        with patch("pyvider.rpcplugin.client.core.grpc.aio.secure_channel") as mock_secure_channel:
            mock_channel = MagicMock()
            mock_secure_channel.return_value = mock_channel

            # Mock channel_ready() to return immediately
            mock_channel.channel_ready = AsyncMock()

            await client_instance._create_grpc_channel()

            # Verify mTLS credentials were used
            expected_root_certs_pem = client_instance._rebuild_x509_pem(dummy_server_root_pem)
            mock_ssl_creds.assert_called_once_with(
                root_certificates=expected_root_certs_pem.encode(),
                private_key=dummy_client_key_pem.encode(),
                certificate_chain=dummy_client_cert_pem.encode(),
            )
            mock_secure_channel.assert_called_once()
            assert client_instance.grpc_channel == mock_channel


@pytest.mark.asyncio
async def test_create_grpc_channel_insecure(client_instance) -> None:
    """Test creating an insecure gRPC channel."""
    # Setup
    client_instance._transport = MagicMock()
    client_instance._transport_name = "tcp"
    client_instance._address = "127.0.0.1:8000"
    client_instance._server_cert = None  # No server cert = insecure channel

    # Mock insecure_channel
    with patch("pyvider.rpcplugin.client.core.grpc.aio.insecure_channel") as mock_insecure_channel:
        mock_channel = MagicMock()
        mock_insecure_channel.return_value = mock_channel

        # Mock channel_ready() to return immediately
        mock_channel.channel_ready = AsyncMock()

        await client_instance._create_grpc_channel()

        # Verify insecure_channel was called
        mock_insecure_channel.assert_called_once()
        assert client_instance.grpc_channel == mock_channel


@pytest.mark.asyncio
async def test_create_grpc_channel_unix_socket(client_instance) -> None:
    """Test creating a gRPC channel for Unix socket transport."""
    # Setup
    client_instance._transport = AsyncMock(spec=UnixSocketTransport)  # Changed to use spec
    client_instance._transport_name = "unix"  # This is correct for the logic path
    client_instance._address = "/tmp/test.sock"  # This is the raw path
    client_instance._server_cert = None  # To ensure insecure_channel is called

    with patch("pyvider.rpcplugin.client.core.grpc.aio.insecure_channel") as mock_insecure_channel:
        mock_channel = MagicMock()
        mock_insecure_channel.return_value = mock_channel
        mock_channel.channel_ready = AsyncMock()  # Mock channel_ready

        await client_instance._create_grpc_channel()

        # Verify unix prefix was used with keepalive options
        mock_insecure_channel.assert_called_once_with("unix:/tmp/test.sock", options=ANY)


@pytest.mark.asyncio
async def test_create_grpc_channel_ready_timeout_unix(client_instance, mocker) -> None:
    """Test channel ready timeout for Unix socket."""
    client_instance._transport = mocker.MagicMock(spec=UnixSocketTransport)
    client_instance._transport_name = "unix"
    client_instance._address = "/tmp/test_timeout.sock"  # Actual path used by transport
    client_instance._server_cert = None  # Insecure channel

    mock_channel = AsyncMock()
    mock_channel.channel_ready = AsyncMock(side_effect=TimeoutError("Channel timed out"))

    mocker.patch(
        "pyvider.rpcplugin.client.core.grpc.aio.insecure_channel",
        return_value=mock_channel,
    )
    mocker.patch("os.path.exists", return_value=True)  # Assume socket file exists for the diagnostic log
    mock_logger_error = mocker.patch("pyvider.rpcplugin.client.core.logger.error")

    with pytest.raises(
        TransportError,
        match=r"\[TransportError\] gRPC channel failed to become ready within .* for endpoint unix:/tmp/test_timeout.sock.*",
    ):
        await client_instance._create_grpc_channel()

    mock_logger_error.assert_any_call(
        "gRPC channel failed to become ready within 10.0s for endpoint unix:/tmp/test_timeout.sock"
    )


@pytest.mark.asyncio
async def test_create_grpc_channel_ready_timeout_tcp(client_instance, mocker) -> None:
    """Test channel ready timeout for TCP socket."""
    client_instance._transport = mocker.MagicMock(spec=TCPSocketTransport)  # Mock TCP transport
    client_instance._transport_name = "tcp"
    client_instance._address = "127.0.0.1:12345"
    client_instance._server_cert = None  # Insecure channel

    mock_channel = AsyncMock()
    mock_channel.channel_ready = AsyncMock(side_effect=TimeoutError("Channel timed out"))

    mocker.patch(
        "pyvider.rpcplugin.client.core.grpc.aio.insecure_channel",
        return_value=mock_channel,
    )
    mock_logger_error = mocker.patch("pyvider.rpcplugin.client.core.logger.error")

    with pytest.raises(
        TransportError,
        match=r"\[TransportError\] gRPC channel failed to become ready within .* for endpoint 127.0.0.1:12345.*",
    ):
        await client_instance._create_grpc_channel()

    mock_logger_error.assert_any_call(
        "gRPC channel failed to become ready within 10.0s for endpoint 127.0.0.1:12345"
    )


@pytest.mark.asyncio
async def test_create_grpc_channel_ready_generic_exception(client_instance, mocker) -> None:
    """Test generic exception during channel_ready."""
    client_instance._transport = mocker.MagicMock(spec=TCPSocketTransport)
    client_instance._transport_name = "tcp"
    client_instance._address = "127.0.0.1:12345"
    client_instance._server_cert = None

    mock_channel = AsyncMock()
    mock_channel.channel_ready = AsyncMock(side_effect=RuntimeError("Other connection issue"))

    mocker.patch(
        "pyvider.rpcplugin.client.core.grpc.aio.insecure_channel",
        return_value=mock_channel,
    )
    mock_logger_error = mocker.patch("pyvider.rpcplugin.client.core.logger.error")

    with pytest.raises(
        TransportError,
        match=r"\[TransportError\] Failed to create gRPC channel: Other connection issue.*",
    ):
        await client_instance._create_grpc_channel()

    mock_logger_error.assert_any_call(
        "Failed to create gRPC channel to 127.0.0.1:12345: Other connection issue", exc_info=True
    )


def test_get_channel_options_unix_with_tls(client_instance) -> None:
    """Test _get_channel_options() for Unix socket with TLS includes SSL target name override."""
    client_instance._transport_name = "unix"
    client_instance._server_cert = "FAKE_CERT_DATA"

    options = client_instance._get_channel_options()

    # Verify standard keepalive options are present
    assert ("grpc.keepalive_time_ms", 30000) in options
    assert ("grpc.keepalive_timeout_ms", 5000) in options
    assert ("grpc.keepalive_permit_without_calls", True) in options

    # CRITICAL: Verify SSL target name override is added for Unix + TLS
    assert ("grpc.ssl_target_name_override", "localhost") in options


def test_get_channel_options_unix_without_tls(client_instance) -> None:
    """Test _get_channel_options() for Unix socket without TLS does NOT include SSL override."""
    client_instance._transport_name = "unix"
    client_instance._server_cert = None  # No TLS

    options = client_instance._get_channel_options()

    # Verify standard options are present
    assert ("grpc.keepalive_time_ms", 30000) in options

    # Verify SSL target name override is NOT added (no TLS)
    ssl_override_present = any(opt[0] == "grpc.ssl_target_name_override" for opt in options)
    assert not ssl_override_present, "SSL target name override should not be present without TLS"


def test_get_channel_options_tcp_with_tls(client_instance) -> None:
    """Test _get_channel_options() for TCP with TLS does NOT include SSL override."""
    client_instance._transport_name = "tcp"
    client_instance._server_cert = "FAKE_CERT_DATA"

    options = client_instance._get_channel_options()

    # Verify standard options are present
    assert ("grpc.keepalive_time_ms", 30000) in options

    # Verify SSL target name override is NOT added (TCP doesn't need it)
    ssl_override_present = any(opt[0] == "grpc.ssl_target_name_override" for opt in options)
    assert not ssl_override_present, "SSL target name override should not be present for TCP"


def test_get_channel_options_tcp_without_tls(client_instance) -> None:
    """Test _get_channel_options() for TCP without TLS does NOT include SSL override."""
    client_instance._transport_name = "tcp"
    client_instance._server_cert = None

    options = client_instance._get_channel_options()

    # Verify standard options are present
    assert ("grpc.keepalive_time_ms", 30000) in options

    # Verify SSL target name override is NOT added
    ssl_override_present = any(opt[0] == "grpc.ssl_target_name_override" for opt in options)
    assert not ssl_override_present, "SSL target name override should not be present for TCP without TLS"


# 🐍🔌🧪🪄

# 📞🔌🔚
