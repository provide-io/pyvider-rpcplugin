#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
"""
Tests for server/network.py to improve code coverage.

Focuses on testing uncovered paths in ServerNetworkMixin.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import SecurityError, TransportError
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.transport import TCPSocketTransport
from pyvider.rpcplugin.types import HandlerT, ServerT


class DummyHandler:
    """Dummy handler for testing."""

    pass


class DummyProtocol(RPCPluginProtocol[ServerT, HandlerT]):
    """Dummy protocol for testing."""

    service_name = "test.Service"

    async def get_grpc_descriptors(self) -> tuple[None, str]:
        return None, self.service_name

    async def add_to_server(self, server: ServerT, handler: HandlerT) -> None:
        pass


@pytest.mark.asyncio
async def test_read_client_cert_config(mocker):
    """Test _read_client_cert reads from config."""
    protocol = DummyProtocol()
    handler = DummyHandler()

    # Set client cert in config
    test_cert = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----"
    config = {"PLUGIN_CLIENT_CERT": test_cert}

    server = RPCPluginServer(protocol=protocol, handler=handler, config=config)

    result = server._read_client_cert()
    assert result == test_cert


@pytest.mark.asyncio
async def test_load_server_certificate_from_pem_failure(mocker):
    """Test certificate loading failure from PEM."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    # Mock Certificate.from_pem to raise exception
    with patch("pyvider.rpcplugin.server.network.Certificate") as mock_cert:
        mock_cert.from_pem.side_effect = RuntimeError("Invalid PEM format")

        with pytest.raises(SecurityError, match="Failed to load server certificate/key"):
            server._load_server_certificate(
                server_cert_conf="cert_pem", server_key_conf="key_pem", auto_mtls=False
            )


@pytest.mark.asyncio
async def test_load_server_certificate_auto_mtls_failure(mocker):
    """Test auto-generated certificate creation failure."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    # Mock Certificate.create_self_signed_server_cert to raise exception
    with patch("pyvider.rpcplugin.server.network.Certificate") as mock_cert:
        mock_cert.create_self_signed_server_cert.side_effect = RuntimeError("Failed to generate")

        with pytest.raises(SecurityError, match="Failed to auto-generate server certificate"):
            server._load_server_certificate(server_cert_conf=None, server_key_conf=None, auto_mtls=True)


@pytest.mark.asyncio
async def test_load_client_root_certificates_file_scheme(mocker):
    """Test loading client root certificates from file:// URL."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    # Create a temporary file with cert content
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as tmpfile:
        tmpfile.write("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----")
        cert_file_path = tmpfile.name

    try:
        file_url = f"file://{cert_file_path}"
        root_certs, require_auth = server._load_client_root_certificates(
            auto_mtls=True, client_root_certs_conf=file_url
        )

        assert root_certs is not None
        assert require_auth is True
        assert b"-----BEGIN CERTIFICATE-----" in root_certs
    finally:
        Path(cert_file_path).unlink()


@pytest.mark.asyncio
async def test_load_client_root_certificates_file_read_failure(mocker):
    """Test failure when loading client root certificates from file."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    # Use a non-existent file
    file_url = "file:///nonexistent/path/cert.pem"

    with pytest.raises(SecurityError, match="Failed to load client root CAs"):
        server._load_client_root_certificates(auto_mtls=True, client_root_certs_conf=file_url)


@pytest.mark.asyncio
async def test_initialize_server_with_services_no_server(mocker):
    """Test _initialize_server_with_services when server is None after init."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    # Mock GRPCServer to return None
    with patch("pyvider.rpcplugin.server.network.GRPCServer", return_value=None):
        with pytest.raises(TransportError, match="Server object not initialized"):
            await server._initialize_server_with_services()


@pytest.mark.asyncio
async def test_prepare_transport_binding_no_endpoint(mocker):
    """Test _prepare_transport_binding with no endpoint."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    transport = TCPSocketTransport(host="127.0.0.1", port=0)
    server = RPCPluginServer(protocol=protocol, handler=handler, transport=transport)

    # Mock transport.listen to not set endpoint
    async def mock_listen():
        transport.endpoint = None

    mocker.patch.object(transport, "listen", side_effect=mock_listen)

    with pytest.raises(TransportError, match="Transport endpoint not available"):
        await server._prepare_transport_binding(transport)


@pytest.mark.asyncio
async def test_determine_requested_tcp_port_invalid_config(mocker):
    """Test _determine_requested_tcp_port with invalid port configuration."""
    protocol = DummyProtocol()
    handler = DummyHandler()

    # Set invalid port in config
    config = {"PLUGIN_SERVER_PORT": "invalid_port"}
    server = RPCPluginServer(protocol=protocol, handler=handler, config=config)

    # Should return 0 (ephemeral) for invalid port
    port = server._determine_requested_tcp_port()
    assert port == 0


@pytest.mark.asyncio
async def test_apply_tcp_port_configuration_requested_port_mismatch(mocker):
    """Test _apply_tcp_port_configuration with requested port mismatch."""
    protocol = DummyProtocol()
    handler = DummyHandler()

    # Create transport with specific port request
    transport = TCPSocketTransport(host="127.0.0.1", port=8080)
    config = {"PLUGIN_SERVER_PORT": 8080}
    server = RPCPluginServer(protocol=protocol, handler=handler, transport=transport, config=config)

    # Mock endpoint
    transport.endpoint = "127.0.0.1:8080"

    # Try to apply port 0 when we requested 8080
    with pytest.raises(TransportError, match="Failed to bind to specifically requested TCP port"):
        server._apply_tcp_port_configuration(transport, 0)


@pytest.mark.asyncio
async def test_build_and_send_handshake_response_no_transport(mocker):
    """Test _build_and_send_handshake_response with no transport."""
    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    # Ensure transport is None
    server._transport = None

    with pytest.raises(TransportError, match="Transport is None before building handshake response"):
        await server._build_and_send_handshake_response()

# 📞🔌🔚
