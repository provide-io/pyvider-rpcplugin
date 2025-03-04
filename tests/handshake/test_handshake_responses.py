# pyvider/rpcplugin/tests/handshake/test_handshake_responses.py

import pytest

from unittest.mock import AsyncMock

from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.handshake import (
    build_handshake_response,
    parse_handshake_response,
)

from tests.fixtures.transport import mock_server_transport


class StubCertificate:
    def __init__(self, pem_str):
        self.cert = pem_str  # e.g. "-----BEGIN CERTIFICATE-----\nbase64encodeddata\n-----END CERTIFICATE-----"


@pytest.mark.asyncio
async def test_build_handshake_response_with_tls():
    # Use StubCertificate instead of raw string
    stub_cert = StubCertificate(
        "-----BEGIN CERTIFICATE-----\nbase64encodeddata\n-----END CERTIFICATE-----"
    )

    response = await build_handshake_response(
        plugin_version=6,
        transport_name="tcp",
        transport=mock_server_transport,
        server_cert=stub_cert,  # we pass the stub object
        port=12345,
    )

    expected_cert = "base64encodeddata"
    expected_response = f"1|6|tcp|127.0.0.1:12345|grpc|{expected_cert}"
    assert response == expected_response


@pytest.mark.asyncio
async def test_build_handshake_response_without_tls(mock_server_transport):
    """Test building a valid handshake response without TLS."""
    transport = mock_server_transport
    transport.listen = UnixSocketTransport(return_value="/tmp/pyvider.sock")

    response = await build_handshake_response(
        plugin_version=6, transport_name="unix", transport=transport, server_cert=None
    )

    expected_response = "1|6|unix|/tmp/pyvider.sock|grpc|"
    assert response == expected_response


@pytest.mark.asyncio
async def test_build_handshake_response_invalid_transport(monkeypatch):
    """Test building handshake response with an invalid transport."""
    # transport = AsyncMock()
    # transport.listen = AsyncMock(return_value=None)

    with pytest.raises(ValueError, match="TCP transport requires a valid port."):
        await build_handshake_response(
            plugin_version=6,
            transport_name="tcp",
            transport=None,
            server_cert=None,
        )


@pytest.mark.asyncio
async def test_parse_handshake_response_with_tls(monkeypatch):
    """Test parsing a valid handshake response with TLS."""

    response = f"{1}|6|tcp|127.0.0.1:12345|grpc|base64_encoded_cert"
    core_version, plugin_version, network, address, protocol, cert = (
        parse_handshake_response(response)
    )

    assert core_version == 1
    assert plugin_version == 6
    assert network == "tcp"
    assert address == "127.0.0.1:12345"
    assert protocol == "grpc"
    assert cert.startswith("base64_encoded_cert")


def test_parse_handshake_response_without_tls():
    """Test parsing a valid handshake response without TLS."""
    response = f"{1}|6|unix|/tmp/pyvider.sock|grpc|"
    core_version, plugin_version, network, address, protocol, cert = (
        parse_handshake_response(response)
    )

    assert core_version == 1
    assert plugin_version == 6
    assert network == "unix"
    assert address == "/tmp/pyvider.sock"
    assert protocol == "grpc"
    assert cert is None


def test_parse_handshake_response_invalid_format():
    """Test parsing an invalid handshake response format."""
    response = "invalid|response"
    with pytest.raises(HandshakeError, match="Failed to parse handshake response."):
        parse_handshake_response(response)


def test_parse_handshake_response_missing_fields():
    """Test parsing a handshake response with missing fields."""
    response = f"{1}|6|tcp"
    with pytest.raises(HandshakeError, match="Failed to parse handshake response."):
        parse_handshake_response(response)


def test_parse_handshake_response_empty():
    """Test parsing an empty handshake response."""
    response = ""
    with pytest.raises(HandshakeError, match="Failed to parse handshake response."):
        parse_handshake_response(response)


def test_parse_handshake_response_excessive_fields():
    """Test parsing a handshake response with too many fields."""
    response = f"{1}|6|tcp|127.0.0.1:12345|grpc|cert|extra_field"
    with pytest.raises(HandshakeError, match="Failed to parse handshake response."):
        parse_handshake_response(response)


def test_parse_handshake_response_invalid_protocol_version():
    """Test parsing a handshake response with an invalid protocol version."""
    response = "1|99|tcp|127.0.0.1:12345|"
    with pytest.raises(HandshakeError, match="Failed to parse handshake response."):
        parse_handshake_response(response)


@pytest.mark.asyncio
async def test_build_handshake_response_missing_port():
    """Test building handshake response for TCP transport without a port."""
    transport = AsyncMock()
    with pytest.raises(ValueError, match="TCP transport requires a valid port."):
        await build_handshake_response(
            plugin_version=6,
            transport_name="tcp",
            transport=transport,
            server_cert=None,
        )
