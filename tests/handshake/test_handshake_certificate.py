# tests/handshake/test_handshake_certificate.py

import pytest

from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.handshake import build_handshake_response
from pyvider.rpcplugin.exception import HandshakeError  # Added import


def test_rebuild_x509_pem():
    """Test rebuilding X509 PEM certificates from base64 data."""

    # Define a function that matches the X509 rebuilding logic in the handshake module
    def rebuild_x509_pem(maybe_cert: str) -> str:
        """
        Rebuilds a single base64 string of the server's certificate into a PEM block if missing headers.
        """
        if maybe_cert.startswith("-----BEGIN CERTIFICATE-----"):
            return maybe_cert
        # Reconstruct lines
        cert_lines = [maybe_cert[i : i + 64] for i in range(0, len(maybe_cert), 64)]
        full_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            + "\n".join(cert_lines)
            + "\n-----END CERTIFICATE-----\n"
        )
        return full_pem

    # Test with already formatted PEM
    existing_pem = "-----BEGIN CERTIFICATE-----\nABCDEF\n-----END CERTIFICATE-----\n"
    result = rebuild_x509_pem(existing_pem)
    assert result == existing_pem

    # Test with base64 data only
    base64_only = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    result = rebuild_x509_pem(base64_only)
    assert "-----BEGIN CERTIFICATE-----" in result
    assert "-----END CERTIFICATE-----" in result
    assert base64_only in result

    # Test with long base64 data (should split into lines)
    long_base64 = "A" * 100
    result = rebuild_x509_pem(long_base64)
    assert "-----BEGIN CERTIFICATE-----" in result
    assert "-----END CERTIFICATE-----" in result

    # Line length should be reasonable (not one giant line)
    lines = result.strip().split("\n")
    for line in lines[1:-1]:  # Skip header and footer
        assert len(line) <= 64, "Line length exceeds 64 characters"


@pytest.mark.asyncio
async def test_handshake_certificate_stripping():
    """Test that certificate data is properly stripped of PEM headers in handshake."""
    # Create a test certificate
    cert = Certificate(generate_keypair=True)

    # Create a mock transport
    class MockTransport:
        async def listen(self):
            return "mock_endpoint"

    transport = MockTransport()

    # Build handshake with certificate
    response = await build_handshake_response(
        plugin_version=7,
        transport_name="unix",
        transport=transport,
        server_cert=cert,
    )

    # Parse the response
    parts = response.split("|")
    assert len(parts) == 6
    cert_part = parts[5]

    # The certificate part should not contain PEM headers
    assert "-----BEGIN CERTIFICATE-----" not in cert_part
    assert "-----END CERTIFICATE-----" not in cert_part

    # Get the PEM body directly from the certificate
    cert_lines = cert.cert.strip().split("\n")
    pem_body = "".join(cert_lines[1:-1])  # Strip header and footer

    # The cert part should be this PEM body (ignoring potential padding differences)
    assert cert_part.rstrip("=") == pem_body.rstrip("=")


@pytest.mark.asyncio
async def test_handshake_with_invalid_certificate():
    """Test error handling when certificate is in invalid format."""

    # Create an invalid certificate object
    class InvalidCert:
        def __init__(self):
            self.cert = "Invalid"

    # Create a mock transport
    class MockTransport:
        async def listen(self):
            return "mock_endpoint"

    transport = MockTransport()

    expected_msg_regex = (
        r"\[HandshakeError\] Failed to build handshake response: "
        r"\[HandshakeError\] Invalid server certificate format provided for handshake response.*"
    )
    with pytest.raises(HandshakeError, match=expected_msg_regex):
        await build_handshake_response(
            plugin_version=7,
            transport_name="unix",
            transport=transport,
            server_cert=InvalidCert(),
        )
