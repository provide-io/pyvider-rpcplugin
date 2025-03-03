# pyvider/rpcplugin/tests/crypto/test_certificate_loading.py

import pytest
from unittest import mock



from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.exception import CertificateError

from tests.fixtures import *

@pytest.mark.asyncio
async def test_load_invalid_pem():
    with pytest.raises(CertificateError):
        Certificate(cert="INVALID DATA", key="INVALID DATA")

@pytest.mark.asyncio
async def test_load_pem_certificate(client_cert):
    """Ensure a valid PEM certificate loads correctly."""
    assert client_cert.subject, "Certificate subject should not be empty"
    assert client_cert.issuer, "Certificate issuer should not be empty"

@pytest.mark.asyncio
async def test_load_pem_private_key(client_cert):
    """Ensure a valid PEM private key loads correctly."""
    assert client_cert.public_key, "Certificate should have a valid public key"

@pytest.mark.asyncio
async def test_load_certificate_from_file(temporary_cert_file):
    """Ensure a certificate loads correctly from a file:// path."""
    cert = Certificate(cert=temporary_cert_file)
    assert cert.subject, "Certificate subject should not be empty"

@pytest.mark.asyncio
async def test_load_key_value_error(valid_cert_pem):
    """Test ValueError in private key loading."""
    with mock.patch(
        "cryptography.hazmat.primitives.serialization.load_pem_private_key",
        side_effect=ValueError("Invalid key format"),
    ):
        with pytest.raises(CertificateError, match="Could not deserialize key data"):
            Certificate(
                cert=valid_cert_pem,
                key="-----BEGIN PRIVATE KEY-----\nINVALID\n-----END PRIVATE KEY-----",
            )

@pytest.mark.asyncio
async def test_load_key_type_error():
    """Test TypeError in private key loading."""
    with mock.patch(
        "cryptography.hazmat.primitives.serialization.load_pem_private_key",
        side_effect=TypeError("Password required"),
    ):
        with pytest.raises(CertificateError, match="Failed to load data"):
            Certificate(cert=valid_cert_pem, key="SOME_KEY")

@pytest.mark.asyncio
async def test_load_cert_with_windows_line_endings(client_cert):
    """Ensure certificate loading works with Windows-style line endings."""
    # Use the actual certificate content from the fixture
    cert_pem = client_cert.cert.replace("\n", "\r\n")
    cert = Certificate(cert=cert_pem)
    assert cert.subject, "Windows line endings should not break parsing"

@pytest.mark.asyncio
async def test_load_private_key_from_file(temporary_key_file, client_cert):
    """Ensure a private key loads correctly from a file:// path."""
    # Create cert from the fixture's actual certificate
    cert = Certificate(cert=client_cert.cert, key=temporary_key_file)
    assert cert.public_key, "Certificate should have a valid private key"

@pytest.mark.asyncio
async def test_invalid_certificate_raises_error(invalid_cert_pem):
    """Ensure an invalid PEM certificate raises CertificateError."""
    with pytest.raises(CertificateError):
        Certificate(cert=invalid_cert_pem)

@pytest.mark.asyncio
async def test_load_cert_with_malformed_pem(malformed_cert_pem):
    """Test loading certificate with malformed PEM format."""
    with pytest.raises(CertificateError, match="Unable to load PEM"):
        Certificate(cert=malformed_cert_pem)

@pytest.mark.asyncio
async def test_malformed_certificate_raises_error(malformed_cert_pem):
    """Ensure a malformed PEM certificate raises CertificateError."""
    with pytest.raises(CertificateError):
        Certificate(cert=malformed_cert_pem)

@pytest.mark.asyncio
async def test_empty_certificate_raises_error(empty_cert):
    """Ensure an empty certificate raises CertificateError."""
    with pytest.raises(CertificateError):
        Certificate(cert=empty_cert)

@pytest.mark.asyncio
async def test_missing_certificate_file_raises_error():
    """Ensure a missing certificate file raises CertificateError."""
    with pytest.raises(CertificateError):
        Certificate(cert="file:///nonexistent/path/cert.pem")

@pytest.mark.asyncio
async def test_load_cert_with_utf8_bom():
    """Ensure certificate loading works with UTF-8 BOM characters."""
    cert_pem = "\ufeff" + client_cert
    cert = Certificate(cert=client_pem)
    assert cert.subject, "UTF-8 BOM should not break certificate parsing"

@pytest.mark.asyncio
async def test_malformed_certificate_loading():
    """Ensure malformed certificates raise CertificateError."""
    with pytest.raises(CertificateError, match="Unable to load PEM"):
        Certificate(
            cert="-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"
        )

@pytest.mark.asyncio
async def test_load_cert_with_extra_whitespace(client_cert):
    """Ensure certificate loading is robust against extra whitespace."""
    # Use cert.cert instead of cert directly
    cert_pem = f"\n\n{client_cert.cert}\n\n"
    cert = Certificate(cert=cert_pem)
    assert cert.subject, "Whitespace should not affect certificate loading"

### 🐍🏗🧪️
