# pyvider/rpcplugin/tests/crypto/test_certificate_create.py

import pytest
from datetime import datetime, timedelta, timezone # Or use UTC if available
from unittest import mock


from pyvider.rpcplugin.exception import CertificateError
from pyvider.rpcplugin.crypto.certificate import (
    Certificate,
    CertificateBase,
    CertificateConfig,
)

@pytest.mark.asyncio
async def test_create_x509_cert_subject_error() -> None:
    """Test error in subject/issuer name creation."""
    with mock.patch("cryptography.x509.Name", side_effect=Exception("Name error")):
        with pytest.raises(CertificateError, match="Failed to initialize certificate"):
            Certificate(generate_keypair=True)

@pytest.mark.asyncio
async def test_create_x509_cert_serial_error() -> None:
    """Test error in serial number generation."""
    with mock.patch("os.urandom", side_effect=Exception("urandom failed")):
        with pytest.raises(CertificateError, match="Failed to initialize certificate"):
            Certificate(generate_keypair=True)

@pytest.mark.asyncio
async def test_create_x509_cert_validity_error() -> None:
    """Test error in validity period calculation."""
    with mock.patch(
        "pyvider.rpcplugin.crypto.certificate.datetime",
        side_effect=Exception("Time error"),
    ):
        with pytest.raises(CertificateError, match="Failed to initialize certificate"):
            Certificate(generate_keypair=True)

@pytest.mark.asyncio
async def test_certificate_extension_failure() -> None:
    """Ensure extension addition failures raise CertificateError."""
    cert = Certificate(generate_keypair=True)

    with mock.patch(
        "cryptography.x509.CertificateBuilder.add_extension",
        side_effect=Exception("Mock failure"),
    ):
        with pytest.raises(CertificateError, match="Failed to create"):
            cert._create_x509_certificate()

@pytest.mark.asyncio
async def test_create_x509_cert_builder_error() -> None:
    """Test error in certificate builder."""
    with mock.patch(
        "cryptography.x509.CertificateBuilder.subject_name",
        side_effect=Exception("Builder error"),
    ):
        with pytest.raises(
            CertificateError, match="Failed to initialize certificate"
        ):
            Certificate(generate_keypair=True)

@pytest.mark.asyncio
async def test_create_x509_cert_extension_error() -> None:
    """Test error in adding certificate extensions."""
    cert = Certificate(generate_keypair=True)

    with mock.patch(
        "cryptography.x509.CertificateBuilder.add_extension",
        side_effect=Exception("Mock failure"),
    ):
        with pytest.raises(CertificateError, match="Failed to create"):
            cert._create_x509_certificate()

@pytest.mark.asyncio
async def test_create_invalid_key_type() -> None:
    """Ensure unsupported key types raise CertificateError when passed to CertificateBase.create."""
    now = datetime.now(timezone.utc)
    config: CertificateConfig = { # Explicitly type hint for clarity
        "common_name": "test",
        "organization": "test",
        "alt_names": ["test.local"], # Added
        "key_type": 123,  # Invalid type, not a KeyType Enum
        "not_valid_before": now - timedelta(days=1), # Added
        "not_valid_after": now + timedelta(days=1),  # Added
        # No need for key_size or curve for this specific test's purpose
    }
    # The error message from CertificateBase.create will be "Failed to generate certificate base: Internal Error: Unsupported key type: 123"
    # The test expects "Unsupported key type"
    with pytest.raises(CertificateError, match="Unsupported key type: 123"):
        CertificateBase.create(config)


### 🐍🏗🧪️
