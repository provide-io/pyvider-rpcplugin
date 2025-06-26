# pyvider/rpcplugin/tests/crypto/test_certificate_create.py

import pytest
from datetime import datetime, timedelta, timezone  # Or use UTC if available
from unittest import mock
from unittest.mock import MagicMock


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
        with pytest.raises(CertificateError, match="Failed to initialize certificate"):
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
    config: CertificateConfig = {  # Explicitly type hint for clarity
        "common_name": "test",
        "organization": "test",
        "alt_names": ["test.local"],  # Added
        "key_type": 123,  # type: ignore[typeddict-item] # Invalid type, not a KeyType Enum
        "not_valid_before": now - timedelta(days=1),  # Added
        "not_valid_after": now + timedelta(days=1),  # Added
        # No need for key_size or curve for this specific test's purpose
    }
    # The error message from CertificateBase.create will be "Failed to generate certificate base: Internal Error: Unsupported key type: 123"
    # The test expects "Unsupported key type"
    with pytest.raises(CertificateError, match="Unsupported key type: 123"):
        CertificateBase.create(config)


def test_certificate_base_create_unsupported_key_type_str(mocker):
    """Test CertificateBase.create with an unsupported string for key_type in config."""
    now = datetime.now(timezone.utc)
    # Prepare a config with an unsupported key_type string
    config: CertificateConfig = {
        "common_name": "test_unsupported",
        "organization": "Test Org",
        "alt_names": ["test.unsupported.local"],
        "key_type": "unsupported_key_type",  # This is the invalid part
        "not_valid_before": now - timedelta(days=1),
        "not_valid_after": now + timedelta(days=30),
    }
    mock_logger_error = mocker.patch(
        "pyvider.rpcplugin.crypto.certificate.logger.error", new=MagicMock()
    )

    with pytest.raises(CertificateError) as excinfo:
        CertificateBase.create(config)  # type: ignore # Deliberately passing invalid type for key_type

    assert "Internal Error: Unsupported key type: unsupported_key_type" in str(
        excinfo.value
    )
    mock_logger_error.assert_called_once()
    args, kwargs = mock_logger_error.call_args
    assert "CertificateBase.create: Failed" in args[0]
    assert "Unsupported key type: unsupported_key_type" in kwargs.get("extra", {}).get(
        "error", ""
    )


@pytest.mark.asyncio  # Keep async if other tests are, though this one is sync
async def test_certificate_init_invalid_ecdsa_curve(mocker):
    """Test Certificate instantiation with an invalid ecdsa_curve string."""
    mock_logger_error = mocker.patch(
        "pyvider.rpcplugin.crypto.certificate.logger.error", new=MagicMock()
    )

    with pytest.raises(CertificateError) as excinfo:
        Certificate(
            generate_keypair=True, key_type="ecdsa", ecdsa_curve="invalid_curve_name"
        )

    # The ValueError from bad curve is wrapped in CertificateError
    assert "Unsupported ECDSA curve: invalid_curve_name" in str(excinfo.value.__cause__)

    mock_logger_error.assert_called_once()
    args, kwargs = mock_logger_error.call_args
    assert "Certificate.__attrs_post_init__: Failed" in args[0]
    assert "Unsupported ECDSA curve: invalid_curve_name" in kwargs.get("extra", {}).get(
        "error", ""
    )


### 🐍🏗🧪️
