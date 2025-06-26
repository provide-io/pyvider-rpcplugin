# pyvider/rpcplugin/tests/test_certificate_credentials.py

import pytest
from dataclasses import dataclass

# Fixtures will be available via tests.fixtures through conftest.py
# from tests.fixtures.crypto import client_cert, server_cert


@dataclass
class MockChannelCredentials:
    """Mock implementation of SSL channel credentials."""

    root_certificates: bytes | None
    private_key: bytes | None
    certificate_chain: bytes | None


@dataclass
class MockServerCredentials:
    """Mock implementation of SSL server credentials."""

    private_key_certificate_chain_pairs: list[tuple[bytes, bytes]]
    root_certificates: bytes | None
    require_client_auth: bool


# Convert async functions to regular functions since they don't need to be async
def mock_ssl_channel_credentials(
    root_certificates: bytes | None = None,
    private_key: bytes | None = None,
    certificate_chain: bytes | None = None,
) -> MockChannelCredentials:
    """Mock implementation of grpc.ssl_channel_credentials."""
    return MockChannelCredentials(
        root_certificates=root_certificates,
        private_key=private_key,
        certificate_chain=certificate_chain,
    )


def mock_ssl_server_credentials(
    private_key_certificate_chain_pairs: list[tuple[bytes, bytes]],
    root_certificates: bytes | None = None,
    require_client_auth: bool = False,
) -> MockServerCredentials:
    """Mock implementation of grpc.ssl_server_credentials."""
    if require_client_auth and root_certificates is None:
        raise ValueError(
            "root_certificates is required when require_client_auth is True"
        )

    if not private_key_certificate_chain_pairs:
        raise ValueError("At least one private_key_certificate_chain_pair is required")

    # Validate all pairs have correct format
    for private_key, certificate_chain in private_key_certificate_chain_pairs:
        if not isinstance(private_key, bytes) or not isinstance(
            certificate_chain, bytes
        ):
            raise TypeError("private_key and certificate_chain must be bytes")

    return MockServerCredentials(
        private_key_certificate_chain_pairs=private_key_certificate_chain_pairs,
        root_certificates=root_certificates,
        require_client_auth=require_client_auth,
    )


# Tests using conftest fixtures
def test_mock_channel_credentials_with_client_cert(client_cert) -> None:
    """Test creating channel credentials using client certificate fixture."""
    creds = mock_ssl_channel_credentials(
        root_certificates=client_cert.cert.encode(),
        private_key=client_cert.key.encode(),
        certificate_chain=client_cert.cert.encode(),
    )
    assert isinstance(creds.root_certificates, bytes)
    assert isinstance(creds.private_key, bytes)
    assert isinstance(creds.certificate_chain, bytes)
    assert creds.root_certificates == client_cert.cert.encode()
    assert creds.private_key == client_cert.key.encode()
    assert creds.certificate_chain == client_cert.cert.encode()


def test_mock_server_credentials_with_server_cert(
    server_cert, client_cert
) -> None:
    """Test creating server credentials using server certificate fixture."""
    pairs = [(server_cert.key.encode(), server_cert.cert.encode())]
    creds = mock_ssl_server_credentials(
        private_key_certificate_chain_pairs=pairs,
        root_certificates=client_cert.cert.encode(),  # For client authentication
        require_client_auth=True,
    )
    assert isinstance(creds.private_key_certificate_chain_pairs[0][0], bytes)
    assert isinstance(creds.private_key_certificate_chain_pairs[0][1], bytes)
    assert isinstance(creds.root_certificates, bytes)
    assert creds.private_key_certificate_chain_pairs == pairs
    assert creds.root_certificates == client_cert.cert.encode()
    assert creds.require_client_auth is True


def test_mock_server_credentials_multiple_certs(server_cert, client_cert) -> None:
    """Test creating server credentials with multiple certificate pairs."""
    # Using both server and client certs as pairs for testing
    pairs = [
        (server_cert.key.encode(), server_cert.cert.encode()),
        (client_cert.key.encode(), client_cert.cert.encode()),
    ]
    creds = mock_ssl_server_credentials(
        private_key_certificate_chain_pairs=pairs,
        root_certificates=client_cert.cert.encode(),
        require_client_auth=True,
    )
    assert len(creds.private_key_certificate_chain_pairs) == 2
    assert creds.private_key_certificate_chain_pairs == pairs


def test_mock_server_credentials_validation_with_certs(
    server_cert, client_cert
) -> None:
    """Test validation rules with real certificates."""
    # Test requiring client auth without root certs
    with pytest.raises(ValueError):
        mock_ssl_server_credentials(
            private_key_certificate_chain_pairs=[
                (server_cert.key.encode(), server_cert.cert.encode())
            ],
            require_client_auth=True,  # Should fail without root_certificates
        )

    # Test with invalid pair types
    with pytest.raises(TypeError):
        mock_ssl_server_credentials(
            private_key_certificate_chain_pairs=[
                (server_cert.key, server_cert.cert)  # Not encoded to bytes
            ]
        )


# FIX: Removed @pytest.mark.asyncio and changed to `def` as the test is synchronous.
def test_mock_channel_credentials_none_values(client_cert) -> None:
    """Test channel credentials with optional parameters as None."""
    creds = mock_ssl_channel_credentials(
        root_certificates=client_cert.cert.encode()
        # Omitting private_key and certificate_chain
    )
    assert isinstance(creds.root_certificates, bytes)
    assert creds.private_key is None
    assert creds.certificate_chain is None


### 🐍🏗🧪️
