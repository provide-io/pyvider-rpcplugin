# tests/fixtures/crypto.py

import pytest


from pyvider.telemetry import logger
from pyvider.rpcplugin.crypto.certificate import Certificate


@pytest.fixture(scope="module")
def client_cert():
    """Loads the server certificate from the environment variable."""
    from pyvider.rpcplugin.config import rpcplugin_config

    cert_env_val = rpcplugin_config.get("PLUGIN_CLIENT_CERT")
    key_env_val = rpcplugin_config.get("PLUGIN_CLIENT_KEY")

    # Determine if the fetched env values are actual PEMs or placeholders/errors
    cert_is_pem_like = cert_env_val and cert_env_val.strip().startswith(
        "-----BEGIN CERTIFICATE-----"
    )
    key_is_pem_like = key_env_val and key_env_val.strip().startswith(
        "-----BEGIN "
    )  # General check for any key type

    cert_to_use = cert_env_val if cert_is_pem_like else None
    key_to_use = key_env_val if key_is_pem_like else None

    if not cert_to_use:
        cert_to_use = """-----BEGIN CERTIFICATE-----
MIIB+jCCAYGgAwIBAgIJAPsxOr78BIU0MAoGCCqGSM49BAMEMCgxEjAQBgNVBAoM
CUhhc2hpQ29ycDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MDIwNTIzMTkzN1oX
DTI2MDIwNTIzMTkzN1owKDESMBAGA1UECgwJSGFzaGlDb3JwMRIwEAYDVQQDDAls
b2NhbGhvc3QwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARCi3SNYYDpSeScRM52tFYr
URzsPOE/ad8BzvpvL+mfy1c5oHQhh6KPnxpoo1WyDJGYplwPTGS68DvvWmolrPAt
C7I7r7spgyJS1358E5fA2NWk9/YPaiUzK2gsyrL9dKajdzB1MA8GA1UdEwEB/wQF
MAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxob3N0MB0GA1UdJQQWMBQGCCsGAQUFBwMC
BggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCA6gwHQYDVR0OBBYEFOwuttXPh5kTPSpX
a2ex0+VKjlpaMAoGCCqGSM49BAMEA2cAMGQCMGbN17Zt1GxZ41cXTaQOKuv/BIQd
nkaRz51XrITKaULNie4bgW6gT94cTUFQ9SNwEAIwOpmKeZqYG9WHcqol4QEUmMVM
MY3jxMiLpb9Mt/ysstXmsrQY7UoLu+c6zfKwyTEJ
-----END CERTIFICATE-----
"""

    if not key_to_use:
        key_to_use = """-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAkxo19KczdciRiJjOWEKGY5mH9s1D0aUS5XBdvktcaonIOdqNrkCt1
BC5YjEAVLNWgBwYFK4EEACKhZANiAARCi3SNYYDpSeScRM52tFYrURzsPOE/ad8B
zvpvL+mfy1c5oHQhh6KPnxpoo1WyDJGYplwPTGS68DvvWmolrPAtC7I7r7spgyJS
1358E5fA2NWk9/YPaiUzK2gsyrL9dKY=
-----END EC PRIVATE KEY-----
"""

    logger.info(f"Loaded CLIENT_CERT: {cert_to_use[:30]}...")
    logger.info(f"Loaded CLIENT_KEY: {key_to_use[:30]}...")

    return Certificate(cert_pem_or_uri=cert_to_use, key_pem_or_uri=key_to_use)


@pytest.fixture(scope="module")
def server_cert():
    """Loads the server certificate from the environment variable."""
    from pyvider.rpcplugin.config import rpcplugin_config

    cert_env_val = rpcplugin_config.get("PLUGIN_SERVER_CERT")
    key_env_val = rpcplugin_config.get("PLUGIN_SERVER_KEY")

    # Determine if the fetched env values are actual PEMs or placeholders/errors
    cert_is_pem_like = cert_env_val and cert_env_val.strip().startswith(
        "-----BEGIN CERTIFICATE-----"
    )
    key_is_pem_like = key_env_val and key_env_val.strip().startswith("-----BEGIN ")

    cert_to_use = cert_env_val if cert_is_pem_like else None
    key_to_use = key_env_val if key_is_pem_like else None

    if not cert_to_use:
        cert_to_use = """-----BEGIN CERTIFICATE-----
MIIB+jCCAYGgAwIBAgIJAKrIoEQw7N9LMAoGCCqGSM49BAMEMCgxEjAQBgNVBAoM
CUhhc2hpQ29ycDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MDIwNTIzMTkzN1oX
DTI2MDIwNTIzMTkzN1owKDESMBAGA1UECgwJSGFzaGlDb3JwMRIwEAYDVQQDDAls
b2NhbGhvc3QwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARMxEVmGX3a4IWPOAJ2MX2s
2Wj3KZ0Io5EwUPMkxknGheO2e55qeHp/tkEFzYt9AH8du1xJLKKFbsGV5q9vipGN
x5XMbj2RMdH5VXHTAdc/bLFFy9kybQqo300Rv6ViW2KjdzB1MA8GA1UdEwEB/wQF
MAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxob3N0MB0GA1UdJQQWMBQGCCsGAQUFBwMC
BggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCA6gwHQYDVR0OBBYEFJy7Iz7whfiALYDB
TsM+IHXb1E8+MAoGCCqGSM49BAMEA2cAMGQCMFwxBS3lZSUprvrNGfJL83oGVY97
emQpHy/SEWpHBK8awn1XeTf+ZAwLaxc3K+AKqwIwPwIbIlmstd69zAYMFNHtzceN
XOzBx35sWRw92gr/hbE4hYeDBqEUwstSFNZ6MZu0
-----END CERTIFICATE-----
"""

    if not key_to_use:  # Corrected variable name from key to key_to_use
        key_to_use = """-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDZ1MORWFVI0HtgKv+zZys/5e1HVmfcs4bwdp3VEsuwS6an3gTwGnSP
Ce+bI6f/TvGgBwYFK4EEACKhZANiAARMxEVmGX3a4IWPOAJ2MX2s2Wj3KZ0Io5Ew
UPMkxknGheO2e55qeHp/tkEFzYt9AH8du1xJLKKFbsGV5q9vipGNx5XMbj2RMdH5
VXHTAdc/bLFFy9kybQqo300Rv6ViW2I=
-----END EC PRIVATE KEY-----
"""

    logger.info(
        f"Loaded SERVER_CERT: {cert_to_use[:30]}..."
    )  # Corrected log message and used correct variable
    logger.info(f"Loaded SERVER_KEY: {key_to_use[:30]}...")  # Used correct variable

    return Certificate(cert_pem_or_uri=cert_to_use, key_pem_or_uri=key_to_use)


@pytest.fixture(scope="module")
def valid_key_pem(client_cert):
    """Get a valid key PEM from the client cert fixture."""
    return client_cert.key


@pytest.fixture
def valid_cert_pem(client_cert):
    """Get a valid certificate PEM from the client cert fixture."""
    return client_cert.cert


@pytest.fixture
def invalid_key_pem() -> str:
    """Returns an invalid PEM certificate."""
    return "INVALID KEY DATA"


@pytest.fixture
def invalid_cert_pem() -> str:
    """Returns an invalid PEM certificate."""
    return "INVALID CERTIFICATE DATA"


@pytest.fixture
def malformed_cert_pem() -> str:
    """Returns a PEM certificate with incorrect headers."""
    return "-----BEGIN CERT-----\nMALFORMED DATA\n-----END CERT-----"


@pytest.fixture
def empty_cert() -> str:
    """Returns an empty certificate string."""
    return ""


@pytest.fixture
def temporary_cert_file(tmp_path, client_cert) -> str:
    """Creates a temporary file containing the client certificate."""
    cert_file = tmp_path / "client_cert.pem"
    cert_file.write_text(client_cert.cert)
    return f"file://{cert_file}"


@pytest.fixture
def temporary_key_file(tmp_path, client_cert) -> str:
    """Creates a temporary file containing the client private key."""
    key_file = tmp_path / "client_key.pem"
    key_file.write_text(client_cert.key)  # Write valid PEM key
    return f"file://{key_file}"


@pytest.fixture(scope="module")
def dev_root_ca() -> Certificate:
    """Generates a self-signed CA certificate for testing mTLS setups."""
    ca_cert = Certificate(
        common_name="Test Development CA",  # Differentiate from other default certs
        generate_keypair=True,
        key_type="ecdsa",  # Default is "ecdsa", explicit for clarity
        # No need for basic_constraints_ca or key_usage_extensions here,
        # as the Certificate class currently makes all generated certs CAs by default.
    )
    logger.info(
        f"Generated Development Root CA (common_name='Test Development CA'): {ca_cert.cert[:30]}..."
    )
    return ca_cert


@pytest.fixture(scope="module")
def external_dev_ca_pem() -> str:
    """Provides a known-good, externally generated self-signed CA certificate PEM string."""
    # This is a sample ECDSA P-256 CA certificate.
    # Issuer: CN=External Test CA, O=MyOrg
    # Subject: CN=External Test CA, O=MyOrg
    # Basic Constraints: CA:TRUE
    # Key Usage: Certificate Sign, CRL Sign
    return """-----BEGIN CERTIFICATE-----
MIIB4TCCAYegAwIBAgIJAPZ9vcVfR8AdMAoGCCqGSM49BAMCMFExCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FuIEZyYW5jaXNjbzEOMAwGA1UE
CgwFTXlPcmcxEzARBgNVBAMMCkV4dGVybmFsIENBMB4XDTI0MDgwMjEwNTgwMVoX
DTM0MDczMDEwNTgwMVowUTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMREwDwYD
VQQHDAhTYW5EaWVnbzEOMAwGA1UECgwFTXlPcmcxEzARBgNVBAMMCkV4dGVybmFs
IENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgyF5Y8upm+M3ZzO8P4n7q2sS+L4c
mhl5XGg3vIOwFf7lG8XZCgJ6Xy4t1t8oD3zY0m9X8H8Z4YhY7K6b7c8Y7Xv6Y9fV
Q8M7Jg9nJ0x5c1N40zQwZzKjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBTGX00Gq7b09y/0C9eK0XgJp0mY7DAKBggqhkjOPQQD
AgNJADBGAiEAx1xH/b83/u5t7r29a/THZnFjQ7pvT2N0L4hG4BgGgXACIQD02W2+
MHB78ZWM+JOgikYj99qD6nLp0nkMyGmkSC7RYg==
-----END CERTIFICATE-----
"""


### 🐍🏗🧪️
