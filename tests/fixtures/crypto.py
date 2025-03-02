# tests/fixtures/crypto.py

import pytest

import os

from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.crypto.certificate import Certificate


@pytest.fixture(scope="module")
def client_cert():
    """Loads the server certificate from the environment variable."""
    from pyvider.rpcplugin.config import rpcplugin_config

    cert = rpcplugin_config.get("PLUGIN_CLIENT_CERT")
    key = rpcplugin_config.get("PLUGIN_CLIENT_KEY")

    if not cert:
        cert = """-----BEGIN CERTIFICATE-----
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

    if not key:
        key = """-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDAkxo19KczdciRiJjOWEKGY5mH9s1D0aUS5XBdvktcaonIOdqNrkCt1
BC5YjEAVLNWgBwYFK4EEACKhZANiAARCi3SNYYDpSeScRM52tFYrURzsPOE/ad8B
zvpvL+mfy1c5oHQhh6KPnxpoo1WyDJGYplwPTGS68DvvWmolrPAtC7I7r7spgyJS
1358E5fA2NWk9/YPaiUzK2gsyrL9dKY=
-----END EC PRIVATE KEY-----
"""

    logger.info(f"Loaded CLIENT_CERT: {cert[:30]}...")
    logger.info(f"Loaded CLIENT_KEY: {key[:30]}...")

    return Certificate(cert=cert, key=key)


@pytest.fixture(scope="module")
def server_cert():
    """Loads the server certificate from the environment variable."""
    from pyvider.rpcplugin.config import rpcplugin_config

    cert = rpcplugin_config.get("PLUGIN_SERVER_CERT")
    key = rpcplugin_config.get("PLUGIN_SERVER_KEY")

    if not cert:
        cert = """-----BEGIN CERTIFICATE-----
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

    if not key:
        key = """-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDDZ1MORWFVI0HtgKv+zZys/5e1HVmfcs4bwdp3VEsuwS6an3gTwGnSP
Ce+bI6f/TvGgBwYFK4EEACKhZANiAARMxEVmGX3a4IWPOAJ2MX2s2Wj3KZ0Io5Ew
UPMkxknGheO2e55qeHp/tkEFzYt9AH8du1xJLKKFbsGV5q9vipGNx5XMbj2RMdH5
VXHTAdc/bLFFy9kybQqo300Rv6ViW2I=
-----END EC PRIVATE KEY-----
"""

    logger.info(f"Loaded SERVER_CERT: {cert[:30]}...")
    logger.info(f"Loaded SERVER_KEY: {key[:30]}...")

    return Certificate(cert=cert, key=key)


@pytest.fixture(scope="module")
def valid_key_pem(client_cert):
    """Get a valid key PEM from the client cert fixture."""
    return client_cert.key


@pytest.fixture
def valid_cert_pem(client_cert):
    """Get a valid certificate PEM from the client cert fixture."""
    return client_cert.cert


@pytest.fixture
def invalid_key_pem():
    """Returns an invalid PEM certificate."""
    return "INVALID KEY DATA"


@pytest.fixture
def invalid_cert_pem():
    """Returns an invalid PEM certificate."""
    return "INVALID CERTIFICATE DATA"


@pytest.fixture
def malformed_cert_pem():
    """Returns a PEM certificate with incorrect headers."""
    return "-----BEGIN CERT-----\nMALFORMED DATA\n-----END CERT-----"


@pytest.fixture
def empty_cert():
    """Returns an empty certificate string."""
    return ""


@pytest.fixture
def temporary_cert_file(tmp_path, client_cert):
    """Creates a temporary file containing the client certificate."""
    cert_file = tmp_path / "client_cert.pem"
    cert_file.write_text(client_cert.cert)
    return f"file://{cert_file}"


@pytest.fixture
def temporary_key_file(tmp_path, client_cert):
    """Creates a temporary file containing the client private key."""
    key_file = tmp_path / "client_key.pem"
    key_file.write_text(client_cert.key)  # Write valid PEM key
    return f"file://{key_file}"

### 🐍🏗🧪️
