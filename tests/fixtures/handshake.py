# tests/fixtures/handshake.py

import pytest

from pyvider.rpcplugin.handshake import HandshakeConfig


@pytest.fixture(scope="module")
def mock_core_version() -> int:
    return 1


@pytest.fixture(scope="module")
def handshake_config() -> HandshakeConfig:
    """Fixture for the default handshake configuration."""
    return HandshakeConfig(
        magic_cookie_key="PLUGIN_MAGIC_COOKIE",
        magic_cookie_value="d602bf8f470bc67ca7faa0386276bbdd4330efaf76d1a219cb4d6991ca9872b2",
        protocol_versions=[1, 2, 3, 4, 5, 6, 7],
        supported_transports=["tcp", "unix"],
    )


@pytest.fixture(scope="module")
def invalid_handshake_config() -> HandshakeConfig:
    """Fixture for an invalid handshake configuration."""
    return HandshakeConfig(
        magic_cookie_key="INVALID_COOKIE_KEY",
        magic_cookie_value="invalid_cookie_value",
        protocol_versions=[999],
        supported_transports=["invalid_transport"],
    )


### 🐍🏗🧪️
