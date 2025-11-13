#!/usr/bin/env python3
# tests/handshake/test_handshake_utils.py


from pyvider.rpcplugin.handshake import (
    HandshakeConfig,
    is_valid_handshake_parts,
)

from pyvider.rpcplugin.transport.tcp import is_valid_tcp_endpoint


def test_is_valid_tcp_endpoint():
    # Valid endpoints
    assert is_valid_tcp_endpoint("localhost:8080") is True
    assert is_valid_tcp_endpoint("127.0.0.1:1234") is True
    assert is_valid_tcp_endpoint("example.com:443") is True

    # Invalid endpoints
    assert is_valid_tcp_endpoint("localhost") is False  # Missing port
    assert is_valid_tcp_endpoint("localhost:") is False  # Empty port
    assert is_valid_tcp_endpoint("localhost:abc") is False  # Non-numeric port
    assert is_valid_tcp_endpoint(":8080") is False  # Empty host
    assert is_valid_tcp_endpoint("") is False  # Empty string
    assert is_valid_tcp_endpoint("host:port:extra") is False  # Too many colons


def test_is_valid_handshake_parts():
    """Test the handshake parts validator function."""
    # Valid parts
    assert (
        is_valid_handshake_parts(["1", "2", "tcp", "localhost:8080", "grpc", ""])
        is True
    )

    # Invalid parts - wrong length
    assert (
        is_valid_handshake_parts(["1", "2", "tcp", "localhost:8080", "grpc"]) is False
    )
    assert (
        is_valid_handshake_parts(
            ["1", "2", "tcp", "localhost:8080", "grpc", "", "extra"]
        )
        is False
    )

    # Invalid parts - first two elements must be digits
    assert (
        is_valid_handshake_parts(["a", "2", "tcp", "localhost:8080", "grpc", ""])
        is False
    )
    assert (
        is_valid_handshake_parts(["1", "b", "tcp", "localhost:8080", "grpc", ""])
        is False
    )


def test_handshake_config_attrs():
    """Test the HandshakeConfig attributes class."""
    config = HandshakeConfig(
        magic_cookie_key="TEST_COOKIE_KEY",
        magic_cookie_value="test_cookie_value",
        protocol_versions=[1, 2, 3],
        supported_transports=["tcp", "unix"],
    )

    assert config.magic_cookie_key == "TEST_COOKIE_KEY"
    assert config.magic_cookie_value == "test_cookie_value"
    assert config.protocol_versions == [1, 2, 3]
    assert config.supported_transports == ["tcp", "unix"]


### 🐍🏗🧪️
