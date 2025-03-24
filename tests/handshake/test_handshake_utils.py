#!/usr/bin/env python3
# tests/handshake/test_handshake_utils.py

import os
import socket
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pyvider.rpcplugin.exception import HandshakeError, TransportError
from pyvider.rpcplugin.handshake import (
    HandshakeConfig,
    HandshakeParts,
    is_valid_handshake_parts,
    validate_transport,
)

from pyvider.rpcplugin.transport.tcp import is_valid_tcp_endpoint


def test_is_valid_tcp_endpoint():
    from pyvider.rpcplugin.transport.tcp import is_valid_tcp_endpoint

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
    assert is_valid_handshake_parts(["1", "2", "tcp", "localhost:8080", "grpc", ""]) is True
    
    # Invalid parts - wrong length
    assert is_valid_handshake_parts(["1", "2", "tcp", "localhost:8080", "grpc"]) is False
    assert is_valid_handshake_parts(["1", "2", "tcp", "localhost:8080", "grpc", "", "extra"]) is False
    
    # Invalid parts - first two elements must be digits
    assert is_valid_handshake_parts(["a", "2", "tcp", "localhost:8080", "grpc", ""]) is False
    assert is_valid_handshake_parts(["1", "b", "tcp", "localhost:8080", "grpc", ""]) is False


def test_validate_transport():
    """Test the transport validation function."""
    # Valid transport
    validate_transport("tcp", ["tcp", "unix"])  # Should not raise
    validate_transport("unix", ["unix"])  # Should not raise
    
    # Invalid transport
    with pytest.raises(TransportError, match="Unsupported transport"):
        validate_transport("unsupported", ["tcp", "unix"])
    
    with pytest.raises(TransportError, match="Unsupported transport"):
        validate_transport("tcp", ["unix"])


def test_handshake_config_attrs():
    """Test the HandshakeConfig attributes class."""
    config = HandshakeConfig(
        magic_cookie_key="TEST_COOKIE_KEY",
        magic_cookie_value="test_cookie_value",
        protocol_versions=[1, 2, 3],
        supported_transports=["tcp", "unix"]
    )
    
    assert config.magic_cookie_key == "TEST_COOKIE_KEY"
    assert config.magic_cookie_value == "test_cookie_value"
    assert config.protocol_versions == [1, 2, 3]
    assert config.supported_transports == ["tcp", "unix"]


def test_handshake_parts_attrs():
    """Test the HandshakeParts attributes class."""
    parts = HandshakeParts(
        core_version=1,
        plugin_version=2,
        network="tcp",
        address="localhost:8080",
        protocol="grpc",
        server_cert="cert123"
    )
    
    assert parts.core_version == 1
    assert parts.plugin_version == 2
    assert parts.network == "tcp"
    assert parts.address == "localhost:8080"
    assert parts.protocol == "grpc"
    assert parts.server_cert == "cert123"
    
    # Test with optional server_cert
    parts_no_cert = HandshakeParts(
        core_version=1,
        plugin_version=2,
        network="tcp",
        address="localhost:8080",
        protocol="grpc",
        server_cert=None
    )
    
    assert parts_no_cert.server_cert is None
