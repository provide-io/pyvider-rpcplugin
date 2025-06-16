# tests/transport/tcp/test_transport_tcp_validation.py

import pytest

from pyvider.rpcplugin.transport.tcp import is_valid_tcp_endpoint


@pytest.mark.parametrize(
    "endpoint, expected",
    [
        ("127.0.0.1:8080", True),
        ("localhost:5000", True),
        ("example.com:12345", True),
        ("192.168.1.100:443", True),
        # Current logic does not support IPv6 without brackets due to multiple colons
        ("::1:8000", False),  # IPv6 - Expected False with current logic
        # Current logic does not correctly parse IPv6 with brackets if host becomes e.g. "[::1]"
        (
            "[::1]:8000",
            False,
        ),  # IPv6 with brackets - Expected False with current simple split logic
    ],
)
def test_is_valid_tcp_endpoint_valid_formats(endpoint: str, expected: bool):
    """Test is_valid_tcp_endpoint with various valid formats."""
    assert is_valid_tcp_endpoint(endpoint) == expected


@pytest.mark.parametrize(
    "endpoint, expected",
    [
        ("127.0.0.1", False),  # Missing port
        ("localhost:http", False),  # Non-numeric port
        (":8080", False),  # Empty host
        ("localhost:", False),  # Empty port
        ("localhost:80:80", False),  # Extra colon
        (
            "localhost: 65530",
            False,
        ),  # Port with space (current logic would make it False due to split)
        (
            "localhost:65536",
            True,
        ),  # Invalid port number, but function only checks isdigit
        ("localhost:-1", False),  # Invalid port number
        ("", False),  # Empty string
        (":", False),  # Just a colon
    ],
)
def test_is_valid_tcp_endpoint_invalid_formats(endpoint: str, expected: bool):
    """Test is_valid_tcp_endpoint with various invalid formats."""
    assert is_valid_tcp_endpoint(endpoint) == expected


def test_is_valid_tcp_endpoint_valid_port_range():
    """Test that port numbers are validated as digits, not their range."""
    # The function currently only checks `isdigit()`, not the valid port range (0-65535).
    # This test documents current behavior.
    assert is_valid_tcp_endpoint("localhost:65535")  # Valid
    assert is_valid_tcp_endpoint("localhost:0")  # Valid
    # The following would be invalid ports in practice, but pass isdigit()
    assert is_valid_tcp_endpoint("localhost:65536")
    assert is_valid_tcp_endpoint("localhost:123456")


def test_is_valid_tcp_endpoint_empty_host_specific():
    """Test specifically for an empty host part."""
    assert not is_valid_tcp_endpoint(":1234")


### 🐍🏗🧪️
