# pyvider/rpcplugin/tests/handshake/test_handshake_responses.py

import pytest
import re # Added import re

from unittest.mock import AsyncMock

from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.handshake import (
    build_handshake_response,
    parse_handshake_response,
)

from tests.fixtures.transport import mock_server_transport


class StubCertificate:
    def __init__(self, pem_str) -> None:
        self.cert = pem_str  # e.g. "-----BEGIN CERTIFICATE-----\nbase64encodeddata\n-----END CERTIFICATE-----"


@pytest.mark.asyncio
async def test_build_handshake_response_with_tls() -> None:
    # Use StubCertificate instead of raw string
    stub_cert = StubCertificate(
        "-----BEGIN CERTIFICATE-----\nbase64encodeddata\n-----END CERTIFICATE-----"
    )

    response = await build_handshake_response(
        plugin_version=6,
        transport_name="tcp",
        transport=mock_server_transport,
        server_cert=stub_cert,  # we pass the stub object
        port=12345,
    )

    expected_cert = "base64encodeddata"
    expected_response = f"1|6|tcp|127.0.0.1:12345|grpc|{expected_cert}"
    assert response == expected_response


@pytest.mark.asyncio
async def test_build_handshake_response_without_tls(mock_server_transport) -> None:
    """Test building a valid handshake response without TLS."""
    transport = mock_server_transport
    transport.listen = AsyncMock(return_value="/tmp/pyvider.sock")

    response = await build_handshake_response(
        plugin_version=6, transport_name="unix", transport=transport, server_cert=None
    )

    expected_response = "1|6|unix|/tmp/pyvider.sock|grpc|"
    assert response == expected_response


@pytest.mark.asyncio
async def test_build_handshake_response_invalid_transport(monkeypatch) -> None:
    """Test building handshake response with an invalid transport."""
    # transport = AsyncMock()
    # transport.listen = AsyncMock(return_value=None)

    with pytest.raises(HandshakeError, match=r"\[HandshakeError\] TCP transport requires a port number.*Hint:.*"):
        await build_handshake_response(
            plugin_version=6,
            transport_name="tcp",
            transport=None,
            server_cert=None,
        )


@pytest.mark.asyncio
async def test_parse_handshake_response_with_tls(monkeypatch) -> None:
    """Test parsing a valid handshake response with TLS."""

    response = f"{1}|6|tcp|127.0.0.1:12345|grpc|base64_encoded_cert"
    core_version, plugin_version, network, address, protocol, cert = (
        parse_handshake_response(response)
    )

    assert core_version == 1
    assert plugin_version == 6
    assert network == "tcp"
    assert address == "127.0.0.1:12345"
    assert protocol == "grpc"
    assert cert.startswith("base64_encoded_cert")


def test_parse_handshake_response_without_tls() -> None:
    """Test parsing a valid handshake response without TLS."""
    response = f"{1}|6|unix|/tmp/pyvider.sock|grpc|"
    core_version, plugin_version, network, address, protocol, cert = (
        parse_handshake_response(response)
    )

    assert core_version == 1
    assert plugin_version == 6
    assert network == "unix"
    assert address == "/tmp/pyvider.sock"
    assert protocol == "grpc"
    assert cert is None


def test_parse_handshake_response_invalid_format() -> None:
    """Test parsing an invalid handshake response format."""
    response = "invalid|response"
    with pytest.raises(HandshakeError, match=r"\[HandshakeError\] Invalid handshake format.*"):
        parse_handshake_response(response)


def test_parse_handshake_response_missing_fields() -> None:
    """Test parsing a handshake response with missing fields."""
    response = f"{1}|6|tcp"
    with pytest.raises(HandshakeError, match=r"\[HandshakeError\] Invalid handshake format.*"):
        parse_handshake_response(response)


def test_parse_handshake_response_empty() -> None:
    """Test parsing an empty handshake response."""
    response = ""
    with pytest.raises(HandshakeError, match=r"\[HandshakeError\] Invalid handshake format.*"):
        parse_handshake_response(response)


def test_parse_handshake_response_excessive_fields() -> None:
    """Test parsing a handshake response with too many fields."""
    response = f"{1}|6|tcp|127.0.0.1:12345|grpc|cert|extra_field"
    with pytest.raises(HandshakeError, match=r"\[HandshakeError\] Invalid handshake format.*"):
        parse_handshake_response(response)


def test_parse_handshake_response_invalid_protocol_version() -> None:
    """Test parsing a handshake response with an invalid protocol version."""
    response = "1|99|tcp|127.0.0.1:12345|"
    with pytest.raises(HandshakeError, match=r"\[HandshakeError\] Unsupported handshake version.*"):
        parse_handshake_response(response)


@pytest.mark.asyncio
async def test_build_handshake_response_missing_port() -> None:
    """Test building handshake response for TCP transport without a port."""
    transport = AsyncMock()
    with pytest.raises(HandshakeError, match=r"\[HandshakeError\] TCP transport requires a port number.*Hint:.*"):
        await build_handshake_response(
            plugin_version=6,
            transport_name="tcp",
            transport=transport,
            server_cert=None,
        )


@pytest.mark.asyncio
async def test_build_handshake_response_unix_transport_already_running(mocker):
    """Test build_handshake_response with a Unix transport that is already running."""
    mock_transport = AsyncMock()
    mock_transport._running = True  # Simulate transport is already running
    mock_transport.endpoint = "/tmp/existing_socket.sock"
    mock_transport.listen = AsyncMock()  # Should not be called

    mock_logger_debug = mocker.patch("pyvider.rpcplugin.handshake.logger.debug")

    response = await build_handshake_response(
        plugin_version=5,
        transport_name="unix",
        transport=mock_transport,
        server_cert=None,
    )

    parts = response.split("|")
    assert parts[3] == "/tmp/existing_socket.sock"
    mock_transport.listen.assert_not_called()

    # Check for the specific debug log
    found_log = False
    for call_args in mock_logger_debug.call_args_list:
        if (
            "Using existing Unix transport endpoint: /tmp/existing_socket.sock"
            in call_args[0][0]
        ):
            found_log = True
            break
    assert found_log, "Log message for existing endpoint not found"


@pytest.mark.asyncio
async def test_build_handshake_response_generic_exception(mocker):
    """Test that a generic exception during handshake building is caught and re-raised."""
    mock_transport = AsyncMock()
    mock_transport._running = False  # Ensure the 'else' branch with .listen() is taken
    mock_transport.endpoint = None  # Ensure it doesn't use existing endpoint
    mock_transport.listen = AsyncMock(
        side_effect=Exception("Unexpected listener error")
    )

    mock_logger_error = mocker.patch("pyvider.rpcplugin.handshake.logger.error")

    with pytest.raises(Exception, match="Unexpected listener error"):
        await build_handshake_response(
            plugin_version=1,
            transport_name="unix",
            transport=mock_transport,
            server_cert=None,
        )

    mock_logger_error.assert_called_once()
    args, kwargs = mock_logger_error.call_args
    assert "Handshake response build failed: Unexpected listener error" in args[0]
    assert "Unexpected listener error" in kwargs.get("extra", {}).get("error", "")


@pytest.mark.parametrize("invalid_input", [None, 123, b"bytes_not_str"])
def test_parse_handshake_response_not_string(invalid_input):
    """Test parse_handshake_response with non-string inputs."""
    with pytest.raises(
        HandshakeError,
        match=r"\[HandshakeError\] Failed to parse handshake response:.*Handshake response is not a string.*Hint:.*",
    ):
        parse_handshake_response(invalid_input)


@pytest.mark.parametrize(
    "core_version_config_val, expected_log_part",
    [
        (None, "PLUGIN_CORE_VERSION is None"),
        ("abc", "Could not convert PLUGIN_CORE_VERSION 'abc' to int"),
    ],
)
def test_parse_handshake_core_version_config_issues(
    mocker, core_version_config_val, expected_log_part
):
    """Test parsing when PLUGIN_CORE_VERSION from config is None or not an int."""
    mock_logger_error = mocker.patch("pyvider.rpcplugin.handshake.logger.error")
    mocker.patch(
        "pyvider.rpcplugin.handshake.rpcplugin_config.get",
        return_value=core_version_config_val,
    )

    # A valid handshake string otherwise, but core version will be compared against fallback 1
    # If core_version in string (e.g., "2") mismatches fallback 1, it will raise HandshakeError
    # If core_version in string is "1", it will pass parsing but log the critical error.
    handshake_str_matching_fallback = "1|1|tcp|127.0.0.1:1234|grpc|"
    core_v, plugin_v, net, addr, proto, cert = parse_handshake_response(
        handshake_str_matching_fallback
    )

    assert core_v == 1  # Should use fallback
    mock_logger_error.assert_called_once()
    args, _ = mock_logger_error.call_args
    assert "CRITICAL" in args[0]
    assert expected_log_part in args[0]

    # Test case where the version in handshake string does NOT match the fallback, causing HandshakeError
    mock_logger_error.reset_mock()
    handshake_str_mismatch_fallback = "2|1|tcp|127.0.0.1:1234|grpc|"
    with pytest.raises(
        HandshakeError, match=r"\[HandshakeError\] Unsupported handshake version: 2 \(expected: 1\).*"
    ):
        parse_handshake_response(handshake_str_mismatch_fallback)

    # The critical log about config should still have happened before the HandshakeError for version mismatch
    mock_logger_error.assert_any_call(
        mocker.ANY, extra=mocker.ANY
    )  # Check it was called
    found_critical_log = False
    for call in mock_logger_error.call_args_list:
        args, _ = call
        if "CRITICAL" in args[0] and expected_log_part in args[0]:
            found_critical_log = True
            break
    assert found_critical_log


def test_parse_handshake_response_generic_exception(mocker):
    """Test that a generic exception during parsing is caught and wrapped."""
    mock_logger_error = mocker.patch("pyvider.rpcplugin.handshake.logger.error")

    # Make response.strip().split('|') raise an unexpected error
    mock_response_str = mocker.MagicMock(spec=str)
    mock_response_str.strip.return_value.split.side_effect = Exception(
        "Unexpected parsing error"
    )

    with pytest.raises(
        HandshakeError,
        match=r"\[HandshakeError\] Failed to parse handshake response: Unexpected parsing error.*Hint:.*",
    ):
        parse_handshake_response(mock_response_str)

    mock_logger_error.assert_called_once()
    args, kwargs = mock_logger_error.call_args
    assert "Handshake parsing failed: Unexpected parsing error" in args[0]
    assert "Unexpected parsing error" in kwargs.get("extra", {}).get("error", "")
