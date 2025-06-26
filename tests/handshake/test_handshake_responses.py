# tests/handshake/test_handshake_responses.py
import pytest
from unittest.mock import patch, MagicMock, AsyncMock  # Added AsyncMock
from pyvider.rpcplugin.transport import UnixSocketTransport # Added import

from pyvider.rpcplugin.handshake import (
    build_handshake_response,
    parse_handshake_response,
)
from pyvider.rpcplugin.crypto import Certificate
from pyvider.rpcplugin.exception import HandshakeError
from pyvider.rpcplugin.config import rpcplugin_config


@pytest.mark.asyncio
async def test_build_handshake_response_with_tls(mock_server_transport_tcp):
    """Test building handshake response with TLS certificate."""
    cert = Certificate(generate_keypair=True)
    response = await build_handshake_response(
        plugin_version=7,
        transport_name="tcp",
        transport=mock_server_transport_tcp,
        server_cert=cert,
        port=mock_server_transport_tcp.port,
    )
    parts = response.split("|")
    assert len(parts) == 6
    assert parts[5] != ""  # Certificate part should not be empty


@pytest.mark.parametrize("transport_type", ["tcp", "unix"])
@pytest.mark.asyncio
async def test_build_handshake_response_without_tls(
    transport_type, mock_server_transport_tcp, mock_server_transport_unix, mocker
):
    """Test building handshake response without TLS."""
    transport_to_use = None
    port_to_use = None

    if transport_type == "tcp":
        transport_to_use = mock_server_transport_tcp
        port_to_use = mock_server_transport_tcp.port
        if not transport_to_use._running:
            mocker.patch.object(
                transport_to_use, "listen", return_value=f"127.0.0.1:{port_to_use}"
            )

    elif transport_type == "unix":
        transport_to_use = mock_server_transport_unix
        if not transport_to_use._running:
            mocker.patch.object(
                transport_to_use, "listen", return_value="/tmp/mock.sock"
            )

    response = await build_handshake_response(
        plugin_version=7,
        transport_name=transport_type,
        transport=transport_to_use,
        server_cert=None,
        port=port_to_use,
    )
    parts = response.split("|")
    assert len(parts) == 6
    assert parts[5] == ""  # Certificate part should be empty


@pytest.mark.asyncio
async def test_build_handshake_response_invalid_transport(mock_server_transport_tcp):
    """Test building handshake with an invalid transport type."""
    with pytest.raises(
        HandshakeError,
        match=r"Failed to build handshake response: .*Unsupported transport type specified for handshake response: 'invalid'",
    ):
        await build_handshake_response(
            plugin_version=7,
            transport_name="invalid",
            transport=mock_server_transport_tcp,
            port=mock_server_transport_tcp.port,
        )


def test_parse_handshake_response_with_tls():
    """Test parsing a handshake response that includes a TLS certificate."""
    cert_data = "FAKECERTDATA"
    response_str = f"1|7|tcp|127.0.0.1:12345|grpc|{cert_data}"

    with patch.object(rpcplugin_config, "get") as mock_get_config:
        mock_get_config.return_value = 1

        core_version, plugin_version, network, address, protocol, server_cert = (
            parse_handshake_response(response_str)
        )
        assert core_version == 1
        assert plugin_version == 7
        assert network == "tcp"
        assert address == "127.0.0.1:12345"
        assert protocol == "grpc"
    assert server_cert == cert_data


def test_parse_handshake_response_without_tls():
    """Test parsing a handshake response without a TLS certificate."""
    response_str = "1|7|unix|/tmp/test.sock|grpc|"
    with patch.object(rpcplugin_config, "get") as mock_get_config:
        mock_get_config.return_value = 1

        core_version, plugin_version, network, address, protocol, server_cert = (
            parse_handshake_response(response_str)
        )
        assert core_version == 1
        assert plugin_version == 7
        assert network == "unix"
        assert address == "/tmp/test.sock"
        assert protocol == "grpc"
        assert server_cert is None


def test_parse_handshake_response_invalid_format():
    """Test parsing an improperly formatted handshake response."""
    response_str = "1|7|tcp"  # Missing parts
    with pytest.raises(
        HandshakeError,
        match=r"Invalid handshake format. Expected 6 pipe-separated parts, got 3: '1\|7\|tcp...'",
    ):
        parse_handshake_response(response_str)


def test_parse_handshake_response_missing_fields():
    """Test parsing a handshake response with missing fields (empty strings)."""
    response_str = "1|7|||grpc|"  # Empty network and address
    with patch.object(rpcplugin_config, "get") as mock_get_config:
        mock_get_config.return_value = 1
        with pytest.raises(
            HandshakeError, match="Invalid network type '' in handshake."
        ):
            parse_handshake_response(response_str)

    response_str_empty_addr = "1|7|tcp||grpc|"
    with patch.object(rpcplugin_config, "get") as mock_get_config:
        mock_get_config.return_value = 1
        with pytest.raises(
            HandshakeError, match="Empty address received in handshake string."
        ):
            parse_handshake_response(response_str_empty_addr)


def test_parse_handshake_response_empty():
    """Test parsing an empty handshake response string."""
    with pytest.raises(
        HandshakeError,
        match=r"Invalid handshake format. Expected 6 pipe-separated parts, got 1: '...'",
    ):
        parse_handshake_response("")


def test_parse_handshake_response_excessive_fields():
    """Test parsing a handshake response with too many fields."""
    response_str = "1|7|tcp|127.0.0.1:12345|grpc|certdata|extrafield"
    with pytest.raises(
        HandshakeError,
        match=r"Invalid handshake format. Expected 6 pipe-separated parts, got 7: '1\|7\|tcp\|127.0.0.1:12345\|grpc\|certdata\|extrafield...'",
    ):
        parse_handshake_response(response_str)


def test_parse_handshake_response_invalid_protocol_version() -> None:
    """Test parsing a handshake response with an invalid protocol version."""
    with patch.object(rpcplugin_config, "get") as mock_get_config:
        # Scenario 1: Core protocol version mismatch (e.g., plugin sends 2, client expects 1)
        response_diff_core = "2|7|tcp|127.0.0.1:12345|grpc|"
        # Configure the mock to return '1' when 'PLUGIN_CORE_VERSION' is fetched.
        mock_get_config.side_effect = (
            lambda key, default=None: 1 if key == "PLUGIN_CORE_VERSION" else default
        )
        # The parse_handshake_response function wraps the specific error.
        # The specific error is "Unsupported handshake version: 2 (expected: 1)".
        # The current regex in the code for this part is correct for matching the specific part.
        expected_regex_diff_core = r"Unsupported handshake version: 2 \(expected: 1\)"
        with pytest.raises(HandshakeError, match=expected_regex_diff_core):
            parse_handshake_response(response_diff_core)

        # Scenario 2: Core protocol version is not a valid integer (e.g., "abc")
        response_bad_core_ver = "abc|7|tcp|127.0.0.1:12345|grpc|"
        # This fails the is_valid_handshake_parts check first, leading to "Invalid handshake format".
        # The error is then wrapped.
        # For a more precise match on the *actual* error thrown due to 'abc':
        # The is_valid_handshake_parts logs "version parts not both digits. Core: 'abc', Plugin: '7'"
        # and then "Invalid handshake format" is raised. The test should check for the raised error.
        # The actual raised error due to `is_valid_handshake_parts` returning False for "abc" is:
        # "[HandshakeError] Failed to parse handshake response: [HandshakeError] Invalid handshake format. Expected 6 pipe-separated parts, got 6: 'abc|7|tcp..."
        expected_regex_bad_core_final = r"\[HandshakeError\] Failed to parse handshake response: \[HandshakeError\] Invalid handshake format.*Expected 6 pipe-separated parts, got 6: 'abc\|7\|tcp"

        with pytest.raises(HandshakeError, match=expected_regex_bad_core_final):
            parse_handshake_response(response_bad_core_ver)


@pytest.mark.asyncio
async def test_build_handshake_response_missing_port(mock_server_transport_unix):
    """Test HandshakeError if TCP transport is used without specifying a port."""
    with pytest.raises(
        HandshakeError,
        match="TCP transport requires a port number to build handshake response.",
    ):
        await build_handshake_response(
            plugin_version=7,
            transport_name="tcp",
            transport=mock_server_transport_unix,
            server_cert=None,
            port=None,
        )


@pytest.mark.asyncio
async def test_build_handshake_response_unix_transport_already_running(mocker):
    """Test build_handshake_response with a Unix transport that is already running."""
    mock_transport = MagicMock()
    mock_transport._running = True
    mock_transport.endpoint = "/tmp/existing.sock"

    mocker.patch.object(rpcplugin_config, "get", return_value="1")

    response = await build_handshake_response(
        plugin_version=7,
        transport_name="unix",
        transport=mock_transport,
        server_cert=None,
    )
    assert "|unix|/tmp/existing.sock|grpc|" in response
    mock_transport.listen.assert_not_called()


@pytest.mark.asyncio
async def test_build_handshake_response_generic_exception(mocker):
    """Test that a generic exception during build_handshake_response is wrapped."""
    mock_transport = AsyncMock()
    mock_transport.listen = AsyncMock(side_effect=Exception("Underlying listen error"))

    mocker.patch.object(rpcplugin_config, "get", return_value="1")

    with pytest.raises(
        HandshakeError,
        match=r"Failed to build handshake response: sequence item 3: expected str instance, AsyncMock found",
    ):
        await build_handshake_response(
            plugin_version=7,
            transport_name="unix",
            transport=mock_transport,
            server_cert=None,
        )


@pytest.mark.parametrize(
    "response_input, error_msg_part",
    [
        (None, "Handshake response is not a string."),
        (123, "Handshake response is not a string."),
        (b"bytes_not_str", "Handshake response is not a string."),
    ],
)
def test_parse_handshake_response_not_string(response_input, error_msg_part):
    """Test parse_handshake_response with non-string inputs."""
    with pytest.raises(HandshakeError, match=error_msg_part):
        parse_handshake_response(response_input)


@pytest.mark.parametrize(
    "config_core_version, expected_parsed_core_version_or_error",
    [(None, 1), ("abc", 1), ("2", 2), (3, 3)],
)
def test_parse_handshake_core_version_config_issues(
    config_core_version, expected_parsed_core_version_or_error, mocker
):
    """Test how parse_handshake_response handles various PLUGIN_CORE_VERSION from config."""
    handshake_line_core_version = 1

    response_str = f"{handshake_line_core_version}|7|tcp|127.0.0.1:1234|grpc|"

    mock_get = mocker.patch.object(rpcplugin_config, "get")

    def side_effect_func(key, default=None):
        if key == "PLUGIN_CORE_VERSION":
            return config_core_version
        return default

    mock_get.side_effect = side_effect_func

    if isinstance(expected_parsed_core_version_or_error, type) and issubclass(
        expected_parsed_core_version_or_error, Exception
    ):
        with pytest.raises(expected_parsed_core_version_or_error):
            parse_handshake_response(response_str)
    else:
        if handshake_line_core_version != expected_parsed_core_version_or_error:
            expected_error_msg = rf"Unsupported handshake version: {handshake_line_core_version} \(expected: {expected_parsed_core_version_or_error}\)"
            with pytest.raises(HandshakeError, match=expected_error_msg):
                parse_handshake_response(response_str)
        else:
            core_v, _, _, _, _, _ = parse_handshake_response(response_str)
            assert core_v == expected_parsed_core_version_or_error


def test_parse_handshake_response_generic_exception(mocker):
    """Test that a generic exception during parsing is caught and wrapped."""
    mock_logger_error = mocker.patch("pyvider.rpcplugin.handshake.logger.error")

    mock_response_str = mocker.MagicMock(spec=str)
    mock_response_str.strip.return_value.split.side_effect = Exception(
        "Unexpected parsing error"
    )

    expected_regex = r"\[HandshakeError\] Failed to parse handshake response: Unexpected parsing error\Z"
    with pytest.raises(HandshakeError, match=expected_regex):
        parse_handshake_response(mock_response_str)

    mock_logger_error.assert_called_once()
    args, kwargs = mock_logger_error.call_args
    assert "📡❌ Handshake parsing failed: Unexpected parsing error" in args[0]
    assert (
        kwargs.get("extra", {}).get("error") == "Unexpected parsing error"
    )  # Check the 'error' key in 'extra'


@pytest.mark.asyncio
async def test_build_handshake_response_invalid_cert_format(mocker):
    # Use AsyncMock for transport methods that need to be awaitable
    mock_transport = AsyncMock(spec=UnixSocketTransport)
    mock_transport.listen = AsyncMock(return_value="/tmp/test.sock")
    mock_transport._running = False
    mock_transport.endpoint = None

    mock_server_cert = MagicMock(spec=Certificate)
    # Ensure .cert attribute exists and is a string
    mock_server_cert.cert = "INVALID\nCERT" # Only 2 lines, will fail len(cert_lines) < 3

    # Mock rpcplugin_config.get for PLUGIN_CORE_VERSION as it's used by build_handshake_response
    mocker.patch.object(rpcplugin_config, "get", return_value="1") # Assuming core version "1"

    with pytest.raises(HandshakeError, match="Invalid server certificate format"):
        await build_handshake_response(
            plugin_version=1,
            transport_name="unix",
            transport=mock_transport,
            server_cert=mock_server_cert # Pass the MagicMock instance
        )

def test_parse_handshake_response_invalid_network(mocker):
    response_str = "1|1|invalidnet|127.0.0.1:12345|grpc|"
    mocker.patch.object(rpcplugin_config, "get", return_value="1") # Mock core version check
    with pytest.raises(HandshakeError, match="Invalid network type 'invalidnet' in handshake."):
        parse_handshake_response(response_str)

# 🐍🏗️🤝
