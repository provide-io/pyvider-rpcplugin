#
# pyvider/rpcplugin/handshake/core.py
#
"""Core handshake functionality for the RPC plugin system.

This module contains the primary handshake configuration, validation,
building, and parsing logic.
"""

from enum import Enum, auto
import os
from typing import Literal, TypeGuard

from attrs import define
from provide.foundation import resilient
from provide.foundation.crypto import Certificate
from provide.foundation.logger import get_logger

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import HandshakeError, TransportError
from pyvider.rpcplugin.telemetry import get_rpc_tracer
from pyvider.rpcplugin.transport.types import TransportT

# Module logger and tracer
logger = get_logger(__name__)
_tracer = get_rpc_tracer()


class _SentinelEnum(Enum):  # type: ignore[type-arg]
    NOT_PASSED = auto()


_SENTINEL_INSTANCE = _SentinelEnum.NOT_PASSED
_SentinelType = Literal[_SentinelEnum.NOT_PASSED]  # type: ignore[misc]


@define
class HandshakeConfig:
    """
    ⚙️🔧✅ Represents the configuration for the RPC plugin handshake.

    Attributes:
      magic_cookie_key: The expected environment key for the handshake cookie.
      magic_cookie_value: The expected handshake cookie value.
      protocol_versions: A list of protocol versions supported by the server.
      supported_transports: A list of supported transport types (e.g. "tcp", "unix").
    """

    magic_cookie_key: str
    magic_cookie_value: str
    protocol_versions: list[int]
    supported_transports: list[str]


def is_valid_handshake_parts(parts: list[str]) -> TypeGuard[list[str]]:
    """
    🔍✅ TypeGuard: Verifies the handshake response format.
    Ensures it contains exactly 6 parts and the first two parts are digits.
    """
    return len(parts) == 6 and parts[0].isdigit() and parts[1].isdigit()


def _split_handshake_response(response: str) -> list[str]:
    if not isinstance(response, str):
        raise HandshakeError(
            message="Handshake response is not a string.",
            hint="Ensure the plugin process outputs a valid string for handshake.",
        )
    parts = response.strip().split("|")
    logger.debug(f"📡🔍 Split handshake response into parts: {parts}")
    if not is_valid_handshake_parts(parts):
        logger.error(
            "📡❌ Invalid handshake response format. Expected 6 parts with numeric versions.",
            parts=parts,
        )
        raise HandshakeError(
            message=(
                "Invalid handshake format. Expected 6 pipe-separated parts, got "
                f"{len(parts)}: '{response[:100]}...'"
            ),
            hint=("Ensure the plugin's handshake output matches 'CORE_VER|PLUGIN_VER|NET|ADDR|PROTO|CERT'."),
        )
    return parts


def _parse_versions(parts: list[str]) -> tuple[int, int]:
    try:
        return int(parts[0]), int(parts[1])
    except ValueError as exc:
        raise HandshakeError(
            message=(f"Invalid version numbers in handshake: '{parts[0]}', '{parts[1]}'."),
            hint="Core and plugin versions in the handshake string must be integers.",
        ) from exc


def _validate_network(network: str, address: str, original: str) -> None:
    if network not in ("tcp", "unix"):
        logger.error("📡❌ Invalid network type in handshake", network=network)
        raise HandshakeError(
            message=f"Invalid network type '{network}' in handshake.",
            hint="Network type must be 'tcp' or 'unix'.",
        )
    if network == "tcp" and not address:
        logger.error(
            "📡❌ Empty address received for TCP transport in handshake",
            handshake=original,
        )
        raise HandshakeError(
            message="Empty address received in handshake string for TCP transport.",
            hint="TCP transport requires a valid address (host:port).",
        )


def _prepare_server_cert(raw_part: str) -> str | None:
    if not raw_part:
        return None
    temp_cert = raw_part.replace("\\n", "").replace("\\r", "")
    return temp_cert.replace("\n", "").replace("\r", "").strip()


def _resolve_expected_core_version() -> int:
    """
    Resolve the expected core version from configuration, falling back to 1 on misconfiguration.
    """
    expected_value = rpcplugin_config.plugin_core_version
    logger.debug(
        f"📡🔍 Retrieved PLUGIN_CORE_VERSION from config: {expected_value} (type: {type(expected_value)})"
    )
    if expected_value is None:
        logger.error(
            "CRITICAL: PLUGIN_CORE_VERSION is None from rpcplugin_config. Falling back to schema default 1."
        )
        return 1

    try:
        return int(expected_value)
    except (TypeError, ValueError) as exc:
        logger.error(
            f"CRITICAL: Could not convert PLUGIN_CORE_VERSION '{expected_value}' to int. Falling back to default 1.",
            exc_info=exc,
        )
        return 1


def _ensure_supported_core_version(core_version: int, expected_version: int) -> None:
    if core_version != expected_version:
        logger.error(f"🤝 Unsupported handshake version: {core_version} (expected: {expected_version})")
        raise HandshakeError(f"Unsupported handshake version: {core_version} (expected: {expected_version})")


def _apply_certificate_padding(server_cert: str | None) -> str | None:
    if not server_cert:
        return None
    padding = len(server_cert) % 4
    if padding:
        logger.debug("📡🔐 Restoring certificate padding for handshake parsing.")
        server_cert += "=" * (4 - padding)
    return server_cert


@resilient(
    context={"operation": "validate_magic_cookie", "component": "handshake"},
    log_errors=True,
)
def validate_magic_cookie(
    magic_cookie_key: str | None | _SentinelType = _SENTINEL_INSTANCE,
    magic_cookie_value: str | None | _SentinelType = _SENTINEL_INSTANCE,
    magic_cookie: str | None | _SentinelType = _SENTINEL_INSTANCE,
) -> None:
    """
    Validates the magic cookie.

    If a parameter is omitted (i.e. remains as the sentinel),
    its value is read from rpcplugin_config. However, if the caller
    explicitly passes None, that is treated as missing and an error is raised.

    Args:
        magic_cookie_key: The environment key for the magic cookie.
        magic_cookie_value: The expected value of the magic cookie.
        magic_cookie: The actual cookie value provided.

    Raises:
        HandshakeError: If cookie validation fails.
    """
    if _tracer:
        with _tracer.start_as_current_span("rpc.handshake.validate_cookie") as span:
            span.set_attribute("component", "handshake")
            _validate_magic_cookie_impl(magic_cookie_key, magic_cookie_value, magic_cookie)
    else:
        _validate_magic_cookie_impl(magic_cookie_key, magic_cookie_value, magic_cookie)


def _validate_magic_cookie_impl(
    magic_cookie_key: str | None | _SentinelType,
    magic_cookie_value: str | None | _SentinelType,
    magic_cookie: str | None | _SentinelType,
) -> None:
    """Implementation of magic cookie validation."""
    logger.debug("Starting magic cookie validation...")

    cookie_key: str | None = (  # type: ignore[assignment]
        rpcplugin_config.plugin_magic_cookie_key
        if magic_cookie_key is _SENTINEL_INSTANCE
        else magic_cookie_key
    )

    # Determine the expected cookie value for the logic, resolving sentinel.
    # Parameter 'magic_cookie_value' can be str | None | _SentinelType.
    # 'rpcplugin_config.magic_cookie_value()' returns str.
    # So, 'expected_value_for_logic' will be str | None.
    expected_value_for_logic: str | None
    if magic_cookie_value is _SENTINEL_INSTANCE:
        expected_value_for_logic = rpcplugin_config.plugin_magic_cookie_value
    else:
        expected_value_for_logic = magic_cookie_value

    # Determine the actual cookie value that was provided by the client/environment.
    # Parameter 'magic_cookie' can be str | None | _SentinelType.
    cookie_provided_by_caller: str | None
    if magic_cookie is _SENTINEL_INSTANCE:
        # If magic_cookie param is sentinel, then we MUST read from env.
        if cookie_key is None or cookie_key == "":
            logger.error("CRITICAL: cookie_key is None or empty before env lookup.")
            raise HandshakeError(
                message="Internal configuration error: cookie_key is missing for lookup.",
                hint="Ensure PLUGIN_MAGIC_COOKIE_KEY is properly configured.",
            )
        cookie_provided_by_caller = os.environ.get(str(cookie_key))
        logger.debug(f"Read magic_cookie from env var '{cookie_key}': '{cookie_provided_by_caller}'")
    else:
        # If magic_cookie param was explicitly passed (even if None), use that.
        cookie_provided_by_caller = magic_cookie
        logger.debug(f"Using explicitly passed magic_cookie parameter: '{cookie_provided_by_caller}'")

    logger.debug(f"Final cookie_key for validation: {cookie_key}")
    logger.debug(f"Expected cookie value (for logic): {expected_value_for_logic}")
    logger.debug(f"Cookie provided by caller/env: {cookie_provided_by_caller}")

    if cookie_key is None or cookie_key == "":  # This check is for the config of the key itself
        logger.error("Configuration error: magic_cookie_key is not set in config.")
        raise HandshakeError(
            message="Magic cookie key is not configured.",
            hint=("Ensure 'PLUGIN_MAGIC_COOKIE_KEY' is defined in the application configuration."),
        )

    if expected_value_for_logic is None or expected_value_for_logic == "":
        logger.error("Configuration error: magic_cookie_value (expected) is not set in config.")
        raise HandshakeError(
            message="Expected magic cookie value is not configured.",
            hint=("Ensure 'PLUGIN_MAGIC_COOKIE_VALUE' is defined in the application configuration."),
        )

    if cookie_provided_by_caller is None or cookie_provided_by_caller == "":
        logger.error(
            "Magic cookie not provided by the client.",
            cookie_key_expected=cookie_key,
        )
        raise HandshakeError(
            message=(
                "Magic cookie not provided by the client. Expected via environment "
                f"variable '{cookie_key}' (if not passed directly to validation)."
            ),
            hint=(
                "Ensure the client process (e.g., Terraform or other plugin host) "
                f"is configured to send the '{cookie_key}' environment variable "
                "with the correct magic cookie value, or that it's passed directly."
            ),
        )

    if cookie_provided_by_caller != expected_value_for_logic:
        logger.error(
            "Magic cookie mismatch.",
            expected=expected_value_for_logic,
            received=cookie_provided_by_caller,
            cookie_key=cookie_key,
        )
        raise HandshakeError(
            message=(
                f"Magic cookie mismatch. Expected: '{expected_value_for_logic}', Received: "
                f"'{cookie_provided_by_caller}'."
            ),
            hint=(
                f"Verify that the environment variable '{cookie_key}' set by the "
                "client matches the server's expected 'PLUGIN_MAGIC_COOKIE_VALUE'."
            ),
        )

    logger.debug("Magic cookie validated successfully.")


@resilient(
    context={"operation": "build_handshake_response", "component": "handshake"},
    log_errors=True,
)
async def build_handshake_response(
    plugin_version: int,
    transport_name: str,
    transport: TransportT,
    server_cert: Certificate | None = None,
    port: int | None = None,
) -> str:
    """
    🤝📝✅ Constructs the handshake response string in the format:
    CORE_VERSION|PLUGIN_VERSION|NETWORK|ADDRESS|PROTOCOL|TLS_CERT

    Note: For TCP transport, the ADDRESS `127.0.0.1` is standard for same-host
    plugin communication, ensuring the plugin host connects to the plugin
    locally. The actual listening interface might be broader (e.g., `0.0.0.0`),
    but the handshake communicates `127.0.0.1` for the host to connect to.

    Args:
        plugin_version: The version of the plugin.
        transport_name: The name of the transport ("tcp" or "unix").
        transport: The transport instance.
        server_cert: Optional server certificate for TLS.
        port: Optional port number, required for TCP transport.

    Returns:
        The constructed handshake response string.

    Raises:
        ValueError: If required parameters are missing (e.g., port for TCP).
        TransportError: If an unsupported transport type is given.
        Exception: Propagates exceptions from underlying operations.
    """
    if _tracer:
        with _tracer.start_as_current_span("rpc.handshake.build_response") as span:
            span.set_attribute("transport", transport_name)
            span.set_attribute("plugin_version", plugin_version)
            span.set_attribute("has_cert", server_cert is not None)
            return await _build_handshake_response_impl(
                plugin_version, transport_name, transport, server_cert, port
            )
    else:
        return await _build_handshake_response_impl(
            plugin_version, transport_name, transport, server_cert, port
        )


async def _build_handshake_response_impl(
    plugin_version: int,
    transport_name: str,
    transport: TransportT,
    server_cert: Certificate | None = None,
    port: int | None = None,
) -> str:
    """Implementation of handshake response building."""
    logger.debug("🤝📝🔄 Building handshake response...")

    try:
        if transport_name == "tcp":
            if port is None:
                logger.error("🤝📝❌ TCP transport requires a valid port for handshake response.")
                raise HandshakeError(
                    message=("TCP transport requires a port number to build handshake response."),
                    hint=(
                        "Ensure the port is correctly passed to build_handshake_response for TCP transport."
                    ),
                )
            endpoint = f"127.0.0.1:{port}"
            logger.debug(f"🤝📝✅ TCP endpoint set: {endpoint}")

        elif transport_name == "unix":
            if hasattr(transport, "_running") and transport._running and transport.endpoint:
                logger.debug(f"🤝📝✅ Using existing Unix transport endpoint: {transport.endpoint}")
                endpoint = transport.endpoint
            else:
                logger.debug("🤝📝🔄 Waiting for Unix transport to listen...")
                endpoint = await transport.listen()
                logger.debug(f"🤝📝✅ Unix transport endpoint received: {endpoint}")
        else:
            logger.error(f"🤝📝❌ Unsupported transport type for handshake response: {transport_name}")
            raise TransportError(
                message=(f"Unsupported transport type specified for handshake response: '{transport_name}'."),
                hint="Valid transport types are 'unix' or 'tcp'.",
            )

        response_parts = [
            str(rpcplugin_config.plugin_core_version),
            str(plugin_version),
            transport_name,
            endpoint,
            "grpc",
            "",
        ]
        logger.debug(f"🤝📝🔄 Base response structure: {response_parts}")

        if server_cert:
            logger.debug("🤝🔐🔄 Processing server certificate...")
            cert_lines = server_cert.cert_pem.strip().split("\n")
            if len(cert_lines) < 3:
                logger.error(
                    "🤝🔐❌ Server certificate appears to be in an invalid PEM format (too few lines)."
                )
                raise HandshakeError(
                    message=("Invalid server certificate format provided for handshake response."),
                    hint=("Ensure the server certificate is a valid PEM-encoded X.509 certificate."),
                )
            cert_body = "".join(cert_lines[1:-1]).rstrip("=")
            response_parts[-1] = cert_body
            logger.debug("🤝🔐✅ Certificate data added to response.")

        handshake_response = "|".join(response_parts)
        logger.debug(f"🤝📝✅ Handshake response successfully built: {handshake_response}")
        return handshake_response

    except Exception as e:
        logger.error(f"🤝📝❌ Handshake response build failed: {e}", error=str(e))
        raise HandshakeError(
            message=f"Failed to build handshake response: {e}",
            hint="Review server logs for details on the failure.",
        ) from e


@resilient(
    context={"operation": "parse_handshake_response", "component": "handshake"},
    log_errors=True,
)
def parse_handshake_response(
    response: str,
) -> tuple[int, int, str, str, str, str | None]:
    """
    (📡🔍 Handshake Parsing) Parses the handshake response string.
    Expected Format: CORE_VERSION|PLUGIN_VERSION|NETWORK|ADDRESS|PROTOCOL|TLS_CERT

    Args:
        response: The handshake response string to parse.

    Returns:
        A tuple containing:
            - core_version (int)
            - plugin_version (int)
            - network (str)
            - address (str)
            - protocol (str)
            - server_cert (str | None)

    Raises:
        HandshakeError: If parsing fails or the format is invalid.
        ValueError: If parts of the handshake string are invalid
                    (e.g., non-integer versions).
    """
    if _tracer:
        with _tracer.start_as_current_span("rpc.handshake.parse_response") as span:
            # Only set response_length if response is a string
            if isinstance(response, str):
                span.set_attribute("response_length", len(response))
            return _parse_handshake_response_impl(response, span)
    else:
        return _parse_handshake_response_impl(response, None)


def _parse_handshake_response_impl(
    response: str,
    span: object | None = None,  # Optional span for adding attributes
) -> tuple[int, int, str, str, str, str | None]:
    """Implementation of handshake response parsing."""
    logger.debug(f"📡🔍 Starting handshake response parsing for: {response}")
    try:
        parts = _split_handshake_response(response)
        core_version, plugin_version = _parse_versions(parts)
        network = parts[2]
        address = parts[3]
        _validate_network(network, address, response)
        protocol = parts[4]
        server_cert = _prepare_server_cert(parts[5])
        expected_core_version_int = _resolve_expected_core_version()
        _ensure_supported_core_version(core_version, expected_core_version_int)
        server_cert = _apply_certificate_padding(server_cert)

        # Add attributes to span if available
        if span:
            span.set_attribute("network", network)
            span.set_attribute("protocol", protocol)
            span.set_attribute("core_version", core_version)
            span.set_attribute("plugin_version", plugin_version)
            span.set_attribute("has_cert", server_cert is not None)

        logger.debug(
            "📡✅ Handshake parsing success: "
            f"core_version={core_version}, plugin_version={plugin_version}, "
            f"network={network}, address={address}, protocol={protocol}, "
            f"server_cert={'present' if server_cert else 'none'}"
        )
        return core_version, plugin_version, network, address, protocol, server_cert

    except Exception as e:
        logger.error(f"📡❌ Handshake parsing failed: {e}", error=str(e))
        raise HandshakeError(f"Failed to parse handshake response: {e}") from e
