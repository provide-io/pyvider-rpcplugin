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
from provide.foundation import logger
from provide.foundation.crypto import Certificate

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import HandshakeError, TransportError
from pyvider.rpcplugin.transport.types import TransportT


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
    logger.debug("Starting magic cookie validation...")

    cookie_key: str | None = (  # type: ignore[assignment]
        rpcplugin_config.plugin_magic_cookie_key if magic_cookie_key is _SENTINEL_INSTANCE else magic_cookie_key
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
            extra={"cookie_key_expected": cookie_key},
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
            extra={
                "expected": expected_value_for_logic,
                "received": cookie_provided_by_caller,
                "cookie_key": cookie_key,
            },
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
            cert_lines = server_cert.cert.strip().split("\n")
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
        logger.error(f"🤝📝❌ Handshake response build failed: {e}", extra={"error": str(e)})
        raise HandshakeError(
            message=f"Failed to build handshake response: {e}",
            hint="Review server logs for details on the failure.",
        ) from e


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
    logger.debug(f"📡🔍 Starting handshake response parsing for: {response}")
    try:
        if not isinstance(response, str):
            raise HandshakeError(
                message="Handshake response is not a string.",
                hint="Ensure the plugin process outputs a valid string for handshake.",
            )
        parts = response.strip().split("|")
        logger.debug(f"📡🔍 Split handshake response into parts: {parts}")
        if not is_valid_handshake_parts(parts):
            logger.error(
                "📡❌ Invalid handshake response format. Expected 6 parts with "
                f"numeric versions, got {len(parts)} parts.",
                extra={"parts": parts},
            )
            raise HandshakeError(
                message=(
                    "Invalid handshake format. Expected 6 pipe-separated parts, got "
                    f"{len(parts)}: '{response[:100]}...'"
                ),
                hint=(
                    "Ensure the plugin's handshake output matches 'CORE_VER|PLUGIN_VER|NET|ADDR|PROTO|CERT'."
                ),
            )
        try:
            core_version = int(parts[0])
            plugin_version = int(parts[1])
        except ValueError as e_ver:
            raise HandshakeError(
                message=(f"Invalid version numbers in handshake: '{parts[0]}', '{parts[1]}'."),
                hint=("Core and plugin versions in the handshake string must be integers."),
            ) from e_ver

        network = parts[2]
        if network not in ("tcp", "unix"):
            logger.error(
                f"📡❌ Invalid network type in handshake: {network}",
                extra={"network": network},
            )
            raise HandshakeError(
                message=f"Invalid network type '{network}' in handshake.",
                hint="Network type must be 'tcp' or 'unix'.",
            )
        address = parts[3]
        if network == "tcp" and not address:
            logger.error(
                f"📡❌ Empty address received for TCP transport in handshake: {response}",
                extra={"address": address},
            )
            raise HandshakeError(
                message="Empty address received in handshake string for TCP transport.",
                hint="TCP transport requires a valid address (host:port).",
            )
        protocol = parts[4]
        raw_server_cert_part = parts[5] if parts[5] else None
        if raw_server_cert_part:
            temp_cert = raw_server_cert_part.replace("\\n", "").replace("\\r", "")
            server_cert = temp_cert.replace("\n", "").replace("\r", "").strip()
        else:
            server_cert = None

        expected_core_version_from_config = rpcplugin_config.plugin_core_version
        logger.debug(
            "📡🔍 Retrieved PLUGIN_CORE_VERSION from config: "
            f"{expected_core_version_from_config} "
            f"(type: {type(expected_core_version_from_config)})"
        )

        if expected_core_version_from_config is None:
            logger.error(
                "CRITICAL: PLUGIN_CORE_VERSION is None from rpcplugin_config. "
                "Falling back to schema default 1."
            )
            expected_core_version_int = 1
        else:
            try:
                expected_core_version_int = int(expected_core_version_from_config)
            except (ValueError, TypeError) as e:
                logger.error(
                    "CRITICAL: Could not convert PLUGIN_CORE_VERSION "
                    f"'{expected_core_version_from_config}' to int. Error: {e}. "
                    "Falling back to default 1."
                )
                expected_core_version_int = 1

        if core_version != expected_core_version_int:
            logger.error(
                f"🤝 Unsupported handshake version: {core_version} (expected: {expected_core_version_int})"
            )
            raise HandshakeError(
                f"Unsupported handshake version: {core_version} (expected: {expected_core_version_int})"
            )

        if server_cert:
            padding = len(server_cert) % 4
            if padding:
                server_cert += "=" * (4 - padding)
            logger.debug("📡🔐 Restored certificate padding for handshake parsing.")

        logger.debug(
            "📡✅ Handshake parsing success: "
            f"core_version={core_version}, plugin_version={plugin_version}, "
            f"network={network}, address={address}, protocol={protocol}, "
            f"server_cert={'present' if server_cert else 'none'}"
        )
        return core_version, plugin_version, network, address, protocol, server_cert

    except Exception as e:
        logger.error(f"📡❌ Handshake parsing failed: {e}", extra={"error": str(e)})
        raise HandshakeError(f"Failed to parse handshake response: {e}") from e
