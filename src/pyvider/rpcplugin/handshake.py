#!/usr/bin/env python3
"""
pyvider/rpcplugin/handshake.py

This module implements handshake logic for the RPC plugin server.
It includes:
  - HandshakeConfig and HandshakeParts data classes.
  - Functions for protocol version negotiation, transport validation,
    handshake response building, magic cookie validation, and handshake
    response parsing.

All logging follows our three‑emoji style to clearly indicate component,
action, and result. Detailed error handling and inline comments are included
for clarity and debugging.
"""

import os
from typing import TypeGuard

import attrs

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.crypto import Certificate
from pyvider.rpcplugin.exception import HandshakeError, ProtocolError, TransportError
from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.transport.types import TransportT

# Use a sentinel value to detect omitted parameters.
_SENTINEL = object()


@attrs.define
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


@attrs.define
class HandshakeParts:
    """
    🤝📝✅ Represents the parts of the handshake response.

    Attributes:
      core_version: The core protocol version.
      plugin_version: The plugin’s protocol version.
      network: The transport/network type (e.g. "tcp" or "unix").
      address: The network address or socket path.
      protocol: The communication protocol (currently fixed as "grpc").
      server_cert: The formatted server certificate (if applicable).
    """

    core_version: int
    plugin_version: int
    network: str
    address: str
    protocol: str
    server_cert: str | None


def validate_transport(transport_name: str, supported_transports: list[str]) -> None:
    """
    🚂🔍 Validates whether the specified transport is supported.

    Raises:
      TransportError: If the transport_name is not in the supported_transports.
    """
    logger.debug(
        f"🤝🚂🔍 Checking transport: {transport_name} against supported list: {supported_transports}"
    )
    if transport_name not in supported_transports:
        logger.error(
            f"🤝🚂❌ Unsupported transport detected: {transport_name}",
            extra={"transport": transport_name},
        )
        raise TransportError(f"Unsupported transport: {transport_name}")
    logger.debug(f"🤝🚂✅ Transport '{transport_name}' is supported.")

def negotiate_protocol_version(server_versions: list[int]) -> int:
    """
    🤝🔄 Selects the highest mutually supported protocol version.

    Compares the server-provided versions against the client's supported versions
    from the configuration.

    Returns:
      The highest mutually supported protocol version.

    Raises:
      ProtocolError: If no mutually supported version is found.
    """
    logger.debug(
        f"🤝🔄 Negotiating protocol version. Server supports: {server_versions}"
    )
    SUPPORTED_PROTOCOL_VERSIONS = rpcplugin_config.get("SUPPORTED_PROTOCOL_VERSIONS")
    for version in sorted(server_versions, reverse=True):
        if version in SUPPORTED_PROTOCOL_VERSIONS:
            logger.info(f"🤝✅ Selected protocol version: {version}")
            return version

    logger.error(
        f"🤝❌ Protocol negotiation failed: No compatible version found. "
        f"Server supports: {server_versions}, Client supports: {SUPPORTED_PROTOCOL_VERSIONS}"
    )
    raise ProtocolError(
        f"No mutually supported protocol version found. Server supports: {server_versions}, "
        f"Client supports: {SUPPORTED_PROTOCOL_VERSIONS}"
    )

################################################################################
# Apply to src/pyvider/rpcplugin/handshake.py

# Modify negotiate_transport to prioritize Unix socket (more robust)
async def negotiate_transport(server_transports: list[str]) -> tuple[str, TransportT]:
    """
    (🗣️🚊 Transport Negotiation) Negotiates the transport type with the server and
    creates the appropriate transport instance.

    Returns:
      A tuple of (transport_name, transport_instance).

    Raises:
      TransportError: If no compatible transport can be negotiated.
    """
    logger.debug(
        f"🗣️🚊 (Transport Negotiation: Starting) => Available transports: {server_transports}"
    )
    if not server_transports:
        logger.error(
            "🗣️🚊❌ (Transport Negotiation: Failed) => No transport options provided"
        )
        raise TransportError("No transport options provided")
    try:
        # Reverse the preference - prioritize Unix sockets first
        if "unix" in server_transports:
            logger.debug(
                "🗣️🚊🧦 (Transport Negotiation: Selected Unix) => Unix socket transport is available"
            )
            transport_path = os.path.join(
                os.environ.get("TEMP_DIR", "/tmp"), f"pyvider-{os.getpid()}.sock"
            )
            from pyvider.rpcplugin.transport import UnixSocketTransport

            return "unix", UnixSocketTransport(path=transport_path)
        elif "tcp" in server_transports:
            logger.debug(
                "🗣️🚊👥 (Transport Negotiation: Selected TCP) => TCP transport is available"
            )
            from pyvider.rpcplugin.transport import TCPSocketTransport

            return "tcp", TCPSocketTransport()
        else:
            logger.error(
                "🗣️🚊❌ (Transport Negotiation: Failed) => No supported transport found",
                extra={"server_transports": server_transports},
            )
            raise TransportError(f"Unsupported transports: {server_transports}")
    except Exception as e:
        logger.error(
            "🗣️🚊❌ (Transport Negotiation: Exception) => Error during transport negotiation",
            extra={"error": str(e)},
        )
        raise TransportError(f"Error negotiating transport: {e}") from e

################################################################################

async def X1_negotiate_transport(server_transports: list[str]) -> tuple[str, TransportT]:
    """
    (🗣️🚊 Transport Negotiation) Negotiates the transport type with the server and
    creates the appropriate transport instance.

    Returns:
      A tuple of (transport_name, transport_instance).

    Raises:
      TransportError: If no compatible transport can be negotiated.
    """
    logger.debug(
        f"🗣️🚊 (Transport Negotiation: Starting) => Available transports: {server_transports}"
    )
    if not server_transports:
        logger.error(
            "🗣️🚊❌ (Transport Negotiation: Failed) => No transport options provided"
        )
        raise TransportError("No transport options provided")
    try:
        if "tcp" in server_transports:
            logger.debug(
                "🗣️🚊👥 (Transport Negotiation: Selected TCP) => TCP transport is available"
            )
            from pyvider.rpcplugin.transport import TCPSocketTransport

            return "tcp", TCPSocketTransport()
        elif "unix" in server_transports:
            logger.debug(
                "🗣️🚊🧦 (Transport Negotiation: Selected Unix) => Unix socket transport is available"
            )
            transport_path = os.path.join(
                os.environ.get("TEMP_DIR", "/tmp"), f"pyvider-{os.getpid()}.sock"
            )
            from pyvider.rpcplugin.transport import UnixSocketTransport

            return "unix", UnixSocketTransport(path=transport_path)
        else:
            logger.error(
                "🗣️🚊❌ (Transport Negotiation: Failed) => No supported transport found",
                extra={"server_transports": server_transports},
            )
            raise TransportError(f"Unsupported transports: {server_transports}")
    except Exception as e:
        logger.error(
            "🗣️🚊❌ (Transport Negotiation: Exception) => Error during transport negotiation",
            extra={"error": str(e)},
        )
        raise TransportError(f"Error negotiating transport: {e}") from e

################################################################################

def is_valid_handshake_parts(parts: list[str]) -> TypeGuard[list[str]]:
    """
    🔍✅ TypeGuard: Verifies the handshake response format.
    Ensures it contains exactly 6 parts and the first two parts are digits.
    """
    return len(parts) == 6 and parts[0].isdigit() and parts[1].isdigit()

def validate_magic_cookie(
    magic_cookie_key: str | None = _SENTINEL,
    magic_cookie_value: str | None = _SENTINEL,
    magic_cookie: str | None = _SENTINEL,
) -> None:
    """
    🍪🔍 Validates the magic cookie.

    If a parameter is omitted (i.e. remains as the sentinel),
    its value is read from rpcplugin_config. However, if the caller
    explicitly passes None, that is treated as missing and an error is raised.
    """
    logger.debug("🍪🔍 Starting magic cookie validation...")

    cookie_key = (
        rpcplugin_config.magic_cookie_key()
        if magic_cookie_key is _SENTINEL
        else magic_cookie_key
    )
    cookie_value = (
        rpcplugin_config.magic_cookie_value()
        if magic_cookie_value is _SENTINEL
        else magic_cookie_value
    )
    cookie_provided = (
        rpcplugin_config.get("PLUGIN_MAGIC_COOKIE")
        if magic_cookie is _SENTINEL
        else magic_cookie
    )

    logger.debug(f"🍪 cookie_key: {cookie_key}")
    logger.debug(f"🍪 cookie_value: {cookie_value}")
    logger.debug(f"🍪 cookie_provided: {cookie_provided}")

    if cookie_key is None or cookie_key == "":
        logger.error("🍪🪄❌ cookie_key not found")
        raise HandshakeError("cookie_key not found")

    if cookie_value is None or cookie_value == "":
        logger.error("🍪🪄❌ Magic cookie value not found.")
        raise HandshakeError("Magic cookie value not found.")

    if cookie_provided is None or cookie_provided == "":
        logger.error("🍪🪄❌ Magic cookie not provided.")
        raise HandshakeError("Magic cookie not provided.")

    if cookie_provided != cookie_value:
        logger.error(
            "🍪❌ cookie_provided does not match required cookie_value",
            extra={"expected": cookie_value, "received": cookie_provided},
        )
        raise HandshakeError("cookie_provided does not match required cookie_value")

    logger.debug("🍪✅ Magic cookie validated successfully.")

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
    """
    logger.debug("🤝📝🔄 Building handshake response...")

    try:
        if transport_name == "tcp":
            if port is None:
                logger.error("🤝📝❌ TCP transport requires a valid port.")
                raise ValueError("TCP transport requires a valid port.")
            endpoint = f"127.0.0.1:{port}"
            logger.debug(f"🤝📝✅ TCP endpoint set: {endpoint}")

        elif transport_name == "unix":
            if hasattr(transport, '_running') and transport._running and transport.endpoint:
                logger.debug(f"🤝📝✅ Using existing Unix transport endpoint: {transport.endpoint}")
                endpoint = transport.endpoint
            else:
                logger.debug("🤝📝🔄 Waiting for Unix transport to listen...")
                endpoint = await transport.listen()
                logger.debug(f"🤝📝✅ Unix transport endpoint received: {endpoint}")
        else:
            logger.error(f"🤝📝❌ Unsupported transport type: {transport_name}")
            raise TransportError(f"Unsupported transport: {transport_name}")

        response_parts = [
            str(rpcplugin_config.get("PLUGIN_CORE_VERSION")),
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
                logger.error("🤝🔐❌ Invalid certificate format.")
                raise ValueError("Invalid certificate format")
            # Remove header and footer, then remove trailing '=' characters.
            cert_body = "".join(cert_lines[1:-1]).rstrip("=")
            response_parts[-1] = cert_body
            logger.debug("🤝🔐✅ Certificate data added to response.")

        handshake_response = "|".join(response_parts)
        logger.debug(
            f"🤝📝✅ Handshake response successfully built: {handshake_response}"
        )
        return handshake_response

    except Exception as e:
        logger.error(
            f"🤝📝❌ Handshake response build failed: {e}", extra={"error": str(e)}
        )
        raise


def parse_handshake_response(
    response: str,
) -> tuple[int, int, str, str, str, str | None]:
    """
    (📡🔍 Handshake Parsing) Parses the handshake response string.
    Expected Format: CORE_VERSION|PLUGIN_VERSION|NETWORK|ADDRESS|PROTOCOL|TLS_CERT
    """
    logger.debug(f"📡🔍 Starting handshake response parsing for: {response}")
    try:
        if not isinstance(response, str):
            raise ValueError("Handshake response is not a string")
        parts = response.strip().split("|")
        logger.debug(f"📡🔍 Split handshake response into parts: {parts}")
        if not is_valid_handshake_parts(parts):
            logger.error(
                f"📡❌ Invalid handshake response format. Expected 6 parts, got {len(parts)}",
                extra={"parts": parts},
            )
            raise ValueError(f"Expected 6 parts, got {len(parts)}")
        core_version = int(parts[0])
        plugin_version = int(parts[1])
        network = parts[2]
        if network not in ("tcp", "unix"):
            logger.error(
                f"📡❌ Invalid network type: {network}", extra={"network": network}
            )
            raise ValueError(f"Invalid network type: {network}")
        address = parts[3]
        protocol = parts[4]
        server_cert = parts[5] if parts[5] else None

        if core_version != int(rpcplugin_config.get("PLUGIN_CORE_VERSION")):
            logger.error(f"🤝 Unsupported handshake version: {core_version}")
            raise HandshakeError(f"Unsupported handshake version: {core_version}")

        if server_cert:
            padding = len(server_cert) % 4
            if padding:
                server_cert += "=" * (4 - padding)
            logger.debug("📡🔐 Restored certificate padding for handshake parsing.")

        logger.debug(
            f"📡✅ Handshake parsing success: core_version={core_version}, plugin_version={plugin_version}, network={network}, address={address}, protocol={protocol}, server_cert={'present' if server_cert else 'none'}"
        )
        return core_version, plugin_version, network, address, protocol, server_cert

    except Exception as e:
        logger.error(f"📡❌ Handshake parsing failed: {e}", extra={"error": str(e)})
        raise HandshakeError(f"Failed to parse handshake response: {e}") from e


### 🐍🏗️🔌
