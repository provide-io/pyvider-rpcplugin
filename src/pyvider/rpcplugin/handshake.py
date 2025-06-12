"""This module implements handshake logic for the RPC plugin server.
It includes:
  - HandshakeConfig data classes.
  - Functions for protocol version negotiation, transport validation,
    handshake response building, magic cookie validation, and handshake
    response parsing.

All logging follows our three‑emoji style to clearly indicate component,
action, and result. Detailed error handling and inline comments are included
for clarity and debugging.
"""

import asyncio
import os
import time
import traceback
from typing import TypeGuard

from attrs import define

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.crypto import Certificate
from pyvider.rpcplugin.exception import HandshakeError, ProtocolError, TransportError
from pyvider.telemetry import logger
from pyvider.rpcplugin.transport.types import TransportT

# Use a sentinel value to detect omitted parameters.
from enum import Enum, auto
from typing import Literal, cast # Ensure Literal and cast are imported

class _SentinelEnum(Enum):
    NOT_PASSED = auto()

_SENTINEL_INSTANCE = _SentinelEnum.NOT_PASSED
_SentinelType = Literal[_SentinelEnum.NOT_PASSED]


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


async def negotiate_transport(server_transports: list[str]) -> tuple[str, TransportT]:
    """
    (🗣️🚊 Transport Negotiation) Negotiates the transport type with the server and
    creates the appropriate transport instance.

    Returns:
      A tuple of (transport_name, transport_instance).

    Raises:
      TransportError: If no compatible transport can be negotiated or an error occurs during negotiation.
    """
    import tempfile # Ensure tempfile is imported here for use below

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
            import tempfile # Ensure tempfile is imported
            # Use tempfile.gettempdir() for a safer temporary directory
            temp_dir = os.environ.get("TEMP_DIR") or tempfile.gettempdir()
            transport_path = os.path.join(
                temp_dir, f"pyvider-{os.getpid()}.sock"
            )
            from pyvider.rpcplugin.transport import UnixSocketTransport

            return "unix", cast(TransportT, UnixSocketTransport(path=transport_path))

        elif "tcp" in server_transports:
            logger.debug(
                "🗣️🚊👥 (Transport Negotiation: Selected TCP) => TCP transport is available"
            )
            from pyvider.rpcplugin.transport import TCPSocketTransport

            return "tcp", cast(TransportT, TCPSocketTransport())
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
    🍪🔍 Validates the magic cookie.

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
    logger.debug("🍪🔍 Starting magic cookie validation...")

    cookie_key = (
        rpcplugin_config.magic_cookie_key()
        if magic_cookie_key is _SENTINEL_INSTANCE
        else magic_cookie_key
    )
    cookie_value = (
        rpcplugin_config.magic_cookie_value()
        if magic_cookie_value is _SENTINEL_INSTANCE
        else magic_cookie_value
    )
    cookie_provided = (
        rpcplugin_config.get("PLUGIN_MAGIC_COOKIE")
        if magic_cookie is _SENTINEL_INSTANCE
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
        ValueError: If parts of the handshake string are invalid (e.g., non-integer versions).
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

        expected_core_version_from_config = rpcplugin_config.get("PLUGIN_CORE_VERSION")
        logger.debug(f"📡🔍 Retrieved PLUGIN_CORE_VERSION from config: {expected_core_version_from_config} (type: {type(expected_core_version_from_config)})")

        if expected_core_version_from_config is None:
            logger.error("CRITICAL: PLUGIN_CORE_VERSION is None from rpcplugin_config. Falling back to schema default 1.")
            expected_core_version_int = 1
        else:
            try:
                expected_core_version_int = int(expected_core_version_from_config)
            except (ValueError, TypeError) as e:
                logger.error(f"CRITICAL: Could not convert PLUGIN_CORE_VERSION '{expected_core_version_from_config}' to int. Error: {e}. Falling back to default 1.")
                expected_core_version_int = 1
        
        if core_version != expected_core_version_int:
            logger.error(f"🤝 Unsupported handshake version: {core_version} (expected: {expected_core_version_int})")
            raise HandshakeError(f"Unsupported handshake version: {core_version} (expected: {expected_core_version_int})")

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

async def read_handshake_response(process) -> str:
    """
    Robust handshake response reader with multiple strategies to handle
    different Go-Python interop challenges.
    
    The handshake response is a pipe-delimited string with format:
    CORE_VERSION|PLUGIN_VERSION|NETWORK|ADDRESS|PROTOCOL|TLS_CERT
    
    Args:
        process: The subprocess.Popen instance representing the plugin.
        
    Returns:
        The complete handshake response string.
        
    Raises:
        HandshakeError: If handshake fails (e.g. process exits early) or times out.
    """
    if not process or not process.stdout:
        raise HandshakeError("No plugin process or stdout stream available")
    
    logger.debug("🤝📥🚀 Reading handshake response from plugin process...")
    
    # Use longer timeout for initial handshake
    timeout = 10.0  # seconds
    start_time = time.time()
    buffer = ""
    
    while (time.time() - start_time) < timeout:
        # Check if process has exited
        if process.poll() is not None:
            stderr_output = ""
            if process.stderr:
                try:
                    stderr_output = process.stderr.read().decode('utf-8', errors='replace')
                except Exception as e:
                    stderr_output = f"Error reading stderr: {e}"
            
            logger.error(f"🤝📥❌ Plugin process exited with code {process.returncode} before handshake")
            raise HandshakeError(
                f"Plugin process exited with code {process.returncode} before completing handshake. "
                f"Stderr: {stderr_output}"
            )
            
        # Read strategies
        try:
            # Strategy 1: Try to read a complete line first
            line_bytes = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None, lambda: process.stdout.readline()
                ),
                timeout=2.0  # Shorter timeout for individual read attempts
            )
            
            if line_bytes:
                line = line_bytes.decode('utf-8', errors='replace').strip()
                logger.debug(f"🤝📥✅ Read line from stdout: '{line}'")
                
                if "|" in line and line.count("|") >= 5:
                    logger.debug("🤝📥✅ Complete handshake response found in line")
                    return line
                
                # Add to buffer if line doesn't contain complete handshake
                buffer += line
                if "|" in buffer and buffer.count("|") >= 5:
                    logger.debug("🤝📥✅ Complete handshake response found in buffer")
                    return buffer
            
        except asyncio.TimeoutError:
            logger.debug("🤝📥⚠️ Timeout reading line, trying chunk read strategy")
            
            try:
                # Strategy 2: Read a small chunk instead
                chunk = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, lambda: process.stdout.read(1024)
                    ),
                    timeout=1.0
                )
                
                if chunk:
                    chunk_str = chunk.decode('utf-8', errors='replace')
                    buffer += chunk_str
                    logger.debug(f"🤝📥✅ Read chunk: {len(chunk_str)} bytes, buffer now has {len(buffer)} bytes")
                    
                    # Check if buffer contains a complete handshake response
                    if "|" in buffer and buffer.count("|") >= 5:
                        # Extract handshake line from buffer
                        lines = buffer.split('\n')
                        for line in lines:
                            if "|" in line and line.count("|") >= 5:
                                logger.debug(f"🤝📥✅ Found complete handshake in buffer: {line}")
                                return line
                        
                        # If no complete line found, but buffer has enough separators,
                        # use the whole buffer (might have newlines removed)
                        return buffer
            
            except asyncio.TimeoutError:
                logger.debug("🤝📥⚠️ Timeout reading chunk, retrying...")
        
        # Brief delay before next attempt
        await asyncio.sleep(0.2)
    
    # If we get here, we've timed out
    stderr_output = ""
    if process.stderr:
        try:
            stderr_output = process.stderr.read().decode('utf-8', errors='replace')
        except Exception as e:
            stderr_output = f"Error reading stderr: {e}"
    
    raise HandshakeError(
        f"Timed out waiting for handshake after {timeout}s. "
        f"Buffer so far: '{buffer}'. Stderr: {stderr_output}"
    )

async def create_stderr_relay(process):
    """
    Creates a background task that continuously reads and logs stderr from the plugin process.
    Essential for debugging handshake issues, especially with Go plugins.
    
    Args:
        process: The subprocess.Popen instance with stderr pipe.
        
    Returns:
        The asyncio.Task managing the stderr relay, or None if stderr is not available.
    """
    if not process or not process.stderr:
        logger.debug("🤝📤⚠️ No process or stderr stream available for relay")
        return None
    
    async def _stderr_reader():
        """Background task to continuously read stderr"""
        logger.debug("🤝📤🚀 Starting stderr relay task")
        while process.poll() is None:  # While process is running
            try:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, process.stderr.readline
                )
                if not line:
                    await asyncio.sleep(0.1)
                    continue
                    
                text = line.decode('utf-8', errors='replace').rstrip()
                if text:
                    logger.debug(f"🤝📤📝 Plugin stderr: {text}")
            except Exception as e:
                logger.error(f"🤝📤❌ Error in stderr relay: {e}")
                break
                
        logger.debug("🤝📤🛑 Stderr relay task ended")
    
    # Create but don't wait for the task
    relay_task = asyncio.create_task(_stderr_reader())
    logger.debug("🤝📤✅ Created stderr relay task")
    return relay_task

async def parse_and_validate_handshake(
    handshake_line: str
) -> tuple[int, int, str, str, str, str | None]:
    """
    Parses and validates a handshake response, checking correct format and values.
    Expected format: CORE_VERSION|PLUGIN_VERSION|NETWORK|ADDRESS|PROTOCOL|TLS_CERT
    
    Args:
        handshake_line: The complete handshake response string
        
    Returns:
        tuple of (core_version, plugin_version, network, address, protocol, server_cert)
        
    Raises:
        HandshakeError: If handshake format or values are invalid
    """
    logger.debug(f"🤝🔍🚀 Parsing handshake response: {handshake_line[:50]}...")
    
    try:
        # Split by pipe character
        parts = handshake_line.strip().split('|')
        
        # Validate parts count
        if len(parts) != 6:
            logger.error(f"🤝🔍❌ Invalid handshake format: expected 6 parts, got {len(parts)}")
            raise HandshakeError(f"Invalid handshake format: expected 6 parts, got {len(parts)}")
        
        # Extract and validate individual parts
        try:
            core_version = int(parts[0])
            plugin_version = int(parts[1])
        except ValueError:
            logger.error("🤝🔍❌ Invalid version numbers in handshake")
            raise HandshakeError("Invalid version numbers in handshake")
            
        network = parts[2]
        if network not in ("tcp", "unix"):
            logger.error(f"🤝🔍❌ Invalid network type: {network}")
            raise HandshakeError(f"Invalid network type: {network}")
            
        address = parts[3]
        if not address:
            logger.error("🤝🔍❌ Empty address in handshake")
            raise HandshakeError("Empty address in handshake")
            
        protocol = parts[4]
        if protocol != "grpc":
            logger.error(f"🤝🔍❌ Unsupported protocol: {protocol}")
            raise HandshakeError(f"Unsupported protocol: {protocol}")
            
        server_cert = parts[5] if parts[5] else None
        
        # Handle certificate padding if present
        if server_cert:
            # Add padding if needed (for base64)
            padding = len(server_cert) % 4
            if padding:
                server_cert += "=" * (4 - padding)
                logger.debug("🤝🔍✅ Added certificate padding")
                
        logger.debug(
            f"🤝🔍✅ Handshake parsed successfully: "
            f"core_version={core_version}, plugin_version={plugin_version}, "
            f"network={network}, address={address}, protocol={protocol}, "
            f"server_cert={'present' if server_cert else 'none'}"
        )
        
        return core_version, plugin_version, network, address, protocol, server_cert
        
    except Exception as e:
        logger.error(
            f"🤝🔍❌ Failed to parse handshake: {e}",
            extra={"trace": traceback.format_exc()}
        )
        raise HandshakeError(f"Failed to parse handshake: {e}") from e

# 🐍🏗️🔌
