#
# pyvider/rpcplugin/handshake/negotiation.py
#
"""Transport and protocol negotiation for the RPC plugin handshake.

This module handles transport negotiation, protocol version negotiation,
and I/O operations for handshake processes.
"""

import asyncio
import os
import subprocess  # nosec B404 # For process type hint only
import time
import tempfile
from typing import cast

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import HandshakeError, ProtocolError, TransportError
from pyvider.rpcplugin.transport.types import TransportT
from provide.foundation import logger


async def negotiate_transport(server_transports: list[str]) -> tuple[str, TransportT]:
    """
    (🗣️🚊 Transport Negotiation) Negotiates the transport type with the server and
    creates the appropriate transport instance.

    Returns:
      A tuple of (transport_name, transport_instance).

    Raises:
      TransportError: If no compatible transport can be negotiated or an error
                      occurs during negotiation.
    """
    logger.debug(
        "(🗣️🚊 Transport Negotiation: Starting) => Available transports: "
        f"{server_transports}"
    )
    if not server_transports:
        logger.error(
            "🗣️🚊❌ (Transport Negotiation: Failed) => No transport options provided"
        )
        raise TransportError(
            message="No transport options were provided by the server for negotiation.",
            hint=(
                "Ensure the server configuration specifies at least one supported "
                "transport (e.g., 'unix', 'tcp')."
            ),
        )
    try:
        if "unix" in server_transports:
            logger.debug(
                "🗣️🚊🧦 (Transport Negotiation: Selected Unix) => Unix socket "
                "transport is available"
            )
            temp_dir = os.environ.get("TEMP_DIR") or tempfile.gettempdir()
            transport_path = os.path.join(temp_dir, f"pyvider-{os.getpid()}.sock")
            from pyvider.rpcplugin.transport import UnixSocketTransport

            return "unix", cast(TransportT, UnixSocketTransport(path=transport_path))

        elif "tcp" in server_transports:
            logger.debug(
                "🗣️🚊👥 (Transport Negotiation: Selected TCP) => TCP transport is "
                "available"
            )
            from pyvider.rpcplugin.transport import TCPSocketTransport

            return "tcp", cast(TransportT, TCPSocketTransport())
        else:
            logger.error(
                "🗣️🚊❌ (Transport Negotiation: Failed) => No supported transport found",
                extra={"server_transports": server_transports},
            )
            client_supported = (
                rpcplugin_config.client_transports()
                if rpcplugin_config
                else "config not loaded"
            )
            raise TransportError(
                message=(
                    "No compatible transport found. Server offered: "
                    f"{server_transports}."
                ),
                hint=(
                    "Ensure the client supports at least one of the server's "
                    f"offered transports. Client supports: {client_supported}."
                ),
            )
    except Exception as e:
        logger.error(
            "🗣️🚊❌ (Transport Negotiation: Exception) => Error during transport "
            "negotiation",
            extra={"error": str(e)},
        )
        raise TransportError(
            message=f"An unexpected error occurred during transport negotiation: {e}",
            hint="Check server logs for more details on transport setup.",
        ) from e


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
    supported_versions_config = rpcplugin_config.supported_protocol_versions
    for version in sorted(server_versions, reverse=True):
        if version in supported_versions_config:
            logger.info(f"🤝✅ Selected protocol version: {version}")
            return version

    logger.error(
        "🤝❌ Protocol negotiation failed: No compatible version found. "
        f"Server supports: {server_versions}, Client supports: "
        f"{supported_versions_config}"
    )
    raise ProtocolError(
        message=(
            "No mutually supported protocol version. Server supports: "
            f"{server_versions}, Client supports: {supported_versions_config}"
        ),
        hint=(
            "Ensure client and server configurations for 'PLUGIN_PROTOCOL_VERSIONS' "
            "and 'SUPPORTED_PROTOCOL_VERSIONS' have at least one common version."
        ),
    )


async def read_handshake_response(process: subprocess.Popen) -> str:
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
        raise HandshakeError(
            message=(
                "Plugin process or its stdout stream is not available for handshake."
            ),
            hint="Ensure the plugin process started correctly and is accessible.",
        )

    logger.debug("🤝📥🚀 Reading handshake response from plugin process...")

    start_time = time.time()
    buffer = ""

    while (time.time() - start_time) < rpcplugin_config.handshake_timeout():
        if process.poll() is not None:
            stderr_output = ""
            if process.stderr:
                try:
                    stderr_output = process.stderr.read().decode(
                        "utf-8", errors="replace"
                    )
                except Exception as e_stderr:
                    stderr_output = f"Error reading stderr: {e_stderr}"

            stderr_output_truncated = (
                (stderr_output[:200] + "...")
                if len(stderr_output) > 200
                else stderr_output
            )

            logger.error(
                "🤝📥❌ Plugin process exited with code "
                f"{process.returncode} before handshake"
            )
            raise HandshakeError(
                message=(
                    f"Plugin process exited prematurely with code {process.returncode} "
                    "before completing handshake."
                ),
                hint=(
                    "Check plugin logs or stderr for details. Stderr captured: "
                    f"'{stderr_output_truncated}'"
                    if stderr_output_truncated
                    else "Check plugin logs for errors."
                ),
                code=process.returncode,
            )

        try:
            # Ensure stdout is not None before accessing readline
            if process.stdout is None:
                await asyncio.sleep(0.1)  # Wait briefly if stdout not ready
                continue

            line_bytes = await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(None, process.stdout.readline),
                timeout=2.0,
            )

            if line_bytes:
                line = line_bytes.decode("utf-8", errors="replace").strip()
                logger.debug(f"🤝📥✅ Read line from stdout: '{line}'")

                if "|" in line and line.count("|") >= 5:
                    logger.debug("🤝📥✅ Complete handshake response found in line")
                    return line

                buffer += line
                if "|" in buffer and buffer.count("|") >= 5:
                    logger.debug("🤝📥✅ Complete handshake response found in buffer")
                    return buffer

        except TimeoutError:
            logger.debug("🤝📥⚠️ Timeout reading line, trying chunk read strategy")

            try:
                # Ensure stdout is not None before accessing read
                if process.stdout is None:
                    await asyncio.sleep(0.1)
                    continue

                chunk = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: process.stdout.read(1024),  # type: ignore[union-attr]
                    ),
                    timeout=1.0,
                )

                if chunk:
                    chunk_str = chunk.decode("utf-8", errors="replace")
                    buffer += chunk_str
                    logger.debug(
                        f"🤝📥✅ Read chunk: {len(chunk_str)} bytes, "
                        f"buffer now has {len(buffer)} bytes"
                    )

                    if "|" in buffer and buffer.count("|") >= 5:
                        lines = buffer.split("\n")
                        for line_in_buf in lines:
                            if "|" in line_in_buf and line_in_buf.count("|") >= 5:
                                logger.debug(
                                    "🤝📥✅ Found complete handshake in buffer: "
                                    f"{line_in_buf}"
                                )
                                return line_in_buf
                        # If complete handshake is split across reads but now in buffer
                        return buffer

            except TimeoutError:
                logger.debug("🤝📥⚠️ Timeout reading chunk, retrying...")

        await asyncio.sleep(0.2)

    stderr_output = ""
    if process.stderr:
        try:
            stderr_output = process.stderr.read().decode("utf-8", errors="replace")
        except Exception as e_stderr_final:
            stderr_output = f"Error reading stderr: {e_stderr_final}"

    stderr_output_truncated = (
        (stderr_output[:200] + "...") if len(stderr_output) > 200 else stderr_output
    )
    raise HandshakeError(
        message=(
            "Timed out waiting for handshake response from plugin after "
            f"{timeout} seconds."
        ),
        hint=(
            f"Ensure plugin starts and prints handshake to stdout promptly. "
            f"Last buffer: '{buffer}'. Stderr: '{stderr_output_truncated}'"
            if stderr_output_truncated
            else (
                f"Ensure plugin starts and prints handshake to stdout promptly. "
                f"Last buffer: '{buffer}'."
            )
        ),
    )


async def create_stderr_relay(
    process: subprocess.Popen,
) -> asyncio.Task[None] | None:
    """
    Creates a background task that continuously reads and logs stderr from the
    plugin process. Essential for debugging handshake issues, especially with Go
    plugins.

    Args:
        process: The subprocess.Popen instance with stderr pipe.

    Returns:
        The asyncio.Task managing the stderr relay, or None if stderr is not available.
    """
    if not process or not process.stderr:
        logger.debug("🤝📤⚠️ No process or stderr stream available for relay")
        return None

    async def _stderr_reader() -> None:
        """Background task to continuously read stderr"""
        logger.debug("🤝📤🚀 Starting stderr relay task")
        # Ensure stderr is not None before accessing readline
        if process.stderr is None:
            logger.error("🤝📤❌ Stderr became None unexpectedly in relay task.")
            return

        while process.poll() is None:
            try:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, process.stderr.readline
                )
                if not line:
                    await asyncio.sleep(0.1)
                    continue

                text = line.decode("utf-8", errors="replace").rstrip()
                if text:
                    logger.debug(f"🤝📤📝 Plugin stderr: {text}")
            except Exception as e:
                logger.error(f"🤝📤❌ Error in stderr relay: {e}")
                break

        logger.debug("🤝📤🛑 Stderr relay task ended")

    relay_task = asyncio.create_task(_stderr_reader())
    logger.debug("🤝📤✅ Created stderr relay task")
    return relay_task