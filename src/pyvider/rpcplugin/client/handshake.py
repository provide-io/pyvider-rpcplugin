#
# pyvider/rpcplugin/client/handshake.py
#
"""
Client handshake functionality for RPC plugin connections.

This module contains handshake-related methods including retry logic,
certificate setup, handshake parsing, and X.509 certificate processing.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import TYPE_CHECKING, NamedTuple

from provide.foundation.crypto import Certificate

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.defaults import (
    DEFAULT_HANDSHAKE_CHUNK_TIMEOUT,
    DEFAULT_HANDSHAKE_INNER_TIMEOUT,
    DEFAULT_PROCESS_WAIT_TIME,
)
from pyvider.rpcplugin.exception import (
    HandshakeError,
    SecurityError,
    TransportError,
)
from pyvider.rpcplugin.handshake import parse_handshake_response

if TYPE_CHECKING:
    from pyvider.rpcplugin.client.core import RPCPluginClient


class HandshakeData(NamedTuple):
    """Represents essential data parsed from the plugin's handshake response."""

    endpoint: str  # The network address (e.g., "host:port" or "/path/to/socket")
    transport_type: str  # The transport protocol (e.g., "tcp", "unix")


# Handshake-related methods that will be mixed into RPCPluginClient
class ClientHandshakeMixin:
    """Mixin class containing handshake-related methods for RPCPluginClient."""

    async def _complete_handshake_setup(self: RPCPluginClient, attempt_num: int | None = None) -> None:  # type: ignore[misc]
        """Complete the handshake setup including certificates, channel, and stdio."""
        if not self._address or not self._transport_name:
            raise HandshakeError(
                "Handshake completed but critical endpoint data (address/transport_name) not set."
            )

        attempt_msg = f" on attempt {attempt_num}" if attempt_num else ""
        self.logger.info(
            f"Handshake successful{attempt_msg}. Endpoint: {self._address}, Transport: {self._transport_name}"
        )

        await self._setup_client_certificates()
        self.logger.debug(f"Creating gRPC channel to {self._address} ({self._transport_name})...")
        await self._create_grpc_channel()
        self.logger.info(f"Successfully connected to gRPC endpoint: {self.target_endpoint}")

        if self._stdio_stub:
            self._stdio_task = asyncio.create_task(self._read_stdio_logs())
            self.logger.debug("Started stdio reading task")

        self.is_started = True
        self._handshake_complete_event.set()

    async def _attempt_single_handshake(self: RPCPluginClient, attempt_num: int | None = None) -> None:  # type: ignore[misc]
        """Attempt a single handshake and complete setup."""
        self._handshake_complete_event.clear()
        self._handshake_failed_event.clear()

        if attempt_num:
            self.logger.debug(f"Attempt {attempt_num}: Performing handshake with plugin server...")
        else:
            self.logger.debug("Performing handshake with plugin server...")

        await self._perform_handshake()
        await self._complete_handshake_setup(attempt_num)

    async def _handle_retry_cleanup(self: RPCPluginClient, retry_interval_ms: int) -> None:  # type: ignore[misc]
        """Handle cleanup and wait before retry."""
        if self._transport:
            try:
                await self._transport.close()
            except TransportError as close_error:
                self.logger.warning(f"Error closing transport before retry: {close_error}")
            finally:
                self._transport = None

        jitter_ms = random.randint(0, min(100, retry_interval_ms // 4))
        wait_time_ms = retry_interval_ms + jitter_ms
        wait_time_s = wait_time_ms / 1000.0

        self.logger.debug(f"Waiting {wait_time_ms}ms before retry...")
        await asyncio.sleep(wait_time_s)

    async def _connect_and_handshake_with_retry(self: RPCPluginClient) -> None:  # type: ignore[misc]
        """
        Performs handshake and creates gRPC channel, with retry logic.

        This method sets instance attributes like _address, _transport_name,
        _protocol_version, _server_cert upon successful handshake, and
        grpc_channel, target_endpoint upon channel creation. It also manages
        _handshake_complete_event and _handshake_failed_event.
        """
        retry_enabled_str = str(rpcplugin_config.plugin_client_retry_enabled)
        retry_enabled = str(retry_enabled_str).lower() == "true"
        self.logger.debug(
            f"Client retry_enabled evaluated to: {retry_enabled} (from string '{retry_enabled_str}')"
        )

        if not retry_enabled:
            self.logger.info("Client retries disabled. Attempting connection and handshake once.")
            try:
                await self._attempt_single_handshake()
            except Exception as e:
                self.logger.error(
                    f"Failed to connect and handshake with plugin (retry disabled): {e}",
                    exc_info=True,
                )
                self._handshake_failed_event.set()
                raise
            return

        max_retries = rpcplugin_config.plugin_client_max_retries
        retry_interval_ms = rpcplugin_config.plugin_client_initial_backoff_ms
        total_timeout_ms = rpcplugin_config.plugin_client_retry_total_timeout_s * 1000

        self.logger.info(
            f"Client retries enabled. Max retries: {max_retries}, "
            f"Retry interval: {retry_interval_ms}ms, "
            f"Total timeout: {total_timeout_ms}ms"
        )

        start_time = time.time() * 1000
        attempt = 0

        while attempt <= max_retries:
            elapsed_time_ms = (time.time() * 1000) - start_time
            if elapsed_time_ms >= total_timeout_ms:
                error_msg = (
                    f"Total timeout of {total_timeout_ms}ms exceeded after "
                    f"{attempt} attempts. Elapsed time: {elapsed_time_ms:.1f}ms"
                )
                self.logger.error(error_msg)
                self._handshake_failed_event.set()
                raise HandshakeError(error_msg)

            try:
                await self._attempt_single_handshake(attempt + 1)
                return

            except Exception as e:
                attempt += 1
                self.logger.warning(f"Attempt {attempt}/{max_retries + 1} failed: {e}")

                if attempt > max_retries:
                    self.logger.error(
                        f"All {max_retries + 1} attempts failed. Last error: {e}",
                        exc_info=True,
                    )
                    self._handshake_failed_event.set()
                    raise HandshakeError(
                        f"Failed to connect after {max_retries + 1} attempts. Last error: {e}"
                    ) from e

                await self._handle_retry_cleanup(retry_interval_ms)

    async def _setup_client_certificates(self: RPCPluginClient) -> None:  # type: ignore[misc]
        """
        Set up client certificates for mTLS authentication.

        This method handles both auto-generation and loading of existing
        client certificates based on configuration.
        """
        auto_mtls = rpcplugin_config.plugin_auto_mtls
        client_cert_config = rpcplugin_config.plugin_client_cert
        client_key_config = rpcplugin_config.plugin_client_key

        if not auto_mtls and not (client_cert_config and client_key_config):
            self.logger.debug("No client certificates configured for mTLS.")
            return

        if client_cert_config and client_key_config:
            try:
                cert_obj = Certificate.from_pem(
                    cert_pem=client_cert_config,
                    key_pem=client_key_config,
                )
                self.client_cert = cert_obj.cert_pem
                self.client_key_pem = cert_obj.key_pem
                self.logger.debug("Loaded existing client certificate for mTLS.")
            except Exception as e:
                raise SecurityError(f"Failed to load client certificate/key: {e}") from e
        elif auto_mtls:
            try:
                cert_obj = Certificate.create_self_signed_client_cert(
                    common_name="pyvider.rpcplugin.autogen.client",
                    organization_name="Pyvider AutoGenerated",
                    validity_days=rpcplugin_config.plugin_cert_validity_days,
                )
                self.client_cert = cert_obj.cert_pem
                self.client_key_pem = cert_obj.key_pem
                self.logger.debug("Generated auto-mTLS client certificate.")
            except Exception as e:
                raise SecurityError(f"Failed to auto-generate client certificate: {e}") from e

    def _get_stderr_output(self: RPCPluginClient) -> str:  # type: ignore[misc]
        """Get stderr output from process with error handling."""
        stderr_output = ""
        if self._process and self._process.process and self._process.process.stderr:
            try:
                stderr_output = self._process.process.stderr.read().decode("utf-8", errors="replace")
            except Exception as e:
                stderr_output = f"Error reading stderr: {e}"
        return (stderr_output[:200] + "...") if len(stderr_output) > 200 else stderr_output

    def _check_process_exit(self: RPCPluginClient) -> None:  # type: ignore[misc]
        """Check if process exited and raise HandshakeError if so."""
        if self._process and not self._process.is_running():
            stderr_output = self._get_stderr_output()
            returncode = self._process.returncode
            self.logger.error(f"Plugin process exited with code {returncode} before handshake completion")
            raise HandshakeError(
                f"Plugin process exited prematurely with code {returncode} before completing handshake.",
                hint=(
                    f"Check plugin logs or stderr. Stderr: '{stderr_output}'"
                    if stderr_output
                    else "Check plugin logs for errors."
                ),
                code=returncode,
            )

    def _is_complete_handshake(self, text: str) -> bool:
        """Check if text contains a complete handshake response."""
        return "|" in text and text.count("|") >= 5

    async def _try_readline_strategy(self: RPCPluginClient, inner_timeout_s: float) -> str | None:  # type: ignore[misc]
        """Try readline strategy to get handshake data."""
        if not self._process or not self._process.process or not self._process.process.stdout:
            await asyncio.sleep(DEFAULT_PROCESS_WAIT_TIME)
            return None

        line_bytes = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, self._process.process.stdout.readline),
            timeout=inner_timeout_s,
        )

        if line_bytes:
            line = line_bytes.decode("utf-8", errors="replace").strip()
            self.logger.debug(f"Read line from plugin stdout: '{line}'")
            if self._is_complete_handshake(line):
                self.logger.debug("Complete handshake response found in line.")
                return line
            return line
        return None

    async def _try_chunk_strategy(self: RPCPluginClient, buffer: str) -> str | None:  # type: ignore[misc]
        """Try chunk read strategy to get handshake data."""
        if not self._process or not self._process.process or not self._process.process.stdout:
            await asyncio.sleep(DEFAULT_PROCESS_WAIT_TIME)
            return None

        chunk = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self._process.process.stdout.read(rpcplugin_config.plugin_chunk_size)
                if self._process and self._process.process and self._process.process.stdout
                else b"",
            ),
            timeout=DEFAULT_HANDSHAKE_CHUNK_TIMEOUT,
        )

        if chunk:
            chunk_str = chunk.decode("utf-8", errors="replace")
            new_buffer = buffer + chunk_str
            self.logger.debug(f"Read chunk: {len(chunk_str)} bytes, buffer now has {len(new_buffer)} bytes")

            if self._is_complete_handshake(new_buffer):
                lines = new_buffer.split("\n")
                for line_in_buf in lines:
                    if self._is_complete_handshake(line_in_buf):
                        self.logger.debug(f"Found complete handshake in buffer: {line_in_buf}")
                        return line_in_buf
                return new_buffer
            return new_buffer
        return buffer

    async def _read_raw_handshake_line_from_stdout(self: RPCPluginClient) -> str:  # type: ignore[misc]
        """
        Read the raw handshake line from the plugin's stdout.

        Uses multiple strategies to handle different buffering and timing issues
        that can occur with Go-Python interop.

        Returns:
            The raw handshake response string

        Raises:
            HandshakeError: If handshake cannot be read or times out
        """
        if not self._process or not self._process.process or not self._process.process.stdout:
            raise HandshakeError("Plugin process or stdout not available for handshake.")

        outer_timeout_ms = rpcplugin_config.plugin_handshake_timeout * 1000
        outer_timeout_s = outer_timeout_ms / 1000.0
        inner_timeout_s = min(DEFAULT_HANDSHAKE_INNER_TIMEOUT, outer_timeout_s / 2)

        self.logger.debug(
            f"Reading handshake from plugin stdout. "
            f"Outer timeout: {outer_timeout_s}s, Inner timeout: {inner_timeout_s}s"
        )

        start_time = time.time()
        buffer = ""

        while (time.time() - start_time) < outer_timeout_s:
            self._check_process_exit()

            try:
                line = await self._try_readline_strategy(inner_timeout_s)
                if line is not None:
                    if self._is_complete_handshake(line):
                        return line
                    buffer += line
                    if self._is_complete_handshake(buffer):
                        self.logger.debug("Complete handshake response found in buffer.")
                        return buffer

            except TimeoutError:
                self.logger.debug("Timeout reading line, trying chunk read strategy...")
                try:
                    result = await self._try_chunk_strategy(buffer)
                    if result and self._is_complete_handshake(result):
                        return result
                    buffer = result or buffer
                except TimeoutError:
                    self.logger.debug("Timeout reading chunk, retrying...")

            await asyncio.sleep(DEFAULT_PROCESS_WAIT_TIME)

        stderr_output = self._get_stderr_output()
        raise HandshakeError(
            f"Timed out waiting for handshake response from plugin after {outer_timeout_s} seconds.",
            hint=(
                f"Ensure plugin starts and prints handshake to stdout promptly. "
                f"Last buffer: '{buffer}'. Stderr: '{stderr_output}'"
                if stderr_output
                else f"Ensure plugin starts and prints handshake to stdout promptly. Last buffer: '{buffer}'."
            ),
        )

    async def _perform_handshake(self: RPCPluginClient) -> None:  # type: ignore[misc]
        """
        Perform the complete handshake process with the plugin.

        This method orchestrates launching the process, reading the handshake
        response, and parsing the connection details.
        """
        try:
            # Launch the plugin process
            await self._launch_process()

            # Read the raw handshake response
            raw_handshake = await self._read_raw_handshake_line_from_stdout()
            self.logger.debug(f"Raw handshake received: {raw_handshake}")

            # Parse the handshake response
            try:
                (
                    core_version,
                    plugin_version,
                    network,
                    address,
                    protocol,
                    server_cert,
                ) = parse_handshake_response(raw_handshake)
            except Exception as parse_error:
                raise HandshakeError(
                    f"Failed to process handshake response or establish transport connection: {parse_error}"
                ) from parse_error

            # Store parsed handshake data
            self._address = address
            self._transport_name = network
            self._protocol_version = plugin_version
            self._server_cert = server_cert

            self.logger.info(
                f"Handshake parsed successfully: "
                f"core_version={core_version}, plugin_version={plugin_version}, "
                f"network={network}, address={address}, protocol={protocol}, "
                f"server_cert={'present' if server_cert else 'none'}"
            )

        except Exception as e:
            self.logger.error(f"Handshake failed: {e}", exc_info=True)
            # Clean up on handshake failure
            if self._process:
                try:
                    # Use ManagedProcess's graceful termination with short timeout
                    self._process.terminate_gracefully(timeout=1.0)
                    self._process.cleanup()
                except Exception as cleanup_error:
                    self.logger.warning(f"Error cleaning up process after handshake failure: {cleanup_error}")
                finally:
                    self._process = None
            raise

    def _rebuild_x509_pem(self: RPCPluginClient, maybe_cert: str) -> str:  # type: ignore[misc]
        """
        Rebuild X.509 PEM certificate from handshake response.

        The handshake response may contain a stripped certificate that needs
        PEM headers and proper formatting restored.

        Args:
            maybe_cert: The certificate string from handshake response

        Returns:
            Properly formatted PEM certificate string
        """
        if not maybe_cert:
            return ""

        # Remove any existing PEM headers/footers and whitespace
        clean_cert = maybe_cert.replace("-----BEGIN CERTIFICATE-----", "")
        clean_cert = clean_cert.replace("-----END CERTIFICATE-----", "")
        clean_cert = clean_cert.replace("\n", "").replace("\r", "").strip()

        if not clean_cert:
            return ""

        # Rebuild as proper PEM format
        pem_cert = "-----BEGIN CERTIFICATE-----\n"
        # Split into 64-character lines
        for i in range(0, len(clean_cert), 64):
            pem_cert += clean_cert[i : i + 64] + "\n"
        pem_cert += "-----END CERTIFICATE-----"

        return pem_cert
