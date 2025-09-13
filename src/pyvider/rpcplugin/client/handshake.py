#
# pyvider/rpcplugin/client/handshake.py
#
"""
Client handshake functionality for RPC plugin connections.

This module contains handshake-related methods including retry logic,
certificate setup, handshake parsing, and X.509 certificate processing.
"""

import asyncio
import random
import time
from typing import Any, NamedTuple

from provide.foundation.crypto import Certificate

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import (
    HandshakeError,
    SecurityError,
)
from pyvider.rpcplugin.handshake import parse_handshake_response


class HandshakeData(NamedTuple):
    """Represents essential data parsed from the plugin's handshake response."""

    endpoint: str  # The network address (e.g., "host:port" or "/path/to/socket")
    transport_type: str  # The transport protocol (e.g., "tcp", "unix")


# Handshake-related methods that will be mixed into RPCPluginClient
class ClientHandshakeMixin:
    """Mixin class containing handshake-related methods for RPCPluginClient."""

    # Forward declarations for attributes that will be on the main client class
    _address: str | None
    _transport_name: str | None
    _protocol_version: int | None
    _server_cert: str | None
    _transport: Any
    _process: Any
    _handshake_complete_event: asyncio.Event
    _handshake_failed_event: asyncio.Event
    is_started: bool
    target_endpoint: str | None
    grpc_channel: Any
    logger: Any
    client_cert: str | None
    client_key_pem: str | None

    # Forward declarations for methods that will be on the main client class
    async def _perform_handshake(self) -> None: ...
    async def _create_grpc_channel(self) -> None: ...
    async def _launch_process(self) -> None: ...
    def _rebuild_x509_pem(self, maybe_cert: str) -> str: ...

    async def _connect_and_handshake_with_retry(self) -> None:
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
            f"Client retry_enabled evaluated to: {retry_enabled} "
            f"(from string '{retry_enabled_str}')"
        )

        if not retry_enabled:
            self.logger.info(
                "Client retries disabled. Attempting connection and handshake once."
            )
            try:
                self._handshake_complete_event.clear()
                self._handshake_failed_event.clear()
                self.logger.debug("Performing handshake with plugin server...")

                await self._perform_handshake()
                if not self._address or not self._transport_name:
                    raise HandshakeError(
                        "Handshake completed but critical endpoint data "
                        "(address/transport_name) not set."
                    )
                self.logger.info(
                    f"Handshake successful. Endpoint: {self._address}, "
                    f"Transport: {self._transport_name}"
                )

                self.logger.debug(
                    f"Creating gRPC channel to {self._address} "
                    f"({self._transport_name})..."
                )
                await self._create_grpc_channel()
                self.logger.info(
                    f"Successfully connected to gRPC endpoint: {self.target_endpoint}"
                )

                self.is_started = True
                self._handshake_complete_event.set()
            except Exception as e:
                self.logger.error(
                    "Failed to connect and handshake with plugin "
                    f"(retry disabled): {e}",
                    exc_info=True,
                )
                self._handshake_failed_event.set()
                raise
        else:
            # Retry logic enabled
            max_retries = rpcplugin_config.plugin_client_max_retries
            retry_interval_ms = rpcplugin_config.plugin_client_retry_interval_ms
            total_timeout_ms = rpcplugin_config.plugin_client_total_timeout_ms

            self.logger.info(
                f"Client retries enabled. Max retries: {max_retries}, "
                f"Retry interval: {retry_interval_ms}ms, "
                f"Total timeout: {total_timeout_ms}ms"
            )

            start_time = time.time() * 1000  # Convert to milliseconds
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
                    self._handshake_complete_event.clear()
                    self._handshake_failed_event.clear()
                    self.logger.debug(
                        f"Attempt {attempt + 1}/{max_retries + 1}: "
                        "Performing handshake with plugin server..."
                    )

                    await self._perform_handshake()
                    if not self._address or not self._transport_name:
                        raise HandshakeError(
                            "Handshake completed but critical endpoint data "
                            "(address/transport_name) not set."
                        )

                    self.logger.info(
                        f"Handshake successful on attempt {attempt + 1}. "
                        f"Endpoint: {self._address}, Transport: {self._transport_name}"
                    )

                    self.logger.debug(
                        f"Creating gRPC channel to {self._address} "
                        f"({self._transport_name})..."
                    )
                    await self._create_grpc_channel()
                    self.logger.info(
                        "Successfully connected to gRPC endpoint: "
                        f"{self.target_endpoint}"
                    )

                    self.is_started = True
                    self._handshake_complete_event.set()
                    return  # Success, exit retry loop

                except Exception as e:
                    attempt += 1
                    self.logger.warning(
                        f"Attempt {attempt}/{max_retries + 1} failed: {e}"
                    )

                    if attempt > max_retries:
                        self.logger.error(
                            f"All {max_retries + 1} attempts failed. "
                            f"Last error: {e}",
                            exc_info=True,
                        )
                        self._handshake_failed_event.set()
                        raise HandshakeError(
                            f"Failed to connect after {max_retries + 1} attempts. "
                            f"Last error: {e}"
                        ) from e

                    # Close transport before retrying if it was created
                    if self._transport:
                        try:
                            await self._transport.close()
                        except Exception as close_error:
                            self.logger.warning(
                                f"Error closing transport before retry: {close_error}"
                            )
                        finally:
                            self._transport = None

                    # Wait before retrying with jitter
                    jitter_ms = random.randint(0, min(100, retry_interval_ms // 4))
                    wait_time_ms = retry_interval_ms + jitter_ms
                    wait_time_s = wait_time_ms / 1000.0

                    self.logger.debug(
                        f"Waiting {wait_time_ms}ms before retry {attempt + 1}..."
                    )
                    await asyncio.sleep(wait_time_s)

    async def _setup_client_certificates(self) -> None:
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
                cert_obj = Certificate(
                    cert_pem_or_uri=client_cert_config,
                    key_pem_or_uri=client_key_config,
                )
                self.client_cert = cert_obj.cert
                self.client_key_pem = cert_obj.key
                self.logger.debug("Loaded existing client certificate for mTLS.")
            except Exception as e:
                raise SecurityError(
                    f"Failed to load client certificate/key: {e}"
                ) from e
        elif auto_mtls:
            try:
                cert_obj = Certificate.create_self_signed_client_cert(
                    common_name="pyvider.rpcplugin.autogen.client",
                    organization_name="Pyvider AutoGenerated",
                    validity_days=365,
                )
                self.client_cert = cert_obj.cert
                self.client_key_pem = cert_obj.key
                self.logger.debug("Generated auto-mTLS client certificate.")
            except Exception as e:
                raise SecurityError(
                    f"Failed to auto-generate client certificate: {e}"
                ) from e

    async def _read_raw_handshake_line_from_stdout(self) -> str:
        """
        Read the raw handshake line from the plugin's stdout.

        Uses multiple strategies to handle different buffering and timing issues
        that can occur with Go-Python interop.

        Returns:
            The raw handshake response string

        Raises:
            HandshakeError: If handshake cannot be read or times out
        """
        if not self._process or not self._process.stdout:
            raise HandshakeError(
                "Plugin process or stdout not available for handshake."
            )

        outer_timeout_ms = rpcplugin_config.plugin_client_handshake_timeout_ms
        outer_timeout_s = outer_timeout_ms / 1000.0
        inner_timeout_s = min(2.0, outer_timeout_s / 2)

        self.logger.debug(
            f"Reading handshake from plugin stdout. "
            f"Outer timeout: {outer_timeout_s}s, Inner timeout: {inner_timeout_s}s"
        )

        start_time = time.time()
        buffer = ""

        while (time.time() - start_time) < outer_timeout_s:
            # Check if process exited
            if self._process.poll() is not None:
                stderr_output = ""
                if self._process.stderr:
                    try:
                        stderr_output = self._process.stderr.read().decode(
                            "utf-8", errors="replace"
                        )
                    except Exception as e_stderr:
                        stderr_output = f"Error reading stderr: {e_stderr}"

                stderr_output_truncated = (
                    (stderr_output[:200] + "...")
                    if len(stderr_output) > 200
                    else stderr_output
                )

                self.logger.error(
                    f"Plugin process exited with code {self._process.returncode} "
                    "before handshake completion"
                )
                raise HandshakeError(
                    f"Plugin process exited prematurely with code "
                    f"{self._process.returncode} before completing handshake.",
                    hint=(
                        f"Check plugin logs or stderr. Stderr: '{stderr_output_truncated}'"
                        if stderr_output_truncated
                        else "Check plugin logs for errors."
                    ),
                    code=self._process.returncode,
                )

            try:
                # Ensure stdout is not None before accessing readline
                if self._process.stdout is None:
                    await asyncio.sleep(0.1)
                    continue

                line_bytes = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, self._process.stdout.readline
                    ),
                    timeout=inner_timeout_s,
                )

                if line_bytes:
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    self.logger.debug(f"Read line from plugin stdout: '{line}'")

                    # Look for complete handshake response (contains pipe separators)
                    if "|" in line and line.count("|") >= 5:
                        self.logger.debug("Complete handshake response found in line.")
                        return line

                    # Accumulate in buffer for potential multi-line handshake
                    buffer += line
                    if "|" in buffer and buffer.count("|") >= 5:
                        self.logger.debug("Complete handshake response found in buffer.")
                        return buffer

            except TimeoutError:
                self.logger.debug("Timeout reading line, trying chunk read strategy...")

                try:
                    # Ensure stdout is not None before accessing read
                    if self._process.stdout is None:
                        await asyncio.sleep(0.1)
                        continue

                    chunk = await asyncio.wait_for(
                        asyncio.get_event_loop().run_in_executor(
                            None,
                            lambda: self._process.stdout.read(1024),
                        ),
                        timeout=1.0,
                    )

                    if chunk:
                        chunk_str = chunk.decode("utf-8", errors="replace")
                        buffer += chunk_str
                        self.logger.debug(
                            f"Read chunk: {len(chunk_str)} bytes, "
                            f"buffer now has {len(buffer)} bytes"
                        )

                        # Check if we now have a complete handshake
                        if "|" in buffer and buffer.count("|") >= 5:
                            # Try to extract handshake from buffer
                            lines = buffer.split("\n")
                            for line_in_buf in lines:
                                if "|" in line_in_buf and line_in_buf.count("|") >= 5:
                                    self.logger.debug(
                                        f"Found complete handshake in buffer: {line_in_buf}"
                                    )
                                    return line_in_buf
                            # If no single line contains complete handshake,
                            # maybe it's split across reads but now complete in buffer
                            return buffer

                except TimeoutError:
                    self.logger.debug("Timeout reading chunk, retrying...")

            # Brief pause before next attempt
            await asyncio.sleep(0.1)

        # If we get here, we've timed out
        stderr_output = ""
        if self._process.stderr:
            try:
                stderr_output = self._process.stderr.read().decode(
                    "utf-8", errors="replace"
                )
            except Exception as e_stderr_final:
                stderr_output = f"Error reading stderr: {e_stderr_final}"

        stderr_output_truncated = (
            (stderr_output[:200] + "...") if len(stderr_output) > 200 else stderr_output
        )

        raise HandshakeError(
            f"Timed out waiting for handshake response from plugin after "
            f"{outer_timeout_s} seconds.",
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

    async def _perform_handshake(self) -> None:
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
            (
                core_version,
                plugin_version,
                network,
                address,
                protocol,
                server_cert,
            ) = parse_handshake_response(raw_handshake)

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
                    if self._process.poll() is None:
                        self._process.terminate()
                        # Give process a moment to terminate gracefully
                        await asyncio.sleep(0.1)
                        if self._process.poll() is None:
                            self._process.kill()
                except Exception as cleanup_error:
                    self.logger.warning(
                        f"Error cleaning up process after handshake failure: "
                        f"{cleanup_error}"
                    )
                finally:
                    self._process = None
            raise

    def _rebuild_x509_pem(self, maybe_cert: str) -> str:
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

        # If it's already a proper PEM format, return as-is
        if (maybe_cert.startswith("-----BEGIN CERTIFICATE-----") and
            "-----END CERTIFICATE-----" in maybe_cert):
            return maybe_cert

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
        pem_cert += "-----END CERTIFICATE-----\n"

        return pem_cert