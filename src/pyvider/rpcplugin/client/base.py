#
# pyvider/rpcplugin/client/base.py
#

"""
RPCPluginClient module for managing plugin connections and lifecycle.

This module provides the core client interface for the Pyvider RPC Plugin system,
enabling secure communication with Terraform-compatible plugin servers through
a robust handshake protocol, TLS security, and gRPC service interfaces.

The client manages the complete lifecycle of plugin connections:
1. Launching or attaching to plugin server subprocesses
2. Performing secure handshake and protocol negotiation
3. Establishing TLS/mTLS encrypted communication channels
4. Providing service stubs for RPC method invocation
5. Monitoring and forwarding plugin stdout/stderr
6. Cleanly shutting down connections and processes

Example usage:
    ```python
    from pyvider.rpcplugin.client import RPCPluginClient

    # Create and start a plugin client
    client = RPCPluginClient(command=["./terraform-provider-example"])
    await client.start()

    # Get access to protocol-specific stubs after connection
    provider_stub = TerraformProviderStub(client._channel)

    # Make RPC calls
    response = await provider_stub.GetSchema(request)

    # Clean shutdown
    await client.shutdown_plugin()
    await client.close()
    ```
"""

import asyncio
import functools  # Added for B023 fix
import os
import random  # Added for retry
import subprocess  # nosec B404
import sys
import time  # Added for retry
import traceback
from types import TracebackType  # Added for ANN001/ANN204 fixes
from typing import Any, NamedTuple

import grpc
from attrs import define, field
from google.protobuf import empty_pb2  # type: ignore[import-untyped]

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.exception import (
    HandshakeError,
    ProtocolError,
    SecurityError,
    TransportError,
)
from pyvider.rpcplugin.handshake import parse_handshake_response
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.transport.types import TransportType
from pyvider.telemetry import logger


class HandshakeData(NamedTuple):
    """Represents essential data parsed from the plugin's handshake response."""

    endpoint: str  # The network address (e.g., "host:port" or "/path/to/socket")
    transport_type: str  # The transport protocol (e.g., "tcp", "unix")


@define
class RPCPluginClient:
    """
    Client interface for interacting with Terraform-compatible plugin servers.

    The RPCPluginClient handles the complete lifecycle of plugin communication:
    1. Launching or attaching to a plugin server subprocess
    2. Performing handshake, protocol negotiation, and transport selection
    3. Setting up secure TLS/mTLS communication when enabled
    4. Creating gRPC channels and service stubs
    5. Providing plugin logs (stdout/stderr) streaming
    6. Managing broker subchannels for multi-service communication
    7. Handling graceful shutdown of plugin processes

    The client follows the Terraform go-plugin protocol, which includes
    a standardized handshake format, negotiated protocol version, and
    support for Unix socket or TCP transport modes.

    Attributes:
        command: List containing the plugin executable command and arguments
        config: Optional configuration dictionary for customizing client behavior

    Example:
        ```python
        # Create a client for a plugin
        client = RPCPluginClient(
            command=["terraform-provider-example"],
            config={"env": {"TF_LOG": "DEBUG"}}
        )

        # Start the client (launches process, performs handshake, etc.)
        await client.start()

        # Use the created channel with protocol-specific stubs
        provider_stub = MyProviderStub(client.grpc_channel)
        response = await provider_stub.SomeMethod(request)

        # Graceful shutdown
        await client.shutdown_plugin()
        await client.close()
        ```

    Note:
        The client supports automatic mTLS if enabled in configuration,
        and can read/generate certificates as needed for secure communication.
    """

    command: list[str] = field()
    config: dict[str, Any] | None = field(default=None)

    # Internal fields
    _process: subprocess.Popen | None = field(init=False, default=None)
    _transport: TransportType | None = field(init=False, default=None)
    _transport_name: str | None = field(init=False, default=None)

    _address: str | None = field(init=False, default=None)
    _protocol_version: int | None = field(init=False, default=None)
    _server_cert: str | None = field(init=False, default=None)
    grpc_channel: grpc.aio.Channel | None = field(init=False, default=None)
    target_endpoint: str | None = field(init=False, default=None)

    # Generated or loaded client certificate
    client_cert: str | None = field(init=False, default=None)
    client_key_pem: str | None = field(init=False, default=None)

    # gRPC stubs for the new services
    _stdio_stub: GRPCStdioStub | None = field(init=False, default=None)
    _broker_stub: GRPCBrokerStub | None = field(init=False, default=None)
    _controller_stub: GRPCControllerStub | None = field(init=False, default=None)

    # Tasks for asynchronous streaming (e.g., reading stdio or broker streams)
    _stdio_task: asyncio.Task | None = field(init=False, default=None)
    _broker_task: asyncio.Task | None = field(init=False, default=None)

    # Events for handshake status
    _handshake_complete_event: asyncio.Event = field(factory=asyncio.Event, init=False)
    _handshake_failed_event: asyncio.Event = field(factory=asyncio.Event, init=False)
    is_started: bool = field(default=False, init=False)
    _stubs: dict[str, Any] = field(factory=dict, init=False)
    logger: Any = field(init=False)

    def __attrs_post_init__(self) -> None:
        """
        Initialize client state after attributes are set.
        """
        self.logger = logger
        self.logger.debug(
            "🔧 RPCPluginClient.__attrs_post_init__: Client object created."
        )

    async def _connect_and_handshake_with_retry(self) -> None:
        """
        Performs handshake and creates gRPC channel, with retry logic.

        This method sets instance attributes like _address, _transport_name,
        _protocol_version, _server_cert upon successful handshake, and
        grpc_channel, target_endpoint upon channel creation. It also manages
        _handshake_complete_event and _handshake_failed_event.
        """
        retry_enabled_str = rpcplugin_config.get("PLUGIN_CLIENT_RETRY_ENABLED", "true")
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
                    f"(retries disabled): {e}",
                    exc_info=True,
                )
                self._handshake_failed_event.set()
                raise
            return

        max_retries = int(rpcplugin_config.get("PLUGIN_CLIENT_MAX_RETRIES", 3))
        initial_backoff_ms = float(
            rpcplugin_config.get("PLUGIN_CLIENT_INITIAL_BACKOFF_MS", 500)
        )
        max_backoff_ms = float(
            rpcplugin_config.get("PLUGIN_CLIENT_MAX_BACKOFF_MS", 5000)
        )
        jitter_ms = float(rpcplugin_config.get("PLUGIN_CLIENT_RETRY_JITTER_MS", 100))
        total_timeout_s = float(
            rpcplugin_config.get("PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S", 60)
        )

        attempts = 0
        current_backoff_ms = initial_backoff_ms
        overall_start_time = time.monotonic()
        last_exception: Exception | None = None

        self.logger.info(
            "Starting connection/handshake sequence with retries enabled "
            f"(max_retries={max_retries}, total_timeout={total_timeout_s}s)."
        )

        while attempts <= max_retries:
            if time.monotonic() - overall_start_time > total_timeout_s:
                self.logger.error(
                    "Client connection/handshake retry sequence timed out after "
                    f"{total_timeout_s}s. Last error: "
                    f"{last_exception if last_exception else 'N/A'}"
                )
                self._handshake_failed_event.set()
                if last_exception:
                    raise last_exception from None
                raise HandshakeError(
                    message="Retry sequence timed out.",
                    hint=(
                        "Increase PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S or "
                        "check server responsiveness."
                    ),
                )

            if self._process and self._process.poll() is not None:
                self.logger.error(
                    f"Plugin process exited with code {self._process.returncode} "
                    f"during retry attempt {attempts + 1}. Aborting retries."
                )
                self._handshake_failed_event.set()
                raise HandshakeError(
                    message=(
                        f"Plugin process exited (code {self._process.returncode}) "
                        "during retry sequence."
                    ),
                    hint="Check plugin logs.",
                )

            try:
                self._handshake_complete_event.clear()
                self._handshake_failed_event.clear()

                if self.grpc_channel:
                    self.logger.debug(
                        "Cleaning up existing gRPC channel before attempt "
                        f"{attempts + 1}."
                    )
                    try:
                        await self.grpc_channel.close(grace=0.1)
                    except Exception:
                        pass  # nosec B110
                    self.grpc_channel = None
                    self._stubs = {}

                if (
                    self._transport
                    and hasattr(self._transport, "close")
                    and callable(self._transport.close)
                ):
                    try:
                        await self._transport.close()
                    except Exception:
                        pass  # nosec B110
                self._transport = None

                self.is_started = False

                self.logger.info(
                    f"Attempt {attempts + 1} of {max_retries + 1} to connect "
                    "and handshake..."
                )

                await self._perform_handshake()
                if not self._address or not self._transport_name:
                    raise HandshakeError(
                        "Handshake completed but critical endpoint data "
                        "(address/transport_name) not set."
                    )
                self.logger.info(
                    f"Handshake attempt {attempts + 1} successful. "
                    f"Endpoint: {self._address}, Transport: {self._transport_name}"
                )

                self.logger.debug(
                    f"Creating gRPC channel (attempt {attempts + 1}) to "
                    f"{self._address} ({self._transport_name})..."
                )
                await self._create_grpc_channel()
                self.logger.info(
                    f"Successfully connected to gRPC endpoint on attempt "
                    f"{attempts + 1}: {self.target_endpoint}"
                )

                self.is_started = True
                self._handshake_complete_event.set()
                self.logger.info(
                    "Client connection and handshake successful on attempt "
                    f"{attempts + 1}."
                )
                return

            except (HandshakeError, TransportError, ProtocolError, SecurityError) as e:
                last_exception = e
                self.logger.warning(
                    f"Attempt {attempts + 1} failed: "
                    f"{e.message if hasattr(e, 'message') else e}"
                )

                if attempts >= max_retries:
                    self.logger.error(
                        f"Maximum retry attempts ({max_retries + 1}) reached for "
                        f"connection/handshake. Last error: {last_exception}"
                    )
                    self._handshake_failed_event.set()
                    raise last_exception from e

                if (
                    time.monotonic() - overall_start_time + (current_backoff_ms / 1000)
                    > total_timeout_s
                ):
                    self.logger.error(
                        "Next retry would exceed total timeout. Aborting. "
                        f"Last error: {last_exception}"
                    )
                    self._handshake_failed_event.set()
                    raise last_exception from e

                delay_ms = current_backoff_ms + random.uniform(-jitter_ms, jitter_ms)  # nosec B311
                delay_ms = min(delay_ms, max_backoff_ms)
                delay_ms = max(delay_ms, 0.0)

                self.logger.info(
                    f"Retrying connection/handshake in {delay_ms / 1000:.2f} seconds..."
                )
                await asyncio.sleep(delay_ms / 1000)

                current_backoff_ms = min(current_backoff_ms * 2, max_backoff_ms)
                attempts += 1

            except Exception as e:
                last_exception = e
                self.logger.error(
                    "Unexpected error during connection/handshake attempt "
                    f"{attempts + 1}: {e}",
                    exc_info=True,
                )
                self._handshake_failed_event.set()
                raise

        self.logger.error(
            f"Exited retry loop without success. Max attempts: {max_retries + 1}. "
            f"Last error: {last_exception if last_exception else 'N/A'}"
        )
        self._handshake_failed_event.set()
        if last_exception:
            raise last_exception from None
        raise HandshakeError(
            message="Failed to connect and handshake after all retries.",
            hint="Check client and server logs.",
        )

    async def start(self) -> None:
        """
        Launch the plugin subprocess, perform handshake, and establish connection.

        This method executes the complete client initialization sequence:
        1. Sets up client certificates if auto-mTLS is enabled
        2. Launches the server subprocess
        3. Performs the handshake protocol
        4. Creates a secure gRPC channel
        5. Initializes service stubs

        Raises:
            HandshakeError: If the handshake fails
            ConnectionError: If the connection cannot be established
            TransportError: If the transport encounters an error

        Example:
            ```python
            client = RPCPluginClient(command=["./my_plugin"])
            await client.start()
            ```
        """
        logger.debug("🔄 Starting RPC plugin client...")
        try:
            await self._setup_client_certificates()

            await self._launch_process()

            await self._connect_and_handshake_with_retry()

            self._init_stubs()

            self._stdio_task = asyncio.create_task(self._read_stdio_logs())

            logger.info("✅ RPC plugin client started and ready.")
        except Exception as e:
            logger.error(f"💥 Client failed to start: {e}", exc_info=True)
            await self.close()
            raise

    async def _setup_client_certificates(self) -> None:
        """
        Load or generate client certificates for mTLS if enabled.

        If PLUGIN_AUTO_MTLS is true, this method will:
        1. Check for existing client certificate/key in config
        2. Generate new ephemeral credentials if not found
        3. Store the certificate/key for later use in TLS setup

        This method is essential for secure communication with the plugin.
        """
        logger.debug("🔐 Checking if auto-mTLS is enabled for client.")

        auto_mtls: bool = rpcplugin_config.auto_mtls_enabled()

        if auto_mtls:
            cert_pem: str = rpcplugin_config.get("PLUGIN_CLIENT_CERT")
            key_pem: str = rpcplugin_config.get("PLUGIN_CLIENT_KEY")

            if cert_pem and key_pem:
                logger.info("🔐 Using existing client cert/key from config.")
                self.client_cert = cert_pem
                self.client_key_pem = key_pem
            else:
                logger.info("🔐 Generating ephemeral self-signed client certificate.")
                client_cert_obj = Certificate(generate_keypair=True, key_type="ecdsa")
                self.client_cert = client_cert_obj.cert
                self.client_key_pem = client_cert_obj.key
        else:
            logger.info("🔐 mTLS not enabled; operating in insecure mode.")

    async def _launch_process(self) -> None:
        """
        Launch the plugin as a subprocess with appropriate environment configuration.

        This method:
        1. Checks if the process is already running
        2. Sets up the environment with configuration values
        3. Starts the subprocess with unbuffered I/O
        4. Handles potential process startup errors

        The subprocess is launched with its stdout/stderr captured for
        handshake and logging purposes.

        Raises:
            RuntimeError: If the process cannot be started
        """
        if self._process:
            logger.debug("🖥️ Plugin subprocess is already running; skipping launch.")
            return

        env = os.environ.copy()
        if self.config and "env" in self.config:
            env.update(self.config["env"])

        env["PYTHONUNBUFFERED"] = "1"

        # Ensure the magic cookie environment variable is set for the plugin server
        # The server will expect to find the cookie value in the environment variable
        # named by PLUGIN_MAGIC_COOKIE_KEY.
        cookie_key = rpcplugin_config.magic_cookie_key()
        cookie_value = rpcplugin_config.magic_cookie_value()
        if cookie_key and cookie_value:
            env[cookie_key] = cookie_value
            logger.debug(
                f"🖥️ Setting environment variable for plugin subprocess: "
                f"{cookie_key}='{cookie_value}'"
            )
        else:
            logger.warning(
                "🖥️ Magic cookie key or value not configured; "
                "plugin subprocess may fail handshake."
            )

        if self.client_cert:
            env["PLUGIN_CLIENT_CERT"] = self.client_cert
            # The following line seems to be a leftover or incorrect,
            # as rpcplugin_config.get() is usually for reading, not setting.
            # If the intent was to ensure it's in the client's own config,
            # it should be handled during client's config loading.
            # rpcplugin_config.get("PLUGIN_CLIENT_CERT", "") # Commented out

        logger.debug(f"🖥️ Launching plugin subprocess with command: {self.command}")
        try:
            self._process = subprocess.Popen(  # nosec B603
                self.command,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                bufsize=0,
                universal_newlines=False,
            )
            logger.info("🖥️ Plugin subprocess started successfully.")
        except Exception as e:
            logger.error(
                f"🖥️❌ Failed to launch plugin subprocess: {e}",
                extra={"trace": traceback.format_exc()},
            )
            raise TransportError(
                message=(
                    f"Failed to launch plugin subprocess for command: "
                    f"'{self.command}'. Error: {e}"
                ),
                hint=(
                    "Ensure the plugin executable path is correct, "
                    "it has execute permissions, and any required dependencies "
                    "are available."
                ),
            ) from e

    async def _relay_stderr_background(self) -> None:
        """
        Continuously read plugin's stderr in a background thread, printing it locally.

        This method creates a non-blocking background thread that reads and logs
        stderr output from the plugin process, which is especially helpful for
        debugging handshake issues in real-time.
        """
        import threading

        def read_stderr() -> None:
            while True:
                if not self._process or self._process.stderr is None:
                    break
                line = self._process.stderr.readline()
                if not line:
                    break
                sys.stderr.write(line.decode("utf-8", errors="replace"))

        t = threading.Thread(target=read_stderr, daemon=True)
        t.start()

    async def _read_raw_handshake_line_from_stdout(self) -> str:
        """Read a complete handshake line from stdout with robust retry logic."""
        loop = asyncio.get_event_loop()
        start_time = loop.time()
        timeout = 10.0

        buffer = ""

        while (loop.time() - start_time) < timeout:
            if self._process is not None and self._process.poll() is not None:
                stderr_output = ""
                if self._process.stderr is not None:
                    stderr_output = self._process.stderr.read().decode(
                        "utf-8", errors="replace"
                    )
                logger.error(
                    "🤝 Plugin process exited with code "
                    f"{self._process.returncode}. Stderr: {stderr_output}"
                )
                raise HandshakeError(
                    message=(
                        f"Plugin process exited prematurely "
                        f"(code {self._process.returncode}) before handshake."
                    ),
                    hint=(
                        "Check plugin logs or stderr for startup errors. "
                        "Ensure the plugin is compatible and outputs a handshake "
                        "string."
                    ),
                    code=self._process.returncode,
                )

            try:
                process = self._process
                if process is not None and process.stdout is not None:
                    # B023 fix: Use functools.partial to bind stdout
                    read_line_func = functools.partial(process.stdout.readline)
                    line_bytes = await asyncio.wait_for(
                        loop.run_in_executor(None, read_line_func),
                        timeout=2.0,
                    )
                else:
                    await asyncio.sleep(0.1)
                    continue

                if line_bytes:
                    line = line_bytes.decode("utf-8", errors="replace").strip()
                    buffer += line
                    logger.debug(
                        f"🤝 Read partial handshake data: '{line}', buffer: '{buffer}'"
                    )

                    if "|" in buffer and buffer.count("|") >= 5:
                        return buffer
                else:
                    await asyncio.sleep(0.25)

            except TimeoutError:
                logger.debug("🤝 Timeout on read attempt, retrying...")
                await asyncio.sleep(0.5)

            try:
                process = self._process
                if process is not None and process.stdout is not None:
                    # B023 fix: Use functools.partial to bind stdout and method
                    read_char_func = functools.partial(process.stdout.read, 1)
                    char_bytes = await asyncio.wait_for(
                        loop.run_in_executor(None, read_char_func),
                        timeout=1.0,
                    )
                    if char_bytes:
                        char = char_bytes.decode("utf-8", errors="replace")
                        buffer += char
                        logger.debug(f"🤝 Byte-by-byte read: buffer now: '{buffer}'")
                        if "|" in buffer and buffer.count("|") >= 5:
                            logger.debug(
                                "🤝 Byte-by-byte path found complete handshake "
                                "in buffer"
                            )
                            return buffer
                else:
                    await asyncio.sleep(0.1)
            except TimeoutError:
                logger.debug(
                    "🤝 Timeout on byte-by-byte read(1) attempt, continuing outer loop."
                )
                pass  # noqa: B012 (silence ruff about pass in except)

        stderr_output = ""
        if self._process is not None and self._process.stderr is not None:
            stderr_output = self._process.stderr.read().decode(
                "utf-8", errors="replace"
            )
        logger.error(f"🤝 Handshake timed out. Stderr output: {stderr_output}")
        raise HandshakeError(
            message="Timed out waiting for handshake line from plugin.",
            hint=(
                f"Ensure the plugin command '{self.command}' starts correctly and "
                f"outputs the handshake string to stdout within {timeout} seconds. "
                f"Last buffer: '{buffer}'. Stderr: '{stderr_output}'"
            ),
        )

    async def _perform_handshake(self) -> None:
        """
        Perform the handshake protocol with the plugin server.

        The handshake is a critical part of the plugin protocol that:
        1. Reads a formatted response line from the plugin's stdout
        2. Parses protocol version, network type, address, and certificate info
        3. Sets up the appropriate transport based on the handshake

        Format: CORE_VERSION|PLUGIN_VERSION|network|address|protocol|serverCert

        Raises:
            HandshakeError: If handshake cannot be completed or is invalid
            TimeoutError: If handshake response is not received in time
        """
        logger.debug("🤝 Initiating handshake with plugin server...")

        if not self._process or not self._process.stdout:
            raise HandshakeError(
                message=(
                    "Plugin process or its stdout stream is not available for "
                    "handshake."
                ),
                hint=(
                    "This typically indicates an issue with launching the plugin "
                    "subprocess. Check prior logs."
                ),
            )

        await self._relay_stderr_background()

        logger.debug(f"🤝 Waiting for handshake from command: {self.command}")

        try:
            line = await self._read_raw_handshake_line_from_stdout()
            logger.debug(f"🤝 Received handshake response: {line[:60]}...")
        except TimeoutError as e_timeout:
            logger.error("🤝 Handshake timed out while reading from plugin stdout.")
            raise HandshakeError(
                message="Handshake timed out waiting for response from plugin.",
                hint=(
                    "The plugin did not provide a handshake string within the "
                    "expected time. Check plugin logs."
                ),
            ) from e_timeout
        except HandshakeError:
            raise
        except Exception as e_read:
            logger.error(
                "🤝❌ Unexpected error reading handshake line.",
                extra={"trace": traceback.format_exc()},
            )
            raise HandshakeError(
                message=(
                    "An unexpected error occurred while reading handshake line: "
                    f"{e_read}"
                ),
                hint="Review client and plugin logs for more details.",
            ) from e_read

        try:
            (
                core_version,
                protocol_version,
                network,
                address,
                protocol,
                server_cert,
            ) = parse_handshake_response(line)
            logger.debug(
                f"🤝 Handshake parse => core_version={core_version}, "
                f"protocol_version={protocol_version}, network={network}, "
                f"address={address}, protocol={protocol}, cert={bool(server_cert)}"
            )
            self._protocol_version = protocol_version
            self._server_cert = server_cert
            self._transport_name = network

            match network:
                case "tcp":
                    self._transport = TCPSocketTransport()
                    logger.debug("*** network is set to tcp")
                    self._address = address
                case "unix":
                    logger.debug("*** network is set to unix")
                    normalized_path = address
                    if address.startswith("unix:"):
                        logger.debug("*** address starts with unix")
                        normalized_path = address[5:]
                        while normalized_path.startswith(
                            "/"
                        ) and not normalized_path.startswith("//"):
                            normalized_path = normalized_path[1:]

                    self._address = normalized_path
                    logger.debug(
                        f"🤝🔍 Normalized Unix path from '{address}' to "
                        f"'{self._address}' for transport init."
                    )
                    self._transport = UnixSocketTransport(path=self._address)
                case _:
                    raise TransportError(
                        message=(
                            f"Unsupported transport type '{network}' received in "
                            "handshake."
                        ),
                        hint=(
                            "Ensure the plugin outputs a supported transport type "
                            "('tcp' or 'unix') in its handshake string."
                        ),
                    )

            if self._transport is not None:
                await self._transport.connect(address)
                logger.info(f"🚄 Transport connected via {network} -> {address}")
            else:
                raise HandshakeError(
                    message=(
                        "Internal error: Transport was not initialized before "
                        "attempting to connect."
                    ),
                    hint="This indicates an issue within the client's handshake logic.",
                )
        except HandshakeError:
            raise
        except TransportError:
            raise
        except Exception as e:
            logger.error(
                "🤝❌ Error parsing handshake response or connecting transport.",
                extra={"trace": traceback.format_exc()},
            )
            raise HandshakeError(
                message=(
                    f"Failed to process handshake response or establish transport "
                    f"connection: {e}"
                ),
                hint=(
                    "Ensure handshake string is valid and network is configured "
                    "correctly."
                ),
            ) from e

    async def _create_grpc_channel(self) -> None:
        """
        Create a secure gRPC channel to communicate with the plugin.

        This method:
        1. Constructs the appropriate target address based on transport type
        2. Sets up TLS credentials if a server certificate is available
        3. Creates and configures the gRPC channel with optimized settings
        4. Waits for the channel to be ready before proceeding

        The channel becomes the foundation for all subsequent RPC communication.

        Raises:
            ConnectionError: If channel creation or connection fails
        """
        logger.debug("🚢 Attempting to create gRPC channel to plugin...")

        if isinstance(self._transport, UnixSocketTransport):
            target = f"unix:{self._address}"
        else:
            target = f"{self._transport_name}:{self._address}"

        logger.debug(f"🚢🔍 Creating gRPC channel with target: {target}")

        logger.debug("🚢 Attempting to create gRPC channel to plugin...")

        if not self._address or not self._transport_name:
            raise ProtocolError(
                message=(
                    "Cannot create gRPC channel: endpoint address or transport type "
                    "not determined."
                ),
                hint=(
                    "Ensure handshake was successful and set the _address and "
                    "_transport_name attributes."
                ),
            )

        if self._transport_name == "unix":
            target = f"unix:{self._address}"
        elif self._transport_name == "tcp":
            target = self._address
        else:
            raise TransportError(
                f"Unsupported transport name '{self._transport_name}' "
                "for channel creation."
            )

        logger.debug(f"🚢🔍 Creating gRPC channel with target: {target}")
        self.target_endpoint = target

        if self._server_cert:
            full_pem = self._rebuild_x509_pem(self._server_cert)

            explicit_client_cert_configured = bool(
                rpcplugin_config.get("PLUGIN_CLIENT_CERT")
            )

            if (
                explicit_client_cert_configured
                and self.client_cert
                and self.client_key_pem
            ):
                logger.debug(
                    "🔐 Creating mTLS channel with explicitly configured client "
                    "certs + server root."
                )
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=full_pem.encode(),
                    private_key=self.client_key_pem.encode(),
                    certificate_chain=self.client_cert.encode(),
                )
            else:
                logger.debug(
                    "🔐 Creating TLS channel (server auth only) using server's "
                    "cert as root CA. Client certs (if auto-generated) will not "
                    "be presented."
                )
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=full_pem.encode()
                )

            self.grpc_channel = grpc.aio.secure_channel(
                target,
                credentials,
                options=[
                    ("grpc.ssl_target_name_override", "localhost"),
                    ("grpc.max_receive_message_length", 32 * 1024 * 1024),
                    ("grpc.max_send_message_length", 32 * 1024 * 1024),
                    ("grpc.keepalive_time_ms", 10000),
                    ("grpc.keepalive_timeout_ms", 5000),
                ],
            )
        else:
            logger.info("🚢 No server certificate. Using insecure channel.")
            self.grpc_channel = grpc.aio.insecure_channel(target)

        logger.debug("🚢 gRPC channel created successfully.")

        try:
            if not self.grpc_channel:
                raise TransportError(
                    "gRPC channel not initialized before checking readiness."
                )
            await asyncio.wait_for(
                self.grpc_channel.channel_ready(),
                timeout=rpcplugin_config.get("PLUGIN_CONNECTION_TIMEOUT", 5.0),
            )
            logger.debug("🚢✅ gRPC channel ready and connected.")
        except TimeoutError as e_timeout:
            socket_path = (
                target.replace("unix:", "") if target.startswith("unix:") else None
            )
            logger.error("🚢❌ gRPC channel failed to become ready (timeout)")
            if socket_path:
                logger.error(
                    "🚢❌ Socket diagnostics: path="
                    f"{socket_path}, exists={os.path.exists(socket_path)}"
                )
            raise TransportError(
                message="Failed to establish gRPC channel to plugin: timeout.",
                hint=(
                    f"Check network connectivity to {target}. Ensure plugin server "
                    f"is responsive. Socket diagnostics: path={socket_path}, "
                    f"exists={os.path.exists(socket_path) if socket_path else 'N/A'}"
                ),
            ) from e_timeout
        except Exception as e:
            logger.error(f"🚢❌ gRPC channel creation failed: {e}")
            raise TransportError(
                message=(
                    f"Failed to establish gRPC channel to plugin at {target}: {e}"
                ),
                hint=(
                    "Verify plugin server is running and network is accessible. "
                    "Check for TLS/mTLS configuration mismatches if applicable."
                ),
            ) from e

    def _rebuild_x509_pem(self, maybe_cert: str) -> str:
        """
        Convert a raw base64 certificate into proper PEM format.

        This method adds the required PEM headers and formatting to a raw
        certificate string if they're missing. This is necessary because the
        handshake protocol transmits certificates without PEM headers.

        Args:
            maybe_cert: The certificate string, either in PEM format already or
                        as raw base64

        Returns:
            A properly formatted PEM certificate string
        """
        if maybe_cert.startswith("-----BEGIN CERTIFICATE-----"):
            logger.debug("🔐 Server cert already has PEM headers.")
            return maybe_cert
        cert_lines = [maybe_cert[i : i + 64] for i in range(0, len(maybe_cert), 64)]
        full_pem = (
            "-----BEGIN CERTIFICATE-----\n"
            + "\n".join(cert_lines)
            + "\n-----END CERTIFICATE-----\n"
        )
        logger.debug("🔐 Rebuilt server certificate into PEM format.")
        return full_pem

    def _init_stubs(self) -> None:
        """
        Initialize gRPC service stubs for communication with the plugin.

        This method creates the standard service stubs that enable:
        1. Stdio: receiving plugin stdout/stderr streams
        2. Broker: managing subchannels for multi-service communication
        3. Controller: sending control commands like shutdown

        These stubs provide the API for client-server interaction.

        Raises:
            RuntimeError: If called before the gRPC channel is established
        """
        if not self.grpc_channel:
            raise ProtocolError(
                message=(
                    "Cannot initialize gRPC stubs; gRPC channel is not available."
                ),
                hint=(
                    "This indicates an internal issue where the client proceeded "
                    "without a valid communication channel."
                ),
            )

        logger.debug(
            "🔌 Creating GRPCStdioStub, GRPCBrokerStub, GRPCControllerStub from "
            "channel."
        )
        self._stubs["stdio"] = GRPCStdioStub(self.grpc_channel)
        self._stubs["broker"] = GRPCBrokerStub(self.grpc_channel)
        self._stubs["controller"] = GRPCControllerStub(self.grpc_channel)

        self._stdio_stub = self._stubs["stdio"]
        self._broker_stub = self._stubs["broker"]
        self._controller_stub = self._stubs["controller"]

    async def _read_stdio_logs(self) -> None:
        """
        Subscribe to and process the plugin's stdout/stderr stream.

        This method starts a long-running task that:
        1. Connects to the plugin's stdio streaming service
        2. Continuously reads stdout/stderr messages
        3. Logs them for monitoring and debugging

        The stream continues until the connection is closed or task is cancelled.
        """
        if not self._stdio_stub:
            logger.debug("🔌📝 _read_stdio_logs called, but no _stdio_stub. Exiting.")
            return
        logger.debug("🔌📝 Starting to read plugin's stdio stream...")

        try:
            async for chunk in self._stdio_stub.StreamStdio(empty_pb2.Empty()):
                if chunk.channel == StdioData.STDERR:
                    logger.debug(f"🔌📝📥 Plugin STDERR: {chunk.data!r}")
                else:
                    logger.debug(f"🔌📝📥 Plugin STDOUT: {chunk.data!r}")
        except asyncio.CancelledError:
            logger.debug(
                "🔌📝 read_stdio_logs task cancelled. Shutting down stdio read."
            )
        except Exception as e:
            logger.error(
                f"🔌📝❌ Error reading plugin stdio stream: {e}",
                extra={"trace": traceback.format_exc()},
            )

        logger.debug("🔌📝 Plugin stdio reading loop ended.")

    async def open_broker_subchannel(self, sub_id: int, address: str) -> None:
        """
        Open a subchannel for additional service communication.

        The broker mechanism allows for multiple logical services to be
        provided over a single plugin connection. This method:
        1. Initiates a streaming RPC with the broker service
        2. Sends a "knock" message to request subchannel establishment
        3. Processes acknowledgment responses

        Args:
            sub_id: Unique identifier for the subchannel
            address: Address for the subchannel connection

        Raises:
            RuntimeError: If broker stub is not initialized
        """
        if not self._broker_stub:
            logger.warning("🔌📡 Broker stub not initialized; cannot open subchannel.")
            return

        logger.debug(
            f"🔌📡 Attempting to open subchannel ID {sub_id} at {address} via Broker."
        )

        async def _broker_coroutine() -> None:
            if self._broker_stub is None:
                return
            call = self._broker_stub.StartStream()
            try:
                knock_info = ConnInfo(
                    service_id=sub_id,
                    network="tcp",
                    address=address,
                    knock=ConnInfo.Knock(knock=True, ack=False, error=""),
                )
                await call.write(knock_info)
                await call.done_writing()

                async for reply in call:
                    logger.debug(
                        f"🔌📡 Broker response => service_id={reply.service_id}, "
                        f"knock.ack={reply.knock.ack}, error={reply.knock.error}"
                    )
                    if not reply.knock.ack:
                        logger.error(
                            f"🔌📡❌ Subchannel open failed: {reply.knock.error}"
                        )
                    else:
                        logger.info(f"🔌📡✅ Subchannel {sub_id} opened successfully!")
            finally:
                logger.debug("🔌📡 Broker subchannel open() streaming call complete.")
                await call.aclose()

        self._broker_task = asyncio.create_task(_broker_coroutine())

    async def shutdown_plugin(self) -> None:
        """
        Request graceful shutdown of the plugin server.

        This method calls the Controller service's Shutdown method,
        which instructs the plugin to perform an orderly shutdown.
        The client should still call close() afterwards to clean up
        local resources.

        Returns:
            None
        """
        if not self._controller_stub:
            logger.debug("🔌🛑 No controller stub found; cannot call Shutdown().")
            return

        logger.debug("🔌🛑 Requesting plugin shutdown via GRPCController.Shutdown()...")
        try:
            await self._controller_stub.Shutdown(ControllerEmpty())
            logger.info("🔌🛑 Plugin acknowledged shutdown request.")
        except grpc.RpcError as e:
            error_code_obj = (
                e.code() if hasattr(e, "code") and callable(e.code) else None
            )
            error_details_str = (
                e.details() if hasattr(e, "details") and callable(e.details) else str(e)
            )

            actual_code_for_log = "UNKNOWN"
            if error_code_obj is not None and hasattr(error_code_obj, "name"):
                actual_code_for_log = error_code_obj.name
            elif error_code_obj is not None:
                actual_code_for_log = str(error_code_obj)

            logger.error(
                f"🔌🛑❌ gRPC error calling Shutdown(): {actual_code_for_log} - "
                f"{error_details_str}",
                extra={"trace": traceback.format_exc()},
            )

            code_int_val = None
            if (
                error_code_obj is not None
                and hasattr(error_code_obj, "value")
                and isinstance(error_code_obj.value, tuple)
                and len(error_code_obj.value) > 0
            ):
                code_int_val = error_code_obj.value[0]

            raise TransportError(
                message=f"gRPC error during plugin shutdown: {error_details_str}",
                code=code_int_val,
                hint=(
                    "The plugin's Shutdown RPC failed. This could be due to "
                    "network issues or an error within the plugin's shutdown "
                    "logic. Check plugin logs."
                ),
            ) from e
        except Exception as e:
            logger.error(
                f"🔌🛑❌ Unexpected error calling Shutdown(): {e}",
                extra={"trace": traceback.format_exc()},
            )
            raise TransportError(
                message=f"Unexpected error during plugin shutdown call: {e}",
                hint="Review client and plugin logs for more details.",
            ) from e

    async def close(self) -> None:
        """
        Clean up all resources and connections.

        This method performs complete cleanup of client resources:
        1. Cancels any background tasks (stdio reading, etc.)
        2. Closes the gRPC channel
        3. Terminates the plugin subprocess
        4. Closes the transport connection

        This method is idempotent and can be called multiple times safely.
        It should be called when the client is no longer needed.
        """
        logger.debug("🔄 Closing RPCPluginClient...")

        tasks_to_cancel = []
        if self._stdio_task and not self._stdio_task.done():
            tasks_to_cancel.append(self._stdio_task)
        if self._broker_task and not self._broker_task.done():
            tasks_to_cancel.append(self._broker_task)

        if tasks_to_cancel:
            for t in tasks_to_cancel:
                t.cancel()
            try:
                await asyncio.wait_for(
                    asyncio.gather(*tasks_to_cancel, return_exceptions=True),
                    timeout=2.0,
                )
                logger.debug("Background tasks cancelled.")
            except TimeoutError:
                logger.warning("Timed out waiting for background tasks to cancel.")
        self._stdio_task = None
        self._broker_task = None

        if self.grpc_channel:
            logger.debug("🔄 Closing gRPC channel...")
            try:
                await self.grpc_channel.close(grace=0.5)
                logger.debug("🔄 gRPC channel closed.")
            except Exception as e:
                logger.error(
                    f"🔄❌ Error closing gRPC channel: {e}",
                    extra={"trace": traceback.format_exc()},
                )
            self.grpc_channel = None
            self._stubs = {}

        if self._process and self._process.poll() is None:
            logger.debug("🔄 Terminating plugin subprocess...")
            try:
                self._process.terminate()
                logger.debug("🔄 Sent terminate signal to plugin subprocess.")
                try:
                    if self._process is not None:
                        self._process.wait(timeout=7)
                        logger.debug("🔄 Plugin subprocess terminated.")
                except Exception as e:
                    logger.error(
                        f"🔄❌ Error waiting for plugin process to terminate: {e}",
                        extra={"trace": traceback.format_exc()},
                    )
            except Exception as e:
                logger.error(
                    f"🔄❌ Error sending terminate signal to plugin process: {e}",
                    extra={"trace": traceback.format_exc()},
                )
            self._process = None

        if self._transport:
            logger.debug("🔄 Closing transport socket...")
            try:
                await self._transport.close()
                logger.debug("🔄 Transport socket closed.")
            except Exception as e:
                logger.error(
                    f"🔄❌ Error closing transport socket: {e}",
                    extra={"trace": traceback.format_exc()},
                )
            self._transport = None

        logger.info("🔄 RPCPluginClient fully closed.")

    async def __aenter__(self) -> "RPCPluginClient":
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._controller_stub:
            try:
                await self.shutdown_plugin()
            except Exception as e:
                logger.error(
                    f"🔌🛑❌ Error during __aexit__ calling shutdown_plugin(): {e}"
                )
        await self.close()


# 🐍🏗️🔌
