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
import contextlib
import os
import subprocess
import sys
import traceback
from typing import Any # Removed Generic

from attrs import define, field

import grpc
from google.protobuf import empty_pb2

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.exception import HandshakeError, TransportError
from pyvider.rpcplugin.handshake import parse_handshake_response
from pyvider.telemetry import logger
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
# Import TransportT temporarily for the Generic base, will remove if client not generic
# Also import TransportType for the actual field type
from pyvider.rpcplugin.transport.types import TransportType


@define
class RPCPluginClient: # No longer Generic[TransportT]
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
        provider_stub = MyProviderStub(client._channel)
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
    _transport: TransportType | None = field(init=False, default=None) # Changed to TransportType
    _transport_name: str | None = field(init=False, default=None)

    _address: str | None = field(init=False, default=None)
    _protocol_version: int | None = field(init=False, default=None)
    _server_cert: str | None = field(init=False, default=None)
    _channel: grpc.aio.Channel | None = field(init=False, default=None)

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

    def __attrs_post_init__(self) -> None:
        """
        Initialize client state after attributes are set.
        
        This method is called automatically after object instantiation
        to set up initial client state. It doesn't perform any network 
        operations - those happen in the start() method.
        """
        logger.debug("🔧 RPCPluginClient.__attrs_post_init__: Client object created.")

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

        # 1) Possibly set up auto mTLS: generate or load client cert/key
        await self._setup_client_certificates()

        # 2) Launch the server process if not already started
        await self._launch_process()

        # 3) Perform handshake + parse handshake response
        await self._perform_handshake()

        # 4) Create the gRPC channel (with TLS)
        await self._create_grpc_channel()

        # 5) Initialize stubs for Stdio / Broker / Controller
        self._init_stubs()

        # 6) Optionally start a background task to read plugin logs from stdio
        self._stdio_task = asyncio.create_task(self._read_stdio_logs())

        logger.info("✅ RPC plugin client started and ready.")

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

        # Force unbuffered output in Python subprocesses
        env["PYTHONUNBUFFERED"] = "1"

        # Pass client cert if needed
        if self.client_cert:
            # set the environment variable so the server knows what the clients
            # certificate is.
            env["PLUGIN_CLIENT_CERT"] = self.client_cert
            rpcplugin_config.get("PLUGIN_CLIENT_CERT", "")

        logger.debug(f"🖥️ Launching plugin subprocess with command: {self.command}")
        try:
            self._process = subprocess.Popen(
                self.command,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                bufsize=0,  # Disable buffering
                universal_newlines=False,
            )
            logger.info("🖥️ Plugin subprocess started successfully.")
        except Exception as e:
            logger.error(f"🖥️❌ Failed to launch plugin subprocess: {e}",
                        extra={"trace": traceback.format_exc()})
            raise

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
                sys.stderr.write(line.decode('utf-8', errors='replace'))  # Decode bytes to str

        t = threading.Thread(target=read_stderr, daemon=True)
        t.start()

    async def _read_raw_handshake_line_from_stdout(self) -> str:
        """Read a complete handshake line from stdout with robust retry logic."""
        loop = asyncio.get_event_loop()
        start_time = loop.time()
        timeout = 10.0  # Increased timeout for handshake

        # Buffer for incomplete handshake lines
        buffer = ""

        while (loop.time() - start_time) < timeout:
            # Check process state
            if self._process is not None and self._process.poll() is not None:
                stderr_output = ""
                if self._process.stderr is not None: # Check stderr is not None
                    stderr_output = self._process.stderr.read().decode('utf-8', errors='replace')
                logger.error(f"🤝 Plugin process exited with code {self._process.returncode}. Stderr: {stderr_output}")
                raise HandshakeError(f"Plugin process exited with code {self._process.returncode} before handshake.")

            # Try to read a complete line with increased timeout
            try:
                # First try: direct read with longer timeout
                if self._process is not None and self._process.stdout is not None: # Check stdout is not None
                    line_bytes = await asyncio.wait_for(
                        loop.run_in_executor(None, lambda: self._process.stdout.readline()), # type: ignore[union-attr]
                        timeout=2.0  # Longer per-read timeout
                    )
                else:
                    # Process or stdout is None, cannot read
                    await asyncio.sleep(0.1) # Wait briefly and re-check loop condition
                    continue


                if line_bytes:
                    line = line_bytes.decode('utf-8', errors='replace').strip()
                    buffer += line
                    logger.debug(f"🤝 Read partial handshake data: '{line}', buffer: '{buffer}'")

                    # Check for complete handshake
                    if "|" in buffer and buffer.count("|") >= 5:
                        return buffer
                else:
                    # Empty read but process still running - wait and retry
                    await asyncio.sleep(0.25)  # Longer sleep to allow buffering

            except asyncio.TimeoutError:
                logger.debug("🤝 Timeout on read attempt, retrying...")
                await asyncio.sleep(0.5)  # Longer backoff

            # Fallback to byte-by-byte reading if line reading doesn't work
            # This might help if the Go server doesn't flush properly or uses different line endings
            if not buffer:  # Only try this if we haven't read anything
                try:
                    if self._process is not None and self._process.stdout is not None: # Check stdout is not None
                        char_bytes = await asyncio.wait_for(
                            loop.run_in_executor(None, lambda: self._process.stdout.read(1)), # type: ignore[union-attr]
                            timeout=1.0
                        )
                        if char_bytes:
                            char = char_bytes.decode('utf-8', errors='replace')
                            buffer += char
                            logger.debug(f"🤝 Byte-by-byte read: buffer now: '{buffer}'")
                    else:
                        # Process or stdout is None, cannot read
                        await asyncio.sleep(0.1) # Wait briefly
                        continue
                except asyncio.TimeoutError:
                    pass  # Just continue the outer loop

        # If we get here, we've timed out
        stderr_output = ""
        if self._process is not None and self._process.stderr is not None: # Check stderr is not None
            stderr_output = self._process.stderr.read().decode('utf-8', errors='replace')
        logger.error(f"🤝 Handshake timed out. Stderr output: {stderr_output}")
        raise TimeoutError("Timed out waiting for handshake line. Check if the server is writing to stdout correctly.")

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
            raise HandshakeError("No server process or no stdout available.")

        # Start stderr relay immediately to see any error output
        await self._relay_stderr_background()

        # Log the command being used
        logger.debug(f"🤝 Waiting for handshake from command: {self.command}")

        try:
            line = await self._read_raw_handshake_line_from_stdout()
            logger.debug(f"🤝 Received handshake response: {line[:60]}...")
        except TimeoutError:
            logger.error("🤝 Handshake timed out; no response from plugin.")
            raise HandshakeError("Handshake timed out.")
        except Exception:
            logger.error(
                "🤝❌ Error reading handshake line.",
                extra={"trace": traceback.format_exc()},
            )
            raise

        # Parse handshake
        try:
            core_version, protocol_version, network, address, protocol, server_cert = (
                parse_handshake_response(line)
            )
            logger.debug(
                f"🤝 Handshake parse => core_version={core_version}, "
                f"protocol_version={protocol_version}, network={network}, "
                f"address={address}, protocol={protocol}, cert={bool(server_cert)}"
            )
            self._protocol_version = protocol_version
            self._server_cert = server_cert
            self.transport_name = network

            if network == "tcp":
                self.transport = TCPSocketTransport()
                logger.debug("*** network is set to tcp")
            elif network == "unix":
                # More robust handling of unix: prefix formats
                logger.debug("*** network is set to unix")

                if address.startswith("unix:"):
                    logger.debug("*** address starts with unix")
                    self._address = address[5:]  # Remove standard unix: prefix
                    # Remove leading slashes (but not all slashes)
                    while self._address.startswith("/") and not self._address.startswith("//"):
                        self._address = self._address[1:]

                else:
                    self._address = address

                logger.debug(f"🤝🔍 Normalized Unix path from '{address}' to '{self._address}'")
                self.transport = UnixSocketTransport(path=self._address)
            else:
                raise TransportError(f"Unsupported transport: {network}")

            # Connect the chosen transport
            if self.transport is not None: # Check transport is not None
                await self.transport.connect(address)
                logger.info(f"🚄 Transport connected via {network} -> {address}")
            else:
                # This case should ideally not be reached if logic is correct
                raise HandshakeError("Transport not initialized before connect call.")
        except Exception as e:
            logger.error(
                "🤝❌ Error parsing handshake response or connecting transport.",
                extra={"trace": traceback.format_exc()},
            )
            raise HandshakeError(f"Handshake parse/connect error: {e}")

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

        # CRITICAL FIX: Use the same address that was established during handshake
        if isinstance(self.transport, UnixSocketTransport):
            # For Unix sockets, we must use the exact same socket path from handshake
            target = f"unix:{self._address}"
        else:
            # For TCP, use standard addressing
            target = f"{self.transport_name}:{self._address}"

        logger.debug(f"🚢🔍 Creating gRPC channel with target: {target}")

        # Rebuild server cert into PEM if needed
        if self._server_cert:
            full_pem = self._rebuild_x509_pem(self._server_cert)

            # Set up credentials
            if self.client_cert and self.client_key_pem:
                logger.debug("🔐 Creating mTLS channel with client certs + server root.")
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=full_pem.encode(),
                    private_key=self.client_key_pem.encode(),
                    certificate_chain=self.client_cert.encode()
                )
            else:
                logger.debug("🔐 Creating TLS channel with server cert only.")
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=full_pem.encode()
                )

            # Create the secure channel
            self._channel = grpc.aio.secure_channel(
                target,
                credentials,
                options=[
                    ("grpc.ssl_target_name_override", "localhost"),
                    ("grpc.max_receive_message_length", 32 * 1024 * 1024),
                    ("grpc.max_send_message_length", 32 * 1024 * 1024),
                    ("grpc.keepalive_time_ms", 10000),
                    ("grpc.keepalive_timeout_ms", 5000)
                ]
            )
        else:
            # Fall back to insecure channel if no cert
            logger.info("🚢 No server certificate. Using insecure channel.")
            self._channel = grpc.aio.insecure_channel(target)

        logger.debug("🚢 gRPC channel created successfully.")

        # Wait for the channel to be ready with timeout
        try:
            await asyncio.wait_for(self._channel.channel_ready(), timeout=5.0)
            logger.debug("🚢✅ gRPC channel ready and connected.")
        except asyncio.TimeoutError:
            socket_path = target.replace("unix:", "") if target.startswith("unix:") else None
            logger.error("🚢❌ gRPC channel failed to become ready (timeout)")
            if socket_path:
                logger.error(f"🚢❌ Socket diagnostics: path={socket_path}, exists={os.path.exists(socket_path)}")
            raise ConnectionError("Failed to establish gRPC channel to plugin: timeout")
        except Exception as e:
            logger.error(f"🚢❌ gRPC channel failed: {e}")
            raise ConnectionError(f"Failed to establish gRPC channel to plugin: {e}")

    def _rebuild_x509_pem(self, maybe_cert: str) -> str:
        """
        Convert a raw base64 certificate into proper PEM format.
        
        This method adds the required PEM headers and formatting to a raw
        certificate string if they're missing. This is necessary because the
        handshake protocol transmits certificates without PEM headers.
        
        Args:
            maybe_cert: The certificate string, either in PEM format already or as raw base64
            
        Returns:
            A properly formatted PEM certificate string
        """
        if maybe_cert.startswith("-----BEGIN CERTIFICATE-----"):
            logger.debug("🔐 Server cert already has PEM headers.")
            return maybe_cert
        # Reconstruct lines
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
        if not self._channel:
            raise RuntimeError("Cannot init stubs; no gRPC channel available.")

        logger.debug(
            "🔌 Creating GRPCStdioStub, GRPCBrokerStub, GRPCControllerStub from channel."
        )
        self._stdio_stub = GRPCStdioStub(self._channel)
        self._broker_stub = GRPCBrokerStub(self._channel)
        self._controller_stub = GRPCControllerStub(self._channel)

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
            # We call StreamStdio once. The plugin sends us lines until it shuts down.
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
        if not self._broker_stub: # Check broker_stub is not None
            logger.warning("🔌📡 Broker stub not initialized; cannot open subchannel.")
            return

        logger.debug(
            f"🔌📡 Attempting to open subchannel ID {sub_id} at {address} via Broker."
        )

        async def _broker_coroutine() -> None:
            if self._broker_stub is None: # Should be caught by the check above, but for type safety
                return
            # Create a bidirectional streaming call
            call = self._broker_stub.StartStream()
            try:
                # 1) Send a ConnInfo with knock=True
                knock_info = ConnInfo(
                    service_id=sub_id,
                    network="tcp",  # or "unix"
                    address=address,
                    knock=ConnInfo.Knock(knock=True, ack=False, error=""),
                )
                await call.write(knock_info)
                await call.done_writing()  # we won't send more messages in this example

                async for reply in call:
                    # The plugin should respond with ack = True
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
        except Exception as e:
            logger.error(
                f"🔌🛑❌ Error calling Shutdown(): {e}",
                extra={"trace": traceback.format_exc()},
            )

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

        # Cancel reading tasks
        tasks_to_cancel = []
        if self._stdio_task and not self._stdio_task.done():
            tasks_to_cancel.append(self._stdio_task)
        if self._broker_task and not self._broker_task.done():
            tasks_to_cancel.append(self._broker_task)

        for t in tasks_to_cancel:
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t

        # Close gRPC channel
        if self._channel:
            logger.debug("🔄 Closing gRPC channel...")
            try:
                await self._channel.close(grace=None) # Added grace=None
                logger.debug("🔄 gRPC channel closed.")
            except Exception as e:
                logger.error(f"🔄❌ Error closing gRPC channel: {e}", extra={"trace": traceback.format_exc()})
            self._channel = None

        # Terminate plugin process
        if self._process:
            logger.debug("🔄 Terminating plugin subprocess...")
            try:
                self._process.terminate()
                logger.debug("🔄 Sent terminate signal to plugin subprocess.")
                try:
                    # Ensure process is not None before calling wait()
                    if self._process is not None:
                        self._process.wait(timeout=7) # should be higher than the server timeout
                        logger.debug("🔄 Plugin subprocess terminated.")
                except Exception as e: # Catches subprocess.TimeoutExpired and other wait issues
                    logger.error(
                        f"🔄❌ Error waiting for plugin process to terminate: {e}",
                        extra={"trace": traceback.format_exc()},
                    )
            except Exception as e: # Catches errors from terminate() itself
                logger.error(
                    f"🔄❌ Error sending terminate signal to plugin process: {e}",
                    extra={"trace": traceback.format_exc()},
                )
            self._process = None

        # Close underlying transport
        if self.transport:
            logger.debug("🔄 Closing transport socket...")
            try:
                await self.transport.close() # TransportType instances have close()
                logger.debug("🔄 Transport socket closed.")
            except Exception as e:
                logger.error(f"🔄❌ Error closing transport socket: {e}", extra={"trace": traceback.format_exc()})
            self.transport = None

        logger.info("🔄 RPCPluginClient fully closed.")

# 🐍🏗️🔌
