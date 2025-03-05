#!/usr/bin/env python3
# pyvider/rpcplugin/client/base.py

import asyncio
import contextlib
import os
import subprocess
import sys
import traceback
from typing import Any

import attrs
import grpc
from google.protobuf import empty_pb2

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.exception import HandshakeError, TransportError
from pyvider.rpcplugin.handshake import parse_handshake_response
from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData

# Generated stubs from your .proto files:
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.transport.types import TransportT


@attrs.define
class RPCPluginClient:
    """
    RPCPluginClient updated to interact with the new broker, stdio, and controller services.
    This version:
      • Launches or attaches to a plugin server subprocess.
      • Performs handshake, sets up TLS.
      • Creates a secure gRPC channel.
      • Exposes methods to:
         => read plugin logs (StdioStub.StreamStdio)
         => manage broker subchannels (BrokerStub.StartStream)
         => send shutdown signals (ControllerStub.Shutdown).
    """

    command: list[str] = attrs.field()
    config: dict[str, Any] | None = attrs.field(default=None)

    # Internal fields
    _process: subprocess.Popen | None = attrs.field(init=False, default=None)
    _transport: TransportT | None = attrs.field(init=False, default=None)
    _protocol_version: int | None = attrs.field(init=False, default=None)
    _server_cert: str | None = attrs.field(init=False, default=None)
    _channel: grpc.aio.Channel | None = attrs.field(init=False, default=None)

    # Generated or loaded client certificate
    client_cert: str | None = attrs.field(init=False, default=None)
    client_key_pem: str | None = attrs.field(init=False, default=None)

    # gRPC stubs for the new services
    _stdio_stub: GRPCStdioStub | None = attrs.field(init=False, default=None)
    _broker_stub: GRPCBrokerStub | None = attrs.field(init=False, default=None)
    _controller_stub: GRPCControllerStub | None = attrs.field(init=False, default=None)

    # Tasks for asynchronous streaming (e.g., reading stdio or broker streams)
    _stdio_task: asyncio.Task | None = attrs.field(init=False, default=None)
    _broker_task: asyncio.Task | None = attrs.field(init=False, default=None)

    def __attrs_post_init__(self) -> None:
        """
        Optionally configure or read environment variables. A place to put
        handshake defaults, but the actual handshake is done in start().
        """
        logger.debug("🔧 RPCPluginClient.__attrs_post_init__: Client object created.")

    async def start(self) -> None:
        """
        Launch the plugin subprocess, do the handshake, create a secure channel,
        init stubs, and optionally begin streaming logs.
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
        If PLUGIN_AUTO_MTLS is true, load or generate a client certificate and key.
        """
        logger.debug("🔐 Checking if auto-mTLS is enabled for client.")
        auto_mtls = rpcplugin_config.get("PLUGIN_AUTO_MTLS", "").lower()
        if auto_mtls in ("true", "1", "yes"):
            cert_pem = rpcplugin_config.get("PLUGIN_CLIENT_CERT", "")
            key_pem = rpcplugin_config.get("PLUGIN_CLIENT_KEY", "")
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

    # Modify _launch_process to configure better process environment
    async def _launch_process(self) -> None:
        """Launch the plugin as a subprocess if not already running."""
        if self._process:
            logger.debug("🖥️ Plugin subprocess is already running; skipping launch.")
            return

        env = os.environ.copy()
        if self.config and "env" in self.config:
            env.update(self.config["env"])

        # Force unbuffered output in Python subprocesses
        env["PYTHONUNBUFFERED"] = "1"

        # Configure Go process environment for better interoperability
        # These settings help Go's stdout flushing behavior
        env["GODEBUG"] = env.get("GODEBUG", "") + ",asyncpreemptoff=1"
        env["GOOPTS"] = env.get("GOOPTS", "") + " -gcflags=all=-N"  # Disable optimizations

        # Pass client cert if needed
        if self.client_cert:
            env["PLUGIN_CLIENT_CERT"] = self.client_cert

        # Force Unix transport preference
        env["PLUGIN_TRANSPORTS"] = "unix,tcp"

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

################################################################################

    # Add this method before _perform_handshake
    async def _relay_stderr_background(self) -> None:
        """
        Continuously read plugin's stderr in a background thread, printing it locally.
        This helps debug handshake issues in real-time.
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

################################################################################

    async def _perform_handshake(self) -> None:
        """
        Reads a single line from the plugin stdout for handshake:
          => Format: CORE_VERSION|PLUGIN_VERSION|network|address|protocol|serverCert
        """
        logger.debug("🤝 Initiating handshake with plugin server...")

        if not self._process or not self._process.stdout:
            raise HandshakeError("No server process or no stdout available.")

        # Start stderr relay immediately to see any error output
        await self._relay_stderr_background()

        # Log the command being used
        logger.debug(f"🤝 Waiting for handshake from command: {self.command}")

        ###
        async def read_stdout_line() -> str:
            loop = asyncio.get_event_loop()
            start_time = loop.time()
            timeout = 10.0  # Increase timeout for handshake

            # Buffer for incomplete handshake lines
            buffer = ""

            while (loop.time() - start_time) < timeout:
                # Check process state
                if self._process.poll() is not None:
                    stderr_output = ""
                    if self._process.stderr:
                        stderr_output = self._process.stderr.read().decode('utf-8', errors='replace')
                    logger.error(f"🤝 Plugin process exited with code {self._process.returncode}. Stderr: {stderr_output}")
                    raise HandshakeError(f"Plugin process exited with code {self._process.returncode} before handshake.")

                # Try to read a complete line with increased timeout
                try:
                    # First try: direct read with longer timeout
                    line_bytes = await asyncio.wait_for(
                        loop.run_in_executor(None, lambda: self._process.stdout.readline()),
                        timeout=2.0  # Longer per-read timeout
                    )

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
                        char_bytes = await asyncio.wait_for(
                            loop.run_in_executor(None, lambda: self._process.stdout.read(1)),
                            timeout=1.0
                        )
                        if char_bytes:
                            char = char_bytes.decode('utf-8', errors='replace')
                            buffer += char
                            logger.debug(f"🤝 Byte-by-byte read: buffer now: '{buffer}'")
                    except asyncio.TimeoutError:
                        pass  # Just continue the outer loop

            # If we get here, we've timed out
            stderr_output = ""
            if self._process.stderr:
                stderr_output = self._process.stderr.read().decode('utf-8', errors='replace')
            logger.error(f"🤝 Handshake timed out. Stderr output: {stderr_output}")
            raise TimeoutError("Timed out waiting for handshake line. Check if the server is writing to stdout correctly.")

        try:
            line = await read_stdout_line()
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

            if network == "tcp":
                self._transport = TCPSocketTransport()
                logger.debug("*** network is set to tcp")
            elif network == "unix":
                # More robust handling of unix: prefix formats
                logger.debug("*** network is set to unix")
                if address.startswith("unix:"):
                    logger.debug("*** address starts with unix")
                    sock_path = address[5:]  # Remove standard unix: prefix
                    # Remove leading slashes (but not all slashes)
                    while sock_path.startswith("/") and not sock_path.startswith("//"):
                        sock_path = sock_path[1:]
                else:
                    sock_path = address

                logger.debug(f"🤝🔍 Normalized Unix path from '{address}' to '{sock_path}'")
                self._transport = UnixSocketTransport() # path=sock_path)
            else:
                raise TransportError(f"Unsupported transport: {network}")

            # Connect the chosen transport
            await self._transport.connect(address)
            logger.info(f"🚄 Transport connected via {network} -> {address}")
        except Exception as e:
            logger.error(
                "🤝❌ Error parsing handshake response or connecting transport.",
                extra={"trace": traceback.format_exc()},
            )
            raise HandshakeError(f"Handshake parse/connect error: {e}")

################################################################################



################################################################################

    async def _create_grpc_channel(self) -> None:
        """Creates a secure gRPC channel with improved timeout handling."""
        logger.debug("🚢 Attempting to create gRPC channel to plugin...")

        # If we only have an insecure scenario, just do an insecure channel
        if not self._server_cert:
            logger.info("🚢 No server certificate. Using insecure channel.")
            endpoint = self._transport.endpoint
            self._channel = grpc.aio.insecure_channel(
                endpoint,
                options=[("grpc.enable_http_proxy", 0)],
            )
            return

        # Rebuild server cert into PEM if needed
        full_pem = self._rebuild_x509_pem(self._server_cert)

        # Also see if we have client cert
        if self.client_cert and self.client_key_pem:
            logger.debug("🔐 Creating mTLS channel with client certs + server root.")
            credentials = grpc.ssl_channel_credentials(
                root_certificates=full_pem.encode(),
                private_key=self.client_key_pem.encode(),
                certificate_chain=self.client_cert.encode(),
            )
        else:
            logger.debug(
                "🔐 Creating TLS channel with server cert only (no client auth)."
            )
            credentials = grpc.ssl_channel_credentials(
                root_certificates=full_pem.encode()
            )

        endpoint = self._transport.endpoint
        self._channel = grpc.aio.secure_channel(
            endpoint,
            credentials,
            options=[
                ("grpc.ssl_target_name_override", "localhost"),
                ("grpc.max_receive_message_length", 32 * 1024 * 1024),
                ("grpc.max_send_message_length", 32 * 1024 * 1024),
                ("grpc.keepalive_time_ms", 10000),           # Added for stability
                ("grpc.keepalive_timeout_ms", 5000),         # Added for stability
                ("grpc.http2.max_pings_without_data", 0),    # Added for stability
                ("grpc.enable_retries", 1),                  # Added for stability
            ],
        )
        logger.debug("🚢 gRPC secure channel created successfully.")

        # Optional: verify channel readiness with timeout
        try:
            # Add timeout to prevent hanging indefinitely
            await asyncio.wait_for(self._channel.channel_ready(), timeout=5.0)
            logger.debug("🚢 gRPC channel is ready for calls.")
        except asyncio.TimeoutError:
            logger.error("🚢❌ gRPC channel failed to become ready (timeout)")
            # Add diagnostic info
            if isinstance(self._transport, UnixSocketTransport):
                socket_path = self._transport.path
                logger.error(f"🚢❌ Socket diagnostics: path={socket_path}, exists={os.path.exists(socket_path)}")
                if os.path.exists(socket_path):
                    try:
                        mode = os.stat(socket_path).st_mode
                        logger.error(f"🚢❌ Socket permissions: {oct(mode & 0o777)}")
                    except Exception as e:
                        logger.error(f"🚢❌ Failed to get socket stats: {e}")
            raise  # Re-raise to let caller handle it
        except grpc.RpcError as e:
            logger.error(f"🚢❌ gRPC channel failed to become ready: {e}")
            raise

################################################################################

    def _rebuild_x509_pem(self, maybe_cert: str) -> str:
        """
        Rebuilds a single base64 string of the server's certificate into a PEM block if missing headers.
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
        Once the channel is established, create stubs for Stdio, Broker, and Controller.
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
        Subscribes to the plugin's stdio stream. This is an infinite loop
        that reads messages from the plugin, logs them, and prints them.
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
        Demonstrates how to dial a subchannel with the broker stub.
        We do so by calling 'StartStream' in a streaming manner and sending a 'knock' message.
        """
        if not self._broker_stub:
            raise RuntimeError("Broker stub not initialized.")
        logger.debug(
            f"🔌📡 Attempting to open subchannel ID {sub_id} at {address} via Broker."
        )

        async def _broker_coroutine() -> None:
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
        Call the plugin's controller to request a graceful shutdown.
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
        Gracefully shut down the client:
         • Cancel tasks (e.g. reading stdio logs).
         • Close gRPC channel.
         • Terminate the plugin subprocess.
         • Close transport sockets.
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
            await self._channel.close()
            logger.debug("🔄 gRPC channel closed.")
            self._channel = None

        # Terminate plugin process
        if self._process:
            logger.debug("🔄 Terminating plugin subprocess...")
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
                logger.debug("🔄 Plugin subprocess terminated.")
            except Exception as e:
                logger.error(
                    f"🔄❌ Error terminating plugin process: {e}",
                    extra={"trace": traceback.format_exc()},
                )
            self._process = None

        # Close underlying transport
        if self._transport:
            logger.debug("🔄 Closing transport socket...")
            await self._transport.close()
            logger.debug("🔄 Transport socket closed.")
            self._transport = None

        logger.info("🔄 RPCPluginClient fully closed.")

### 🐍🏗️🔌
