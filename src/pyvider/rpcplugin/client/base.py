"""RPCPluginClient module for managing plugin connections and lifecycle.

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
from pathlib import Path
from typing import Any

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
from pyvider.rpcplugin.transport.types import TransportT


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
    _transport: TransportT | None = field(init=False, default=None)
    _transport_name: str | None = field(init=False, default=None)

    _address: str | None = field(init=False, default=None) # Corrected type hint
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

        await self._setup_client_certificates()
        await self._launch_process()
        await self._perform_handshake()
        await self._create_grpc_channel()
        self._init_stubs()
        self._stdio_task = asyncio.create_task(self._read_stdio_logs())

        logger.info("✅ RPC plugin client started and ready.")

    async def _setup_client_certificates(self) -> None:
        logger.debug("🔐 Checking if auto-mTLS is enabled for client.")
        auto_mtls: bool = rpcplugin_config.auto_mtls_enabled()
        if auto_mtls:
            cert_pem: str | None = rpcplugin_config.get("PLUGIN_CLIENT_CERT")
            key_pem: str | None = rpcplugin_config.get("PLUGIN_CLIENT_KEY")
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
        if self._process:
            logger.debug("🖥️ Plugin subprocess is already running; skipping launch.")
            return
        env = os.environ.copy()
        if self.config and "env" in self.config:
            env.update(self.config["env"])
        env["PYTHONUNBUFFERED"] = "1"
        if self.client_cert:
            env["PLUGIN_CLIENT_CERT"] = self.client_cert
            rpcplugin_config.get("PLUGIN_CLIENT_CERT", "")
        logger.debug(f"🖥️ Launching plugin subprocess with command: {self.command}")
        try:
            self._process = subprocess.Popen(
                self.command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=False, bufsize=0, universal_newlines=False,
            )
            logger.info("🖥️ Plugin subprocess started successfully.")
        except Exception as e:
            logger.error(f"🖥️❌ Failed to launch plugin subprocess: {e}", extra={"trace": traceback.format_exc()})
            raise

    async def _relay_stderr_background(self) -> None:
        import threading
        def read_stderr() -> None:
            while True:
                if not self._process or self._process.stderr is None: break
                line = self._process.stderr.readline()
                if not line: break
                sys.stderr.write(f"{line.decode('utf-8', errors='replace')}")
        t = threading.Thread(target=read_stderr, daemon=True)
        t.start()

    async def _read_raw_handshake_line_from_stdout(self) -> str:
        loop = asyncio.get_event_loop()
        start_time = loop.time()
        timeout = 10.0
        buffer = ""
        while (loop.time() - start_time) < timeout:
            if self._process is None: raise HandshakeError("Plugin process not launched.")
            if self._process.poll() is not None:
                stderr_output = ""
                if self._process.stderr:
                    stderr_output = self._process.stderr.read().decode('utf-8', errors='replace')
                logger.error(f"🤝 Plugin process exited with code {self._process.returncode}. Stderr: {stderr_output}")
                raise HandshakeError(f"Plugin process exited with code {self._process.returncode} before handshake.")
            try:
                if self._process.stdout is None: raise HandshakeError("Plugin process stdout not available.")
                line_bytes = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: self._process.stdout.readline()),
                    timeout=2.0
                )
                if line_bytes:
                    line = line_bytes.decode('utf-8', errors='replace').strip()
                    buffer += line
                    logger.debug(f"🤝 Read partial handshake data: '{line}', buffer: '{buffer}'")
                    if "|" in buffer and buffer.count("|") >= 5: return buffer
                else:
                    await asyncio.sleep(0.25)
            except asyncio.TimeoutError:
                logger.debug("🤝 Timeout on read attempt, retrying...")
                await asyncio.sleep(0.5)
            if not buffer:
                try:
                    if self._process.stdout is None: raise HandshakeError("Plugin process stdout not available for byte-by-byte read.")
                    char_bytes = await asyncio.wait_for(
                        loop.run_in_executor(None, lambda: self._process.stdout.read(1)),
                        timeout=1.0
                    )
                    if char_bytes:
                        char = char_bytes.decode('utf-8', errors='replace')
                        buffer += char
                        logger.debug(f"🤝 Byte-by-byte read: buffer now: '{buffer}'")
                except asyncio.TimeoutError: pass
                except HandshakeError: raise
        stderr_output = ""
        if self._process and self._process.stderr:
            stderr_output = self._process.stderr.read().decode('utf-8', errors='replace')
        logger.error(f"🤝 Handshake timed out. Stderr output: {stderr_output}")
        raise TimeoutError("Timed out waiting for handshake line. Check if the server is writing to stdout correctly.")

    async def _perform_handshake(self) -> None:
        logger.debug("🤝 Initiating handshake with plugin server...")
        if not self._process or not self._process.stdout:
            raise HandshakeError("No server process or no stdout available.")
        await self._relay_stderr_background()
        logger.debug(f"🤝 Waiting for handshake from command: {self.command}")
        try:
            line = await self._read_raw_handshake_line_from_stdout()
            logger.debug(f"🤝 Received handshake response: {line[:60]}...")
        except TimeoutError:
            logger.error("🤝 Handshake timed out; no response from plugin.")
            raise HandshakeError("Handshake timed out.")
        except Exception: # Catch other potential errors from read_raw_handshake_line_from_stdout
            logger.error("🤝❌ Error reading handshake line.", extra={"trace": traceback.format_exc()})
            raise # Re-raise the original exception
        try:
            core_version, protocol_version, network, address_from_handshake, protocol, server_cert = (
                parse_handshake_response(line)
            )
            logger.debug(
                f"🤝 Handshake parse => core_version={core_version}, "
                f"protocol_version={protocol_version}, network={network}, "
                f"address='{address_from_handshake}', protocol={protocol}, cert={bool(server_cert)}"
            )
            self._protocol_version = protocol_version
            self._server_cert = server_cert
            self._transport_name = network

            actual_address_to_use = address_from_handshake # Default for TCP or if no special handling
            match network:
                case "tcp":
                    self._transport = TCPSocketTransport()
                    # For TCP, address_from_handshake is host:port
                    actual_address_to_use = address_from_handshake
                    logger.debug(f"🤝 TCP transport selected. Address: {actual_address_to_use}")
                case "unix":
                    logger.debug(f"🤝 Unix transport selected. Raw address from handshake: {address_from_handshake}")
                    path_to_use = address_from_handshake
                    if path_to_use.startswith("unix:"):
                        path_to_use = path_to_use[5:]

                    # Simplified and corrected path handling for Unix:
                    # If path_to_use is absolute (e.g., /tmp/foo.sock), it's used directly.
                    # Otherwise, it's used as is (could be relative or abstract).
                    actual_address_to_use = path_to_use

                    logger.debug(f"🤝🔍 Unix path for transport init set to '{actual_address_to_use}'")
                    self._transport = UnixSocketTransport(path=actual_address_to_use)
                case _:
                    raise TransportError(f"Unsupported transport: {network}")

            self._address = actual_address_to_use # Store the address used by the transport

            # For connect(), use the address appropriate for the transport type.
            # For TCP, it's host:port. For Unix, it's the socket path.
            connect_target = self._address # This is now consistently the processed address string

            if self._transport is None: # Should be set by match block
                raise TransportError(f"Transport not initialized for network type: {network}")

            await self._transport.connect(connect_target)
            logger.info(f"🚄 Transport connected via {network} -> {connect_target}")
        except Exception as e:
            logger.error("🤝❌ Error parsing handshake response or connecting transport.", extra={"trace": traceback.format_exc()})
            raise HandshakeError(f"Handshake parse/connect error: {e}")

    async def _create_grpc_channel(self) -> None:
        logger.debug("🚢 Attempting to create gRPC channel to plugin...")
        if self._address is None or self._transport_name is None:
             raise ConnectionError("Cannot create gRPC channel: address or transport name not set.")
        target: str
        if self._transport_name == "unix":
            target = f"unix:{self._address}"
        elif self._transport_name == "tcp":
            target = str(self._address)
        else:
            raise ConnectionError(f"Invalid transport name '{self._transport_name}' for gRPC channel.")
        logger.debug(f"🚢🔍 Creating gRPC channel with target: '{target}'")
        if self._server_cert:
            full_pem = self._rebuild_x509_pem(self._server_cert)
            if self.client_cert and self.client_key_pem:
                logger.debug("🔐 Creating mTLS channel with client certs + server root.")
                credentials = grpc.ssl_channel_credentials(
                    root_certificates=full_pem.encode(),
                    private_key=self.client_key_pem.encode(),
                    certificate_chain=self.client_cert.encode()
                )
            else:
                logger.debug("🔐 Creating TLS channel with server cert only.")
                credentials = grpc.ssl_channel_credentials(root_certificates=full_pem.encode())
            self._channel = grpc.aio.secure_channel(
                target, credentials,
                options=[
                    ("grpc.ssl_target_name_override", "localhost"),
                    ("grpc.max_receive_message_length", 32 * 1024 * 1024),
                    ("grpc.max_send_message_length", 32 * 1024 * 1024),
                    ("grpc.keepalive_time_ms", 10000),
                    ("grpc.keepalive_timeout_ms", 5000)
                ]
            )
        else:
            logger.info("🚢 No server certificate. Using insecure channel.")
            self._channel = grpc.aio.insecure_channel(target)
        logger.debug("🚢 gRPC channel created successfully.")
        try:
            if self._channel is None: raise ConnectionError("gRPC channel was not initialized.")
            await asyncio.wait_for(self._channel.channel_ready(), timeout=5.0)
            logger.debug("🚢✅ gRPC channel ready and connected.")
        except asyncio.TimeoutError:
            socket_path_diag = target.replace("unix:", "") if target.startswith("unix:") else None
            exists_diag = os.path.exists(socket_path_diag) if socket_path_diag else "N/A"
            logger.error("🚢❌ gRPC channel failed to become ready (timeout)")
            if socket_path_diag:
                logger.error(f"🚢❌ Socket diagnostics: path={socket_path_diag}, exists={exists_diag}")
            raise ConnectionError("Failed to establish gRPC channel to plugin: timeout")
        except Exception as e:
            logger.error(f"🚢❌ gRPC channel failed: {e}")
            raise ConnectionError(f"Failed to establish gRPC channel to plugin: {e}")

    def _rebuild_x509_pem(self, maybe_cert: str) -> str:
        if maybe_cert.startswith("-----BEGIN CERTIFICATE-----"):
            logger.debug("🔐 Server cert already has PEM headers.")
            return maybe_cert
        cert_lines = [maybe_cert[i : i + 64] for i in range(0, len(maybe_cert), 64)]
        full_pem = ("-----BEGIN CERTIFICATE-----\n" + "\n".join(cert_lines) + "\n-----END CERTIFICATE-----\n")
        logger.debug("🔐 Rebuilt server certificate into PEM format.")
        return full_pem

    def _init_stubs(self) -> None:
        if not self._channel: raise RuntimeError("Cannot init stubs; no gRPC channel available.")
        logger.debug("🔌 Creating GRPCStdioStub, GRPCBrokerStub, GRPCControllerStub from channel.")
        self._stdio_stub = GRPCStdioStub(self._channel)
        self._broker_stub = GRPCBrokerStub(self._channel)
        self._controller_stub = GRPCControllerStub(self._channel)

    async def _read_stdio_logs(self) -> None:
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
            logger.debug("🔌📝 _read_stdio_logs task cancelled. Shutting down stdio read.")
        except Exception as e:
            logger.error(f"🔌📝❌ Error reading plugin stdio stream: {e!s}", extra={"trace": traceback.format_exc()})
        logger.debug("🔌📝 Plugin stdio reading loop ended.")

    async def open_broker_subchannel(self, sub_id: int, address: str) -> None:
        if not self._broker_stub: raise RuntimeError("Broker stub not initialized.")
        logger.debug(f"🔌📡 Attempting to open subchannel ID {sub_id} at {address} via Broker.")
        async def _broker_coroutine() -> None:
            call = self._broker_stub.StartStream()
            try:
                knock_info = ConnInfo(
                    service_id=sub_id, network=self._transport_name if self._transport_name else "tcp",
                    address=address, knock=ConnInfo.Knock(knock=True, ack=False, error=""),
                )
                await call.write(knock_info)
                await call.done_writing()
                async for reply in call:
                    logger.debug(f"🔌📡 Broker response => service_id={reply.service_id}, knock.ack={reply.knock.ack}, error='{reply.knock.error}'")
                    if not reply.knock.ack:
                        logger.error(f"🔌📡❌ Subchannel open failed for ID {sub_id}: {reply.knock.error}")
                    else:
                        logger.info(f"🔌📡✅ Subchannel {sub_id} at {address} opened successfully via broker!")
                    break
            except grpc.aio.AioRpcError as rpc_error:
                logger.error(f"🔌📡❌ RPC error during broker subchannel open: {rpc_error.details()}")
            except Exception as e:
                logger.error(f"🔌📡❌ Unexpected error during broker subchannel open: {e!s}", extra={"trace": traceback.format_exc()})
            finally:
                logger.debug(f"🔌📡 Broker stream for subchannel {sub_id} concluding.")
                if not call.done(): call.cancel()
        self._broker_task = asyncio.create_task(_broker_coroutine())

    async def shutdown_plugin(self) -> None:
        if not self._controller_stub:
            logger.debug("🔌🛑 No controller stub found; cannot call Shutdown().")
            return
        logger.debug("🔌🛑 Requesting plugin shutdown via GRPCController.Shutdown()...")
        try:
            await self._controller_stub.Shutdown(ControllerEmpty())
            logger.info("🔌🛑 Plugin acknowledged shutdown request.")
        except Exception as e:
            logger.error(f"🔌🛑❌ Error calling Shutdown(): {e}", extra={"trace": traceback.format_exc()})

    async def close(self) -> None:
        logger.debug("🔄 Closing RPCPluginClient...")
        tasks_to_cancel = []
        if self._stdio_task and not self._stdio_task.done(): tasks_to_cancel.append(self._stdio_task)
        if self._broker_task and not self._broker_task.done(): tasks_to_cancel.append(self._broker_task)
        for t in tasks_to_cancel:
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError): await t
        if self._channel:
            logger.debug("🔄 Closing gRPC channel...")
            try:
                await asyncio.wait_for(self._channel.close(grace=1.0), timeout=2.0)
                logger.debug("🔄 gRPC channel closed.")
            except asyncio.TimeoutError: logger.warning("🔄⏳ Timeout closing gRPC channel.")
            except Exception as e: logger.error(f"🔄❌ Error closing gRPC channel: {e}", extra={"trace": traceback.format_exc()})
            self._channel = None
        if self._process:
            logger.debug("🔄 Terminating plugin subprocess...")
            try:
                self._process.terminate()
                logger.debug("🔄 Sent terminate signal to plugin subprocess.")
                try:
                    await asyncio.wait_for(asyncio.to_thread(self._process.wait, timeout=7), timeout=7.5)
                    logger.debug("🔄 Plugin subprocess terminated.")
                except asyncio.TimeoutError:
                     logger.warning(f"🔄⏳ Timeout waiting for plugin process {self._process.pid} to terminate. Forcing kill.")
                     self._process.kill()
                     await asyncio.to_thread(self._process.wait)
                     logger.debug("🔄 Plugin subprocess killed.")
                except Exception as e:
                    logger.error(f"🔄❌ Error waiting for plugin process to terminate: {e}", extra={"trace": traceback.format_exc()})
            except Exception as e:
                logger.error(f"🔄❌ Error sending terminate signal to plugin process: {e}", extra={"trace": traceback.format_exc()})
            self._process = None
        if self._transport:
            logger.debug("🔄 Closing transport socket...")
            try:
                await self._transport.close()
                logger.debug("🔄 Transport socket closed.")
            except Exception as e: logger.error(f"🔄❌ Error closing transport socket: {e}", extra={"trace": traceback.format_exc()})
            self._transport = None
        logger.info("🔄 RPCPluginClient fully closed.")

# 🐍🏗️🔌
