#!/usr/bin/env python3
# pyvider/rpcplugin/client/base.py

import asyncio
import contextlib
import os
import subprocess
import sys
import time
import traceback
from typing import Any, Dict, List, Optional

import attrs
import grpc
from google.protobuf import empty_pb2

from pyvider.rpcplugin.client.handshake import (
    create_stderr_relay,
    parse_and_validate_handshake,
    read_handshake_response,
)
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.exception import HandshakeError, TransportError
from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.transport.types import TransportT
from pyvider.rpcplugin.transport.unix import normalize_unix_path


@attrs.define
class RPCPluginClient:
    """
    RPCPluginClient interacts with plugin server processes via grpc and custom handshake.
    
    This implementation includes:
    * Process management with improved stdout/stderr handling
    * Robust handshake with configurable timeout and retries
    * Support for Unix and TCP transports
    * mTLS certificate management 
    * Service stubs for Stdio, Broker, and Controller
    """

    command: List[str] = attrs.field()
    config: Dict[str, Any] | None = attrs.field(default=None)

    # Internal fields
    _process: subprocess.Popen | None = attrs.field(init=False, default=None)
    _transport: TransportT | None = attrs.field(init=False, default=None)
    _protocol_version: int | None = attrs.field(init=False, default=None)
    _server_cert: str | None = attrs.field(init=False, default=None)
    _channel: grpc.aio.Channel | None = attrs.field(init=False, default=None)

    # Certificate fields
    _client_cert_obj: Optional[Certificate] = attrs.field(init=False, default=None)
    client_cert: str | None = attrs.field(init=False, default=None)
    client_key_pem: str | None = attrs.field(init=False, default=None)

    # gRPC stubs
    _stdio_stub: GRPCStdioStub | None = attrs.field(init=False, default=None)
    _broker_stub: GRPCBrokerStub | None = attrs.field(init=False, default=None)
    _controller_stub: GRPCControllerStub | None = attrs.field(init=False, default=None)

    # Background tasks
    _stdio_task: asyncio.Task | None = attrs.field(init=False, default=None)
    _broker_task: asyncio.Task | None = attrs.field(init=False, default=None)
    _stderr_task: asyncio.Task | None = attrs.field(init=False, default=None)

    # Connection state
    _started: bool = attrs.field(init=False, default=False)
    _closing: bool = attrs.field(init=False, default=False)
    
    # Synchronization
    _start_lock: asyncio.Lock = attrs.field(init=False, factory=asyncio.Lock)

    def __attrs_post_init__(self):
        """Initialize client with basic configuration."""
        logger.debug("🙋⚙️✅ Initializing RPCPluginClient")

    async def start(self) -> None:
        """
        Launch plugin process, perform handshake, and establish connection.
        
        This method coordinates the full startup sequence:
        1. Client certificate setup (if mTLS is enabled)
        2. Process launch with environment configuration
        3. Handshake protocol
        4. Transport setup (TCP or Unix)
        5. Channel creation with appropriate credentials
        6. Service stub initialization
        7. Background tasks for monitoring
        
        Raises:
            HandshakeError: If handshake fails
            TransportError: If transport setup fails 
            Various exceptions related to process or connection issues
        """
        async with self._start_lock:
            if self._started:
                logger.debug("🙋🚀⚠️ Client already started, skipping")
                return
                
            logger.debug("🙋🚀🚀 Starting RPC plugin client...")
            start_time = time.time()
            
            try:
                # 1. Set up client certificates if needed
                await self._setup_client_certificates()
                
                # 2. Launch plugin process
                await self._launch_process()
                
                # 3. Start stderr relay for debugging
                self._stderr_task = await create_stderr_relay(self._process)
                
                # 4. Perform handshake (allow small delay for process to initialize)
                await asyncio.sleep(0.2)
                await self._perform_handshake()
                
                # 5. Create gRPC channel
                await self._create_grpc_channel()
                
                # 6. Initialize service stubs
                self._init_stubs()
                
                # 7. Start background tasks (stdio monitoring)
                self._stdio_task = asyncio.create_task(self._read_stdio_logs())
                
                self._started = True
                dur = time.time() - start_time
                logger.info(f"🙋🚀✅ RPC plugin client started successfully in {dur:.2f}s")
                
            except Exception as e:
                logger.error(f"🙋🚀❌ Failed to start RPC plugin client: {e}")
                logger.debug(f"🙋🚀❌ Stack trace: {traceback.format_exc()}")
                await self.close()  # Clean up any resources
                raise

    async def _setup_client_certificates(self) -> None:
        """
        Set up client certificates for mTLS if enabled.
        Either loads existing certificates or generates new ones.
        """
        logger.debug("🙋🔐🚀 Setting up client certificates")
        
        # Check if mTLS is enabled
        auto_mtls = rpcplugin_config.get("PLUGIN_AUTO_MTLS", "").lower()
        if auto_mtls not in ("true", "1", "yes"):
            logger.info("🙋🔐⚠️ mTLS not enabled; operating in insecure mode")
            return
            
        # Check if certificates are already provided
        cert_pem = rpcplugin_config.get("PLUGIN_CLIENT_CERT")
        key_pem = rpcplugin_config.get("PLUGIN_CLIENT_KEY")
        
        if cert_pem and key_pem:
            logger.info("🙋🔐✅ Using existing client cert/key from config")
            self.client_cert = cert_pem
            self.client_key_pem = key_pem
        else:
            # Generate ephemeral certificate
            logger.info("🙋🔐🚀 Generating ephemeral self-signed client certificate")
            self._client_cert_obj = Certificate(
                generate_keypair=True, 
                key_type="ecdsa",
                common_name="pyvider-client",
                organization_name="Pyvider",
                alt_names=["localhost"],
            )
            self.client_cert = self._client_cert_obj.cert
            self.client_key_pem = self._client_cert_obj.key
            logger.debug("🙋🔐✅ Generated client certificate successfully")

    async def _launch_process(self) -> None:
        """
        Launch the plugin process with properly configured environment.
        Sets unbuffered I/O for better interoperability with Go processes.
        """
        if self._process:
            logger.debug("🙋🖥️⚠️ Plugin process already running")
            return

        # Prepare environment with defaults and config overrides
        env = os.environ.copy()
        if self.config and "env" in self.config:
            env.update(self.config["env"])

        # Force unbuffered output for all subprocesses
        env["PYTHONUNBUFFERED"] = "1"
        
        # Configure Go process environment for better interoperability
        env["GODEBUG"] = f"{env.get('GODEBUG', '')},asyncpreemptoff=1"
        
        # Pass certificate if we have one
        if self.client_cert:
            env["PLUGIN_CLIENT_CERT"] = self.client_cert
            logger.debug("🙋🖥️✅ Passed client certificate to plugin environment")

        # Start process
        logger.debug(f"🙋🖥️🚀 Launching plugin process: {' '.join(self.command)}")
        try:
            self._process = subprocess.Popen(
                self.command,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                bufsize=0,  # Disable buffering (crucial for handshake)
            )
            logger.info(f"🙋🖥️✅ Plugin process started with PID {self._process.pid}")
        except Exception as e:
            logger.error(f"🙋🖥️❌ Failed to launch plugin process: {e}")
            raise

    async def _perform_handshake(self) -> None:
        """
        Perform handshake with the plugin server process.
        Reads handshake string from stdout, parses it, and configures transport.
        """
        logger.debug("🙋🤝🚀 Initiating handshake with plugin server")
        
        if not self._process or not self._process.stdout:
            raise HandshakeError("No server process or stdout available")
            
        try:
            # Read and parse handshake response
            handshake_line = await read_handshake_response(self._process)
            
            core_version, plugin_version, network, address, protocol, server_cert = (
                await parse_and_validate_handshake(handshake_line)
            )
            
            # Store protocol info
            self._protocol_version = plugin_version
            self._server_cert = server_cert
            
            # Create appropriate transport based on network type
            if network == "tcp":
                self._transport = TCPSocketTransport()
                logger.debug(f"🙋🤝✅ Created TCP transport for address: {address}")
            elif network == "unix":
                # Normalize Unix path
                normalized_path = normalize_unix_path(address)
                self._transport = UnixSocketTransport(path=normalized_path)
                logger.debug(f"🙋🤝✅ Created Unix transport with path: {normalized_path}")
            else:
                raise TransportError(f"Unsupported transport: {network}")
            
            # Connect transport
            connect_start = time.time()
            await self._transport.connect(address)
            connect_duration = time.time() - connect_start
            logger.info(f"🙋🤝✅ Transport connected via {network} to {address} in {connect_duration:.2f}s")
            
        except Exception as e:
            logger.error(f"🙋🤝❌ Handshake failed: {e}")
            raise HandshakeError(f"Handshake failed: {e}") from e

    async def _create_grpc_channel(self) -> None:
        """
        Create secure or insecure gRPC channel based on certificate availability.
        Configures proper TLS settings and channel options.
        """
        logger.debug("🙋🚢🚀 Creating gRPC channel")
        
        if not self._transport or not self._transport.endpoint:
            raise TransportError("Cannot create channel without transport endpoint")
            
        endpoint = self._transport.endpoint
            
        # Determine if using secure or insecure channel
        if not self._server_cert:
            logger.info("🙋🚢⚠️ No server certificate available, using insecure channel")
            self._channel = grpc.aio.insecure_channel(
                endpoint,
                options=[
                    ("grpc.enable_http_proxy", 0),
                    ("grpc.max_receive_message_length", 32 * 1024 * 1024),
                    ("grpc.max_send_message_length", 32 * 1024 * 1024),
                    ("grpc.keepalive_time_ms", 10000),
                    ("grpc.keepalive_timeout_ms", 5000),
                ],
            )
            return
            
        # Format server cert PEM
        server_cert_pem = self._format_certificate_pem(self._server_cert)
            
        # Prepare credentials based on client cert availability
        if self.client_cert and self.client_key_pem:
            logger.debug("🙋🚢🔐 Creating mTLS channel with client & server certificates")
            credentials = grpc.ssl_channel_credentials(
                root_certificates=server_cert_pem.encode(),
                private_key=self.client_key_pem.encode(),
                certificate_chain=self.client_cert.encode(),
            )
        else:
            logger.debug("🙋🚢🔐 Creating TLS channel with server certificate only")
            credentials = grpc.ssl_channel_credentials(
                root_certificates=server_cert_pem.encode()
            )
            
        # Create secure channel with options
        self._channel = grpc.aio.secure_channel(
            endpoint,
            credentials,
            options=[
                ("grpc.ssl_target_name_override", "localhost"),
                ("grpc.max_receive_message_length", 32 * 1024 * 1024),
                ("grpc.max_send_message_length", 32 * 1024 * 1024),
                ("grpc.keepalive_time_ms", 10000),
                ("grpc.keepalive_timeout_ms", 5000),
                ("grpc.http2.max_pings_without_data", 0),
                ("grpc.enable_retries", 1),
            ],
        )
        
        # Verify channel readiness
        try:
            await asyncio.wait_for(self._channel.channel_ready(), timeout=5.0)
            logger.debug("🙋🚢✅ gRPC channel ready for calls")
        except asyncio.TimeoutError:
            logger.error("🙋🚢❌ gRPC channel failed to become ready (timeout)")
            raise
        except Exception as e:
            logger.error(f"🙋🚢❌ gRPC channel failed: {e}")
            raise

    def _format_certificate_pem(self, cert_data: str) -> str:
        """
        Format raw certificate data into proper PEM format.
        Adds BEGIN/END CERTIFICATE headers if missing.
        """
        if not cert_data:
            return ""
            
        if cert_data.startswith("-----BEGIN CERTIFICATE-----"):
            return cert_data
            
        # Convert base64 cert to PEM format
        # Wrap at 64 characters per line
        cert_lines = [cert_data[i:i+64] for i in range(0, len(cert_data), 64)]
        
        pem = (
            "-----BEGIN CERTIFICATE-----\n" +
            "\n".join(cert_lines) +
            "\n-----END CERTIFICATE-----\n"
        )
        
        logger.debug("🙋🔐✅ Converted base64 certificate to PEM format")
        return pem

    def _init_stubs(self) -> None:
        """Initialize gRPC service stubs for Stdio, Broker, and Controller."""
        if not self._channel:
            raise RuntimeError("Cannot initialize stubs without gRPC channel")
            
        logger.debug("🙋🔌🚀 Creating gRPC service stubs")
        
        self._stdio_stub = GRPCStdioStub(self._channel)
        self._broker_stub = GRPCBrokerStub(self._channel)
        self._controller_stub = GRPCControllerStub(self._channel)
        
        logger.debug("🙋🔌✅ gRPC service stubs created successfully")

    async def _read_stdio_logs(self) -> None:
        """
        Read stdout/stderr logs from plugin via gRPC Stdio service.
        Runs as a background task until client is closed.
        """
        if not self._stdio_stub:
            logger.debug("🙋📝⚠️ No stdio stub available, skipping log reading")
            return
            
        logger.debug("🙋📝🚀 Starting plugin stdio log monitoring")
        
        try:
            async for chunk in self._stdio_stub.StreamStdio(empty_pb2.Empty()):
                channel_type = "STDERR" if chunk.channel == StdioData.STDERR else "STDOUT"
                try:
                    message = chunk.data.decode("utf-8", errors="replace")
                    logger.debug(f"🙋📝📥 Plugin {channel_type}: {message}")
                except Exception:
                    # If decoding fails, log the raw bytes length
                    logger.debug(f"🙋📝📥 Plugin {channel_type}: {len(chunk.data)} bytes (binary)")
        except asyncio.CancelledError:
            logger.debug("🙋📝🛑 Stdio monitoring task cancelled")
        except Exception as e:
            logger.error(f"🙋📝❌ Error reading plugin stdio: {e}")
            
        logger.debug("🙋📝🛑 Plugin stdio monitoring ended")

    async def shutdown_plugin(self) -> None:
        """
        Request plugin shutdown via Controller.Shutdown RPC.
        This is the graceful way to terminate the plugin.
        """
        if not self._controller_stub:
            logger.debug("🙋🛑⚠️ No controller stub available, cannot shutdown plugin gracefully")
            return
            
        logger.debug("🙋🛑🚀 Requesting plugin shutdown via Controller.Shutdown")
        
        try:
            await asyncio.wait_for(
                self._controller_stub.Shutdown(ControllerEmpty()),
                timeout=5.0
            )
            logger.info("🙋🛑✅ Plugin acknowledged shutdown request")
        except asyncio.TimeoutError:
            logger.warning("🙋🛑⚠️ Plugin shutdown request timed out")
        except Exception as e:
            logger.error(f"🙋🛑❌ Error requesting plugin shutdown: {e}")

    async def close(self) -> None:
        """
        Clean up all resources and terminate plugin process.
        Ensures all resources are properly released.
        """
        if self._closing:
            logger.debug("🙋🔒⚠️ Close already in progress, skipping")
            return
            
        self._closing = True
        logger.debug("🙋🔒🚀 Closing RPC plugin client")
        
        # 1. Try graceful shutdown first
        if self._started and self._controller_stub:
            try:
                await self.shutdown_plugin()
                # Give plugin time to shut down
                await asyncio.sleep(0.5)
            except Exception as e:
                logger.error(f"🙋🔒❌ Error during graceful shutdown: {e}")
        
        # 2. Cancel background tasks
        tasks_to_cancel = []
        if self._stdio_task and not self._stdio_task.done():
            tasks_to_cancel.append(self._stdio_task)
        if self._broker_task and not self._broker_task.done():
            tasks_to_cancel.append(self._broker_task)
        if self._stderr_task and not self._stderr_task.done():
            tasks_to_cancel.append(self._stderr_task)
            
        for task in tasks_to_cancel:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
                
        # 3. Close gRPC channel
        if self._channel:
            logger.debug("🙋🔒🚀 Closing gRPC channel")
            await self._channel.close()
            self._channel = None
            logger.debug("🙋🔒✅ gRPC channel closed")
        
        # 4. Terminate process if still running
        if self._process:
            logger.debug("🙋🔒🚀 Terminating plugin process")
            try:
                self._process.terminate()
                try:
                    exit_code = self._process.wait(timeout=3.0)
                    logger.debug(f"🙋🔒✅ Plugin process terminated with code {exit_code}")
                except subprocess.TimeoutExpired:
                    logger.warning("🙋🔒⚠️ Plugin process didn't terminate, killing")
                    self._process.kill()
                    exit_code = self._process.wait(timeout=1.0)
                    logger.debug(f"🙋🔒✅ Plugin process killed with code {exit_code}")
            except Exception as e:
                logger.error(f"🙋🔒❌ Error terminating plugin process: {e}")
            finally:
                self._process = None
        
        # 5. Close transport
        if self._transport:
            logger.debug("🙋🔒🚀 Closing transport")
            try:
                await self._transport.close()
                logger.debug("🙋🔒✅ Transport closed")
            except Exception as e:
                logger.error(f"🙋🔒❌ Error closing transport: {e}")
            self._transport = None
        
        # Reset state
        self._started = False
        self._closing = False
        logger.info("🙋🔒✅ RPCPluginClient fully closed")

### 🐍🏗️🔌