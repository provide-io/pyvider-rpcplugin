#
# pyvider/rpcplugin/client/process.py
#
"""
Process management and gRPC operations for RPC plugin clients.

This module handles subprocess launching, gRPC channel creation,
stub initialization, and stdio/broker operations.
"""

import asyncio
import os
import subprocess  # nosec B404
from typing import Any

import grpc
from google.protobuf import empty_pb2  # type: ignore[import-untyped]

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import (
    HandshakeError,
    ProtocolError,
    TransportError,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.transport.types import TransportType
from provide.foundation import logger
from .types import ClientProtocol


# Process and gRPC-related methods that will be mixed into RPCPluginClient
class ClientProcessMixin:
    """Mixin class containing process and gRPC methods for RPCPluginClient."""

    async def _launch_process(self: ClientProtocol) -> None:
        """
        Launch the plugin subprocess with proper environment and configuration.

        This method starts the plugin process with the necessary environment
        variables and subprocess configuration for the handshake protocol.
        """
        if self._process:
            if self._process.poll() is None:
                self.logger.warning(
                    "Plugin process already running. Skipping launch."
                )
                return
            else:
                self.logger.debug(
                    "Previous plugin process has terminated. Launching new process."
                )

        # Prepare environment variables
        env = os.environ.copy()

        # Set PYTHONUNBUFFERED for real-time output
        env["PYTHONUNBUFFERED"] = "1"

        if self.config and "env" in self.config:
            env.update(self.config["env"])

        # Add required magic cookie for handshake
        env[rpcplugin_config.plugin_magic_cookie_key] = (
            rpcplugin_config.plugin_magic_cookie_value
        )

        # Add client certificate to environment if available
        if self.client_cert:
            env["PLUGIN_CLIENT_CERT"] = self.client_cert

        self.logger.debug(f"Launching plugin process: {self.command}")
        self.logger.debug(
            f"Environment includes magic cookie: "
            f"{rpcplugin_config.plugin_magic_cookie_key}"
        )

        try:
            self._process = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                text=False,  # Use bytes for better control over encoding
            )

            if self._process is not None:
                self.logger.debug(f"Plugin process started with PID: {self._process.pid}")

                # Start stderr relay task
                if self._process.stderr:
                    self._stdio_task = asyncio.create_task(
                        self._relay_stderr_background()
                    )

        except Exception as e:
            self.logger.error(f"Failed to launch plugin process: {e}", exc_info=True)
            raise TransportError(f"Failed to launch plugin subprocess for command: '{' '.join(self.command)}'. Error: {e}") from e

    async def _relay_stderr_background(self: ClientProtocol) -> None:
        """
        Background task to relay stderr from plugin process to logger.

        This helps capture plugin error output for debugging handshake
        and runtime issues.
        """
        if not self._process or not self._process.stderr:
            self.logger.debug("No process or stderr available for relay")
            return

        self.logger.debug("Starting stderr relay task for plugin process")

        try:
            while self._process.poll() is None:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, self._process.stderr.readline
                )
                if not line:
                    await asyncio.sleep(0.1)
                    continue

                text = line.decode("utf-8", errors="replace").rstrip()
                if text:
                    self.logger.debug(f"Plugin stderr: {text}")
        except asyncio.CancelledError:
            self.logger.debug("Stderr relay task cancelled")
        except Exception as e:
            self.logger.error(f"Error in stderr relay task: {e}", exc_info=True)
        finally:
            self.logger.debug("Stderr relay task ended")

    async def _create_grpc_channel(self: ClientProtocol) -> None:
        """
        Create and configure the gRPC channel for plugin communication.

        This method sets up the channel with appropriate credentials and
        connection options based on transport type and security configuration.
        """
        if not self._address or not self._transport_name:
            raise TransportError(
                "Address and transport type must be set before creating gRPC channel"
            )

        # Determine target endpoint format
        if self._transport_name == "unix":
            self.target_endpoint = f"unix:{self._address}"
        else:  # TCP
            self.target_endpoint = self._address

        self.logger.debug(f"Creating gRPC channel to: {self.target_endpoint}")

        # Set up channel credentials
        credentials = None
        options = [
            ("grpc.keepalive_time_ms", 30000),
            ("grpc.keepalive_timeout_ms", 5000),
            ("grpc.keepalive_permit_without_calls", True),
            ("grpc.http2.max_pings_without_data", 0),
            ("grpc.http2.min_ping_interval_without_data_ms", 300000),
        ]

        # Configure TLS/mTLS if certificates are available
        if self._server_cert:
            self.logger.debug("Setting up secure channel with server certificate")

            # Rebuild server certificate PEM format
            server_cert_pem = self._rebuild_x509_pem(self._server_cert)
            server_cert_bytes = server_cert_pem.encode("utf-8")

            # Set up client credentials if available
            private_key_bytes = None
            cert_chain_bytes = None

            if self.client_cert and self.client_key_pem:
                self.logger.debug("Using client certificate for mTLS")
                private_key_bytes = self.client_key_pem.encode("utf-8")
                cert_chain_bytes = self.client_cert.encode("utf-8")

            credentials = grpc.ssl_channel_credentials(
                root_certificates=server_cert_bytes,
                private_key=private_key_bytes,
                certificate_chain=cert_chain_bytes,
            )
        else:
            self.logger.debug("Setting up insecure channel (no server certificate)")

        try:
            # Create the channel
            if credentials:
                self.grpc_channel = grpc.aio.secure_channel(
                    self.target_endpoint, credentials, options=options
                )
            else:
                self.grpc_channel = grpc.aio.insecure_channel(
                    self.target_endpoint, options=options
                )

            # Test channel connectivity
            if self.grpc_channel is not None:
                await asyncio.wait_for(
                    self.grpc_channel.channel_ready(),
                    timeout=rpcplugin_config.channel_ready_timeout()
                )

            self.logger.debug("gRPC channel is ready")

            # Initialize service stubs
            self._init_stubs()

        except TimeoutError as e:
            error_msg = (
                f"gRPC channel failed to become ready within {channel_ready_timeout}s "
                f"for endpoint {self.target_endpoint}"
            )
            self.logger.error(error_msg)
            if self.grpc_channel:
                await self.grpc_channel.close()
                self.grpc_channel = None
            raise TransportError(error_msg) from e
        except Exception as e:
            self.logger.error(
                f"Failed to create gRPC channel to {self.target_endpoint}: {e}",
                exc_info=True,
            )
            if self.grpc_channel:
                await self.grpc_channel.close()
                self.grpc_channel = None
            raise TransportError(
                f"Failed to create gRPC channel: {e}"
            ) from e

    def _init_stubs(self: ClientProtocol) -> None:
        """
        Initialize gRPC service stubs for plugin communication.

        Creates stubs for stdio, broker, and controller services that are
        part of the standard go-plugin protocol.
        """
        if not self.grpc_channel:
            error_msg = "Cannot initialize gRPC stubs; gRPC channel is not available."
            self.logger.warning("Cannot initialize stubs: gRPC channel not available")
            raise ProtocolError(error_msg)

        try:
            self._stdio_stub = GRPCStdioStub(self.grpc_channel)
            self._broker_stub = GRPCBrokerStub(self.grpc_channel)
            self._controller_stub = GRPCControllerStub(self.grpc_channel)

            # Store in stubs dictionary for backward compatibility
            self._stubs["stdio"] = self._stdio_stub
            self._stubs["broker"] = self._broker_stub
            self._stubs["controller"] = self._controller_stub

            self.logger.debug("Initialized gRPC service stubs")
        except Exception as e:
            self.logger.error(f"Failed to initialize gRPC stubs: {e}", exc_info=True)
            raise ProtocolError(f"Failed to initialize gRPC stubs: {e}") from e

    async def _read_stdio_logs(self: ClientProtocol) -> None:
        """
        Read and log stdio streams from the plugin via gRPC.

        This method streams stdio data from the plugin and logs it,
        providing visibility into plugin runtime output.
        """
        if not self._stdio_stub:
            self.logger.warning("Cannot read stdio logs: stdio stub not available")
            return

        try:
            self.logger.debug("Starting stdio log streaming from plugin")

            # Start streaming stdio
            stream = self._stdio_stub.StreamStdio(empty_pb2.Empty())

            async for stdio_data in stream:
                if stdio_data.channel == StdioData.Channel.STDOUT:
                    output = stdio_data.data.decode("utf-8", errors="replace")
                    self.logger.debug(f"Plugin stdout: {output.rstrip()}")
                elif stdio_data.channel == StdioData.Channel.STDERR:
                    output = stdio_data.data.decode("utf-8", errors="replace")
                    self.logger.debug(f"Plugin stderr: {output.rstrip()}")

        except grpc.RpcError as e:
            if e.code() != grpc.StatusCode.CANCELLED:
                self.logger.warning(f"stdio streaming ended with RPC error: {e}")
        except Exception as e:
            self.logger.error(f"Error in stdio log streaming: {e}", exc_info=True)
        finally:
            self.logger.debug("stdio log streaming ended")

    async def open_broker_subchannel(self: ClientProtocol, sub_id: int, address: str) -> None:
        """
        Open a broker subchannel for multi-service communication.

        Args:
            sub_id: Unique identifier for the subchannel
            address: Network address for the subchannel

        Raises:
            ProtocolError: If broker operations fail
        """
        if not self._broker_stub:
            self.logger.warning("Broker stub not available for subchannel operations")
            return

        try:
            self.logger.debug(
                f"Opening broker subchannel {sub_id} at address {address}"
            )

            # Create connection info
            conn_info = ConnInfo()
            conn_info.service_id = sub_id
            conn_info.network = "tcp"  # Typically TCP for subchannels
            conn_info.address = address

            # Start broker stream
            stream = self._broker_stub.StartStream()

            # Send connection request
            await stream.write(conn_info)

            # Wait for acknowledgment
            response = await stream.read()
            if response and response.service_id == sub_id:
                # Check knock acknowledgment
                if hasattr(response, 'knock') and hasattr(response.knock, 'ack'):
                    if response.knock.ack:
                        self.logger.debug(f"Broker subchannel {sub_id} opened successfully")
                    else:
                        error_msg = response.knock.error if hasattr(response.knock, 'error') else "Unknown error"
                        self.logger.error(f"Subchannel open failed: {error_msg}")
                        # Don't raise exception, just log error and continue
                else:
                    self.logger.debug(f"Broker subchannel {sub_id} opened successfully")
            else:
                raise ProtocolError(
                    f"Failed to get acknowledgment for broker subchannel {sub_id}"
                )

            await stream.done_writing()

        except grpc.RpcError as e:
            raise ProtocolError(
                f"gRPC error opening broker subchannel {sub_id}: {e}"
            ) from e
        except Exception as e:
            raise ProtocolError(
                f"Error opening broker subchannel {sub_id}: {e}"
            ) from e