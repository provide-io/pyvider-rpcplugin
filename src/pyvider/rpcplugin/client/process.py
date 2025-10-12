#
# pyvider/rpcplugin/client/process.py
#
"""
Process management and gRPC operations for RPC plugin clients.

This module handles subprocess launching, gRPC channel creation,
stub initialization, and stdio/broker operations.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from google.protobuf import empty_pb2  # type: ignore[import-untyped]
import grpc
from provide.foundation import retry
from provide.foundation.process import ManagedProcess
from provide.foundation.resilience import BackoffStrategy

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.defaults import DEFAULT_PROCESS_WAIT_TIME
from pyvider.rpcplugin.exception import (
    ProtocolError,
    TransportError,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.telemetry import get_rpc_tracer

# Get tracer for client process operations
_tracer = get_rpc_tracer()

if TYPE_CHECKING:
    from pyvider.rpcplugin.client.core import RPCPluginClient


# Process and gRPC-related methods that will be mixed into RPCPluginClient
class ClientProcessMixin:
    """Mixin class containing process and gRPC methods for RPCPluginClient."""

    async def _launch_process(self: RPCPluginClient) -> None:  # type: ignore[misc]
        """
        Launch the plugin subprocess with proper environment and configuration.

        This method starts the plugin process with the necessary environment
        variables and subprocess configuration for the handshake protocol.
        """
        if self._process and self._process.is_running():
            self.logger.warning("Plugin process already running. Skipping launch.")
            return

        if self._process and not self._process.is_running():
            self.logger.debug("Previous plugin process has terminated. Launching new process.")

        # Prepare environment variables
        env = {
            "PYTHONUNBUFFERED": "1",  # Set for real-time output
            rpcplugin_config.plugin_magic_cookie_key: rpcplugin_config.plugin_magic_cookie_value,
        }

        # Add custom environment from config
        if self.config and "env" in self.config:
            env.update(self.config["env"])

        # Add client certificate to environment if available
        if self.client_cert:
            env["PLUGIN_CLIENT_CERT"] = self.client_cert

        self.logger.debug(f"Launching plugin process: {self.command}")
        self.logger.debug(f"Environment includes magic cookie: {rpcplugin_config.plugin_magic_cookie_key}")

        try:
            # Create ManagedProcess with stderr_relay=False for custom logging
            self._process = ManagedProcess(
                command=self.command,
                env=env,
                capture_output=True,
                text_mode=False,  # Use bytes for better control over encoding
                stderr_relay=False,  # We'll use custom stderr logging
            )

            # Launch the process
            self._process.launch()

            if self._process.pid:
                self.logger.debug(f"Plugin process started with PID: {self._process.pid}")

                # Start custom stderr relay task that logs instead of writing to sys.stderr
                if self._process.process and self._process.process.stderr:
                    self._stdio_task = asyncio.create_task(self._relay_stderr_background())

        except Exception as e:
            self.logger.error(f"Failed to launch plugin process: {e}", exc_info=True)
            raise TransportError(
                f"Failed to launch plugin subprocess for command: '{' '.join(self.command)}'. Error: {e}"
            ) from e

    async def _relay_stderr_background(self: RPCPluginClient) -> None:  # type: ignore[misc]
        """
        Background task to relay stderr from plugin process to logger.

        This helps capture plugin error output for debugging handshake
        and runtime issues.
        """
        if not self._process or not self._process.process or not self._process.process.stderr:
            self.logger.debug("No process or stderr available for relay")
            return

        self.logger.debug("Starting stderr relay task for plugin process")

        try:
            # Access the underlying Popen process for stderr reading
            process = self._process.process
            while self._process.is_running():
                line = await asyncio.get_event_loop().run_in_executor(None, process.stderr.readline)
                if not line:
                    await asyncio.sleep(DEFAULT_PROCESS_WAIT_TIME)
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

    def _determine_target_endpoint(self: RPCPluginClient) -> None:  # type: ignore[misc]
        """Determine the target endpoint format based on transport type."""
        if self._transport_name == "unix":
            self.target_endpoint = f"unix:{self._address}"
        else:  # TCP
            self.target_endpoint = self._address

    def _get_channel_options(self) -> list[tuple[str, int | bool]]:
        """Get standard gRPC channel options."""
        return [
            ("grpc.keepalive_time_ms", rpcplugin_config.plugin_grpc_keepalive_time_ms),
            ("grpc.keepalive_timeout_ms", rpcplugin_config.plugin_grpc_keepalive_timeout_ms),
            ("grpc.keepalive_permit_without_calls", True),
            ("grpc.http2.max_pings_without_data", 0),
            ("grpc.http2.min_ping_interval_without_data_ms", 300000),
        ]

    def _setup_channel_credentials(self: RPCPluginClient) -> grpc.ChannelCredentials | None:  # type: ignore[misc]
        """Set up channel credentials for TLS/mTLS if certificates are available."""
        if not self._server_cert:
            self.logger.debug("Setting up insecure channel (no server certificate)")
            return None

        self.logger.debug("Setting up secure channel with server certificate")
        server_cert_pem = self._rebuild_x509_pem(self._server_cert)
        server_cert_bytes = server_cert_pem.encode("utf-8")

        private_key_bytes = None
        cert_chain_bytes = None

        if self.client_cert and self.client_key_pem:
            self.logger.debug("Using client certificate for mTLS")
            private_key_bytes = self.client_key_pem.encode("utf-8")
            cert_chain_bytes = self.client_cert.encode("utf-8")

        return grpc.ssl_channel_credentials(
            root_certificates=server_cert_bytes,
            private_key=private_key_bytes,
            certificate_chain=cert_chain_bytes,
        )

    async def _cleanup_failed_channel(self: RPCPluginClient) -> None:  # type: ignore[misc]
        """Clean up gRPC channel on failure."""
        if self.grpc_channel:
            await self.grpc_channel.close()
            self.grpc_channel = None

    @retry(
        TransportError,
        TimeoutError,
        OSError,
        max_attempts=3,
        backoff=BackoffStrategy.EXPONENTIAL,
        base_delay=0.1,
        max_delay=2.0,
    )
    async def _create_grpc_channel(self: RPCPluginClient) -> None:  # type: ignore[misc]
        """
        Create and configure the gRPC channel for plugin communication.

        This method sets up the channel with appropriate credentials and
        connection options based on transport type and security configuration.

        Retry policy: Exponential backoff with 3 attempts for transient connection errors.
        """
        if _tracer:
            with _tracer.start_as_current_span("rpc.client.create_channel") as span:
                span.set_attribute("transport", self._transport_name or "unknown")
                span.set_attribute("address", self._address or "unknown")
                await self._create_grpc_channel_impl()
        else:
            await self._create_grpc_channel_impl()

    async def _create_grpc_channel_impl(self: RPCPluginClient) -> None:  # type: ignore[misc]
        """Implementation of gRPC channel creation."""
        if not self._address or not self._transport_name:
            raise TransportError("Address and transport type must be set before creating gRPC channel")

        self._determine_target_endpoint()
        self.logger.debug(f"Creating gRPC channel to: {self.target_endpoint}")

        credentials = self._setup_channel_credentials()
        options = self._get_channel_options()

        try:
            if not self.target_endpoint:
                raise TransportError("Target endpoint must be set before creating gRPC channel")

            if credentials:
                self.grpc_channel = grpc.aio.secure_channel(self.target_endpoint, credentials, options=options)
            else:
                self.grpc_channel = grpc.aio.insecure_channel(self.target_endpoint, options=options)

            if self.grpc_channel is not None:
                await asyncio.wait_for(
                    self.grpc_channel.channel_ready(), timeout=rpcplugin_config.plugin_channel_ready_timeout
                )

            self.logger.debug("gRPC channel is ready")
            self._init_stubs()

        except TimeoutError as e:
            error_msg = (
                f"gRPC channel failed to become ready within {rpcplugin_config.plugin_channel_ready_timeout}s "
                f"for endpoint {self.target_endpoint}"
            )
            self.logger.error(error_msg)
            await self._cleanup_failed_channel()
            raise TransportError(error_msg) from e
        except Exception as e:
            self.logger.error(
                f"Failed to create gRPC channel to {self.target_endpoint}: {e}",
                exc_info=True,
            )
            await self._cleanup_failed_channel()
            raise TransportError(f"Failed to create gRPC channel: {e}") from e

    def _init_stubs(self: RPCPluginClient) -> None:  # type: ignore[misc]
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

    async def _read_stdio_logs(self: RPCPluginClient) -> None:  # type: ignore[misc]
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

    async def open_broker_subchannel(self: RPCPluginClient, sub_id: int, address: str) -> None:  # type: ignore[misc]
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
            self.logger.debug(f"Opening broker subchannel {sub_id} at address {address}")

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
                if hasattr(response, "knock") and hasattr(response.knock, "ack"):
                    if response.knock.ack:
                        self.logger.debug(f"Broker subchannel {sub_id} opened successfully")
                    else:
                        error_msg = (
                            response.knock.error if hasattr(response.knock, "error") else "Unknown error"
                        )
                        self.logger.error(f"Subchannel open failed: {error_msg}")
                        # Don't raise exception, just log error and continue
                else:
                    self.logger.debug(f"Broker subchannel {sub_id} opened successfully")
            else:
                raise ProtocolError(f"Failed to get acknowledgment for broker subchannel {sub_id}")

            await stream.done_writing()

        except grpc.RpcError as e:
            raise ProtocolError(f"gRPC error opening broker subchannel {sub_id}: {e}") from e
        except Exception as e:
            raise ProtocolError(f"Error opening broker subchannel {sub_id}: {e}") from e
