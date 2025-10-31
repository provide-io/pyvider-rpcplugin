# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""TODO: Add module docstring."""

# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Core RPCPluginClient class definition and lifecycle management.

This module contains the main RPCPluginClient class with its attributes,
initialization, and core lifecycle methods like start, close, and shutdown."""

from __future__ import annotations

import asyncio
from types import TracebackType
from typing import TYPE_CHECKING, Any

from attrs import define, field
import grpc
from provide.foundation.logger import get_logger

from pyvider.rpcplugin.client.handshake import ClientHandshakeMixin
from pyvider.rpcplugin.client.process import ClientProcessMixin
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.defaults import (
    DEFAULT_CLEANUP_WAIT_TIME,
)
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerStub
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as ControllerEmpty
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerStub
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioStub
from pyvider.rpcplugin.transport.types import TransportType

if TYPE_CHECKING:
    from provide.foundation.process import ManagedProcess

logger = get_logger(__name__)


@define
class RPCPluginClient(ClientHandshakeMixin, ClientProcessMixin):
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
    _process: ManagedProcess | None = field(init=False, default=None)  # type: ignore[assignment]
    _transport: TransportType | None = field(init=False, default=None)  # type: ignore[assignment]
    _transport_name: str | None = field(init=False, default=None)  # type: ignore[assignment]

    _address: str | None = field(init=False, default=None)  # type: ignore[assignment]
    _protocol_version: int | None = field(init=False, default=None)  # type: ignore[assignment]
    _server_cert: str | None = field(init=False, default=None)
    grpc_channel: grpc.aio.Channel | None = field(init=False, default=None)  # type: ignore[assignment]
    target_endpoint: str | None = field(init=False, default=None)  # type: ignore[assignment]

    # Generated or loaded client certificate
    client_cert: str | None = field(init=False, default=None)
    client_key_pem: str | None = field(init=False, default=None)

    # gRPC stubs for the new services
    _stdio_stub: GRPCStdioStub | None = field(init=False, default=None)  # type: ignore[assignment]
    _broker_stub: GRPCBrokerStub | None = field(init=False, default=None)  # type: ignore[assignment]
    _controller_stub: GRPCControllerStub | None = field(init=False, default=None)  # type: ignore[assignment]

    # Tasks for asynchronous streaming (e.g., reading stdio or broker streams)
    _stdio_task: asyncio.Task[None] | None = field(init=False, default=None)  # type: ignore[assignment]
    _broker_task: asyncio.Task[None] | None = field(init=False, default=None)

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

    async def start(self) -> None:
        """
        Start the plugin client: launch process, perform handshake, create channel.

        This is the main entry point for establishing communication with a plugin.
        It orchestrates the complete connection process.

        Raises:
            HandshakeError: If handshake fails
            TransportError: If transport setup fails
            ProtocolError: If protocol negotiation fails
        """
        self.logger.debug("🚀 Starting RPCPluginClient...")

        try:
            await self._connect_and_handshake_with_retry()
            self.is_started = True
        except Exception as e:
            self.logger.error(f"❌ Failed to start RPCPluginClient: {e}")
            self._handshake_failed_event.set()
            # Clean up any partial state on start failure
            await self.close()
            raise

    async def shutdown_plugin(self) -> None:
        """
        Gracefully shutdown the plugin server through gRPC controller.

        This method sends a shutdown signal to the plugin server, allowing it
        to clean up resources before termination.
        """
        try:
            if self._controller_stub:
                await self._controller_stub.Shutdown(ControllerEmpty())
                self.logger.debug("📤 Shutdown signal sent to plugin.")
            else:
                self.logger.warning("⚠️ No controller stub available for shutdown signal.")
        except grpc.RpcError as e:
            # Expected behavior when plugin shuts down immediately
        except Exception as e:
            self.logger.warning(f"⚠️ Error sending shutdown signal to plugin: {e}", exc_info=True)

        # Give the plugin a moment to shut down gracefully
        await asyncio.sleep(DEFAULT_CLEANUP_WAIT_TIME)

    async def _cancel_tasks(self) -> None:
        """Cancel all active streaming tasks."""
        for task_name, task in [
            ("stdio", self._stdio_task),
            ("broker", self._broker_task),
        ]:
            if task and not task.done():
                self.logger.debug(f"🛑 Cancelling {task_name} task...")
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                except Exception as e:
                    self.logger.warning(f"⚠️ Error cancelling {task_name} task: {e}", exc_info=True)

    async def _close_grpc_channel(self) -> None:
        """Close the gRPC channel with error handling."""
        if self.grpc_channel:
            try:
                await self.grpc_channel.close(grace=rpcplugin_config.plugin_grpc_grace_period)
            except Exception as e:
                self.logger.warning(f"⚠️ Error closing gRPC channel: {e}", exc_info=True)
            finally:
                self.grpc_channel = None

    async def _terminate_process(self) -> None:
        """Terminate the plugin process gracefully or forcefully."""
        if not self._process:
            return

        try:
            # Use ManagedProcess's built-in graceful termination
            self.logger.debug("🛑 Terminating plugin process...")
            terminated = await asyncio.get_event_loop().run_in_executor(
                None, self._process.terminate_gracefully, 5.0
            )

            if terminated:
            else:
                self.logger.warning("⚠️ Plugin process was force-killed.")

            # Clean up process resources
            self._process.cleanup()

        except Exception as e:
            self.logger.error(
                f"⚠️ Error terminating plugin process: {e}",
                extra={"trace": str(e)},
                exc_info=True,
            )
        finally:
            self._process = None

    async def _close_transport(self) -> None:
        """Close the transport with error handling."""
        if self._transport:
            try:
                self.logger.debug("🚪 Closing transport...")
                await self._transport.close()
            except Exception as e:
                self.logger.warning(f"⚠️ Error closing transport: {e}", exc_info=True)
            finally:
                self._transport = None

    def _reset_state(self) -> None:
        """Reset client state after cleanup."""
        self.is_started = False
        self._stubs.clear()
        self._stdio_stub = None
        self._broker_stub = None
        self._controller_stub = None

    async def close(self) -> None:
        """
        Close the client connection and clean up all resources.

        This method performs a complete cleanup of the client state,
        including stopping tasks, closing channels, terminating processes,
        and cleaning up transport resources.
        """
        self.logger.debug("🔒 Closing RPCPluginClient...")

        await self._cancel_tasks()
        await self._close_grpc_channel()
        await self._terminate_process()
        await self._close_transport()
        self._reset_state()


    async def __aenter__(self) -> RPCPluginClient:
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Async context manager exit with cleanup."""
        try:
            await self.shutdown_plugin()
        except Exception as e:
            self.logger.warning(f"⚠️ Error during shutdown in context manager: {e}", exc_info=True)
        finally:
            await self.close()

# 🔌📞🔚
