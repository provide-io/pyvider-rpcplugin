#
# pyvider/rpcplugin/server/core.py
#
"""
Core RPCPluginServer class definition and lifecycle management.

This module contains the main RPCPluginServer class with its attributes,
initialization, configuration, and core server lifecycle methods.
"""

import asyncio
from collections.abc import Awaitable, Callable
import contextlib
import os
from pathlib import Path
import signal
import socket
import sys
from typing import Any, Generic, TypeVar, cast

from attrs import define, field
import grpc
from provide.foundation import timed_block
from provide.foundation.logger import get_logger
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import ConfigError, TransportError
from pyvider.rpcplugin.handshake import HandshakeConfig
from pyvider.rpcplugin.health_servicer import HealthServicer
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol as BaseRpcAbcProtocol
from pyvider.rpcplugin.telemetry import get_rpc_tracer
from pyvider.rpcplugin.transport.types import (
    RPCPluginTransport as RPCPluginTransportType,
)

# Import the network mixin
from .network import ServerNetworkMixin

# Module logger and tracer
logger = get_logger(__name__)
_tracer = get_rpc_tracer()

_ServerT = TypeVar("_ServerT", bound=grpc.aio.Server)
_HandlerT = TypeVar("_HandlerT")
_TransportT = TypeVar("_TransportT", bound=RPCPluginTransportType)


class RateLimitingInterceptor(grpc.aio.ServerInterceptor):
    def __init__(self, limiter: TokenBucketRateLimiter) -> None:
        self._limiter = limiter

    async def intercept_service(
        self,
        continuation: Callable[[grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler]],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        if not await self._limiter.is_allowed():
            raise grpc.aio.AbortError(grpc.StatusCode.RESOURCE_EXHAUSTED, "Rate limit exceeded.")
        return await continuation(handler_call_details)


ServerT = TypeVar("ServerT")
HandlerT = TypeVar("HandlerT")
TransportT = TypeVar("TransportT")


@define(slots=False)
class RPCPluginServer(Generic[ServerT, HandlerT, TransportT], ServerNetworkMixin):
    """
    Server interface for hosting Terraform-compatible plugin services.

    The RPCPluginServer handles the complete lifecycle of plugin hosting:
    1. Transport setup (Unix socket or TCP) with optional mTLS
    2. Handshake protocol negotiation with clients
    3. gRPC server initialization and service registration
    4. Rate limiting and health check services
    5. Signal handling for graceful shutdown
    6. Optional shutdown file monitoring

    The server follows the Terraform go-plugin protocol, which includes
    a standardized handshake format, negotiated protocol version, and
    support for Unix socket or TCP transport modes.

    Attributes:
        protocol: Protocol implementation for the plugin service
        handler: Service handler instance for the protocol
        config: Optional configuration dictionary for customizing server behavior
        transport: Optional pre-configured transport instance

    Example:
        ```python
        # Create a server for a plugin
        server = RPCPluginServer(
            protocol=MyProtocol(),
            handler=MyServiceHandler(),
            config={"PLUGIN_AUTO_MTLS": True}
        )

        # Start the server (setup transport, handshake, serve)
        await server.serve()
        ```

    Note:
        The server supports automatic mTLS if enabled in configuration,
        and can generate certificates as needed for secure communication.
    """

    protocol: BaseRpcAbcProtocol[ServerT, HandlerT] = field()
    handler: HandlerT = field()
    config: dict[str, Any] | None = field(default=None)
    transport: TransportT | None = field(default=None)
    _exit_on_stop: bool = field(default=True, init=False)
    _transport: TransportT | None = field(init=False, default=None)
    _server: ServerT | None = field(init=False, default=None)
    _handshake_config: HandshakeConfig = field(init=False)
    _protocol_version: int = field(init=False)
    _transport_name: str = field(init=False)
    _server_cert_obj: Any | None = field(init=False, default=None)  # Certificate type
    _port: int | None = field(init=False, default=None)
    _serving_future: asyncio.Future[None] = field(init=False, factory=asyncio.Future)
    _serving_event: asyncio.Event = field(init=False, factory=asyncio.Event)
    _shutdown_event: asyncio.Event = field(init=False, factory=asyncio.Event)
    _shutdown_file_path: str | None = field(init=False, default=None)
    _shutdown_watcher_task: asyncio.Task[None] | None = field(init=False, default=None)
    _rate_limiter: TokenBucketRateLimiter | None = field(init=False, default=None)
    _health_servicer: HealthServicer | None = field(init=False, default=None)
    _main_service_name: str = field(default="pyvider.default.plugin.Service", init=False)

    def _get_instance_override(self, key: str, default_value: Any) -> Any:
        """
        Get instance config override if present, otherwise return default.
        """
        if isinstance(self.config, dict) and key in self.config:
            val = self.config[key]
            if val is not None:
                return val
        return default_value

    def __attrs_post_init__(self) -> None:
        try:
            # Use direct attribute access with instance config overrides
            self._handshake_config = HandshakeConfig(
                magic_cookie_key=self._get_instance_override(
                    "PLUGIN_MAGIC_COOKIE_KEY", rpcplugin_config.plugin_magic_cookie_key
                ),
                magic_cookie_value=self._get_instance_override(
                    "PLUGIN_MAGIC_COOKIE_VALUE", rpcplugin_config.plugin_magic_cookie_value
                ),
                protocol_versions=self._get_instance_override(
                    "PLUGIN_PROTOCOL_VERSIONS", rpcplugin_config.plugin_protocol_versions
                ),
                supported_transports=self._get_instance_override(
                    "PLUGIN_SERVER_TRANSPORTS", rpcplugin_config.plugin_server_transports
                ),
            )
        except ConfigError:
            raise
        except Exception as e:
            raise ConfigError(
                message=f"Failed to initialize handshake configuration: {e}",
                hint="Check rpcplugin_config settings and instance config overrides.",
            ) from e

        if self.transport is not None:
            self._transport = self.transport

        self._serving_future = asyncio.Future()
        self._shutdown_file_path = self._get_instance_override(
            "PLUGIN_SHUTDOWN_FILE_PATH", rpcplugin_config.plugin_shutdown_file_path
        )

        if self._get_instance_override(
            "PLUGIN_RATE_LIMIT_ENABLED", rpcplugin_config.plugin_rate_limit_enabled
        ):
            capacity = self._get_instance_override(
                "PLUGIN_RATE_LIMIT_BURST_CAPACITY",
                rpcplugin_config.plugin_rate_limit_burst_capacity,
            )
            refill_rate = self._get_instance_override(
                "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND",
                rpcplugin_config.plugin_rate_limit_requests_per_second,
            )
            if capacity > 0 and refill_rate > 0:
                self._rate_limiter = TokenBucketRateLimiter(capacity=capacity, refill_rate=refill_rate)

        if hasattr(self.protocol, "service_name") and isinstance(self.protocol.service_name, str):
            protocol_class_service_name = self.protocol.service_name
            if protocol_class_service_name:
                self._main_service_name = protocol_class_service_name

        if self._get_instance_override(
            "PLUGIN_HEALTH_SERVICE_ENABLED", rpcplugin_config.plugin_health_service_enabled
        ):
            self._health_servicer = HealthServicer(
                app_is_healthy_callable=self._is_main_app_healthy,
                service_name=self._main_service_name,
            )

    def _is_main_app_healthy(self) -> bool:
        return not (self._shutdown_event and self._shutdown_event.is_set())

    async def _watch_shutdown_file(self) -> None:
        if not self._shutdown_file_path:
            return
        max_consecutive_os_errors = 3
        consecutive_os_errors = 0
        while not self._shutdown_event.is_set():
            try:
                if Path(self._shutdown_file_path).exists():
                    with contextlib.suppress(OSError):
                        Path(self._shutdown_file_path).unlink()
                    self._shutdown_requested()
                    logger.info(f"Shutdown triggered by file: {self._shutdown_file_path}")
                    break
                consecutive_os_errors = 0
            except OSError:
                consecutive_os_errors += 1
                if consecutive_os_errors >= max_consecutive_os_errors:
                    logger.error(
                        f"Shutdown file watcher has encountered {consecutive_os_errors} "
                        "consecutive OS errors. Stopping shutdown file monitoring."
                    )
                    break
            except Exception as e:
                logger.error(f"Unexpected error in shutdown file watcher: {e}")
                break
            await asyncio.sleep(1.0)
        logger.debug("Shutdown file watcher stopped")

    async def wait_for_server_ready(self, timeout: float | None = None) -> None:
        """
        Wait for the server to be ready to accept connections.

        Args:
            timeout: Maximum time to wait for server readiness

        Raises:
            TimeoutError: If server doesn't become ready within timeout
            TransportError: If server setup fails
        """
        if timeout is None:
            timeout = rpcplugin_config.plugin_server_ready_timeout

        logger.debug(f"Waiting for server to be ready (timeout: {timeout}s)")

        try:
            await asyncio.wait_for(self._serving_event.wait(), timeout=timeout)
            logger.debug("Server serving event is set")

            # Perform transport-specific readiness checks
            await self._verify_transport_readiness()

            logger.debug("Server is ready")
        except TimeoutError as e:
            error_msg = f"Server failed to become ready within {timeout} seconds"
            logger.error(error_msg)
            raise TimeoutError(error_msg) from e

    async def _verify_transport_readiness(self) -> None:
        """
        Verify that the transport is ready to accept connections.

        Raises:
            TransportError: If transport readiness verification fails
        """
        if not self._transport:
            raise TransportError("Transport is not configured")

        transport_name = getattr(self._transport, "_transport_name", None)

        if transport_name == "unix":
            # Unix socket readiness check
            socket_path = getattr(self._transport, "path", None)
            if socket_path and not Path(socket_path).exists():
                raise TransportError(f"Unix socket file {socket_path} does not exist.")

        elif transport_name == "tcp":
            # TCP socket readiness check
            if not hasattr(self, "_port") or self._port is None:
                raise TransportError("TCP port not available for readiness check.")

            # Attempt a connection to verify the port is ready
            try:
                host = getattr(self._transport, "host", "127.0.0.1")
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(1.0)
                try:
                    test_socket.connect((host, self._port))
                finally:
                    test_socket.close()
            except OSError as e:
                raise TransportError(f"Server readiness check failed: {e}") from e

    def _register_signal_handlers(self) -> None:
        """Register signal handlers for graceful shutdown."""
        if sys.platform != "win32":
            loop = asyncio.get_event_loop()
            for sig in [signal.SIGINT, signal.SIGTERM]:
                with contextlib.suppress(RuntimeError):
                    loop.add_signal_handler(sig, self._shutdown_requested)

    def _shutdown_requested(self, *args: Any) -> None:
        """Handle shutdown request from signal or file watcher."""
        logger.info("Shutdown requested")
        if not self._serving_future.done():
            self._serving_future.set_result(None)
        self._shutdown_event.set()

    async def serve(self) -> None:
        """
        Start the plugin server and serve until shutdown.

        This is the main entry point for running the server. It orchestrates
        the complete server lifecycle including transport setup, handshake,
        gRPC server initialization, and serving until shutdown.

        Raises:
            TransportError: If transport setup fails
            ProtocolError: If handshake or protocol setup fails
        """
        if _tracer:
            with _tracer.start_as_current_span("rpc.server.serve") as span:
                span.set_attribute("component", "server")
                await self._serve_impl()
        else:
            await self._serve_impl()

    async def _serve_impl(self) -> None:
        """Implementation of server serve logic."""
        logger.info("🚀 Starting RPCPluginServer...")

        try:
            # Register signal handlers for graceful shutdown
            self._register_signal_handlers()

            # Negotiate handshake and setup transport
            with timed_block(logger, "handshake_negotiation", component="server"):
                await self._negotiate_handshake()

            # Setup server infrastructure
            with timed_block(logger, "server_setup", component="server"):
                await self._setup_server()

            # Start shutdown file watcher if configured
            if self._shutdown_file_path:
                self._shutdown_watcher_task = asyncio.create_task(self._watch_shutdown_file())

            # Send handshake response to stdout
            with timed_block(logger, "handshake_response", component="server"):
                await self._build_and_send_handshake_response()

            # Indicate server is ready
            self._serving_event.set()
            logger.info("✅ RPCPluginServer is ready and serving")

            # Wait for shutdown signal
            await self._serving_future
            logger.info("🛑 Shutdown event received")

        except Exception as e:
            logger.error(f"❌ Error starting RPCPluginServer: {e}", exc_info=True)
            raise
        finally:
            await self.stop()

    async def stop(self) -> None:
        """
        Stop the server and clean up resources.

        This method performs graceful shutdown of the server including
        stopping the gRPC server, cleaning up transport resources,
        and canceling background tasks.
        """
        logger.info("🔒 Stopping RPCPluginServer...")

        # Cancel shutdown watcher task
        if self._shutdown_watcher_task and not self._shutdown_watcher_task.done():
            self._shutdown_watcher_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._shutdown_watcher_task

        # Stop gRPC server
        if self._server is not None:
            logger.debug("Stopping gRPC server...")
            server_to_stop = cast(grpc.aio.Server, self._server)
            await server_to_stop.stop(grace=0.5)
            self._server = None

        # Clean up transport
        if self._transport is not None:
            logger.debug("Closing transport...")
            transport_to_close = cast(RPCPluginTransportType, self._transport)
            await transport_to_close.close()
            self._transport = None

        # Complete the serving future if not already done
        if not self._serving_future.done():
            self._serving_future.set_result(None)

        # Exit if configured to do so (only in non-test environments)
        if self._exit_on_stop and not os.environ.get("PYTEST_CURRENT_TEST"):
            logger.info("⚡ Exiting process...")
            sys.exit(0)

        logger.info("✅ RPCPluginServer stopped")
