#
# src/pyvider/rpcplugin/server.py
#

"""
RPC Plugin Server Implementation.

This module defines `RPCPluginServer`, a class responsible for initializing,
running, and managing the lifecycle of a gRPC server that conforms to the
Pyvider RPC plugin protocol. It handles transport setup (Unix sockets or TCP),
secure handshakes, protocol negotiation, and graceful shutdown via signals.
"""

import asyncio
import contextlib
import os
import signal
import socket
import sys
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar, cast

import grpc
from attrs import define, field
from grpc.aio import server as GRPCServer  # Ensure this is the alias used
from grpc_health.v1 import health_pb2_grpc

from pyvider.rpcplugin.config import ConfigError, rpcplugin_config
from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.exception import (
    ProtocolError,
    SecurityError,
    TransportError,
)
from pyvider.rpcplugin.handshake import (
    HandshakeConfig,
    build_handshake_response,
    negotiate_protocol_version,
    negotiate_transport,
    validate_magic_cookie,
)
from pyvider.rpcplugin.health_servicer import HealthServicer
from pyvider.rpcplugin.protocol import register_protocol_service
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol as BaseRpcAbcProtocol
from pyvider.rpcplugin.rate_limiter import TokenBucketRateLimiter
from pyvider.rpcplugin.transport import TCPSocketTransport, UnixSocketTransport
from pyvider.rpcplugin.transport.types import (
    RPCPluginTransport as RPCPluginTransportType,
)
from pyvider.telemetry import logger

_ServerT = TypeVar("_ServerT", bound=grpc.aio.Server)
_HandlerT = TypeVar("_HandlerT")
_TransportT = TypeVar("_TransportT", bound=RPCPluginTransportType)

# Import for protocol field type moved to top


class RateLimitingInterceptor(grpc.aio.ServerInterceptor):
    """
    A gRPC interceptor that uses a TokenBucketRateLimiter to enforce rate limits.
    """

    def __init__(self, limiter: TokenBucketRateLimiter) -> None:
        self._limiter = limiter

    async def intercept_service(
        self,
        continuation: Callable[
            [grpc.HandlerCallDetails], Awaitable[grpc.RpcMethodHandler]
        ],
        handler_call_details: grpc.HandlerCallDetails,
    ) -> grpc.RpcMethodHandler:
        """Intercepts incoming RPCs to check against the rate limiter."""
        if not await self._limiter.is_allowed():
            raise grpc.aio.AbortError(
                grpc.StatusCode.RESOURCE_EXHAUSTED, "Rate limit exceeded."
            )
        return await continuation(handler_call_details)


@define(slots=False)
class RPCPluginServer[ServerT, HandlerT, TransportT]:  # Simplified generic parameters
    protocol: BaseRpcAbcProtocol[ServerT, HandlerT] = field()  # Type field directly
    handler: HandlerT = field()
    config: dict[str, Any] | None = field(default=None)
    transport: TransportT | None = field(default=None)
    _exit_on_stop: bool = field(default=True, init=False)
    _transport: TransportT | None = field(init=False, default=None)
    _server: ServerT | None = field(init=False, default=None)
    _handshake_config: HandshakeConfig = field(init=False)
    _protocol_version: int = field(init=False)
    _transport_name: str = field(init=False)
    _server_cert_obj: Certificate | None = field(init=False, default=None)
    _port: int | None = field(init=False, default=None)
    _serving_future: asyncio.Future[None] = field(init=False, factory=asyncio.Future)
    _serving_event: asyncio.Event = field(init=False, factory=asyncio.Event)
    _shutdown_event: asyncio.Event = field(init=False, factory=asyncio.Event)
    _shutdown_file_path: str | None = field(init=False, default=None)
    _shutdown_watcher_task: asyncio.Task[None] | None = field(init=False, default=None)
    _rate_limiter: TokenBucketRateLimiter | None = field(init=False, default=None)
    _health_servicer: HealthServicer | None = field(init=False, default=None)
    _main_service_name: str = field(
        default="pyvider.default.plugin.Service", init=False
    )

    def __attrs_post_init__(self) -> None:
        try:
            self._handshake_config = HandshakeConfig(
                magic_cookie_key=rpcplugin_config.magic_cookie_key(),
                magic_cookie_value=rpcplugin_config.magic_cookie_value(),
                protocol_versions=[
                    int(v)
                    for v in rpcplugin_config.get_list("PLUGIN_PROTOCOL_VERSIONS")
                ],
                supported_transports=rpcplugin_config.server_transports(),
            )
        except Exception as e:
            raise ConfigError(
                message=f"Failed to initialize handshake configuration: {e}",
                hint="Check rpcplugin_config settings.",
            ) from e

        if self.transport is not None:  # Use the public 'transport' field
            self._transport = self.transport

        self._serving_future = asyncio.Future()
        self._shutdown_file_path = rpcplugin_config.shutdown_file_path()

        if rpcplugin_config.rate_limit_enabled():
            capacity = rpcplugin_config.rate_limit_burst_capacity()
            refill_rate = rpcplugin_config.rate_limit_requests_per_second()
            if capacity > 0 and refill_rate > 0:
                self._rate_limiter = TokenBucketRateLimiter(
                    capacity=capacity, refill_rate=refill_rate
                )

        if hasattr(self.protocol, "service_name") and isinstance(
            self.protocol.service_name,
            str,  # type: ignore
        ):
            protocol_class_service_name = self.protocol.service_name  # type: ignore
            if protocol_class_service_name:
                self._main_service_name = protocol_class_service_name

        if rpcplugin_config.health_service_enabled():
            self._health_servicer = HealthServicer(
                app_is_healthy_callable=self._is_main_app_healthy,
                service_name=self._main_service_name,
            )

    def _is_main_app_healthy(self) -> bool:
        return not (self._shutdown_event and self._shutdown_event.is_set())

    async def _watch_shutdown_file(self) -> None:
        if not self._shutdown_file_path:
            return

        max_consecutive_os_errors = 3  # Max retries for os.path.exists errors
        consecutive_os_errors = 0

        while not self._shutdown_event.is_set():
            try:
                if os.path.exists(self._shutdown_file_path):  # Potential error source
                    with contextlib.suppress(
                        OSError
                    ):  # Gracefully handle removal error
                        os.remove(self._shutdown_file_path)
                    self._shutdown_requested()
                    logger.info(
                        f"Shutdown triggered by file: {self._shutdown_file_path}"
                    )
                    break
                consecutive_os_errors = 0  # Reset counter on success
                await asyncio.sleep(1)  # Regular check interval
            except asyncio.CancelledError:
                logger.debug("Shutdown file watcher task cancelled.")
                break
            except (
                OSError
            ) as oe:  # Specifically catch OSError from os.path.exists or os.remove
                consecutive_os_errors += 1
                logger.error(
                    f"OSError in shutdown file watcher "
                    f"({consecutive_os_errors}/{max_consecutive_os_errors}): {oe}"
                )
                if consecutive_os_errors >= max_consecutive_os_errors:
                    logger.error(
                        f"Max OSError retries for {self._shutdown_file_path}. "
                        "Stopping watcher."
                    )
                    self._shutdown_requested()  # Trigger shutdown to prevent hang
                    break
                await asyncio.sleep(
                    1 + consecutive_os_errors
                )  # Exponential backoff for OS errors
            except Exception as e:
                # Generic errors, less aggressive retry, but still important to log
                logger.error(
                    f"Unexpected error in shutdown file watcher: {e}", exc_info=True
                )
                await asyncio.sleep(5)  # Longer sleep for unexpected errors

    async def wait_for_server_ready(self, timeout: float = 5.0) -> None:
        try:
            await asyncio.wait_for(self._serving_event.wait(), timeout)
            if self._transport is not None:
                transport_checked = cast(RPCPluginTransportType, self._transport)
                if transport_checked.endpoint:
                    if isinstance(transport_checked, UnixSocketTransport):
                        if not transport_checked.path or not os.path.exists(
                            transport_checked.path
                        ):
                            err_msg = (
                                f"Unix socket file {transport_checked.path} "
                                "does not exist."
                            )
                            raise TransportError(err_msg)
                        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        sock.settimeout(1.0)
                        sock.connect(transport_checked.path)
                        sock.close()
                    elif isinstance(transport_checked, TCPSocketTransport):
                        host = transport_checked.host or "127.0.0.1"
                        port = self._port
                        if port is None:
                            raise TransportError(
                                "TCP port not available for readiness check."
                            )
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1.0)
                        sock.connect((host, port))
                        sock.close()
        except TimeoutError as e:
            raise TransportError(
                f"Server failed to signal readiness within {timeout}s."
            ) from e
        except (TransportError, OSError) as e:
            raise TransportError(f"Server readiness check failed: {e}") from e

    def _read_client_cert(self) -> str | None:
        if self.config and (client_cert := self.config.get("PLUGIN_CLIENT_CERT")):
            return client_cert
        return rpcplugin_config.get("PLUGIN_CLIENT_CERT")

    def _generate_server_credentials(self) -> grpc.ServerCredentials:
        server_cert_conf = rpcplugin_config.get("PLUGIN_SERVER_CERT")
        server_key_conf = rpcplugin_config.get("PLUGIN_SERVER_KEY")
        auto_mtls = rpcplugin_config.auto_mtls_enabled()
        client_root_certs_conf = rpcplugin_config.get("PLUGIN_CLIENT_ROOT_CERTS")

        if server_cert_conf and server_key_conf:
            try:
                self._server_cert_obj = Certificate(
                    cert_pem_or_uri=server_cert_conf, key_pem_or_uri=server_key_conf
                )
            except Exception as e:
                raise SecurityError(
                    f"Failed to load server certificate/key: {e}"
                ) from e
        elif auto_mtls:
            try:
                self._server_cert_obj = Certificate.create_self_signed_server_cert(
                    common_name="pyvider.rpcplugin.autogen.server",
                    organization_name="Pyvider AutoGenerated",
                    validity_days=365,
                    alt_names=["localhost"],
                )
            except Exception as e:
                raise SecurityError(
                    f"Failed to auto-generate server certificate: {e}"
                ) from e
        else:
            raise SecurityError(
                "Server certificate or key not configured for secure mode."
            )

        if not (
            self._server_cert_obj
            and self._server_cert_obj.cert
            and self._server_cert_obj.key
        ):
            raise SecurityError(
                "Server certificate object is invalid or missing PEM data."
            )

        key_bytes = self._server_cert_obj.key.encode("utf-8")
        cert_bytes = self._server_cert_obj.cert.encode("utf-8")
        client_ca_pem_bytes = None
        require_auth = False

        if auto_mtls and client_root_certs_conf:
            require_auth = True
            try:
                if client_root_certs_conf.startswith("file://"):
                    with open(client_root_certs_conf[7:], "rb") as f:
                        client_ca_pem_bytes = f.read()
                else:
                    client_ca_pem_bytes = client_root_certs_conf.encode("utf-8")
            except Exception as e:
                raise SecurityError(f"Failed to load client root CAs: {e}") from e

        return grpc.ssl_server_credentials(
            private_key_certificate_chain_pairs=[(key_bytes, cert_bytes)],
            root_certificates=client_ca_pem_bytes,
            require_client_auth=require_auth,
        )

    async def _setup_server(self, client_cert_str: str | None) -> None:
        try:
            interceptors_list: list[grpc.aio.ServerInterceptor] = (
                [RateLimitingInterceptor(self._rate_limiter)]
                if self._rate_limiter
                else []
            )
            self._server = cast(  # Use _server
                ServerT,
                GRPCServer(interceptors=interceptors_list),  # Use GRPCServer
            )

            # self.protocol is an instance of a type bound by RPCPluginProtocol.
            # No need to check if callable or call it.
            proto_instance = self.protocol  # Let MyPy infer the type
            await proto_instance.add_to_server(
                handler=self.handler, server=self._server
            )

            if self._server is None:
                raise TransportError(
                    "Server object not initialized before registration."
                )

            concrete_server = cast(grpc.aio.Server, self._server)
            register_protocol_service(
                server=concrete_server, shutdown_event=self._shutdown_event
            )
            if self._health_servicer and self._server:
                health_pb2_grpc.add_HealthServicer_to_server(
                    self._health_servicer, concrete_server
                )

            creds = (
                self._generate_server_credentials()
                if rpcplugin_config.auto_mtls_enabled()
                or rpcplugin_config.get("PLUGIN_SERVER_CERT")
                else None
            )

            if self._transport is None:
                raise TransportError("Transport not initialized before server setup.")

            active_transport_checked = cast(RPCPluginTransportType, self._transport)
            await active_transport_checked.listen()
            endpoint = active_transport_checked.endpoint
            if not endpoint:
                raise TransportError("Transport endpoint not available after listen.")

            bind_address = (
                f"unix:{endpoint}"
                if isinstance(active_transport_checked, UnixSocketTransport)
                else endpoint
            )

            server_for_port = cast(grpc.aio.Server, self._server)
            port_num = (
                server_for_port.add_secure_port(bind_address, creds)
                if creds
                else server_for_port.add_insecure_port(bind_address)
            )

            if isinstance(active_transport_checked, TCPSocketTransport):
                if port_num == 0 and bind_address != "0.0.0.0:0":
                    raise TransportError(f"Failed to bind to TCP port: {bind_address}")
                self._port = port_num
                active_transport_checked.port = port_num
                active_transport_checked.endpoint = (
                    f"{active_transport_checked.host}:{port_num}"
                )

            server_to_start = cast(grpc.aio.Server, self._server)
            await server_to_start.start()
        except (TransportError, ProtocolError, SecurityError):
            raise
        except Exception as e:
            raise TransportError(f"gRPC server failed to start: {e}") from e

    async def _negotiate_handshake(self) -> None:
        # Call validate_magic_cookie without arguments.
        # It will use rpcplugin_config for expected key/value
        # and check os.environ for the provided cookie.
        validate_magic_cookie()
        self._protocol_version = negotiate_protocol_version(
            self._handshake_config.protocol_versions
        )
        if not self._transport:
            # Type hint for what negotiate_transport returns
            negotiated_transport_typed: (
                RPCPluginTransportType  # Use the concrete Union or base class
            )
            (
                self._transport_name,
                negotiated_transport_typed,
            ) = await negotiate_transport(self._handshake_config.supported_transports)
            self._transport = cast(TransportT, negotiated_transport_typed)
        else:
            self._transport_name = (
                "tcp" if isinstance(self._transport, TCPSocketTransport) else "unix"
            )

    def _register_signal_handlers(self) -> None:
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(RuntimeError, NotImplementedError):
                loop.add_signal_handler(sig, self._shutdown_requested)

    def _shutdown_requested(self, *args: Any) -> None:
        if not self._serving_future.done():
            self._serving_future.set_result(None)
        self._shutdown_event.set()

    async def serve(self) -> None:
        try:
            self._register_signal_handlers()
            await self._negotiate_handshake()
            client_cert_str = self._read_client_cert()
            await self._setup_server(client_cert_str)

            if self._shutdown_file_path:
                self._shutdown_watcher_task = asyncio.create_task(
                    self._watch_shutdown_file()
                )

            if self._transport is None:
                err_msg = (
                    "Internal error: Transport is None before building "
                    "handshake response."
                )
                logger.error(f"💣💥 {err_msg}")
                raise TransportError(err_msg)

            concrete_transport = cast(RPCPluginTransportType, self._transport)
            response = await build_handshake_response(
                plugin_version=self._protocol_version,
                transport_name=self._transport_name,
                transport=concrete_transport,
                server_cert=self._server_cert_obj,
                port=self._port,
            )
            sys.stdout.buffer.write(f"{response}\n".encode())
            sys.stdout.buffer.flush()

            self._serving_event.set()
            await self._serving_future
        finally:
            await self.stop()

    async def stop(self) -> None:
        if self._shutdown_watcher_task and not self._shutdown_watcher_task.done():
            self._shutdown_watcher_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._shutdown_watcher_task

        if self._server is not None:
            server_to_stop = cast(grpc.aio.Server, self._server)
            await server_to_stop.stop(grace=0.5)
            self._server = None

        if self._transport is not None:
            transport_to_close = cast(RPCPluginTransportType, self._transport)
            await transport_to_close.close()
            self._transport = None

        if not self._serving_future.done():
            self._serving_future.set_result(None)


# 🐍🏗️🔌
