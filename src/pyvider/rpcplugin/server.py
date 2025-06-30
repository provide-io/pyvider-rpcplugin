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

from pyvider.rpcplugin.config import CONFIG_SCHEMA, ConfigError, rpcplugin_config # Import CONFIG_SCHEMA
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
class RPCPluginServer[ServerT, HandlerT, TransportT]:
    protocol: BaseRpcAbcProtocol[ServerT, HandlerT] = field()
    handler: HandlerT = field()
    config: dict[str, Any] | None = field(default=None) # Instance-specific config
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

    def _get_config_value(self, key: str, default_value: Any = None) -> Any:
        """
        Gets a config value, preferring instance config then global.
        Correctly typed values are expected if coming from self.config
        that was populated from a processed source (e.g. rpc_plugin_server_manager).
        """
        if self.config is not None and key in self.config:
            val = self.config[key]
            # If self.config might contain raw strings (e.g. "true", "1,2,3")
            # that need conversion based on CONFIG_SCHEMA, that logic would go here.
            # For now, assume self.config values are appropriately typed if provided.
            # Example for boolean string conversion:
            if CONFIG_SCHEMA.get(key, {}).get("type") == "bool" and isinstance(val, str):
                return val.lower() in ("true", "yes", "1", "on")
            # Example for list_str string conversion:
            if CONFIG_SCHEMA.get(key, {}).get("type") == "list_str" and isinstance(val, str):
                return [v.strip() for v in val.split(",")] if val.strip() else []
            # Example for list_int string conversion:
            if CONFIG_SCHEMA.get(key, {}).get("type") == "list_int" and isinstance(val, str):
                return [int(v.strip()) for v in val.split(",")] if val.strip() else []
            return val
        return rpcplugin_config.get(key, default_value)

    def _get_bool_config_value(self, key: str, global_config_method: Callable[[], bool]) -> bool:
        """
        Gets a boolean config value, preferring instance config.
        Falls back to the provided global config method (e.g., rpcplugin_config.auto_mtls_enabled).
        """
        if self.config is not None and key in self.config:
            val = self.config[key]
            if isinstance(val, str): # Handle string "true"/"false"
                return val.lower() in ("true", "yes", "1", "on")
            return bool(val)
        return global_config_method()


    def __attrs_post_init__(self) -> None:
        try:
            # Use helper methods to read from config, preferring instance config
            self._handshake_config = HandshakeConfig(
                magic_cookie_key=self._get_config_value("PLUGIN_MAGIC_COOKIE_KEY", rpcplugin_config.magic_cookie_key()),
                magic_cookie_value=self._get_config_value("PLUGIN_MAGIC_COOKIE_VALUE", rpcplugin_config.magic_cookie_value()),
                protocol_versions=[
                    int(v) for v in self._get_config_value("PLUGIN_PROTOCOL_VERSIONS", []) # Default to empty list
                ],
                supported_transports=self._get_config_value("PLUGIN_SERVER_TRANSPORTS", []) # Default to empty list
            )
        except Exception as e:
            raise ConfigError(
                message=f"Failed to initialize handshake configuration: {e}",
                hint="Check rpcplugin_config settings and instance config overrides.",
            ) from e

        if self.transport is not None:
            self._transport = self.transport

        self._serving_future = asyncio.Future()
        self._shutdown_file_path = self._get_config_value("PLUGIN_SHUTDOWN_FILE_PATH")

        if self._get_bool_config_value("PLUGIN_RATE_LIMIT_ENABLED", rpcplugin_config.rate_limit_enabled):
            capacity = self._get_config_value("PLUGIN_RATE_LIMIT_BURST_CAPACITY", rpcplugin_config.rate_limit_burst_capacity())
            refill_rate = self._get_config_value("PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND", rpcplugin_config.rate_limit_requests_per_second())
            if capacity > 0 and refill_rate > 0:
                self._rate_limiter = TokenBucketRateLimiter(
                    capacity=capacity, refill_rate=refill_rate
                )

        if hasattr(self.protocol, "service_name") and isinstance(
            getattr(self.protocol, "service_name"), str
        ):
            protocol_class_service_name = getattr(self.protocol, "service_name")
            if protocol_class_service_name:
                self._main_service_name = protocol_class_service_name

        if self._get_bool_config_value("PLUGIN_HEALTH_SERVICE_ENABLED", rpcplugin_config.health_service_enabled):
            self._health_servicer = HealthServicer(
                app_is_healthy_callable=self._is_main_app_healthy,
                service_name=self._main_service_name,
            )

    def _is_main_app_healthy(self) -> bool:
        return not (self._shutdown_event and self._shutdown_event.is_set())

    async def _watch_shutdown_file(self) -> None:
        if not self._shutdown_file_path:
            return
        # ... (rest of the method remains the same)
        max_consecutive_os_errors = 3
        consecutive_os_errors = 0
        while not self._shutdown_event.is_set():
            try:
                if os.path.exists(self._shutdown_file_path):
                    with contextlib.suppress(OSError):
                        os.remove(self._shutdown_file_path)
                    self._shutdown_requested()
                    logger.info(
                        f"Shutdown triggered by file: {self._shutdown_file_path}"
                    )
                    break
                consecutive_os_errors = 0
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                logger.debug("Shutdown file watcher task cancelled.")
                break
            except OSError as oe:
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
                    self._shutdown_requested()
                    break
                await asyncio.sleep(1 + consecutive_os_errors)
            except Exception as e:
                logger.error(
                    f"Unexpected error in shutdown file watcher: {e}", exc_info=True
                )
                await asyncio.sleep(5)


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
        return self._get_config_value("PLUGIN_CLIENT_CERT")

    def _generate_server_credentials(self) -> grpc.ServerCredentials | None: # Can return None now
        server_cert_conf = self._get_config_value("PLUGIN_SERVER_CERT")
        server_key_conf = self._get_config_value("PLUGIN_SERVER_KEY")
        auto_mtls = self._get_bool_config_value("PLUGIN_AUTO_MTLS", rpcplugin_config.auto_mtls_enabled)
        client_root_certs_conf = self._get_config_value("PLUGIN_CLIENT_ROOT_CERTS")

        if not auto_mtls and not (server_cert_conf and server_key_conf):
            logger.info("auto_mtls is false and no server cert/key provided. Operating insecurely.")
            return None # Insecure mode

        if server_cert_conf and server_key_conf:
            try:
                self._server_cert_obj = Certificate(
                    cert_pem_or_uri=server_cert_conf, key_pem_or_uri=server_key_conf
                )
            except Exception as e:
                raise SecurityError(
                    f"Failed to load server certificate/key: {e}"
                ) from e
        elif auto_mtls: # Implies server_cert_conf or server_key_conf was missing
            try:
                self._server_cert_obj = Certificate.create_self_signed_server_cert(
                    common_name="pyvider.rpcplugin.autogen.server",
                    organization_name="Pyvider AutoGenerated",
                    validity_days=365,
                    alt_names=["localhost"],
                )
                logger.info(f"📜🔑🏭 Created new self-signed SERVER certificate for CN={self._server_cert_obj.common_name}")
            except Exception as e:
                raise SecurityError(
                    f"Failed to auto-generate server certificate: {e}"
                ) from e
        else: # Should be caught by the first check, but as a safeguard
            logger.warning("Unexpected state in _generate_server_credentials: no certs, not auto_mtls, but didn't return None earlier.")
            return None


        if not (
            self._server_cert_obj
            and self._server_cert_obj.cert
            and self._server_cert_obj.key
        ):
            # This case implies auto_mtls was true but generation failed, or provided certs were bad
            raise SecurityError(
                "Server certificate object is invalid or missing PEM data after processing."
            )

        key_bytes = self._server_cert_obj.key.encode("utf-8")
        cert_bytes = self._server_cert_obj.cert.encode("utf-8")
        client_ca_pem_bytes = None
        require_auth = False

        if auto_mtls and client_root_certs_conf: # Full mTLS
            require_auth = True
            try:
                if isinstance(client_root_certs_conf, str) and client_root_certs_conf.startswith("file://"):
                    with open(client_root_certs_conf[7:], "rb") as f:
                        client_ca_pem_bytes = f.read()
                elif isinstance(client_root_certs_conf, str): # Assume direct PEM string
                    client_ca_pem_bytes = client_root_certs_conf.encode("utf-8")
                # Else, if it's already bytes (e.g. from a test), it might be used directly if gRPC allows
            except Exception as e:
                raise SecurityError(f"Failed to load client root CAs: {e}") from e
        elif auto_mtls: # Server-side TLS only, client cert not verified
            logger.warning("auto_mtls is True, but PLUGIN_CLIENT_ROOT_CERTS not provided. Client certs will not be required/verified.")
            require_auth = False
        # If not auto_mtls, require_auth remains False, client_ca_pem_bytes is None.

        return grpc.ssl_server_credentials(
            private_key_certificate_chain_pairs=[(key_bytes, cert_bytes)],
            root_certificates=client_ca_pem_bytes,
            require_client_auth=require_auth,
        )

    async def _setup_server(self, client_cert_str: str | None) -> None: # client_cert_str not used here
        try:
            interceptors_list: list[grpc.aio.ServerInterceptor] = (
                [RateLimitingInterceptor(self._rate_limiter)]
                if self._rate_limiter
                else []
            )
            self._server = cast(
                ServerT,
                GRPCServer(interceptors=interceptors_list),
            )

            proto_instance = self.protocol
            await proto_instance.add_to_server(
                handler=self.handler, server=self._server
            )

            if self._server is None: # Should not happen if GRPCServer() succeeded
                raise TransportError(
                    "Server object not initialized before registration."
                )

            concrete_server = cast(grpc.aio.Server, self._server)
            register_protocol_service(
                server=concrete_server, shutdown_event=self._shutdown_event
            )
            if self._health_servicer and self._server : # Check self._server again
                health_pb2_grpc.add_HealthServicer_to_server(
                    self._health_servicer, concrete_server
                )

            creds = self._generate_server_credentials() # This can return None

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
            port_num = 0
            if creds:
                port_num = server_for_port.add_secure_port(bind_address, creds)
                logger.info(f"🔒 Server starting in secure mode on {bind_address} (port_num: {port_num})")
            else:
                port_num = server_for_port.add_insecure_port(bind_address)
                logger.info(f"🔌 Server starting in insecure mode on {bind_address} (port_num: {port_num})")


            if isinstance(active_transport_checked, TCPSocketTransport):
                requested_port_str = self._get_config_value("PLUGIN_SERVER_ENDPOINT", "0.0.0.0:0").split(':')[-1]
                if port_num == 0 and requested_port_str != "0": # Bind failed if not requesting ephemeral
                    raise TransportError(f"Failed to bind to TCP port: {bind_address}. Port returned was 0.")
                self._port = port_num
                active_transport_checked.port = port_num

                current_host = active_transport_checked.host if active_transport_checked.host else "0.0.0.0"
                active_transport_checked.endpoint = f"{current_host}:{port_num}"


            server_to_start = cast(grpc.aio.Server, self._server)
            await server_to_start.start()
        except (TransportError, ProtocolError, SecurityError):
            raise
        except Exception as e:
            raise TransportError(f"gRPC server failed to start: {e}") from e

    async def _negotiate_handshake(self) -> None:
        # HandshakeConfig is now built in __attrs_post_init__ using _get_config_value
        validate_magic_cookie(
            magic_cookie_key=self._handshake_config.magic_cookie_key,
            magic_cookie_value=self._handshake_config.magic_cookie_value
            # Relies on os.environ for the actual cookie provided by client, which is correct.
        )
        self._protocol_version = negotiate_protocol_version(
            self._handshake_config.protocol_versions
        )
        if not self._transport:
            negotiated_transport_typed: RPCPluginTransportType
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
            # _read_client_cert() result wasn't used by _setup_server, so removed the call here
            await self._setup_server(client_cert_str=None) # Pass None, it's not used

            if self._shutdown_file_path: # Check if path is configured
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
                server_cert=self._server_cert_obj, # Set in _generate_server_credentials
                port=self._port, # Set in _setup_server for TCP
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
