"""
RPC Plugin Server Implementation.

This module defines `RPCPluginServer`, a class responsible for initializing,
running, and managing the lifecycle of a gRPC server that conforms to the
Pyvider RPC plugin protocol. It handles transport setup (Unix sockets or TCP),
secure handshakes, protocol negotiation, and graceful shutdown via signals.
"""

import asyncio
import os
import signal
import socket
import stat
import sys  # Single import
import traceback
from abc import ABC
from typing import Generic, cast, Any  # Added Any

import grpc
from attrs import define, field
from grpc.aio import server as GRPCServer

from pyvider.rpcplugin.config import ConfigError, rpcplugin_config  # Added ConfigError
from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.exception import (
    HandshakeError,
    ProtocolError,
    SecurityError,
    TransportError,
)  # Added SecurityError, ProtocolError
from pyvider.rpcplugin.handshake import (
    HandshakeConfig,
    build_handshake_response,
    negotiate_protocol_version,
    negotiate_transport,
    validate_magic_cookie,
)
from pyvider.rpcplugin.protocol import register_protocol_service
from pyvider.rpcplugin.transport import (
    TCPSocketTransport,
    UnixSocketTransport,
)
from pyvider.rpcplugin.transport.types import TransportT
from pyvider.rpcplugin.types import (
    HandlerT,
    ProtocolT,
    ServerT,
)
from pyvider.telemetry import logger

# ClientT is already imported from pyvider.rpcplugin.client.types


@define(slots=False)
class RPCPluginServer(
    ABC,
    Generic[ServerT, HandlerT, TransportT, ProtocolT],  # Removed ClientT from Generic
):
    """
    RPCPluginServer initializes and runs a gRPC server according to negotiated
    handshake parameters.

    This class manages the complete lifecycle of a plugin server:
    1. Setting up the transport (Unix socket or TCP)
    2. Performing the handshake protocol with clients
    3. Starting the gRPC server with the provided protocol and handler
    4. Managing server shutdown and cleanup

    The server supports mTLS for secure communication and can operate with either
    TCP or Unix socket transports. It handles signals for graceful shutdown and
    provides a comprehensive logging interface for debugging.

    Attributes:
        protocol: The protocol implementation describing the gRPC service
        handler: The handler implementation that processes requests
        config: Optional configuration parameters
        transport: Optional pre-configured transport instance
    """

    # Public initialization parameters.
    protocol: ProtocolT = field()
    handler: HandlerT = field()
    config: dict[str, Any] | None = field(default=None)  # Changed type hint
    transport: TransportT | None = field(default=None)

    _exit_on_stop: bool = field(default=True, init=False)

    # Internal attributes.
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

    # _instance and get_instance class-level features have been removed.

    def __attrs_post_init__(self) -> None:
        """
        Initializes handshake configuration.

        This method:
        1. Loads handshake configuration from rpcplugin_config
        2. Sets up protocol versions and supported transports
        3. Registers this instance as the global server instance

        Raises:
            Exception: If initialization of handshake configuration fails
        """
        try:
            logger.debug("🛎️⚙️ Initializing HandshakeConfig from configuration.")
            self._handshake_config = HandshakeConfig(
                magic_cookie_key=rpcplugin_config.magic_cookie_key(),
                magic_cookie_value=rpcplugin_config.magic_cookie_value(),
                protocol_versions=[
                    int(v)
                    for v in rpcplugin_config.get_list("PLUGIN_PROTOCOL_VERSIONS")
                ],
                supported_transports=rpcplugin_config.server_transports(),
            )
            logger.debug(f"🛎️⚙️ HandshakeConfig set: {self._handshake_config}")
        except Exception as e:
            logger.error(
                f"🛎️⚙️❌ Failed to initialize handshake configuration from rpcplugin_config: {e}",  # Corrected logging
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise ConfigError(
                message=f"Failed to initialize handshake configuration: {e}",
                hint="Check rpcplugin_config settings related to 'PLUGIN_PROTOCOL_VERSIONS', 'PLUGIN_SERVER_TRANSPORTS', and magic cookie values.",
            ) from e
        # Ensure each instance has a truly unique future.
        self._serving_future = asyncio.Future()
        logger.debug(
            f"🛎️⚙️ RPCPluginServer instance initialized. New _serving_future created (ID: {id(self._serving_future)})."
        )

    async def wait_for_server_ready(self, timeout: float = 3.14) -> None:
        """
        Wait for the server to be in a ready state.

        This method blocks until the server is fully initialized and ready to accept
        connections, or until the specified timeout is reached.

        Args:
            timeout: Maximum time to wait for server readiness, in seconds

        Raises:
            TimeoutError: If the server does not become ready within the timeout period
        """
        # Removed print DEBUG statements
        logger.info(
            f"W4SR: Checking readiness. Transport: {self._transport}, Server Port: {self._port}"
        )
        try:
            logger.debug("W4SR: Waiting for server ready event...")

            # First wait for the internal event to be set
            await asyncio.wait_for(self._serving_event.wait(), timeout)
            logger.debug("W4SR: Server ready event received.")

            # Additional verification: ensure transport endpoint is active and connectable
            logger.debug(
                f"W4SR: Before transport match. self._transport type: {type(self._transport)}"
            )
            if (
                self._transport
                and hasattr(self._transport, "endpoint")
                and self._transport.endpoint
                and isinstance(
                    self._transport, (UnixSocketTransport, TCPSocketTransport)
                )
            ):
                match self._transport:
                    case UnixSocketTransport():
                        logger.debug("W4SR: Matched UnixSocketTransport.")
                        transport_path = self._transport.path
                        logger.debug(f"W4SR: Unix transport_path: {transport_path}")
                        if transport_path is None:
                            logger.debug(
                                "W4SR: transport_path is None, raising TransportError."
                            )
                            logger.error(
                                "🛎️❌ Unix socket transport path is None."
                            )  # Original log
                            raise TransportError(
                                message="Unix socket path not set for server readiness check.",
                                hint="Ensure the Unix socket transport was properly initialized and its path is set before checking readiness.",
                            )

                        logger.debug(
                            f"W4SR: Checking if Unix socket file exists. Path: {transport_path}"
                        )
                        if not os.path.exists(transport_path):
                            logger.debug(
                                f"W4SR: Unix socket file {transport_path} does not exist, raising TransportError."
                            )
                            logger.error(
                                f"🛎️❌ Unix socket file {transport_path} doesn't exist for readiness check."  # Original log
                            )
                            raise TransportError(
                                message=f"Unix socket file {transport_path} does not exist.",
                                hint="Ensure the server has started and created the socket file. Check file system permissions.",
                            )

                        try:
                            logger.debug(
                                f"W4SR: Testing Unix socket connection to {transport_path}"
                            )
                            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                            sock.settimeout(1.0)
                            sock.connect(transport_path)
                            sock.close()
                            logger.debug(
                                "W4SR: Unix socket connection test successful."
                            )
                        except Exception as e:
                            logger.debug(
                                f"W4SR: Unix socket connection test failed for {transport_path}, raising TransportError. Error: {e!s}"
                            )
                            logger.error(
                                f"🛎️❌ Unix socket connection test failed for {transport_path}: {e!s}"  # Original log
                            )
                            raise TransportError(
                                message=f"Unix socket at {transport_path} is not connectable: {e!s}",
                                hint="Verify the server process is running and listening on the socket. Check for other processes locking the socket.",
                            ) from e

                    case TCPSocketTransport():
                        logger.debug("W4SR: Matched TCPSocketTransport.")
                        actual_server_host = (
                            self._transport.host
                            if self._transport.host
                            else "127.0.0.1"
                        )
                        actual_server_port = self._port
                        logger.debug(
                            f"W4SR: TCP actual_server_host: {actual_server_host}, actual_server_port: {actual_server_port}"
                        )

                        logger.debug(
                            f"W4SR: Checking if TCP actual_server_port is None. Port: {actual_server_port}"
                        )
                        if actual_server_port is None:
                            logger.debug(
                                "W4SR: TCP actual_server_port is None, raising TransportError."
                            )
                            logger.error(
                                "🛎️❌ TCP port not set after server start for readiness check."
                            )  # Original log
                            raise TransportError(
                                message="TCP port not available for server readiness check.",
                                hint="Ensure the server started correctly and the TCP port was successfully bound and recorded.",
                            )

                        logger.debug(
                            f"W4SR: Testing TCP connection to {actual_server_host}:{actual_server_port}"
                        )
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(1.0)
                            sock.connect((actual_server_host, actual_server_port))
                            sock.close()
                            logger.debug("W4SR: TCP connection test successful.")
                        except Exception as e:
                            logger.debug(
                                f"W4SR: TCP connection test failed for {actual_server_host}:{actual_server_port}, raising TransportError. Error: {e!s}"
                            )
                            logger.error(
                                f"🛎️❌ TCP connection test failed for {actual_server_host}:{actual_server_port}: {e!s}"
                            )  # Original log
                            raise TransportError(
                                message=f"TCP socket at {actual_server_host}:{actual_server_port} is not connectable: {e!s}",
                                hint="Verify the server process is running, listening on the port, and firewall rules allow connection.",
                            ) from e
            else:
                logger.debug(
                    "W4SR: Transport not suitable for detailed readiness check or not set."
                )

        except asyncio.TimeoutError as e:
            logger.debug(
                f"W4SR: asyncio.TimeoutError caught, raising TransportError. Original error: {e!s}"
            )
            logger.error(
                f"🛎️❌ Server did not become ready (serving event not set) within timeout ({timeout}s).",  # Original log
                extra={"timeout": timeout, "trace": traceback.format_exc()},
            )
            raise TransportError(
                message=f"Server failed to signal readiness via event within the {timeout}s timeout.",
                hint="Check server logs for startup errors. Increase timeout if server initialization is expected to be slow.",
            ) from e
        except TransportError:
            logger.debug("W4SR: TransportError caught, re-raising.")
            raise
        except Exception as e:
            logger.debug(
                f"W4SR: Generic Exception caught, raising TransportError. Original error: {e!s}"
            )
            logger.error(
                f"🛎️❌ Unexpected error during server readiness check: {e!s}",
                extra={"trace": traceback.format_exc()},
            )  # Original log
            raise TransportError(
                message=f"An unexpected error occurred during server readiness check: {e!s}",
                hint="Review server logs for details on the failure.",
            ) from e

    # get_instance class method removed.

    def _read_client_cert(self) -> str | None:
        """
        Reads the client certificate from configuration.

        This method attempts to find a client certificate in either:
        1. The server's local configuration
        2. The global rpcplugin_config

        Returns:
            The client certificate as a string, or None if not found
        """
        try:
            # First check the config provided to the server
            if self.config and hasattr(self.config, "get"):
                client_cert = self.config.get("PLUGIN_CLIENT_CERT")
                if client_cert:
                    logger.debug("🛎️🔐✅ Client cert found in server config.")
                    return client_cert

            # Then check the global config
            client_cert = rpcplugin_config.get("PLUGIN_CLIENT_CERT")
            if client_cert:
                logger.debug("🛎️🔐✅ Client cert found in global config.")
            else:
                logger.debug(
                    "🛎️🔐⚠️ No client certificate provided; operating insecurely."
                )
                return None

            return client_cert
        except Exception as e:
            logger.error(f"🛎️🔐❌ Error reading client certificate: {e}")
            return None

    def _generate_server_credentials(self) -> grpc.ServerCredentials:
        # Inside _generate_server_credentials(self)
        logger.debug("🛎️🔐 Generating server credentials...")
        server_cert_conf = rpcplugin_config.get("PLUGIN_SERVER_CERT")
        server_key_conf = rpcplugin_config.get("PLUGIN_SERVER_KEY")
        auto_mtls = rpcplugin_config.auto_mtls_enabled()  # This is True by default
        client_root_certs_conf = rpcplugin_config.get("PLUGIN_CLIENT_ROOT_CERTS")

        generated_self_signed_server_cert = False  # Flag to track if we auto-generated

        if server_cert_conf and server_key_conf:
            # Certs are provided by user, load them
            try:
                self._server_cert_obj = Certificate(
                    cert_pem_or_uri=server_cert_conf,
                    key_pem_or_uri=server_key_conf,
                    # generate_keypair=False is default when cert_pem_or_uri is provided
                )
                logger.debug(
                    "🛎️🔐 Server certificate and key loaded from configuration."
                )
            except Exception as e:
                logger.error(
                    f"🛎️🔐❌ Failed to load server certificate/key from configuration: {e}",
                    extra={"trace": traceback.format_exc()},
                )
                raise SecurityError(
                    f"Failed to load server certificate/key from configuration: {e}"
                ) from e
        elif auto_mtls:
            # PLUGIN_AUTO_MTLS is True, but server certs are NOT provided by user.
            # Implement "automatic" server cert generation.
            logger.info(
                "🛎️🔐 `PLUGIN_AUTO_MTLS` is true and server certs not provided. Auto-generating self-signed server certificate."
            )
            try:
                self._server_cert_obj = Certificate.create_self_signed_server_cert(
                    common_name="pyvider.rpcplugin.autogen.server",
                    alt_names=["localhost"],
                    organization_name="Pyvider AutoGenerated",
                    validity_days=365,  # Example, can be configured
                )
                generated_self_signed_server_cert = True
                logger.info(
                    f"🛎️🔐 Successfully auto-generated self-signed server certificate and key. Subject: {self._server_cert_obj.subject}"
                )
            except Exception as e:
                logger.error(
                    f"🛎️🔐❌ Failed to auto-generate self-signed server certificate: {e}",
                    extra={"trace": traceback.format_exc()},
                )
                raise SecurityError(
                    f"Failed to auto-generate self-signed server certificate for automatic mTLS: {e}"
                ) from e
        else:
            # This block handles cases where certs are partially provided or not provided AND auto_mtls is False.
            # The calling condition in _setup_server should ideally prevent reaching here if both are missing and auto_mtls is False,
            # as _generate_server_credentials wouldn't be called.
            if server_cert_conf and not server_key_conf:
                raise SecurityError(
                    message="Server certificate (PLUGIN_SERVER_CERT) provided without a server key (PLUGIN_SERVER_KEY) when mTLS is disabled.",
                    hint="Provide PLUGIN_SERVER_KEY or remove PLUGIN_SERVER_CERT for insecure mode if PLUGIN_AUTO_MTLS is false.",
                )
            elif not server_cert_conf and server_key_conf:
                raise SecurityError(
                    message="Server key (PLUGIN_SERVER_KEY) provided without a server certificate (PLUGIN_SERVER_CERT) when mTLS is disabled.",
                    hint="Provide PLUGIN_SERVER_CERT or remove PLUGIN_SERVER_KEY for insecure mode if PLUGIN_AUTO_MTLS is false.",
                )
            else:  # Both missing, auto_mtls is false.
                logger.error(
                    "🛎️🔐❌ _generate_server_credentials called inappropriately for an insecure configuration (auto_mtls=false, no certs)."
                )
                raise SecurityError(
                    "Credential generation called unexpectedly for an insecure configuration."
                )

        if (
            not self._server_cert_obj
            or not self._server_cert_obj.cert
            or not self._server_cert_obj.key
        ):
            raise SecurityError(
                message="Server certificate object is invalid or missing PEM data after loading/generation.",
                hint="Verify certificate source or generation process. This should not happen if loading/generation was successful.",
            )

        try:
            key_bytes = self._server_cert_obj.key.encode("utf-8")
            cert_bytes = self._server_cert_obj.cert.encode("utf-8")
        except Exception as e:
            logger.error(
                f"🛎️🔐❌ Failed to encode server certificate/key to bytes: {e}",
                extra={"trace": traceback.format_exc()},
            )
            raise SecurityError(f"Failed to encode server certificate/key: {e}") from e

        client_ca_pem_bytes = None
        require_auth = False

        if auto_mtls:
            if client_root_certs_conf:
                logger.debug(
                    "🛎️🔐 mTLS enabled with user-provided `PLUGIN_CLIENT_ROOT_CERTS`. Client certificate validation will be required."
                )
                require_auth = True
                try:
                    if client_root_certs_conf.startswith("file://"):
                        ca_path = client_root_certs_conf[len("file://") :]
                        with open(ca_path, "rb") as f:
                            client_ca_pem_bytes = f.read()
                        logger.info(
                            f"🛎️🔐 Loaded client root CAs for mTLS from {ca_path}."
                        )
                    else:
                        client_ca_pem_bytes = client_root_certs_conf.encode("utf-8")
                        logger.info(
                            "🛎️🔐 Loaded client root CAs for mTLS from configuration string."
                        )
                except Exception as e:
                    logger.error(
                        f"🛎️🔐❌ Failed to load `PLUGIN_CLIENT_ROOT_CERTS`: {e}",
                        extra={"trace": traceback.format_exc()},
                    )
                    raise SecurityError(
                        f"Failed to load `PLUGIN_CLIENT_ROOT_CERTS`: {e}"
                    ) from e
            elif generated_self_signed_server_cert:
                logger.info(
                    "🛎️🔐 Server certificate auto-generated for `PLUGIN_AUTO_MTLS`, and no `PLUGIN_CLIENT_ROOT_CERTS` provided. Operating with server-side TLS (client certs not required/validated by server)."
                )
                require_auth = False
            else:  # auto_mtls is true, server certs were user-provided, but no client_root_certs_conf.
                logger.info(
                    "🛎️🔐 `PLUGIN_AUTO_MTLS` is true, server certs provided by user, but no `PLUGIN_CLIENT_ROOT_CERTS`. Operating with server-side TLS (client certs not required/validated by server)."
                )
                require_auth = False
        elif rpcplugin_config.get(
            "PLUGIN_SERVER_CERT"
        ):  # auto_mtls is FALSE, but server cert is provided
            logger.info(
                "🛎️🔐 Server-only TLS configured (PLUGIN_AUTO_MTLS is false, server cert provided). Client certificates will not be required by server."
            )
            require_auth = False

        try:
            creds = grpc.ssl_server_credentials(
                private_key_certificate_chain_pairs=[(key_bytes, cert_bytes)],
                root_certificates=client_ca_pem_bytes,
                require_client_auth=require_auth,
            )
            if require_auth:
                logger.debug(
                    "🛎️🔐✅ mTLS server credentials created successfully (client auth required)."
                )
            else:
                logger.debug(
                    "🛎️🔐✅ Server-only TLS credentials created successfully (client auth not required)."
                )
            return creds
        except Exception as e:
            logger.error(
                f"🛎️🔐❌ Failed to create grpc.ssl_server_credentials: {e}",
                extra={"trace": traceback.format_exc()},
            )
            raise SecurityError(
                f"Failed to create gRPC SSL server credentials: {e}"
            ) from e

    async def stop(self) -> None:
        """
        Stop the server gracefully, cleaning up all resources.

        This method performs a complete shutdown sequence:
        1. Cancels any pending tasks
        2. Stops the gRPC server with a grace period
        3. Closes the transport
        4. Completes the serving future to signal shutdown

        The method is designed to be idempotent and can be called multiple times safely.
        """
        logger.debug(
            f"‼️ RPCPluginServer.stop() CALLED. Current _serving_future done: {self._serving_future.done() if hasattr(self, '_serving_future') else 'N/A'}"
        )

        if (
            hasattr(self, "_serving_future")
            and self._serving_future
            and not self._serving_future.done()
        ):
            self._serving_future.set_result(None)
            logger.debug("🛎️ Serving future resolved at the beginning of stop().")
        self._shutdown_event.set()

        # Cancel any pending tasks first
        # Consider if this task cancellation is still needed or if it should be more targeted.
        # For now, keeping it as it might relate to other plugin activities.
        all_tasks = [
            task
            for task in asyncio.all_tasks()
            if task is not asyncio.current_task()
            and not task.done()
            and hasattr(task, "get_name")
            and task.get_name().startswith("RPCPlugin")
        ]

        if all_tasks:
            logger.debug(f"Cancelling {len(all_tasks)} plugin-related tasks...")
            for task in all_tasks:
                task.cancel()
            try:
                await asyncio.wait_for(
                    asyncio.gather(*all_tasks, return_exceptions=True), timeout=2.0
                )
                logger.debug("Plugin-related tasks cancelled.")
            except asyncio.TimeoutError:
                logger.warning(
                    "🛎️ Timed out waiting for plugin-related tasks to cancel."
                )
            except asyncio.CancelledError:
                logger.warning("🛎️ Task cancellation gather itself was cancelled.")

        # Stop gRPC server with timeout
        if self._server:
            try:
                await asyncio.wait_for(self._server.stop(grace=0.5), timeout=1.5)
                logger.debug("🛎️ gRPC server stopped successfully.")
            except asyncio.TimeoutError:
                logger.error("🛎️❌ Timeout stopping gRPC server.")
            except Exception as e:
                logger.error(f"🛎️❌ Error stopping gRPC server: {e}")
            finally:
                self._server = None

        # Close transport with timeout
        if self._transport:
            try:
                await asyncio.wait_for(self._transport.close(), timeout=1.0)
                logger.debug("🛎️ Transport closed successfully.")
            except asyncio.TimeoutError:
                logger.error("🛎️❌ Timeout closing transport.")
            except Exception as e:
                logger.error(f"🛎️❌ Error closing transport: {e}")
            finally:
                self._transport = None

        logger.debug("🛎️ Server shutdown sequence in stop() complete.")

    async def _setup_server(self, client_cert: str | None) -> None:
        """
        Sets up the gRPC server instance and registers the provider service.

        This method:
        1. Creates a gRPC server with optimized options
        2. Registers the protocol service and handler
        3. Configures TLS if needed
        4. Binds to the transport endpoint
        5. Starts the server

        Args:
            client_cert: Client certificate for mTLS, or None for insecure mode

        Raises:
            RuntimeError: If protocol service registration fails
            TransportError: If server setup or binding fails
        """
        logger.debug("🛎️ Setting up gRPC server instance...")
        try:
            # Ensure ServerT is compatible with grpc.aio.Server or use cast
            # For now, assuming ServerT is bound correctly or compatible.
            # If server.py:378 (self._server = GRPCServer(...)) error persists, a cast might be needed:
            # from typing import cast
            # self._server = cast(ServerT, GRPCServer(...))
            temp_server = GRPCServer(  # Assign to temp var first
                options=[
                    ("grpc.ssl_target_name_override", "localhost"),
                    ("grpc.use_local_subchannel_pool", 1),
                    ("grpc.max_receive_message_length", 16 * 1024 * 1024),
                    ("grpc.max_send_message_length", 16 * 1024 * 1024),
                    ("grpc.keepalive_time_ms", 10000),
                    ("grpc.keepalive_timeout_ms", 5000),
                    ("grpc.keepalive_permit_without_calls", True),
                    ("grpc.http2.max_pings_without_data", 0),
                    ("grpc.http2.min_time_between_pings_ms", 10000),
                    ("grpc.http2.min_ping_interval_without_data_ms", 5000),
                ]
            )
            self._server = cast(
                ServerT, temp_server
            )  # Assign to self._server if successful, with cast
            logger.debug("🛎️ gRPC server instance created.")
        except Exception as e:
            logger.error(
                f"🛎️❌ gRPC server instance creation failed: {e}",  # Corrected logging
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise TransportError(
                message=f"Failed to create gRPC server instance: {e}",
                hint="This may indicate an issue with the gRPC library or system resources.",
            ) from e

        try:
            logger.debug("🛎️ Registering protocol service to gRPC server...")
            # If protocol is callable, instantiate it.
            proto = self.protocol() if callable(self.protocol) else self.protocol
            if not hasattr(proto, "add_to_server"):
                raise AttributeError("Protocol instance lacks 'add_to_server'")

            await proto.add_to_server(handler=self.handler, server=self._server)

            register_protocol_service(
                server=self._server, shutdown_event=self._shutdown_event
            )

            self.protocol = proto
            logger.debug("🛎️ Protocol service registered successfully.")
        except Exception as e:
            logger.error(
                f"🛎️❌ Failed to register protocol service with handler {self.handler.__class__.__name__} for protocol {self.protocol.__class__.__name__}: {e}",
                extra={
                    "error": str(e),
                    "trace": traceback.format_exc(),
                },  # Corrected logging
            )
            if isinstance(e, AttributeError):
                raise RuntimeError(
                    f"Protocol service registration failed due to AttributeError: {e}. Ensure protocol has 'add_to_server'."
                ) from e
            raise ProtocolError(
                message=f"Failed to register protocol service: {e}",
                hint="Ensure the protocol and handler are correctly implemented and compatible.",
            ) from e

        try:
            # Determine if secure credentials are required
            creds = None
            if rpcplugin_config.auto_mtls_enabled() or rpcplugin_config.get(
                "PLUGIN_SERVER_CERT"
            ):
                logger.debug(
                    "🛎️🔐 Secure mode (mTLS or TLS) enabled – configuring TLS credentials."
                )
                creds = (
                    self._generate_server_credentials()
                )  # No longer takes client_cert argument
            else:
                logger.debug("🛎️🔐 Insecure mode – no TLS credentials used.")
        except (
            SecurityError
        ):  # Let SecurityErrors from _generate_server_credentials propagate
            raise
        except (
            Exception
        ) as e:  # Catch other unexpected errors during credential decision/call
            logger.error(
                f"🛎️❌ Error during mTLS configuration or credential generation: {e}",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise SecurityError(
                message=f"Failed to configure TLS/mTLS credentials: {e}",
                hint="This could be due to issues with certificate loading, generation, or gRPC credential setup.",
            ) from e

        try:
            bind_address = (
                rpcplugin_config.get("PLUGIN_SERVER_ENDPOINT")
                or "127.0.0.1:0"  # Default for TCP if not specified
            )

            match self._transport:
                case UnixSocketTransport():
                    logger.debug(
                        "🛎️ Using Unix socket transport; listening on socket..."
                    )
                    logger.info(
                        f"🛎️ RPCPluginServer: About to call listen() on transport: {self._transport}"
                    )
                    await self._transport.listen()  # type: ignore[union-attr] # self._transport cannot be None here
                    logger.info(
                        f"🛎️ RPCPluginServer: Transport listen() called. Transport endpoint: {getattr(self._transport, 'endpoint', 'N/A')}, Transport host: {getattr(self._transport, 'host', 'N/A')}, Transport port: {getattr(self._transport, 'port', 'N/A')}"
                    )

                    transport_path = self._transport.path  # type: ignore[union-attr]
                    if transport_path is None:
                        raise TransportError(
                            "Unix transport path is None after listen."
                        )
                    socket_path = f"unix:{transport_path}"

                    if self._server is not None:  # Check _server is not None
                        port_returned = (  # gRPC returns 0 for unix sockets if successful, or port number for TCP
                            self._server.add_secure_port(socket_path, creds)
                            if creds
                            else self._server.add_insecure_port(socket_path)
                        )
                        logger.debug(
                            f"🛎️ Bound to Unix socket at {socket_path}. gRPC port returned: {port_returned}"
                        )
                    else:
                        raise TransportError(
                            "Server object not initialized before adding port."
                        )
                    # self._port remains None for Unix, as port is not applicable in the same way.

                case TCPSocketTransport():
                    # Use bind_address from config if it's specifically for TCP, otherwise transport's own
                    if bind_address.startswith("tcp:"):
                        logger.debug(f"🛎️ TCP address from config: {bind_address}")
                        # Potentially parse host/port from bind_address to set on transport if needed
                        # For now, assume transport's host/port are primary if already set,
                        # or that listen() will use a default or configured host/port.
                        pass  # self._transport.listen() below will handle it.

                    logger.info(
                        f"🛎️ RPCPluginServer: About to call listen() on transport: {self._transport}"
                    )
                    await self._transport.listen()  # type: ignore[union-attr] # self._transport cannot be None here
                    logger.info(
                        f"🛎️ RPCPluginServer: Transport listen() called. Transport endpoint: {getattr(self._transport, 'endpoint', 'N/A')}, Transport host: {getattr(self._transport, 'host', 'N/A')}, Transport port: {getattr(self._transport, 'port', 'N/A')}"
                    )

                    # Ensure host and port are not None before forming address
                    transport_host = self._transport.host  # type: ignore[union-attr]
                    transport_port = self._transport.port  # type: ignore[union-attr]
                    if transport_host is None or transport_port is None:
                        raise TransportError(
                            "TCP transport host or port is None after listen."
                        )
                    actual_bind_address = f"{transport_host}:{transport_port}"

                    logger.debug(
                        f"🛎️ Binding gRPC server to actual_bind_address: {actual_bind_address}"
                    )

                    if self._server is not None:  # Check _server is not None
                        returned_port = (
                            self._server.add_secure_port(actual_bind_address, creds)
                            if creds
                            else self._server.add_insecure_port(actual_bind_address)
                        )
                        if (
                            returned_port == 0 and actual_bind_address != "0.0.0.0:0"
                        ):  # 0 means bind failed unless we asked for any port
                            raise TransportError(
                                f"gRPC server failed to bind to TCP port: {actual_bind_address}. Returned port 0."
                            )
                        self._port = returned_port  # This is the gRPC chosen port
                    else:
                        raise TransportError(
                            "Server object not initialized before adding port."
                        )
                    logger.info(
                        f"🛎️ RPCPluginServer: Server _port (from grpc) set to {self._port}"
                    )

                    # Ensure the transport's port and endpoint are updated to the actual bound port by gRPC.
                    current_transport_port = self._transport.port  # type: ignore[union-attr]
                    if (
                        current_transport_port != self._port and self._port != 0
                    ):  # Port 0 might mean wildcard, gRPC picks one
                        logger.info(
                            f"🛎️ RPCPluginServer: Updating transport port from {current_transport_port} to gRPC bound port {self._port}"
                        )
                        self._transport.port = self._port  # type: ignore[union-attr]

                    current_transport_host = self._transport.host  # type: ignore[union-attr]
                    current_transport_port_after_update = self._transport.port  # type: ignore[union-attr]

                    if (
                        current_transport_host
                        and current_transport_port_after_update is not None
                    ):
                        self._transport.endpoint = f"{current_transport_host}:{current_transport_port_after_update}"  # type: ignore[union-attr]
                    else:  # Should ideally not happen if listen() and gRPC bind are successful
                        self._transport.endpoint = actual_bind_address  # type: ignore[union-attr] # Fallback

                    logger.debug(
                        f"🛎️ Transport details post-update: host={self._transport.host}, port={self._transport.port}, endpoint attribute: {self._transport.endpoint}"
                    )  # type: ignore[union-attr]

                case _:  # Should be caught by earlier transport negotiation, but as a safeguard
                    raise TransportError(
                        f"Unsupported transport instance type: {type(self._transport)}"
                    )

            if self._server is not None:  # Check _server is not None
                await self._server.start()
                logger.debug("🛎️ gRPC server started successfully.")
            else:
                raise TransportError("Server object not initialized before start.")
        except Exception as e:
            logger.error(
                f"🛎️❌ gRPC server failed to start on configured transport: {e}",  # Corrected logging
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise TransportError(
                message=f"gRPC server failed to start: {e}",
                hint="Check logs for details on binding or server start issues. Ensure the address is not already in use.",
            ) from e

        try:
            if isinstance(self._transport, UnixSocketTransport):
                transport_path = self._transport.path
                if transport_path is None:
                    raise TransportError("Unix transport path is None for post-check.")
                if not os.path.exists(transport_path):
                    error_msg = f"Socket file {transport_path} not created."
                    logger.error("🛎️❌ " + error_msg)
                    raise TransportError(error_msg)
                mode = os.stat(transport_path).st_mode
                # Check for owner RWX and group RWX. Corresponds to 0o770 (ignoring 'others').
                # The transport class now sets permissions to 0o770 (respecting umask).
                if not ((mode & stat.S_IRWXU) and (mode & stat.S_IRWXG)):
                    error_msg = (
                        f"Socket file {transport_path} has incorrect permissions. "
                        f"Expected owner and group RWX (e.g., 0o770). Got: {oct(mode & 0o777)}"
                    )
                    logger.error("🛎️❌ " + error_msg)
                    raise TransportError(error_msg)
                logger.debug(
                    f"🛎️ Verified Unix socket file permissions at {transport_path}."
                )
        except Exception as e:
            logger.error(
                f"🛎️❌ Server setup post-check (e.g. socket permissions) failed: {e}",  # Corrected logging
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            if isinstance(e, TransportError):
                raise
            raise TransportError(
                message=f"Server setup post-verification failed: {e}",
                hint="This often relates to file system permissions for Unix sockets or other post-start checks.",
            ) from e

    async def _negotiate_handshake(self) -> bool | None:
        """
        Negotiate the handshake parameters with the client.

        This method:
        1. Validates the magic cookie for authentication
        2. Negotiates the protocol version
        3. Selects and initializes the appropriate transport

        Returns:
            True if handshake negotiation succeeds

        Raises:
            HandshakeError: If handshake negotiation fails
            TransportError: If transport negotiation fails
        """
        logger.debug("🤝 Starting handshake negotiation...")
        try:
            validate_magic_cookie()

            logger.debug("🤝 Magic cookie validated.")
            self._protocol_version = negotiate_protocol_version(
                self._handshake_config.protocol_versions
            )
            logger.info(f"🤝 Selected protocol version: {self._protocol_version}")

            if self.transport:
                if isinstance(self.transport, tuple) and len(self.transport) >= 2:
                    self._transport_name, self._transport = (
                        self.transport[0],
                        self.transport[1],
                    )
                    logger.debug("🤝 Transport tuple provided; unpacked transport.")
                else:
                    logger.debug("🤝 Using provided transport instance.")
                    self._transport = self.transport
                    self._transport_name = (
                        "tcp"
                        if isinstance(self.transport, TCPSocketTransport)
                        else "unix"
                    )
            else:
                logger.debug("🤝 Negotiating transport from configuration...")
                supported_transports = self._handshake_config.supported_transports
                if callable(supported_transports):
                    supported_transports = supported_transports()
                self._transport_name, self._transport = await negotiate_transport(
                    supported_transports
                )
            logger.debug(
                f"🤝 Handshake negotiation completed; transport selected: {self._transport_name}."
            )

            return True
        except Exception as e:
            logger.error(
                "🤝❌ Handshake negotiation failed",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise HandshakeError(f"Handshake negotiation failed: {e}") from e

    def _register_signal_handlers(self) -> None:
        """
        Register signal handlers for graceful shutdown.

        This method sets up handlers for SIGINT and SIGTERM to trigger
        graceful shutdown when the process receives these signals.
        """
        logger.debug("🛎️ Registering signal handlers for graceful shutdown...")
        try:
            loop = asyncio.get_event_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, self._shutdown_requested)
                    logger.debug(f"🛎️ Signal handler registered for {sig.name}.")
                except NotImplementedError:
                    logger.warning(
                        f"🛎️ Signal handler for {sig.name} not supported on this platform."
                    )
        except Exception as e:
            logger.exception(
                "Error registering signal handlers",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )

    def _shutdown_requested(self, *args) -> None:
        """
        Handle a shutdown request, either from a signal or explicit call.

        This method:
        1. Initiates a graceful shutdown sequence
        2. Resolves the serving future to signal completion

        Args:
            *args: Optional arguments passed by signal handlers (ignored)
        """
        logger.info(
            f"‼️ RPCPluginServer._shutdown_requested() CALLED. Args: {args}. Current _serving_future done: {self._serving_future.done() if hasattr(self, '_serving_future') else 'N/A'}"
        )
        if (
            hasattr(self, "_serving_future")
            and self._serving_future
            and not self._serving_future.done()
        ):
            self._serving_future.set_result(None)
            logger.debug("🛎️ Serving future resolved by _shutdown_requested.")
        self._shutdown_event.set()

    async def serve(self) -> None:
        """
        Main entry point for starting the server.

        This method:
        1. Sets up signal handlers
        2. Negotiates handshake parameters
        3. Sets up the server with the chosen transport
        4. Sends the handshake response to stdout
        5. Runs until shutdown is requested
        6. Performs graceful shutdown

        This is a blocking method that runs until the server is shut down.

        Raises:
            Any exception that occurs during setup or serving
        """
        logger.debug(
            f"🛎️ Entering serve(); initial _serving_future (ID: {id(self._serving_future)}) done state: {self._serving_future.done()}"
        )
        try:
            self._register_signal_handlers()
            await self._negotiate_handshake()
            client_cert = self._read_client_cert()
            await self._setup_server(client_cert)
        except (
            ConfigError,
            HandshakeError,
            TransportError,
            SecurityError,
            ProtocolError,
        ) as e:
            logger.error(
                f"🛎️❌ Serve() failed during setup phase due to {e.__class__.__name__}: {e.message}",
                extra={
                    "error": str(e),
                    "trace": traceback.format_exc(),
                    "hint": e.hint,
                    "code": e.code,
                },
            )
            raise
        except Exception as e:
            logger.error(
                f"🛎️❌ Serve() failed during setup with an unexpected error: {e}",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise ConfigError(
                message=f"An unexpected error occurred during server setup: {e}",
                hint="Review server logs for detailed diagnostics. This might involve issues with configuration, system resources, or permissions.",
            ) from e

        try:
            if self._transport is None:
                raise HandshakeError(
                    "Transport not initialized before building handshake response."
                )
            response = await build_handshake_response(
                plugin_version=self._protocol_version,
                transport_name=self._transport_name,
                transport=self._transport,  # Now checked not to be None
                server_cert=self._server_cert_obj,
                port=self._port,
            )
            logger.debug(f"🤝📝 Handshake response built: {response}")

            # Write directly to stdout in the most unambiguous way
            response_with_newline = response + "\n"
            response_bytes = response_with_newline.encode("utf-8")

            # Try both methods to maximize compatibility
            sys.stdout.buffer.write(response_bytes)
            sys.stdout.buffer.flush()
            sys.stdout.flush()

            logger.debug("🤝📝✅ Handshake response sent to stdout")
        except Exception as e:
            logger.error(
                f"🛎️❌ Error building or sending handshake response: {e}",  # Corrected logging
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise HandshakeError(
                message=f"Failed to build or send handshake response: {e}",
                hint="Ensure transport is correctly initialized and stdout is accessible for writing.",
            ) from e

        try:
            self._serving_event.set()
            logger.debug(
                f"🛎️ Server running; _serving_future created at {id(self._serving_future)}, done={self._serving_future.done()}. Awaiting shutdown signal..."
            )
            await self._serving_future
            logger.debug(
                f"🛎️ Server _serving_future completed. Done state: {self._serving_future.done()}"
            )
        except asyncio.CancelledError:
            logger.info("🛎️ Serve task explicitly cancelled.")
            raise
        except Exception as e:
            logger.error(
                f"🛎️❌ Serve() encountered an unexpected error during main execution loop: {e}",  # Corrected logging
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise TransportError(
                message=f"An unexpected error occurred while server was running: {e}",
                hint="Check server logs for details. This could be a gRPC internal error, resource issue, or unhandled exception in a service implementation.",
            ) from e
        finally:
            logger.debug("🛎️ Exiting serve(); initiating shutdown...")
            try:
                await self.stop()
            except Exception as stop_e:
                logger.error(
                    "🛎️❌ Error during stop()",
                    extra={"error": str(stop_e), "trace": traceback.format_exc()},
                )
            logger.debug("🛎️ Shutdown complete; exiting process.")

    def __del__(self) -> None:
        # Check if the server was properly shut down via explicit stop()
        # The _serving_future is resolved by stop() or _shutdown_requested()
        serving_future_exists = (
            hasattr(self, "_serving_future") and self._serving_future
        )
        server_was_shutdown = serving_future_exists and self._serving_future.done()

        if not server_was_shutdown:
            # Determine a representative endpoint for logging, if possible
            endpoint_info = "unknown endpoint"
            if (
                hasattr(self, "_transport")
                and self._transport
                and hasattr(self._transport, "endpoint")
                and self._transport.endpoint
            ):
                endpoint_info = self._transport.endpoint
            elif (
                hasattr(self, "_port") and self._port is not None
            ):  # For TCP if endpoint wasn't formed on transport
                endpoint_info = f"port {self._port}"

            logger.warning(
                f"RPCPluginServer for {endpoint_info} was not explicitly stopped before garbage collection. "
                f"Ensure stop() is called to properly release resources."
            )

        # It's generally unsafe to call async methods or methods that might rely on a
        # running event loop from __del__. Explicit cleanup via stop() is essential.
        # The original attempt to call self._server.close() is also risky here
        # as grpc.aio.Server's own __del__ might handle some synchronous cleanup,
        # but complex operations should be in stop().


# 🐍🏗️🔌
