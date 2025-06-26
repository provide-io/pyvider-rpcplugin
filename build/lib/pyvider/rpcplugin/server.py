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
import sys # Single import
import traceback
from abc import ABC
from typing import Generic, cast # Added cast

from attrs import define, field
import grpc
from grpc.aio import server as GRPCServer

from pyvider.rpcplugin.client.types import ClientT
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.crypto.certificate import Certificate
from pyvider.rpcplugin.exception import HandshakeError, TransportError
from pyvider.rpcplugin.handshake import (
    HandshakeConfig,
    build_handshake_response,
    negotiate_protocol_version,
    negotiate_transport,
    validate_magic_cookie,
)
from pyvider.telemetry import logger
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
# ClientT is already imported from pyvider.rpcplugin.client.types


@define(slots=False)
class RPCPluginServer(ABC, Generic[ServerT, HandlerT, TransportT, ProtocolT, ClientT]): # Added ClientT
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
    config: ClientT | None = field(default=None)
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
    _serving_future: asyncio.Future = field(init=False, factory=asyncio.Future)
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
                "🛎️⚙️❌ Failed to initialize handshake configuration",
                extra={"error": str(e)},
            )
            raise
        # Ensure each instance has a truly unique future.
        self._serving_future = asyncio.Future()
        logger.debug(f"🛎️⚙️ RPCPluginServer instance initialized. New _serving_future created (ID: {id(self._serving_future)}).")

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
        logger.info(f"🛎️⏳ RPCPluginServer.wait_for_server_ready: Checking readiness. Transport: {self.transport}, Server Port: {self._port}")
        try:
            logger.debug("🛎️⏳ Waiting for server ready event...")

            # First wait for the internal event to be set
            await asyncio.wait_for(self._serving_event.wait(), timeout)
            logger.debug("🛎️✅ Server ready event received.")

            # Additional verification: ensure transport endpoint is active and connectable
            if self.transport and hasattr(self.transport, 'endpoint') and self.transport.endpoint and isinstance(self.transport, (UnixSocketTransport, TCPSocketTransport)): # Added isinstance check
                match self.transport:
                    case UnixSocketTransport():
                        # For Unix sockets, check file exists and is connectable
                        transport_path = self.transport.path
                        if transport_path is None:
                            logger.error("🛎️❌ Unix socket transport path is None.")
                            raise TimeoutError("Unix socket path not set for readiness check.")
                        if not os.path.exists(transport_path):
                            logger.error(f"🛎️❌ Unix socket file {transport_path} doesn't exist")
                            raise TimeoutError("Unix socket file not created")

                        # Try to connect to verify socket is active
                        try:
                            logger.info(f"🛎️🔍 RPCPluginServer.wait_for_server_ready (Unix): path={transport_path}")
                            logger.debug(f"🛎️🔍 Testing Unix socket connection to {transport_path}")
                            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                            sock.settimeout(1.0)
                            sock.connect(transport_path)
                            sock.close()
                            logger.debug("🛎️✅ Unix socket connection test successful")
                        except Exception as e:
                            logger.error(f"🛎️❌ Unix socket connection test failed: {e!s}")
                            raise TimeoutError(f"Unix socket not connectable: {e!s}")

                    case TCPSocketTransport():
                        # For TCP, verify endpoint is reachable
                        # Use self._port (actual bound port) and self.transport.host
                        actual_server_host = self.transport.host if self.transport.host else "127.0.0.1"
                        actual_server_port = self._port
                        if actual_server_port is None:
                            logger.error("🛎️❌ TCP port not set after server start.")
                            raise TimeoutError("TCP port not available for readiness check")

                        logger.info(f"🛎️🔍 RPCPluginServer.wait_for_server_ready (TCP): actual_server_host={actual_server_host}, actual_server_port={actual_server_port}, transport_host={getattr(self.transport, 'host', 'N/A')}")
                        logger.debug(f"🛎️🔍 Testing TCP connection to {actual_server_host}:{actual_server_port}")
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(1.0)
                            sock.connect((actual_server_host, actual_server_port))
                            sock.close()
                            logger.debug("🛎️✅ TCP connection test successful")
                        except Exception as e:
                            logger.error(f"🛎️❌ TCP connection test failed: {e!s}")
                            raise TimeoutError(f"TCP socket not connectable: {e!s}")
        except asyncio.TimeoutError:
            logger.error(
                "🛎️❌ Server did not become ready within timeout.",
                extra={"timeout": timeout},
            )
            raise TimeoutError("Server failed to become ready")
        except Exception as e:
            logger.error(f"🛎️❌ Error during server readiness check: {e!s}")
            raise TimeoutError(f"Server readiness check failed: {e!s}")

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
                logger.debug("🛎️🔐⚠️ No client certificate provided; operating insecurely.")
                return None

            return client_cert
        except Exception as e:
            logger.error(f"🛎️🔐❌ Error reading client certificate: {e}")
            return None

    def _generate_server_credentials(
        self, client_cert: str | None
    ) -> grpc.ServerCredentials | None:
        """
        Generates gRPC server TLS credentials using the Certificate API.

        This method creates the necessary TLS credentials for secure communication:
        1. Loads or generates a server certificate
        2. Creates gRPC server credentials with the certificate
        3. Optionally configures mutual TLS (mTLS) with client verification

        Args:
            client_cert: The client certificate for mTLS validation, or None for regular TLS

        Returns:
            gRPC server credentials object, or None for insecure operation

        Raises:
            Exception: If credential generation fails
        """
        logger.debug("🛎️ Generating server credentials using Certificate API.")
        try:
            if not client_cert:
                logger.debug("🛎️ Insecure mode: skipping TLS setup.")
                return None

            server_cert_conf = rpcplugin_config.get("PLUGIN_SERVER_CERT")
            server_key_conf = rpcplugin_config.get("PLUGIN_SERVER_KEY")
            self._server_cert_obj = Certificate(

                # Use new keyword names:
                cert_pem_or_uri=server_cert_conf,
                key_pem_or_uri=server_key_conf,
                # Other args remain the same if their names match fields:
                generate_keypair=not (server_cert_conf and server_key_conf),
                key_type="ecdsa", # Or get from config if applicable
                common_name="localhost",
            )
            logger.debug("🛎️ Server certificate loaded/generated successfully.")

            # Ensure key is not None before encoding
            if self._server_cert_obj.key is None:
                raise ValueError("Server certificate private key is None, cannot create credentials.")

            key_bytes = self._server_cert_obj.key.encode()
            # cert is always a string (non-optional field in Certificate)
            cert_bytes = self._server_cert_obj.cert.encode()
            # client_cert is already checked for None before calling this function

            creds = grpc.ssl_server_credentials(
                private_key_certificate_chain_pairs=[(key_bytes, cert_bytes)], # Now key_bytes is definitely bytes
                root_certificates=None,       # Temporarily disable client cert verification
                require_client_auth=False     # Temporarily disable client cert requirement
            )
            logger.debug("🛎️ Server TLS credentials created for server-side TLS only (no mTLS).")
            return creds
        except Exception as e:
            logger.error(
                "🛎️❌ Error generating server credentials", extra={"error": str(e)}
            )
            raise

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
        logger.debug(f"‼️ RPCPluginServer.stop() CALLED. Current _serving_future done: {self._serving_future.done() if hasattr(self, '_serving_future') else 'N/A'}")

        if hasattr(self, '_serving_future') and self._serving_future and not self._serving_future.done():
            self._serving_future.set_result(None)
            logger.debug("🛎️ Serving future resolved at the beginning of stop().")
        self._shutdown_event.set()

        # Cancel any pending tasks first
        # Consider if this task cancellation is still needed or if it should be more targeted.
        # For now, keeping it as it might relate to other plugin activities.
        all_tasks = [task for task in asyncio.all_tasks()
                    if task is not asyncio.current_task() and
                       not task.done() and
                        hasattr(task, 'get_name') and task.get_name().startswith('RPCPlugin')]

        if all_tasks:
            logger.debug(f"Cancelling {len(all_tasks)} plugin-related tasks...")
            for task in all_tasks:
                task.cancel()
            try:
                await asyncio.wait_for(asyncio.gather(*all_tasks, return_exceptions=True), timeout=2.0)
                logger.debug("Plugin-related tasks cancelled.")
            except asyncio.TimeoutError:
                logger.warning("🛎️ Timed out waiting for plugin-related tasks to cancel.")
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
        if self.transport:
            try:
                await asyncio.wait_for(self.transport.close(), timeout=1.0)
                logger.debug("🛎️ Transport closed successfully.")
            except asyncio.TimeoutError:
                logger.error("🛎️❌ Timeout closing transport.")
            except Exception as e:
                logger.error(f"🛎️❌ Error closing transport: {e}")
            finally:
                self.transport = None

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
            temp_server = GRPCServer( # Assign to temp var first
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
            self._server = cast(ServerT, temp_server) # Assign to self._server if successful, with cast
            logger.debug("🛎️ gRPC server instance created.")
        except Exception as e:
            logger.error(
                "🛎️❌ gRPC server setup failed",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise

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
                "🛎️❌ Failed to register protocol service", extra={"error": str(e)}
            )
            raise RuntimeError(f"Protocol service registration failed: {e}") from e

        try:
            if client_cert:
                logger.debug("🛎️ mTLS enabled – configuring TLS credentials.")
                creds = self._generate_server_credentials(client_cert)
            else:
                creds = None
                logger.debug("🛎️ Insecure mode – no TLS credentials used.")
        except Exception as e:
            logger.error("🛎️❌ Error during mTLS configuration", extra={"error": str(e)})
            raise

        try:
            bind_address = (
                rpcplugin_config.get("PLUGIN_SERVER_ENDPOINT") or "127.0.0.1:0" # Default for TCP if not specified
            )

            match self.transport:
                case UnixSocketTransport():
                    logger.debug("🛎️ Using Unix socket transport; listening on socket...")
                    logger.info(f"🛎️ RPCPluginServer: About to call listen() on transport: {self.transport}")
                    await self.transport.listen() # type: ignore[union-attr] # self.transport cannot be None here
                    logger.info(f"🛎️ RPCPluginServer: Transport listen() called. Transport endpoint: {getattr(self.transport, 'endpoint', 'N/A')}, Transport host: {getattr(self.transport, 'host', 'N/A')}, Transport port: {getattr(self.transport, 'port', 'N/A')}")

                    transport_path = self.transport.path # type: ignore[union-attr]
                    if transport_path is None:
                        raise TransportError("Unix transport path is None after listen.")
                    socket_path = f"unix:{transport_path}"

                    if self._server is not None: # Check _server is not None
                        port_returned = ( # gRPC returns 0 for unix sockets if successful, or port number for TCP
                            self._server.add_secure_port(socket_path, creds)
                            if creds
                            else self._server.add_insecure_port(socket_path)
                        )
                        logger.debug(f"🛎️ Bound to Unix socket at {socket_path}. gRPC port returned: {port_returned}")
                    else:
                        raise TransportError("Server object not initialized before adding port.")
                    # self._port remains None for Unix, as port is not applicable in the same way.

                case TCPSocketTransport():
                    # Use bind_address from config if it's specifically for TCP, otherwise transport's own
                    if bind_address.startswith("tcp:"):
                        logger.debug(f"🛎️ TCP address from config: {bind_address}")
                        # Potentially parse host/port from bind_address to set on transport if needed
                        # For now, assume transport's host/port are primary if already set,
                        # or that listen() will use a default or configured host/port.
                        pass # self.transport.listen() below will handle it.

                    logger.info(f"🛎️ RPCPluginServer: About to call listen() on transport: {self.transport}")
                    await self.transport.listen() # type: ignore[union-attr] # self.transport cannot be None here
                    logger.info(f"🛎️ RPCPluginServer: Transport listen() called. Transport endpoint: {getattr(self.transport, 'endpoint', 'N/A')}, Transport host: {getattr(self.transport, 'host', 'N/A')}, Transport port: {getattr(self.transport, 'port', 'N/A')}")

                    # Ensure host and port are not None before forming address
                    transport_host = self.transport.host # type: ignore[union-attr]
                    transport_port = self.transport.port # type: ignore[union-attr]
                    if transport_host is None or transport_port is None:
                        raise TransportError("TCP transport host or port is None after listen.")
                    actual_bind_address = f"{transport_host}:{transport_port}"

                    logger.debug(f"🛎️ Binding gRPC server to actual_bind_address: {actual_bind_address}")

                    if self._server is not None: # Check _server is not None
                        returned_port = (
                            self._server.add_secure_port(actual_bind_address, creds)
                            if creds
                            else self._server.add_insecure_port(actual_bind_address)
                        )
                        if returned_port == 0 and actual_bind_address != "0.0.0.0:0": # 0 means bind failed unless we asked for any port
                             raise TransportError(f"gRPC server failed to bind to TCP port: {actual_bind_address}. Returned port 0.")
                        self._port = returned_port # This is the gRPC chosen port
                    else:
                        raise TransportError("Server object not initialized before adding port.")
                    logger.info(f"🛎️ RPCPluginServer: Server _port (from grpc) set to {self._port}")

                    # Ensure the transport's port and endpoint are updated to the actual bound port by gRPC.
                    current_transport_port = self.transport.port # type: ignore[union-attr]
                    if current_transport_port != self._port and self._port != 0: # Port 0 might mean wildcard, gRPC picks one
                        logger.info(f"🛎️ RPCPluginServer: Updating transport port from {current_transport_port} to gRPC bound port {self._port}")
                        self.transport.port = self._port # type: ignore[union-attr]

                    current_transport_host = self.transport.host # type: ignore[union-attr]
                    current_transport_port_after_update = self.transport.port # type: ignore[union-attr]

                    if current_transport_host and current_transport_port_after_update is not None:
                        self.transport.endpoint = f"{current_transport_host}:{current_transport_port_after_update}" # type: ignore[union-attr]
                    else: # Should ideally not happen if listen() and gRPC bind are successful
                        self.transport.endpoint = actual_bind_address # type: ignore[union-attr] # Fallback

                    logger.debug(f"🛎️ Transport details post-update: host={self.transport.host}, port={self.transport.port}, endpoint attribute: {self.transport.endpoint}") # type: ignore[union-attr]

                case _: # Should be caught by earlier transport negotiation, but as a safeguard
                    raise TransportError(f"Unsupported transport instance type: {type(self.transport)}")

            if self._server is not None: # Check _server is not None
                await self._server.start()
                logger.debug("🛎️ gRPC server started successfully.")
            else:
                raise TransportError("Server object not initialized before start.")
        except Exception as e:
            logger.error(
                "🛎️❌ gRPC server failed to start",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise

        try:
            if isinstance(self.transport, UnixSocketTransport):
                transport_path = self.transport.path
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
                "🛎️❌ Server setup post-check failed",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise

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
                    self.transport_name, self.transport = self.transport[0], self.transport[1]
                    logger.debug("🤝 Transport tuple provided; unpacked transport.")
                else:
                    logger.debug("🤝 Using provided transport instance.")
                    self.transport = self.transport
                    self.transport_name = (
                        "tcp"
                        if isinstance(self.transport, TCPSocketTransport)
                        else "unix"
                    )
            else:
                logger.debug("🤝 Negotiating transport from configuration...")
                supported_transports = self._handshake_config.supported_transports
                if callable(supported_transports):
                    supported_transports = supported_transports()
                self.transport_name, self.transport = await negotiate_transport(
                    supported_transports
                )
            logger.debug(
                f"🤝 Handshake negotiation completed; transport selected: {self.transport_name}."
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
        logger.info(f"‼️ RPCPluginServer._shutdown_requested() CALLED. Args: {args}. Current _serving_future done: {self._serving_future.done() if hasattr(self, '_serving_future') else 'N/A'}")
        if hasattr(self, '_serving_future') and self._serving_future and not self._serving_future.done():
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
        logger.debug(f"🛎️ Entering serve(); initial _serving_future (ID: {id(self._serving_future)}) done state: {self._serving_future.done()}")
        try:
            self._register_signal_handlers()
            await self._negotiate_handshake()
            client_cert = self._read_client_cert()
            await self._setup_server(client_cert)
        except Exception as e:
            logger.error(
                "🛎️❌ Serve() failed during setup",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise

        try:
            if self.transport is None:
                raise HandshakeError("Transport not initialized before building handshake response.")
            response = await build_handshake_response(
                plugin_version=self._protocol_version,
                transport_name=self.transport_name,
                transport=self.transport, # Now checked not to be None
                server_cert=self._server_cert_obj,
                port=self._port,
            )
            logger.debug(f"🤝📝 Handshake response built: {response}")

            # Write directly to stdout in the most unambiguous way
            response_with_newline = response + "\n"
            response_bytes = response_with_newline.encode('utf-8')

            # Try both methods to maximize compatibility
            sys.stdout.buffer.write(response_bytes)
            sys.stdout.buffer.flush()
            sys.stdout.flush()

            logger.debug("🤝📝✅ Handshake response sent to stdout")
        except Exception as e:
            logger.error(f"🛎️❌ Error building handshake response: {e}",
                        extra={"error": str(e), "trace": traceback.format_exc()})
            raise

        try:
            self._serving_event.set()
            logger.debug(f"🛎️ Server running; _serving_future created at {id(self._serving_future)}, done={self._serving_future.done()}. Awaiting shutdown signal...")
            await self._serving_future
            logger.debug(f"🛎️ Server _serving_future completed. Done state: {self._serving_future.done()}")
        except asyncio.CancelledError:
            logger.info("🛎️ Serve task explicitly cancelled.")
            raise
        except Exception as e:
            logger.error(
                "🛎️❌ Serve() encountered an error during run",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise
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
        serving_future_exists = hasattr(self, '_serving_future') and self._serving_future
        server_was_shutdown = serving_future_exists and self._serving_future.done()

        if not server_was_shutdown:
            # Determine a representative endpoint for logging, if possible
            endpoint_info = "unknown endpoint"
            if hasattr(self, '_transport') and self.transport and hasattr(self.transport, 'endpoint') and self.transport.endpoint:
                endpoint_info = self.transport.endpoint
            elif hasattr(self, '_port') and self._port is not None: # For TCP if endpoint wasn't formed on transport
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
