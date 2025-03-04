#!/usr/bin/env python3
# pyvider/rpcplugin/server.py

import asyncio
import os
import signal
import stat
import sys
import traceback
from abc import ABC
from typing import Generic, Optional

import attrs
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
from pyvider.rpcplugin.logger import logger
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


@attrs.define(slots=False)
class RPCPluginServer(ABC, Generic[ServerT, HandlerT, TransportT, ProtocolT]):
    """
    RPCPluginServer initializes and runs a gRPC server according to negotiated
    handshake parameters. It supports mTLS via the Certificate API and can use
    either TCP or Unix socket transports.

    This version includes:
      - Global instance access.
      - Shutdown signaling via a serving future.
      - Detailed debug logging and robust exception handling.
    """

    # Public initialization parameters.
    protocol: ProtocolT = attrs.field()
    handler: HandlerT = attrs.field()
    config: ClientT | None = attrs.field(default=None)
    transport: TransportT | None = attrs.field(default=None)

    _exit_on_stop: bool = attrs.field(default=True, init=False)

    # Internal attributes.
    _transport: TransportT | None = attrs.field(init=False, default=None)
    _server: ServerT | None = attrs.field(init=False, default=None)
    _handshake_config: HandshakeConfig = attrs.field(init=False)
    _protocol_version: int = attrs.field(init=False)
    _transport_name: str = attrs.field(init=False)
    _server_cert_obj: Certificate | None = attrs.field(init=False, default=None)
    _port: int | None = attrs.field(init=False, default=None)
    _serving_future: asyncio.Future = attrs.field(init=False, factory=asyncio.Future)
    _serving_event: asyncio.Event = attrs.field(init=False, factory=asyncio.Event)
    _shutdown_event: asyncio.Event = attrs.field(init=False, factory=asyncio.Event)

    # Class-level instance for global access.
    _instance: ServerT | None = None

    def __attrs_post_init__(self):
        """
        Initializes handshake configuration and sets the global server instance.
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
        RPCPluginServer._instance = self
        logger.debug("🛎️⚙️ Global RPCPluginServer instance set.")

    async def wait_for_server_ready(self, timeout: float = 3.14) -> None:
        """Wait for server to be ready."""
        try:
            logger.debug("Waiting for server ready event...")
            await asyncio.wait_for(self._serving_event.wait(), timeout)
            logger.debug("Server ready event received.")
        except TimeoutError as e:
            logger.error(
                "Server did not become ready within timeout.",
                extra={"timeout": timeout},
            )
            raise TimeoutError("Server failed to become ready") from e

    @classmethod
    def get_instance(cls) -> Optional["RPCPluginServer"]:
        """
        Retrieve the currently running server instance.
        """
        return cls._instance

    def _read_client_cert(self) -> str | None:
        """
        Reads the client certificate from configuration with better error handling.
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
        """
        logger.debug("🛎️ Generating server credentials using Certificate API.")
        try:
            if not client_cert:
                logger.debug("🛎️ Insecure mode: skipping TLS setup.")
                return None

            server_cert_conf = rpcplugin_config.get("PLUGIN_SERVER_CERT")
            server_key_conf = rpcplugin_config.get("PLUGIN_SERVER_KEY")
            self._server_cert_obj = Certificate(
                cert=server_cert_conf,
                key=server_key_conf,
                generate_keypair=not (server_cert_conf and server_key_conf),
                key_type="ecdsa",
                common_name="localhost",
            )
            logger.debug("🛎️ Server certificate loaded/generated successfully.")

            key_bytes = self._server_cert_obj.key.encode() if isinstance(self._server_cert_obj.key, str) else self._server_cert_obj.key
            cert_bytes = self._server_cert_obj.cert.encode() if isinstance(self._server_cert_obj.cert, str) else self._server_cert_obj.cert
            client_cert_bytes = client_cert.encode() if isinstance(client_cert, str) else client_cert

            creds = grpc.ssl_server_credentials(
                private_key_certificate_chain_pairs=[(key_bytes, cert_bytes)],
                root_certificates=client_cert_bytes,
                require_client_auth=False,
            )
            # creds = grpc.ssl_server_credentials(
            #     private_key_certificate_chain_pairs=[
            #         (
            #             self._server_cert_obj.key.encode(),
            #             self._server_cert_obj.cert.encode(),
            #         )
            #     ],
            #     root_certificates=client_cert.encode(),
            #     require_client_auth=False,
            # )
            logger.debug("🛎️ Server TLS credentials created with mTLS enabled.")
            return creds
        except Exception as e:
            logger.error(
                "🛎️❌ Error generating server credentials", extra={"error": str(e)}
            )
            raise

    async def stop(self) -> None:
        logger.debug("🛎️ Stopping server...")

        # Cancel any pending tasks first
        all_tasks = [task for task in asyncio.all_tasks()
                    if task is not asyncio.current_task() and
                       not task.done() and
                       task.get_name().startswith('RPCPlugin')]

        for task in all_tasks:
            task.cancel()

        try:
            await asyncio.wait_for(asyncio.gather(*all_tasks, return_exceptions=True), timeout=2.0)
        except asyncio.TimeoutError:
            logger.warning("🛎️ Timed out waiting for tasks to cancel")

        # Stop gRPC server with timeout
        if self._server:
            try:
                await asyncio.wait_for(self._server.stop(grace=1.0), timeout=2.0)
                logger.debug("🛎️ gRPC server stopped successfully.")
            except Exception as e:
                logger.error(f"🛎️❌ Error stopping gRPC server: {e}")
            finally:
                self._server = None

        # Close transport with timeout
        if self._transport:
            try:
                await asyncio.wait_for(self._transport.close(), timeout=3.0)
                logger.debug("🛎️ Transport closed successfully.")
            except Exception as e:
                logger.error(f"🛎️❌ Error closing transport: {e}")
            finally:
                self._transport = None

        # Ensure serving future completion
        if hasattr(self, '_serving_future') and self._serving_future and not self._serving_future.done():
            self._shutdown_requested()

        logger.debug("🛎️ Server shutdown complete.")

    async def _setup_server(self, client_cert: str | None) -> None:
        """
        Sets up the gRPC server instance and registers the provider service.
        """
        logger.debug("🛎️ Setting up gRPC server instance...")
        try:
            self._server = GRPCServer(
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
                rpcplugin_config.get("PLUGIN_SERVER_ENDPOINT") or "127.0.0.1:0"
            )
            if isinstance(self._transport, UnixSocketTransport):
                logger.debug("🛎️ Using Unix socket transport; listening on socket...")
                await self._transport.listen()
                socket_path = f"unix:{self._transport.path}"
                port = (
                    self._server.add_secure_port(socket_path, creds)
                    if creds
                    else self._server.add_insecure_port(socket_path)
                )
                logger.debug(f"🛎️ Bound to Unix socket at {socket_path}.")
            else:
                if bind_address.startswith("tcp:"):
                    logger.debug(f"🛎️ TCP address before stripping: {bind_address}")
                    bind_address = bind_address[len("tcp:") :]
                logger.debug(f"🛎️ Binding to TCP address: {bind_address}")
                port = (
                    self._server.add_secure_port(bind_address, creds)
                    if creds
                    else self._server.add_insecure_port(bind_address)
                )
                self._port = port
                logger.debug(f"🛎️ Bound to TCP port: {port}.")
            await self._server.start()
            logger.debug("🛎️ gRPC server started successfully.")
        except Exception as e:
            logger.error(
                "🛎️❌ gRPC server failed to start",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise

        try:
            if isinstance(self._transport, UnixSocketTransport):
                if not os.path.exists(self._transport.path):
                    error_msg = f"Socket file {self._transport.path} not created."
                    logger.error("🛎️❌ " + error_msg)
                    raise TransportError(error_msg)
                mode = os.stat(self._transport.path).st_mode
                if not (
                    mode & stat.S_IRWXU and mode & stat.S_IRWXG and mode & stat.S_IRWXO
                ):
                    error_msg = (
                        f"Socket file {self._transport.path} has incorrect permissions."
                    )
                    logger.error("🛎️❌ " + error_msg)
                    raise TransportError(error_msg)
                logger.debug(
                    f"🛎️ Verified Unix socket file permissions at {self._transport.path}."
                )
        except Exception as e:
            logger.error(
                "🛎️❌ Server setup post-check failed",
                extra={"error": str(e), "trace": traceback.format_exc()},
            )
            raise

    async def _negotiate_handshake(self) -> bool | None:
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
                    self._transport_name, self._transport = self.transport[0], self.transport[1]
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
        logger.info("🛎️ Shutdown signal received; initiating graceful shutdown...")
        if self._server:
            asyncio.create_task(self.stop())
        if not self._serving_future.done():
            self._serving_future.set_result(None)
            logger.debug("🛎️ Serving future resolved on shutdown request.")

    async def serve(self) -> None:
        logger.debug("🛎️ Entering serve(); starting server setup...")
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
            response = await build_handshake_response(
                plugin_version=self._protocol_version,
                transport_name=self._transport_name,
                transport=self._transport,
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

            # Also try direct print for good measure
            print(response, flush=True)

            logger.debug("🤝📝✅ Handshake response sent to stdout")
        except Exception as e:
            logger.error(f"🛎️❌ Error building handshake response: {e}",
                        extra={"error": str(e), "trace": traceback.format_exc()})
            raise

        try:
            self._serving_event.set()
            logger.debug("🛎️ Server running; awaiting shutdown signal...")
            await self._serving_future
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
        """Safe cleanup in garbage collection."""
        try:
            # Check if event loop exists and is running
            try:
                loop = asyncio.get_running_loop()
                if not loop.is_closed():
                    # Create non-coroutine cleanup
                    if hasattr(self, '_server') and self._server:
                        if hasattr(self._server, 'close'):
                            self._server.close()

                    # Signal shutdown without awaiting
                    if hasattr(self, '_serving_future') and not self._serving_future.done():
                        self._shutdown_requested()
            except RuntimeError:
                # No running event loop, just pass
                pass
        except Exception:
            # Suppress all exceptions in __del__
            pass

### 🐍🏗️🔌
