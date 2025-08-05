#
# src/pyvider/rpcplugin/transport/tcp.py
#

"""pyvider.rpcplugin.transport.tcp
--------------------------------
TCP Socket Transport implementation using asyncio.
Uses Python 3.11+ features such as TypeGuard and structural pattern matching.
Logging uses a three-emoji system:
  [Component][Action][Result] – e.g. "🔌🚀✅" means Transport starting successfully.
"""

import asyncio
import socket
from typing import TypeGuard

from attrs import define, field

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport.base import RPCPluginTransport
from pyvider.telemetry import logger


def is_valid_tcp_endpoint(endpoint: str) -> TypeGuard[str]:
    """
    🔌✅🕵️  Validate that a TCP endpoint is of the form 'host:port' with a numeric port.
    Returns True if valid; otherwise, False.
    """
    parts = endpoint.split(":")
    if len(parts) != 2:
        return False
    _host, port_str = parts
    if not _host:  # Added check for empty host
        return False
    return port_str.isdigit()


@define(frozen=False)
class TCPSocketTransport(RPCPluginTransport):
    """
    🔌🚀📝  TCP Socket Transport implementing the Transport interface.
    Provides methods to listen for connections, connect to a remote endpoint,
    and close the transport.
    """

    host: str = field(default="127.0.0.1")
    port: int = field(default=0)  # 0 = Random port assigned by OS

    _server: asyncio.AbstractServer | None = field(init=False, default=None)
    _writer: asyncio.StreamWriter | None = field(init=False, default=None)
    _reader: asyncio.StreamReader | None = field(init=False, default=None)
    endpoint: str | None = field(init=False, default=None)

    _connections: set = field(init=False, factory=set)
    _running: bool = field(init=False, default=False)
    _connection_attempts: int = field(init=False, default=0)
    _transport_name: str = "tcp"  # Class attribute identifying the transport type

    def __attrs_post_init__(self) -> None:
        """Initializes locks and events for managing transport state."""
        self._lock = asyncio.Lock()  # Lock for synchronizing access to shared resources
        self._server_ready = asyncio.Event()  # Event to signal when the server is ready
        logger.debug(
            f"🔌🚀✅: TCP transport initialized with host={self.host}, port={self.port}"
        )

    async def listen(self) -> str:
        """
        🔌🚀🕹 Start a TCP server on a random available port and return the
        endpoint (host:port).
        """
        async with self._lock:
            if self._running:
                logger.error(
                    "🔌❌⚠: Server endpoint is already determined and possibly in "
                    "use by gRPC"
                )
                # If gRPC is managing, this might be okay if called multiple times,
                # but for now, let's assume it means endpoint is set.
                if self.endpoint:
                    return self.endpoint
                raise TransportError(
                    "TCP transport is already configured with an endpoint but "
                    "it's None."
                )

            logger.debug("🔌🚀🕹: Determining endpoint for TCP server (gRPC managed)...")

            if self.port == 0:
                # Find an ephemeral port
                try:
                    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    temp_sock.bind((self.host, 0))
                    self.port = temp_sock.getsockname()[1]
                    temp_sock.close()
                    logger.info(
                        "🔌✅ TCPSocketTransport: Ephemeral port "
                        f"{self.port} selected for host {self.host}"
                    )
                except OSError as e:
                    logger.error(f"🔌❌⚠: Failed to find an ephemeral port: {e}")
                    raise TransportError(
                        f"Failed to find an ephemeral port: {e}"
                    ) from e

            # If self.port was non-zero, we use it directly.
            self.endpoint = f"{self.host}:{self.port}"
            self._running = True  # Mark as "endpoint determined"
            self._server_ready.set()  # Signal readiness (endpoint is known)

            # self._server remains None as gRPC will handle the actual server lifecycle.
            self._server = None

            logger.info(
                f"🔌✅👍: TCP endpoint determined for gRPC: {self.endpoint} "
                f"(Host: {self.host}, Port: {self.port})"
            )
            return self.endpoint

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Handles an incoming client connection by echoing received data.

        This method is registered as a callback with `asyncio.start_server`.
        It reads data from the client and writes it back, effectively an echo server,
        primarily for testing or basic interaction.

        Args:
            reader: The `asyncio.StreamReader` for reading data from the client.
            writer: The `asyncio.StreamWriter` for writing data to the client.
        """
        client_info = writer.get_extra_info("peername")
        logger.debug(f"🔌🤝👀: New client connected from {client_info}")
        try:
            while True:
                data = await reader.read(100)
                if not data:
                    logger.debug(f"🔌🤝🛑: Client {client_info} disconnected")
                    break
                logger.debug(f"🔌🤝🔍: Received data from {client_info}: {data!r}")
                writer.write(data)
                await writer.drain()
                logger.debug(f"🔌🤝✅: Echoed data to {client_info}")
        except asyncio.IncompleteReadError as e:
            logger.warning(f"🔌🤝⚠: Client {client_info} disconnected abruptly: {e}")
        except Exception as e:
            logger.error(f"🔌🤝❌: Error handling client {client_info}: {e}")
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
                await writer.wait_closed()
                logger.info(f"🔌🤝🔒: Closed connection to {client_info}")
            except Exception as e:
                logger.error(f"🔌🤝❌: Error closing connection to {client_info}: {e}")

    async def connect(self, endpoint: str) -> None:
        """
        Connects to a remote TCP endpoint.

        The endpoint string must be in the format 'host:port'. This method
        parses the endpoint, performs DNS resolution, and establishes a
        connection.

        Args:
            endpoint: The target TCP endpoint string (e.g., "127.0.0.1:12345").

        Raises:
            TransportError: If the endpoint format is invalid, DNS resolution fails,
                            or the connection cannot be established
                            (e.g., timeout, refused).
        """
        logger.debug(f"🔌🚀🕵️: Attempting connection to TCP endpoint: {endpoint}")
        if not is_valid_tcp_endpoint(endpoint):
            logger.error(f"🔌❌⚠: Invalid TCP endpoint format: {endpoint}")
            raise TransportError(f"Invalid TCP endpoint format: {endpoint}")

        try:
            # Parse the endpoint
            parts = endpoint.split(":")
            match parts:
                case [host, port_str] if port_str.isdigit():
                    self.host = host
                    self.port = int(port_str)
                    self.endpoint = f"{self.host}:{self.port}"
                case _:
                    logger.error(f"🔌❌⚠: Unexpected endpoint format: {endpoint}")
                    raise TransportError(f"Unexpected endpoint format: {endpoint}")

            # Perform DNS resolution to ensure the address is reachable.
            try:
                socket.getaddrinfo(self.host, self.port)
            except socket.gaierror as e:
                logger.error(
                    f"🔌❌⚠: getaddrinfo failed for {self.host}:{self.port}: {e}"
                )
                raise TransportError(
                    f"Address resolution failed for {self.host}:{self.port}: {e}"
                ) from e

            try:
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port), timeout=5.0
                )
                logger.info(
                    f"🔌✅👍: Successfully connected to TCP endpoint: {self.endpoint}"
                )
            except TimeoutError as e_timeout:
                logger.error(f"🔌❌⚠: Timeout for TCP endpoint {endpoint}: {e_timeout}")
                raise TransportError(
                    f"Connection timed out: {e_timeout}"
                ) from e_timeout
            except ConnectionRefusedError as e_refused:
                logger.error(
                    f"🔌❌⚠: Connection refused to TCP endpoint {endpoint}: {e_refused}"
                )
                raise TransportError(f"Connection refused: {e_refused}") from e_refused

        except TransportError:
            # Re-raise TransportError without additional wrapping
            raise
        except Exception as e:
            logger.error(f"🔌❌⚠: Failed to connect to TCP endpoint {endpoint}: {e}")
            raise TransportError(
                f"Failed to connect to TCP endpoint {endpoint}: {e}"
            ) from e

    async def _close_writer(self, writer: asyncio.StreamWriter | None) -> None:
        """Close a StreamWriter with proper error handling."""
        if writer is None:
            return

        transport_to_abort = None
        if hasattr(writer, "transport"):
            transport_to_abort = writer.transport

        try:
            # writer.close() is synchronous and signals the intent to close.
            if not writer.is_closing():  # Check if already closing
                writer.close()

            # await writer.wait_closed() can hang.
            await asyncio.wait_for(writer.wait_closed(), timeout=5.0)
            logger.debug("🔌🔒✅ Writer closed successfully")
        except TimeoutError:
            logger.warning(
                "🔌🔒⚠️ Timeout closing writer for endpoint "
                f"{self.endpoint if self.endpoint else 'unknown'}"
            )
            # If timeout occurs, also attempt to abort the transport
            if (
                transport_to_abort
                and hasattr(transport_to_abort, "abort")
                and callable(transport_to_abort.abort)
            ):
                logger.warning(
                    "🔌🔒✍️ Timeout, attempting direct abort of transport: "
                    f"{transport_to_abort!r}"
                )
                transport_to_abort.abort()
        except Exception as e:
            logger.error(f"🔌🔒⚠️ Error closing writer: {e}", exc_info=True)
            # If any other exception occurs, also attempt to abort
            if (
                transport_to_abort
                and hasattr(transport_to_abort, "abort")
                and callable(transport_to_abort.abort)
            ):
                logger.warning(
                    "🔌🔒✍️ Exception, attempting direct abort of transport: "
                    f"{transport_to_abort!r}"
                )
                transport_to_abort.abort()

    async def close(self) -> None:
        """
        Closes the TCP transport, including any active server or client connections.

        This method is idempotent and ensures that all resources associated with
        this transport instance are released.
        """
        logger.debug(f"🔌🔒🛑: Closing TCP transport at endpoint {self.endpoint}")

        async with self._lock:
            # Close client connection
            if self._writer:
                try:
                    await self._close_writer(self._writer)
                    logger.info("🔌🔒✅: Client writer closed successfully")
                except Exception as e:
                    logger.error(f"🔌🔒❌: Error closing client writer: {e}")
                finally:
                    self._writer = None
                    self._reader = None

            # Close server
            if self._server:
                server_was_serving = self._server.is_serving()  # Store initial state
                try:
                    if server_was_serving:
                        self._server.close()  # This is synchronous, initiates closing

                    # Only await wait_closed if close was called or it was serving
                    if server_was_serving:
                        await asyncio.wait_for(self._server.wait_closed(), timeout=5.0)
                        logger.info("🔌🔒✅: TCP server closed successfully")
                    else:  # If it wasn't serving, log that no action was needed.
                        logger.debug(
                            "🔌🔒ℹ️: TCP server was not serving, no close/wait action "
                            "needed."
                        )
                except TimeoutError:
                    logger.warning(
                        "🔌🔒⚠️ Timeout closing TCP server for endpoint "
                        f"{self.endpoint if self.endpoint else 'unknown'}"
                    )
                except Exception as e:
                    logger.error(f"🔌🔒❌: Error closing TCP server: {e}")
                finally:
                    self._server = None

            # This should be set regardless of whether self._server (asyncio server)
            # was active, as close() means the transport is shutting down.
            self._running = False

        self.endpoint = None
        logger.debug("🔌🔒✅: TCP socket transport closed completely")


# 🐍🏗️🔌
