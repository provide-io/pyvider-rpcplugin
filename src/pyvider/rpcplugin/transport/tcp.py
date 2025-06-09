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
from pyvider.telemetry import logger
from pyvider.rpcplugin.transport.base import RPCPluginTransport


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
    _transport_name: str = "tcp" # Class attribute identifying the transport type

    def __attrs_post_init__(self) -> None:
        """Initializes locks and events for managing transport state."""
        self._lock = asyncio.Lock() # Lock for synchronizing access to shared resources
        self._server_ready = asyncio.Event() # Event to signal when the server is ready
        logger.debug(f"🔌🚀✅: TCP transport initialized with host={self.host}, port={self.port}")

    async def listen(self) -> str:
        """
        🔌🚀🕹  Start a TCP server on a random available port and return the endpoint (host:port).
        """
        async with self._lock:
            if self._running:
                logger.error("🔌❌⚠: Server is already running")
                raise TransportError("TCP server is already running")
                
            logger.debug("🔌🚀🕹: Starting listen() for TCP server...")
            try:
                self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
            except OSError as e:
                logger.error(f"🔌❌⚠: Failed to bind TCP server: {e}")
                raise TransportError(f"Failed to bind TCP server: {e}") from e

            try:
                sock = self._server.sockets[0]
                addr = sock.getsockname()
                # self.host remains what was passed or default '127.0.0.1'
                # self.port is updated to the actual bound port
                self.port = addr[1]
                logger.info(f"🔌✅ TCPSocketTransport: Server socket bound. Host: {self.host}, Actual Port: {self.port}")
                self.endpoint = f"{self.host}:{self.port}"
                logger.info(f"🔌✅👍 TCPSocketTransport: Endpoint set to {self.endpoint} (Host: {self.host}, Port: {self.port})")
                self._running = True
                self._server_ready.set()
                logger.info(f"🔌✅👍: TCP server listening at {self.endpoint}") # This one is slightly redundant now but fine
                return self.endpoint
            except Exception as e:
                logger.error(f"🔌❌⚠: Error initializing TCP server: {e}")
                raise TransportError(f"Error initializing TCP server: {e}") from e

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
                            or the connection cannot be established (e.g., timeout, refused).
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
            except asyncio.TimeoutError as e:
                logger.error(f"🔌❌⚠: Connection timeout for TCP endpoint {endpoint}: {e}")
                raise TransportError(f"Connection timed out: {e}") from e
            except ConnectionRefusedError as e:
                logger.error(f"🔌❌⚠: Connection refused to TCP endpoint {endpoint}: {e}")
                raise TransportError(f"Connection refused: {e}") from e
            
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

        try:
            # writer.close() is synchronous and signals the intent to close.
            if not writer.is_closing(): # Check if already closing
                 writer.close()
            
            # await writer.wait_closed() can hang.
            await asyncio.wait_for(writer.wait_closed(), timeout=5.0) 
            logger.debug("🔌🔒✅ Writer closed successfully")
        except asyncio.TimeoutError:
            logger.warning(f"🔌🔒⚠️ Timeout closing writer for endpoint {self.endpoint if self.endpoint else 'unknown'}")
        except Exception as e:
            logger.error(f"🔌🔒⚠️ Error closing writer: {e}")
            # Don't propagate exception to avoid crashing cleanup, as this is part of cleanup.

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
                try:
                    if self._server.is_serving(): # Check if it's serving before trying to close
                        self._server.close() # This is synchronous, initiates closing
                    
                    # await self._server.wait_closed() can hang.
                    await asyncio.wait_for(self._server.wait_closed(), timeout=5.0)
                    logger.info("🔌🔒✅: TCP server closed successfully")
                except asyncio.TimeoutError:
                    logger.warning(f"🔌🔒⚠️ Timeout closing TCP server for endpoint {self.endpoint if self.endpoint else 'unknown'}")
                except Exception as e:
                    logger.error(f"🔌🔒❌: Error closing TCP server: {e}")
                finally:
                    self._server = None
                    self._running = False

        self.endpoint = None
        logger.debug("🔌🔒✅: TCP socket transport closed completely")

# 🐍🏗️🔌
