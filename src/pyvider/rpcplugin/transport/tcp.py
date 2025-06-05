#
# pyvider/rpcplugin/transport/tcp.py
#

"""
pyvider.rpcplugin.transport.tcp
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
    _transport_name: str = "tcp"

    def __attrs_post_init__(self) -> None:
        """Initialize transport state and resources."""
        self._lock = asyncio.Lock()
        self._server_ready = asyncio.Event()
        logger.debug(f"🔌🚀✅: TCP transport initialized with host={self.host}, port={self.port}")

    async def listen(self) -> str:
        """
        🔌🚀🕹  Start a TCP server on a random available port and return the endpoint (host:port).
        """
        async with self._lock:
            if self._running:
                logger.error("🔌❌⚠: Server is already running (listen called)")
                raise TransportError("TCP transport is already marked as running.") # Message changed slightly for clarity
                
            logger.debug(f"🔌🚀🕹: Marking TCP transport as listening on {self.host}:{self.port}. Socket management deferred to gRPC server.")
            # If port is 0, it's problematic as this method no longer resolves it.
            # For now, proceed with the configured port. External mechanism must ensure it's valid and available.
            if self.port == 0:
                logger.warning(f"🔌⚠️ TCPTransport.listen() called with port 0. Port resolution is now external to this method.")

            self.endpoint = f"{self.host}:{self.port}"
            self._running = True # Mark as running
            self._server_ready.set() # Signal readiness, though no server is started here
            logger.info(f"🔌✅👍: TCP transport configured to listen at {self.endpoint}. Actual binding/listening is external.")
            return self.endpoint

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        🔌🤝👀  Handle an incoming client connection by echoing received data.
        """
        client_info = writer.get_extra_info("peername")
        logger.debug(f"🔌🤝👀: New client connected from {client_info}")
        try:
            while True:
                data = await reader.read(100)
                if not data:
                    logger.debug(f"🔌🤝🛑: Client {client_info} disconnected")
                    break
                logger.debug(f"🔌🤝🔍: Received data from {client_info}: {data}")
                writer.write(data)
                await writer.drain()
                logger.debug(f"🔌🤝✅: Echoed data to {client_info}")
        except asyncio.IncompleteReadError as e:
            logger.warning(f"🔌🤝⚠: Client {client_info} disconnected abruptly: {e}")
        except Exception as e:
            logger.error(f"🔌🤝❌: Error handling client {client_info}: {e}")
        finally:
            try:
                writer.close()
                # Check if close() returns a coroutine (e.g. when using an AsyncMock)
                maybe_coro = writer.close()
                if asyncio.iscoroutine(maybe_coro):
                    await maybe_coro
                await writer.wait_closed()
                logger.info(f"🔌🤝🔒: Closed connection to {client_info}")
            except Exception as e:
                logger.error(f"🔌🤝❌: Error closing connection to {client_info}: {e}")

    async def connect(self, endpoint: str) -> None:
        """
        🔌🚀🕵️  Connect to a remote TCP endpoint.
        The endpoint must be in the format 'host:port'.
        Performs DNS resolution before attempting to connect.
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
            # Don't propagate exception to avoid crashing cleanup

    async def close(self) -> None:
        """
        🔌🔒🛑  Close the TCP transport.
        Closes both the client connection (if any) and the server.
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

            # Close server - Removed as self._server is no longer created by listen()
            # if self._server:
            #     try:
            #         if self._server.is_serving():
            #             self._server.close()
            #         await asyncio.wait_for(self._server.wait_closed(), timeout=5.0)
            #         logger.info("🔌🔒✅: asyncio server (if any was externally managed) closed successfully logic removed here")
            #     except asyncio.TimeoutError:
            #         logger.warning(f"🔌🔒⚠️ Timeout closing asyncio server for endpoint {self.endpoint if self.endpoint else 'unknown'}")
            #     except Exception as e:
            #         logger.error(f"🔌🔒❌: Error closing asyncio server: {e}")
            #     finally:
            #         self._server = None # Ensure it's None if it was ever set externally

            # Only set _running to False and clear endpoint if this transport instance was marked as running
            if self._running:
                self._running = False
                logger.info(f"🔌🔒✅: TCP transport marked as not running for {self.endpoint}.")
            else:
                logger.debug(f"🔌🔒ℹ️: TCP transport close called but was not marked as running for {self.endpoint}.")

            self._server = None # Ensure _server attribute is cleared
            self.endpoint = None # Clear the endpoint

        logger.debug("🔌🔒✅: TCP socket transport close() finished.")

# 🐍🏗️🔌
