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
from typing import Optional, TypeGuard

import attrs

from pyvider.rpcplugin.logger    import logger
from pyvider.rpcplugin.exception import TransportError

from pyvider.rpcplugin.transport.base import RPCPluginTransport


def is_valid_tcp_endpoint(endpoint: str) -> TypeGuard[str]:
    """
    🔌✅🕵️  Validate that a TCP endpoint is of the form 'host:port' with a numeric port.
    Returns True if valid; otherwise, False.
    """
    parts = endpoint.split(":")
    if len(parts) != 2:
        return False
    host, port_str = parts
    return port_str.isdigit()


@attrs.define(frozen=False)
class TCPSocketTransport(RPCPluginTransport):
    """
    🔌🚀📝  TCP Socket Transport implementing the Transport interface.
    Provides methods to listen for connections, connect to a remote endpoint,
    and close the transport.
    """
    host: str = attrs.field(default="127.0.0.1")
    port: int = attrs.field(init=False, default=0)

    _server: Optional[asyncio.AbstractServer] = attrs.field(init=False, default=None)
    _writer: Optional[asyncio.StreamWriter] = attrs.field(init=False, default=None)
    endpoint: Optional[str] = attrs.field(init=False, default=None)

    async def listen(self) -> str:
        """
        🔌🚀🕹  Start a TCP server on a random available port and return the endpoint (host:port).
        """
        logger.debug("🔌🚀🕹: Starting listen() for TCP server...")
        try:
            self._server = await asyncio.start_server(self._handle_client, self.host, 0)
        except OSError as e:
            logger.error(f"🔌❌⚠: Failed to bind TCP server: {e}")
            raise TransportError(f"Failed to bind TCP server: {e}") from e

        try:
            sock = self._server.sockets[0]
            addr = sock.getsockname()
            self.port = addr[1]
            self.endpoint = f"{self.host}:{self.port}"
            logger.info(f"🔌✅👍: TCP server listening at {self.endpoint}")
            return self.endpoint
        except Exception as e:
            logger.error(f"🔌❌⚠: Error initializing TCP server: {e}")
            raise TransportError(f"Error initializing TCP server: {e}") from e

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
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
                logger.error(f"🔌❌⚠: getaddrinfo failed for {self.host}:{self.port}: {e}")
                raise TransportError(f"Address resolution failed for {self.host}:{self.port}: {e}") from e

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=5.0
            )
            self._writer = writer
            logger.info(f"🔌✅👍: Successfully connected to TCP endpoint: {self.endpoint}")
        except asyncio.TimeoutError as e:
            logger.error(f"🔌❌⚠: Connection timeout for TCP endpoint {endpoint}: {e}")
            raise TransportError(f"Connection timed out: {e}") from e
        except Exception as e:
            logger.error(f"🔌❌⚠: Failed to connect to TCP endpoint {endpoint}: {e}")
            raise TransportError(f"Failed to connect to TCP endpoint {endpoint}: {e}") from e

    async def close(self) -> None:
        """
        🔌🔒🛑  Close the TCP transport.
        Closes both the client connection (if any) and the server.
        """
        logger.debug(f"🔌🔒🛑: Closing TCP transport at endpoint {self.endpoint}")
        if self._writer:
            try:
                result = self._writer.close()
                if asyncio.iscoroutine(result):
                    await result
                await self._writer.wait_closed()
                logger.info("🔌🔒✅: Client writer closed successfully")
            except Exception as e:
                logger.error(f"🔌🔒❌: Error closing client writer: {e}")
                raise TransportError(f"Error closing client writer: {e}") from e
            finally:
                self._writer = None

        if self._server:
            try:
                self._server.close()
                await self._server.wait_closed()
                logger.info("🔌🔒✅: TCP server closed successfully")
            except Exception as e:
                logger.error(f"🔌🔒❌: Error closing TCP server: {e}")
            finally:
                self._server = None
