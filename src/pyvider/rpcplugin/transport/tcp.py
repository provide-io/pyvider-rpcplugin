# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""TODO: Add module docstring."""

# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""pyvider.rpcplugin.transport.tcp
--------------------------------
TCP Socket Transport implementation using asyncio.
Uses Python 3.11+ features such as TypeGuard and structural pattern matching.
Logging uses a three-emoji system:

import asyncio
import socket
from typing import Any, TypeGuard

from attrs import define, field
from provide.foundation.logger import get_logger

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport.base import RPCPluginTransport

logger = get_logger(__name__)


def is_valid_tcp_endpoint(endpoint: str) -> TypeGuard[str]:
    """
    Validate that a TCP endpoint has the correct format.

    A valid TCP endpoint must be in the format 'host:port' where:
    - host is a non-empty string (can be hostname or IP address)
    - port is a numeric value

    Args:
        endpoint: String to validate as a TCP endpoint.

    Returns:
        TypeGuard[str]: True if the endpoint is valid, False otherwise.

    Example:
        ```python
        assert is_valid_tcp_endpoint("127.0.0.1:8080")  # True
        assert is_valid_tcp_endpoint("localhost:443")    # True
        assert not is_valid_tcp_endpoint("invalid")      # False
        assert not is_valid_tcp_endpoint(":8080")        # False
        ```
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
    TCP socket transport for network-based RPC communication.

    This transport implementation provides TCP/IP connectivity for RPC plugins,
    supporting both server (listen) and client (connect) modes. It's suitable
    for network communication between processes on the same machine or across
    a network.

    The transport handles:
    - Dynamic port allocation (when port=0)
    - DNS resolution for hostnames
    - Connection lifecycle management
    - Graceful shutdown with timeouts

    Attributes:
        host: IP address or hostname to bind/connect to (default: "127.0.0.1")
        port: Port number to use (0 for dynamic allocation, default: 0)
        endpoint: The resolved endpoint string in "host:port" format (set after listen/connect)

    Example:
        ```python
        # Server mode with dynamic port
        transport = TCPSocketTransport()
        endpoint = await transport.listen()  # Returns "127.0.0.1:45678"

        # Server mode with specific port
        transport = TCPSocketTransport(host="0.0.0.0", port=8080)
        endpoint = await transport.listen()  # Returns "0.0.0.0:8080"

        # Client mode
        transport = TCPSocketTransport()
        await transport.connect("remote.host:8080")

        # Cleanup
        await transport.close()
        ```

    Note:
        This transport is typically created automatically by the factory functions
        (plugin_server, plugin_client) rather than instantiated directly.
        For local IPC on Unix-like systems, prefer UnixSocketTransport for
        better performance and security.
    """

    host: str = field(default="127.0.0.1")
    port: int = field(default=0)  # 0 = Random port assigned by OS

    _server: asyncio.AbstractServer | None = field(init=False, default=None)
    _writer: asyncio.StreamWriter | None = field(init=False, default=None)
    _reader: asyncio.StreamReader | None = field(init=False, default=None)
    endpoint: str | None = field(init=False, default=None)

    _connections: set[Any] = field(init=False, factory=set)
    _running: bool = field(init=False, default=False)
    _connection_attempts: int = field(init=False, default=0)
    _transport_name: str = "tcp"  # Class attribute identifying the transport type

    def __attrs_post_init__(self) -> None:
        """Initializes locks and events for managing transport state."""
        self._lock = asyncio.Lock()  # Lock for synchronizing access to shared resources
        self._server_ready = asyncio.Event()  # Event to signal when the server is ready

    async def listen(self) -> str:
        """
        endpoint (host:port).
        """
        async with self._lock:
            if self._running:
                # If gRPC is managing, this might be okay if called multiple times,
                # but for now, let's assume it means endpoint is set.
                if self.endpoint:
                    return self.endpoint
                raise TransportError("TCP transport is already configured with an endpoint but it's None.")


            if self.port == 0:
                # Find an ephemeral port
                try:
                    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    temp_sock.bind((self.host, 0))
                    self.port = temp_sock.getsockname()[1]
                    temp_sock.close()
                    logger.info(
                    )
                except OSError as e:
                    raise TransportError(f"Failed to find an ephemeral port: {e}") from e

            # If self.port was non-zero, we use it directly.
            self.endpoint = f"{self.host}:{self.port}"
            self._running = True  # Mark as "endpoint determined"
            self._server_ready.set()  # Signal readiness (endpoint is known)

            # self._server remains None as gRPC will handle the actual server lifecycle.
            self._server = None

            logger.info(
                f"(Host: {self.host}, Port: {self.port})"
            )
            return self.endpoint

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
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
        try:
            while True:
                data = await reader.read(100)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except asyncio.IncompleteReadError as e:
        except Exception as e:
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
                await writer.wait_closed()
            except Exception as e:

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
        if not is_valid_tcp_endpoint(endpoint):
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
                    raise TransportError(f"Unexpected endpoint format: {endpoint}")

            # Perform DNS resolution to ensure the address is reachable.
            try:
                socket.getaddrinfo(self.host, self.port)
            except socket.gaierror as e:
                raise TransportError(f"Address resolution failed for {self.host}:{self.port}: {e}") from e

            try:
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_connection(self.host, self.port), timeout=5.0
                )
            except TimeoutError as e_timeout:
                raise TransportError(f"Connection timed out: {e_timeout}") from e_timeout
            except ConnectionRefusedError as e_refused:
                raise TransportError(f"Connection refused: {e_refused}") from e_refused

        except TransportError:
            # Re-raise TransportError without additional wrapping
            raise
        except Exception as e:
            raise TransportError(f"Failed to connect to TCP endpoint {endpoint}: {e}") from e

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
        except TimeoutError:
            logger.warning(
            )
            # If timeout occurs, also attempt to abort the transport
            if (
                transport_to_abort
                and hasattr(transport_to_abort, "abort")
                and callable(transport_to_abort.abort)
            ):
                transport_to_abort.abort()
        except Exception as e:
            # If any other exception occurs, also attempt to abort
            if (
                transport_to_abort
                and hasattr(transport_to_abort, "abort")
                and callable(transport_to_abort.abort)
            ):
                logger.warning(
                )
                transport_to_abort.abort()

    async def close(self) -> None:
        """
        Closes the TCP transport, including any active server or client connections.

        This method is idempotent and ensures that all resources associated with
        this transport instance are released.
        """

        async with self._lock:
            # Close client connection
            if self._writer:
                try:
                    await self._close_writer(self._writer)
                except Exception as e:
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
                    else:  # If it wasn't serving, log that no action was needed.
                except TimeoutError:
                    logger.warning(
                        f"{self.endpoint if self.endpoint else 'unknown'}"
                    )
                except Exception as e:
                finally:
                    self._server = None

            # This should be set regardless of whether self._server (asyncio server)
            # was active, as close() means the transport is shutting down.
            self._running = False

        self.endpoint = None

# 🔌📞🔚
