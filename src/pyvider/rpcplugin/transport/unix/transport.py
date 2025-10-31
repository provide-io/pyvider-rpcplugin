# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""TODO: Add module docstring."""

# 
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Unix Domain Socket Transport Implementation.

This module provides the `UnixSocketTransport` class, an implementation of the
`RPCPluginTransport` interface for communication over Unix domain sockets.
It includes logic for socket creation, connection handling, and robust cleanup."""

import asyncio
import errno
import os
from pathlib import Path
import socket
import stat
import tempfile
from typing import Any
import uuid

from attrs import define, field
from provide.foundation.logger import get_logger

from pyvider.rpcplugin.client.connection import ClientConnection
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport.base import RPCPluginTransport
from pyvider.rpcplugin.transport.unix.utils import normalize_unix_path

logger = get_logger(__name__)


@define(frozen=False, slots=True)
class UnixSocketTransport(RPCPluginTransport):
    """
    Unix domain socket transport for local IPC communication.

    This transport provides high-performance local inter-process communication
    using Unix domain sockets. It's the preferred transport for plugin communication
    on Linux and macOS systems, offering better security and performance than TCP
    for local connections.

    The implementation is compatible with HashiCorp's go-plugin protocol, handling:
    - Automatic socket path generation when path is None
    - Path normalization for unix:, unix:/, unix:// prefixes
    - Proper file permissions (0660) for cross-process access
    - Socket lifecycle management with cleanup on close
    - Stale socket detection and removal

    Attributes:
        path: Unix socket file path. If None, generates temporary path.
        endpoint: The normalized endpoint string (e.g., "unix:/tmp/plugin.sock")

    Example:
        ```python
        # Server with auto-generated path
        transport = UnixSocketTransport()
        endpoint = await transport.listen()  # Returns "unix:/tmp/pyvider-xxx.sock"

        # Server with specific path
        transport = UnixSocketTransport(path="/var/run/myplugin.sock")
        endpoint = await transport.listen()  # Returns "unix:/var/run/myplugin.sock"

        # Client connection
        transport = UnixSocketTransport()
        await transport.connect("unix:/tmp/server.sock")

        # Cleanup (removes socket file)
        await transport.close()
        ```

    Platform Notes:
        - Linux/macOS: Full support with optimal performance
        - Windows: Not supported (use TCPSocketTransport instead)
        - Docker: Ensure socket paths are in shared volumes for cross-container IPC

    Security Notes:
        - Socket files are created with 0660 permissions (user/group read/write)
        - Consider socket file location for security (avoid world-writable directories)
        - Socket files are automatically removed on close()

    Note:
        This transport is typically created automatically by factory functions
        (plugin_server, plugin_client) when transport="unix" is specified.
    """

    path: str | None = field(default=None)
    _server: asyncio.AbstractServer | None = field(init=False, default=None)
    _writer: asyncio.StreamWriter | None = field(init=False, default=None)
    _reader: asyncio.StreamReader | None = field(init=False, default=None)
    endpoint: str | None = field(init=False, default=None)

    _connections: set[ClientConnection] = field(init=False, factory=set)
    _running: bool = field(init=False, default=False)
    _closing: bool = field(init=False, default=False)
    _lock: asyncio.Lock = field(init=False, factory=asyncio.Lock)

    _transport_name: str = "unix"  # Identifier for this transport type

    def __attrs_post_init__(self) -> None:
        """
        Post-initialization hook for UnixSocketTransport.

        If a socket path is not provided, it generates an ephemeral path.
        Otherwise, it normalizes the provided path. Initializes locks and events.
        """
        if not self.path:
            # Generate ephemeral path if none provided
            self.path = str(Path(tempfile.gettempdir()) / f"pyvider-{uuid.uuid4().hex[:8]}.sock")
        else:
            # Normalize path if it has a unix: prefix
            self.path = normalize_unix_path(self.path)

        self._server_ready = asyncio.Event()
        self._connections = set()  # Initialize connection set

    async def _check_socket_in_use(self) -> bool:
        """Check if socket is already in use by another process."""
        if not self.path:
            return False

        try:
            path_exists = Path(self.path).exists()
        except PermissionError as e:
            return False

        if not path_exists:
            return False

        # Path exists, check if it's actually a socket and connectable
        try:
            mode = Path(self.path).stat().st_mode
            if not stat.S_ISSOCK(mode):
                logger.debug(
                    f"(mode: {oct(mode)}). Considering available."
                )
                return False
        except OSError as e:
            # Failed to stat path (e.g., permissions, or it disappeared)
            return False

        # Path exists and is a socket, now try to connect
        sock = None  # Initialize sock to None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect(self.path)
            # If connect succeeds, the socket is in use by another process
            return True
        except (ConnectionRefusedError, FileNotFoundError):
            # Connection refused or socket file disappeared: it's available
            logger.debug(
            )
            return False
        except OSError as e:
            # Other OSErrors (e.g., timeout, permission issues during connect)
            # If we can't connect for any other OSError, assume it's not actively
            # listening in a way that would conflict.
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e_sock_close:
                    logger.warning(
                    )

    def _raise_if_running(self) -> None:
        if self._running:
            raise TransportError(f"Socket {self.path} is already running")

    async def _ensure_socket_available(self) -> None:
        if await self._check_socket_in_use():
            raise TransportError(f"Socket {self.path} is already running")

    def _require_socket_path(self) -> str:
        if self.path is None:
            raise RuntimeError(
                "self.path was not initialized. This should not happen if __attrs_post_init__ ran correctly."
            )
        return self.path

    def _ensure_socket_directory(self, socket_path: str) -> None:
        dir_path = Path(socket_path).parent
        if dir_path == Path():
            return
        try:
            dir_path.mkdir(parents=True, exist_ok=True)
        except (PermissionError, OSError) as exc:
            raise TransportError(f"Failed to create Unix socket directory: {exc}") from exc

    async def _remove_stale_socket_file(self, socket_path: str) -> None:
        try:
            path_exists = Path(socket_path).exists()
        except PermissionError as exc:
            logger.warning(
            )
            path_exists = False

        if not path_exists:
            return

        try:
            Path(socket_path).unlink()
            await asyncio.sleep(0.1)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise TransportError(f"Failed to remove stale socket: {exc}") from exc

    def _set_socket_permissions(self, socket_path: str) -> None:
        try:
            current_mask = os.umask(0)
            os.umask(current_mask)
            desired_permissions = 0o660 & ~current_mask
            Path(socket_path).chmod(desired_permissions)  # nosec B103
            logger.debug(
            )
        except Exception as exc:
            logger.warning(
            )

    async def _start_server_at_path(self, socket_path: str) -> str:
        try:
            self._server = await asyncio.start_unix_server(self._handle_client, path=socket_path)
        except OSError as exc:
            raise TransportError(f"Failed to create Unix socket: {exc}") from exc

        self._set_socket_permissions(socket_path)
        self._running = True
        self.endpoint = socket_path
        self._server_ready.set()
        return socket_path

    async def listen(self) -> str:
        """Start listening on Unix socket with cross-platform compatibility."""
        async with self._lock:
            self._raise_if_running()
            await self._ensure_socket_available()
            socket_path = self._require_socket_path()
            self._ensure_socket_directory(socket_path)
            await self._remove_stale_socket_file(socket_path)
            return await self._start_server_at_path(socket_path)

    async def connect(self, endpoint: str) -> None:
        """
        Connect to a remote Unix socket with robust path handling.

        This method:
        1. Normalizes the endpoint path to handle various formats
        2. Verifies the socket file exists (with retries)
        3. Establishes the connection with timeout handling

        Args:
            endpoint: The Unix socket path to connect to, which can be in
                      various formats:
                     - Absolute path: "/tmp/socket.sock"
                     - With prefix: "unix:/tmp/socket.sock"

        Raises:
            TransportError: If the socket file doesn't exist or connection fails
            TimeoutError: If the connection attempt times out
        """
        # Save original endpoint for logging
        orig_endpoint = endpoint

        # Normalize endpoint path
        endpoint = normalize_unix_path(endpoint)


        # Verify socket file exists with retries
        retries = 3
        for attempt in range(retries):
            if Path(endpoint).exists():
                break
            if attempt < retries - 1:
                await asyncio.sleep(0.5)  # Short delay between retries

        if not Path(endpoint).exists():
            raise TransportError(f"Socket {endpoint} does not exist")

        # Add validation that it's actually a socket
        try:
            if not stat.S_ISSOCK(Path(endpoint).stat().st_mode):
                raise TransportError(f"Path exists but is not a socket: {endpoint}")
        except OSError as e:
            raise TransportError(f"Error checking socket status: {e}") from e

        try:
            reader_writer = await asyncio.wait_for(asyncio.open_unix_connection(endpoint), timeout=5.0)
            self._reader, self._writer = reader_writer  # Unpack after awaiting
            self.endpoint = endpoint
        except TimeoutError as e_timeout:
            raise TransportError(f"Connection to Unix socket timed out: {e_timeout}") from e_timeout
        except Exception as e:
            raise TransportError(f"Failed to connect to Unix socket: {e}") from e

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """
        Handles an incoming client connection.

        This method is registered as a callback with `asyncio.start_unix_server`.
        It creates a `ClientConnection` object to manage the connection,
        tracks active connections, and echoes data received from the client.

        Args:
            reader: The `asyncio.StreamReader` for reading data from the client.
            writer: The `asyncio.StreamWriter` for writing data to the client.
        """
        peer_info = writer.get_extra_info("peername") or "unknown"

        conn = ClientConnection(reader=reader, writer=writer, remote_addr=str(peer_info))

        try:
            async with self._lock:
                self._connections.add(conn)
                logger.debug(
                )

            while self._running and not conn.is_closed:
                data = await conn.receive_data()
                if not data:
                    break

                await conn.send_data(data)  # echo

        except asyncio.CancelledError:
        except Exception as e:
        finally:
            async with self._lock:
                if conn in self._connections:
                    self._connections.remove(conn)
            await conn.close()

    async def _wait_for_writer_close(self, writer: asyncio.StreamWriter) -> None:
        if hasattr(writer, "wait_closed"):
            await writer.wait_closed()
        else:

    def _abort_transport(self, transport: Any, message: str) -> None:
        if not transport:
            return
        if hasattr(transport, "abort") and callable(transport.abort):
            transport.abort()
        else:

    def _finalize_transport_shutdown(self, transport: Any) -> None:
        if not transport:
            return

        has_is_closing = hasattr(transport, "is_closing") and callable(transport.is_closing)
        if has_is_closing and transport.is_closing():
            return
        if has_is_closing:
            self._abort_transport(transport, "Transport not closing after writer.close().")
            return

        self._abort_transport(transport, "Transport missing is_closing; aborting proactively.")

    async def _close_writer(self, writer: asyncio.StreamWriter | None) -> None:
        """Close a StreamWriter with proper error handling."""
        if writer is None:
            return

        transport_to_abort = getattr(writer, "transport", None)
        try:
            writer.close()
            await self._wait_for_writer_close(writer)
        except Exception as exc:
            self._abort_transport(transport_to_abort, "Exception during writer.close().")
        finally:
            self._finalize_transport_shutdown(transport_to_abort)

    async def _close_connections(self) -> None:
        """Close all active connections."""
        async with self._lock:
            connection_count = len(self._connections)
            if connection_count > 0:
                close_tasks = [conn.close() for conn in self._connections]
                await asyncio.gather(*close_tasks, return_exceptions=True)
                self._connections.clear()

    async def _close_client_connection(self) -> None:
        """Close client writer/reader."""
        if self._writer:
            await self._close_writer(self._writer)
            self._writer = None
            self._reader = None

    async def _close_server(self) -> None:
        """Close the server with error handling."""
        if self._server:
            try:
                self._server.close()
                await self._server.wait_closed()
            except Exception as e:
            finally:
                self._server = None

    async def _remove_socket_file(self, socket_path: str) -> None:
        """Remove socket file with retry logic."""
        if not socket_path or not Path(socket_path).exists():
            return

        try:
            for _ in range(3):
                try:
                    Path(socket_path).chmod(0o660)  # nosec B103
                    Path(socket_path).unlink()
                    break
                except OSError as e_unlink:
                    if e_unlink.errno != errno.ENOENT:
                        await asyncio.sleep(0.1)
                    else:
                        break
            else:
                if Path(socket_path).exists():
                    raise TransportError("Failed to remove socket file after multiple attempts")
        except Exception as e:
            await asyncio.sleep(0)
            raise TransportError(f"Failed to remove socket file: {e}") from e

    async def close(self) -> None:
        """
        Closes the Unix socket transport.

        This involves closing any active client connections, stopping the server,
        and removing the socket file from the filesystem.
        It is designed to be idempotent.
        """

        if self._closing:
            return

        self._closing = True
        self._running = False

        try:
            await self._close_connections()
            await self._close_client_connection()
            await self._close_server()
            if self.path:
                await self._remove_socket_file(self.path)
        finally:
            # Always reset state even if socket removal fails
            self.endpoint = None
            self._closing = False

# 🔌📞🔚
