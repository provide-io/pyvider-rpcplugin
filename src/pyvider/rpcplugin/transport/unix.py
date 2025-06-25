#
# src/pyvider/rpcplugin/transport/unix.py
#

"""
Unix Domain Socket Transport Implementation.

This module provides the `UnixSocketTransport` class, an implementation of the
`RPCPluginTransport` interface for communication over Unix domain sockets.
It includes logic for path normalization, socket creation, connection handling,
and robust cleanup, tailored for interoperability with Go-based plugins.
"""

import asyncio
import errno
import os
import socket
import stat

from attrs import define, field

from pyvider.rpcplugin.client.connection import ClientConnection
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport.base import RPCPluginTransport
from pyvider.telemetry import logger


def normalize_unix_path(path: str) -> str:
    """
    Standardized Unix socket path normalization, handling:
    - unix: prefix
    - unix:/ prefix
    - unix:// prefix
    - Multiple leading slashes

    Returns a clean path suitable for socket operations.
    """
    logger.debug(f"📞🔍🚀 * Normalizing Unix path: {path}")

    # Handle unix: prefix formats
    if path.startswith("unix:"):
        path = path[5:]  # Remove 'unix:'

    # Handle multiple leading slashes
    if path.startswith("//"):
        # Split by / and rebuild with single leading slash
        parts = [p for p in path.split("/") if p]
        path = "/" + "/".join(parts)
    elif path.startswith("/"):
        # Keep absolute paths as-is
        pass
    # Relative paths remain unchanged

    logger.debug(f"📞🔍✅ * Normalized path: {path}")
    return path


@define(frozen=False, slots=True)
class UnixSocketTransport(RPCPluginTransport):
    """
    Unix domain socket transport compatible with Go plugin implementation.

    This transport implementation handles Unix domain socket communication with
    specific adaptations for interoperability with HashiCorp's Go-based plugin
    system. It manages socket creation, permission handling, and cleanup.

    Key features:
    - Socket path normalization (supporting unix:, unix:/, unix:// prefixes)
    - File permission management (0770 for cross-process access)
    - Proper socket state verification and cleanup
    - Connection tracking

    Example:
        ```python
        transport = UnixSocketTransport(path="/tmp/plugin.sock")
        endpoint = await transport.listen()  # Start listening
        # ... use in server ...
        await transport.close()  # Clean up resources
        ```
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
            import tempfile
            import uuid

            self.path = os.path.join(
                tempfile.gettempdir(), f"pyvider-{uuid.uuid4().hex[:8]}.sock"
            )
            logger.debug(f"📞🚀✅ Generated ephemeral Unix socket path: {self.path}")
        else:
            # Normalize path if it has a unix: prefix
            self.path = normalize_unix_path(self.path)

        self._server_ready = asyncio.Event()
        self._connections = set()  # Initialize connection set
        logger.debug(f"📞🚀✅ UnixSocketTransport initialized with path={self.path}")

    async def _check_socket_in_use(self) -> bool:
        """Check if socket is already in use by another process."""
        if not self.path or not os.path.exists(self.path):
            logger.debug(
                f"📞🔍✅ Socket path {self.path} does not exist or is None, "
                "considering available."
            )
            return False

        # Path exists, check if it's actually a socket and connectable
        try:
            mode = os.stat(self.path).st_mode
            if not stat.S_ISSOCK(mode):
                logger.debug(
                    f"📞🔍✅ Path {self.path} exists but is not a socket "
                    f"(mode: {oct(mode)}). Considering available."
                )
                return False
        except OSError as e:
            # Failed to stat path (e.g., permissions, or it disappeared)
            logger.warning(
                f"📞🔍⚠️ Could not stat {self.path} ({e}). Assuming available."
            )
            return False

        # Path exists and is a socket, now try to connect
        sock = None  # Initialize sock to None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            logger.debug(
                f"📞🔍🚀 Checking if socket {self.path} is in use by "
                "attempting connect."
            )
            sock.connect(self.path)
            # If connect succeeds, the socket is in use by another process
            logger.debug(
                f"📞🔍❌ Socket {self.path} is in use (connection successful)."
            )
            return True
        except (ConnectionRefusedError, FileNotFoundError):
            # Connection refused or socket file disappeared: it's available
            logger.debug(
                f"📞🔍✅ Socket {self.path} is available (ConnectionRefusedError or "
                "FileNotFoundError)."
            )
            return False
        except OSError as e:
            # Other OSErrors (e.g., timeout, permission issues during connect)
            # If we can't connect for any other OSError, assume it's not actively
            # listening in a way that would conflict.
            logger.warning(
                f"📞🔍⚠️ OSError while connecting to {self.path} ({e}). "
                "Assuming available."
            )
            return False
        finally:
            if sock:
                try:
                    sock.close()
                except Exception as e_sock_close:
                    logger.warning(
                        "📞🔍⚠️ Error closing temporary socket in "
                        f"_check_socket_in_use: {e_sock_close}"
                    )

    async def listen(self) -> str:
        """Start listening on Unix socket with cross-platform compatibility."""
        async with self._lock:
            if self._running:
                logger.error(f"📞🕹❌ Socket {self.path} is already running")
                raise TransportError(f"Socket {self.path} is already running")

            # Check if socket file is in use
            socket_in_use = await self._check_socket_in_use()
            if socket_in_use:
                logger.error(f"📞🕹❌ Socket {self.path} is already running")
                raise TransportError(f"Socket {self.path} is already running")

            if self.path is None:
                raise RuntimeError(
                    "self.path was not initialized. This should not happen if "
                    "__attrs_post_init__ ran correctly."
                )

            # Create directory if needed
            dir_path = os.path.dirname(self.path)
            if dir_path:
                try:
                    os.makedirs(dir_path, exist_ok=True)
                    logger.debug(f"📞🕹✅ Created directory: {dir_path}")
                except (PermissionError, OSError) as e:
                    logger.error(f"📞🕹❌ Failed to create directory {dir_path}: {e}")
                    raise TransportError(
                        f"Failed to create Unix socket directory: {e}"
                    ) from e

            if os.path.exists(self.path):
                try:
                    os.unlink(self.path)
                    logger.debug(f"📞🕹✅ Removed stale socket file: {self.path}")
                    # Brief pause to ensure file system syncs
                    await asyncio.sleep(0.1)
                except OSError as e:
                    if e.errno != errno.ENOENT:  # Ignore if file doesn't exist
                        logger.error(f"📞🕹❌ Failed to remove stale socket: {e}")
                        raise TransportError(
                            f"Failed to remove stale socket: {e}"
                        ) from e

            try:
                logger.debug(f"📞🕹🚀 Creating Unix socket at {self.path}")
                self._server = await asyncio.start_unix_server(
                    self._handle_client, path=self.path
                )

                # Set permissions for user and group (owner rwx, group rwx)
                # This is safer than 0o777 and suitable if client/server share a group.
                # For broader interop where group sharing isn't guaranteed,
                # this might be too restrictive.
                # However, 0o777 is generally too permissive for production.
                # Acknowledging the "test/interop environments" comment,
                # 0o770 is a step down.
                # Ideal solution might involve configurable permissions or
                # group ownership.
                try:
                    current_mask = os.umask(
                        0
                    )  # Get current umask, set to 0 temporarily
                    os.umask(current_mask)  # Restore original umask
                    desired_permissions = (
                        0o660 & ~current_mask
                    )  # Apply umask, changed from 0o770
                    os.chmod(self.path, desired_permissions)  # nosec B103
                    logger.debug(
                        f"📞🕹✅ Set permissions to {oct(desired_permissions)} on "
                        f"{self.path} (considering umask {oct(current_mask)})"
                    )
                except Exception as e_chmod:
                    logger.warning(
                        f"📞🕹⚠️ Failed to set permissions on {self.path}: {e_chmod}. "
                        "Proceeding with default permissions."
                    )

                self._running = True
                self.endpoint = self.path
                logger.info(
                    f"📞🕹✅ UnixSocketTransport: Endpoint set to {self.endpoint}"
                )
                logger.debug(f"📞🕹✅ Server listening on {self.path}")
                self._server_ready.set()
                if (
                    self.path is None
                ):  # Should be caught by earlier check, but safeguard
                    raise RuntimeError(
                        "self.path became None before returning from listen()."
                    )
                return self.path

            except OSError as e:
                logger.error(f"📞🕹❌ Failed to create Unix socket: {e}")
                raise TransportError(f"Failed to create Unix socket: {e}") from e

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

        logger.debug(
            f"📞🤝🚀 Connecting to Unix socket at '{endpoint}' (from '{orig_endpoint}')"
        )

        # Verify socket file exists with retries
        retries = 3
        for attempt in range(retries):
            if os.path.exists(endpoint):
                break
            if attempt < retries - 1:
                logger.debug(
                    f"📞🤝⚠️ Socket file not found, retrying ({attempt + 1}/{retries})"
                )
                await asyncio.sleep(0.5)  # Short delay between retries

        if not os.path.exists(endpoint):
            logger.error(f"📞🤝❌ Socket file does not exist: {endpoint}")
            raise TransportError(f"Socket {endpoint} does not exist")

        # Add validation that it's actually a socket
        try:
            if not stat.S_ISSOCK(os.stat(endpoint).st_mode):
                logger.error(f"📞🤝❌ Path exists but is not a socket: {endpoint}")
                raise TransportError(f"Path exists but is not a socket: {endpoint}")
        except OSError as e:
            logger.error(f"📞🤝❌ Error checking if path is a socket: {e}")
            raise TransportError(f"Error checking socket status: {e}") from e

        try:
            reader_writer = await asyncio.wait_for(
                asyncio.open_unix_connection(endpoint), timeout=5.0
            )
            self._reader, self._writer = reader_writer  # Unpack after awaiting
            self.endpoint = endpoint
            logger.debug(f"📞🤝✅ Connected to Unix socket at {endpoint}")
        except TimeoutError as e_timeout:
            logger.error(f"📞🤝❌ Connection to Unix socket timed out: {e_timeout}")
            raise TransportError(
                f"Connection to Unix socket timed out: {e_timeout}"
            ) from e_timeout
        except Exception as e:
            logger.error(f"📞🤝❌ Failed to connect to Unix socket: {e}")
            raise TransportError(f"Failed to connect to Unix socket: {e}") from e

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
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
        logger.debug(f"📞🤝🚀 New client connection from {peer_info}")

        conn = ClientConnection(
            reader=reader, writer=writer, remote_addr=str(peer_info)
        )

        try:
            async with self._lock:
                self._connections.add(conn)
                logger.debug(
                    f"📞📥✅ Added connection to pool: {conn.remote_addr}, "
                    f"total: {len(self._connections)}"
                )

            while self._running and not conn.is_closed:
                data = await conn.receive_data()
                if not data:
                    logger.debug(
                        f"📞📥⚠️ No data received from {peer_info}, closing connection"
                    )
                    break

                logger.debug(
                    f"📞📥✅ Received data from {peer_info}: {len(data)} bytes"
                )
                await conn.send_data(data)  # echo
                logger.debug(f"📞📤✅ Echoed data back to {peer_info}")

        except asyncio.CancelledError:
            logger.debug(f"📞🛑✅ Connection handler cancelled for {peer_info}")
        except Exception as e:
            logger.error(f"📞❗❌ Error handling client {peer_info}: {e}")
        finally:
            async with self._lock:
                if conn in self._connections:
                    self._connections.remove(conn)
                    logger.debug(
                        "📞🔒✅ Removed connection from pool, remaining: "
                        f"{len(self._connections)}"
                    )
            await conn.close()
            logger.debug(f"📞🔒✅ Closed connection from {peer_info}")

    async def _close_writer(self, writer: asyncio.StreamWriter | None) -> None:
        """Close a StreamWriter with proper error handling."""
        if writer is None:
            logger.debug("📞🔒✍️ _close_writer: writer is None, returning.")
            return

        transport_to_abort = None
        if hasattr(writer, "transport"):
            transport_to_abort = writer.transport

        try:
            logger.debug(f"📞🔒✍️ _close_writer: writer.close() called for {writer!r}")
            writer.close()

            # Add detailed diagnostic logging here
            logger.debug(f"📞🔒✍️ DIAGNOSTIC: type(writer): {type(writer)}")
            logger.debug(f"📞🔒✍️ DIAGNOSTIC: repr(writer): {writer!r}")
            logger.debug(
                "📞🔒✍️ DIAGNOSTIC: hasattr(writer, 'wait_closed'): "
                f"{hasattr(writer, 'wait_closed')}"
            )
            if hasattr(writer, "wait_closed"):
                logger.debug(
                    "📞🔒✍️ DIAGNOSTIC: type(writer.wait_closed): "
                    f"{type(writer.wait_closed)}"
                )
                logger.debug(
                    "📞🔒✍️ DIAGNOSTIC: repr(writer.wait_closed): "
                    f"{writer.wait_closed!r}"
                )
            if hasattr(writer, "is_closing") and callable(writer.is_closing):
                logger.debug(
                    f"📞🔒✍️ DIAGNOSTIC: writer.is_closing(): {writer.is_closing()}"
                )
            else:
                logger.debug("📞🔒✍️ DIAGNOSTIC: writer has no is_closing() method.")

            await writer.wait_closed()
            logger.debug("📞🔒✅ Writer closed successfully")
        except Exception as e:
            logger.error(f"📞🔒⚠️ Error closing writer: {e}", exc_info=True)
            # If wait_closed() failed, attempt to abort the transport directly
            # as the normal cleanup might be compromised.
            if (
                transport_to_abort
                and hasattr(transport_to_abort, "abort")
                and callable(transport_to_abort.abort)
            ):
                logger.warning(
                    "📞🔒✍️ Exception during wait_closed, attempting direct "
                    f"abort of transport: {transport_to_abort!r}"
                )
                transport_to_abort.abort()
        finally:
            # This existing finally block can act as a final check, though the
            # direct abort in the except block should handle the primary case.
            if (
                transport_to_abort
            ):  # transport_to_abort was defined at the start of the method
                if (
                    hasattr(transport_to_abort, "is_closing")
                    and callable(transport_to_abort.is_closing)
                    and hasattr(transport_to_abort, "abort")
                    and callable(transport_to_abort.abort)
                ):
                    if not transport_to_abort.is_closing():
                        logger.debug(
                            "📞🔒✍️ FINALLY: Aggro abort in _close_writer for "
                            f"transport: {transport_to_abort!r}"
                        )
                        transport_to_abort.abort()
                    else:
                        logger.debug(
                            "📞🔒✍️ FINALLY: Transport already closing in "
                            f"_close_writer: {transport_to_abort!r}"
                        )
                elif hasattr(transport_to_abort, "abort") and callable(
                    transport_to_abort.abort
                ):
                    logger.debug(
                        "📞🔒✍️ FINALLY: No is_closing, attempting abort: "
                        f"{transport_to_abort!r}"
                    )
                    transport_to_abort.abort()
                else:
                    logger.debug(
                        f"📞🔒✍️ FINALLY: Transport {transport_to_abort!r} "
                        "has no abort method."
                    )
            else:
                logger.debug("📞🔒✍️ writer has no transport attribute in finally.")

    async def close(self) -> None:
        """
        Closes the Unix socket transport.

        This involves closing any active client connections, stopping the server,
        and removing the socket file from the filesystem.
        It is designed to be idempotent.
        """
        logger.debug(f"📞🔒🚀 Closing Unix socket transport at {self.path}")

        if self._closing:
            logger.debug("📞🔒✅ Already closing, skipping duplicate close")
            return

        self._closing = True
        self._running = False

        # Close active connections
        async with self._lock:
            connection_count = len(self._connections)
            if connection_count > 0:
                logger.debug(f"📞🔒🔄 Closing {connection_count} active connections")
                close_tasks = [conn.close() for conn in self._connections]
                await asyncio.gather(*close_tasks, return_exceptions=True)
                self._connections.clear()

        # Close client writer/reader
        if self._writer:
            await self._close_writer(self._writer)
            self._writer = None
            self._reader = None

        # Close server
        if self._server:
            try:
                self._server.close()
                await self._server.wait_closed()
                logger.debug("📞🔒✅ Closed server")
            except Exception as e:
                logger.error(f"📞🔒⚠️ Error closing server: {e}")
            finally:
                self._server = None

        socket_path = self.path
        if socket_path and os.path.exists(socket_path):
            try:
                # Make multiple attempts with proper error handling
                for _ in range(3):
                    try:
                        # Permissions are intentionally 0o660 for
                        # owner/group r/w during cleanup.
                        os.chmod(socket_path, 0o660)  # nosec B103
                        # Changed from 0o770, to ensure write access if needed
                        # for unlinking
                        os.unlink(socket_path)
                        logger.debug(f"📞🔒✅ Removed socket file: {socket_path}")
                        break
                    except OSError as e_unlink:
                        if e_unlink.errno != errno.ENOENT:  # Ignore file not found
                            logger.warning(
                                f"📞🔒⚠️ Retry removing socket file: {e_unlink}"
                            )
                            await asyncio.sleep(0.1)  # Brief pause before retry
                        else:
                            break  # File already gone
                else:  # If all retries failed
                    # Only raise if file still exists after retries
                    if os.path.exists(socket_path):
                        raise TransportError(
                            "Failed to remove socket file after multiple attempts"
                        )
            except Exception as e:
                logger.error(f"📞🔒❌ Failed to remove socket file: {e}")
                # Before raising, ensure loop has a chance to process other tasks
                await asyncio.sleep(
                    0
                )  # Yield just before raising the error from this path
                raise TransportError(f"Failed to remove socket file: {e}") from e

        self.endpoint = None
        self._closing = False
        logger.debug("📞🔒✅ Unix socket transport closed completely")


# 🐍🏗️🔌
