#!/usr/bin/env python3
# pyvider/rpcplugin/transport/unix.py

import asyncio
import errno
import os
import socket
import stat
from contextlib import suppress

import attrs

from pyvider.rpcplugin.client.connection import ClientConnection
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.transport.base import RPCPluginTransport


@attrs.define(frozen=False, slots=True)
class UnixSocketTransport(RPCPluginTransport):
    """
    Unix domain socket transport with enhanced reliability and state management.

    Features:
      - _check_socket_in_use() method (used by certain tests)
      - _verify_socket_state() for stale detection
      - Connection tracking for proper close
      - Crash / error handling
      - Emphasis on cleaning up .sock files
    """

    path: str | None = attrs.field(default=None)
    _server: asyncio.AbstractServer | None = attrs.field(init=False, default=None)
    _writer: asyncio.StreamWriter | None = attrs.field(init=False, default=None)
    endpoint: str | None = attrs.field(init=False, default=None)

    _connections: set[ClientConnection] = attrs.field(init=False, factory=set)
    _running: bool = attrs.field(init=False, default=False)
    _closing: bool = attrs.field(init=False, default=False)
    _lock: asyncio.Lock = attrs.field(init=False, factory=asyncio.Lock)

    def __attrs_post_init__(self):
        """
        Initialize transport state and possibly assign ephemeral sock name if none is provided.
        """
        logger.debug(f"🚀 __attrs_post_init__ called, path={self.path}")
        if not self.path:
            # fallback ephemeral name
            import tempfile
            import uuid
            self.path = os.path.join(tempfile.gettempdir(), f"pyvider-{uuid.uuid4()}.sock")
            logger.debug(f"🚀 Assigned ephemeral Unix socket path={self.path}")

        # Some test code calls _close_writer directly, so we keep it
        self._server_ready = asyncio.Event()
        logger.debug(f"🚀 UnixSocketTransport init complete for path={self.path}")

    async def _close_writer(self, writer: asyncio.StreamWriter | None) -> None:
        """
        Helper method for tests that may call _close_writer directly.
        This method only closes the provided writer.
        """
        logger.debug("🔒 Attempting _close_writer on a writer object.")
        if not writer:
            return
        try:
            writer.close()
            await writer.wait_closed()
            logger.debug("🔒 _close_writer succeeded.")
        except Exception as e:
            logger.error(f"🔒 _close_writer encountered error: {e}")

    async def _check_socket_in_use(self) -> bool:
        """
        Some tests specifically monkeypatch `_check_socket_in_use()` to simulate scenarios.
        By default, just calls _verify_socket_state to see if socket is truly active.
        """
        logger.debug(f"🔎 Checking if socket is in use via _check_socket_in_use(): {self.path}")
        # Re-use _verify_socket_state's logic. If it returns True => in use
        return await self._verify_socket_state()

    async def _verify_socket_state(self) -> bool:
        """
        If the socket file is present and connectable, we consider it in use.
        If present but not connectable, we consider it stale and remove it.
        """
        logger.debug(f"🔎 _verify_socket_state: Checking {self.path}")
        if not self.path or not os.path.exists(self.path):
            logger.debug("🔎 Socket file doesn't exist.")
            return False

        # If path is a directory or otherwise invalid
        if os.path.isdir(self.path):
            logger.error(f"🔎 Invalid path (dir, not socket): {self.path}")
            raise TransportError("Failed to create Unix socket: Path is a directory.")

        # Attempt to connect quickly
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                sock.connect(self.path)
                logger.debug(f"🔎 Socket {self.path} is active/in use.")
                return True
            except (ConnectionRefusedError, OSError) as e:
                logger.debug(f"🔎 Socket {self.path} found stale, removing. Reason: {e}")
                with suppress(OSError):
                    os.unlink(self.path)
                return False
            finally:
                sock.close()
        except Exception as e:
            logger.error(f"🔎 Unexpected error verifying socket state: {e}")
            return False

    async def _ensure_socket_directory(self) -> None:
        """
        If there's a directory in self.path, ensure it exists (some tests expect 'Failed to create Unix socket')
        """
        directory = os.path.dirname(self.path or "")
        if not directory:
            logger.debug("🗂️ No directory to ensure.")
            return
        try:
            os.makedirs(directory, mode=0o755, exist_ok=True)
        except OSError as e:
            logger.error(f"🗂️ Error creating dir {directory}: {e}")
            # Some tests want exactly "Failed to create Unix socket"
            raise TransportError(f"Failed to create Unix socket: {e}")

    async def _cleanup_stale_socket(self) -> None:
        """
        Remove an old or stale socket file if it exists. Some tests want to see 'Failed to remove stale socket'.
        """
        logger.debug("🧹 Checking for stale socket file.")
        if self.path and os.path.exists(self.path):
            try:
                os.unlink(self.path)
                logger.debug(f"🧹 Removed stale socket file: {self.path}")
                await asyncio.sleep(0.1)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    logger.error(f"🧹 Could not remove stale socket: {e}")
                    raise TransportError(f"Failed to remove stale socket: {e}")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ) -> None:
        """
        Echo-like handle. In actual usage, might be your gRPC server. 
        Some tests do direct read/write checks expecting an echo.
        """
        peer_info = writer.get_extra_info('peername')
        logger.debug(f"👥 _handle_client invoked, peer={peer_info}")

        conn = ClientConnection(
            reader=reader,
            writer=writer,
            remote_addr=str(peer_info)
        )
        try:
            async with self._lock:
                self._connections.add(conn)
            logger.debug(f"👥 Tracking new connection from {peer_info}")

            # Some concurrency tests rely on a small sleep so that multiple clients can connect
            await asyncio.sleep(0.05)

            while self._running and not conn.is_closed:
                data = await conn.receive_data()
                if not data:
                    logger.debug(f"👥 No data from {peer_info}, likely closed.")
                    break
                logger.debug(f"👥 Received {len(data)} bytes from {peer_info}")
                await conn.send_data(data)  # echo
                logger.debug(f"👥 Echoed data back to {peer_info}")

        except asyncio.CancelledError:
            logger.debug(f"👥 Connection to {peer_info} cancelled.")
        except Exception as e:
            logger.error(f"👥❌ Error in handle_client for {peer_info}: {e}")
        finally:
            async with self._lock:
                if conn in self._connections:
                    self._connections.remove(conn)
            await conn.close()
            logger.debug(f"👥 Connection closed from {peer_info}")

    async def listen(self) -> str:
        """
        Start listening on the Unix socket. Some tests look for 'Failed to start Unix socket server' 
        if we raise an exception here.
        """
        async with self._lock:
            logger.debug(f"🔉 Attempting to listen on path={self.path}")

            if await self._check_socket_in_use():
                msg = f"Socket {self.path} is already in use"
                logger.error(msg)
                raise TransportError(msg)

            await self._ensure_socket_directory()
            await self._cleanup_stale_socket()

            try:
                self._server = await asyncio.start_unix_server(
                    self._handle_client, path=self.path
                )
                self._running = True
                self.endpoint = self.path

                # Some tests check for 0o777 specifically
                os.chmod(self.path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)

                logger.debug(f"🔉✅ Server listening on {self.path}")
                self._server_ready.set()
                return self.path

            except Exception as e:
                logger.error(f"🔉❌ Could not start server on {self.path}: {e}")
                raise TransportError(f"Failed to start Unix socket server: {e}")

    async def connect(self, endpoint: str) -> None:
        """
        Connect as a client to the Unix socket. Some tests expect 'does not exist' if the file is missing.
        or 'Failed to connect to Unix socket' if there's an OSError.
        """
        logger.debug(f"🔌 connect called with endpoint={endpoint}")
        ep = endpoint.replace("unix:", "", 1)

        if not os.path.exists(ep):
            logger.error(f"🔌❌ Socket {ep} does not exist")
            raise TransportError(f"Socket {ep} does not exist")

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_unix_connection(ep), timeout=5.0
            )
            self._writer = writer
            self.endpoint = ep
            logger.debug(f"🔌✅ Connected to {ep}")
        except TimeoutError as e:
            logger.error(f"🔌❌ Timed out connecting to {ep}: {e}")
            raise TransportError(f"Connection timeout: {e}")
        except OSError as e:
            logger.error(f"🔌❌ OSError while connecting to {ep}: {e}")
            raise TransportError(f"Failed to connect to Unix socket: {e}")

    async def close(self) -> None:
        """
        Close everything: the connections, the server, the writer, then remove the socket file.
        Some tests specifically check for 'Mocked unlink error' or 'Failed to remove socket file:'.
        """
        logger.debug("🚪 close() called on UnixSocketTransport.")
        if self._closing:
            logger.debug("🚪 Already closing, skipping.")
            return
        self._closing = True
        self._running = False

        # close connections
        async with self._lock:
            close_tasks = [c.close() for c in self._connections]
            if close_tasks:
                logger.debug(f"🚪 Closing {len(close_tasks)} active connections.")
                await asyncio.gather(*close_tasks, return_exceptions=True)
            self._connections.clear()

        # close any client writer
        if self._writer:
            await self._close_writer(self._writer)
            self._writer = None

        # close server
        if self._server:
            self._server.close()
            try:
                await self._server.wait_closed()
                logger.debug("🚪 Server closed.")
            except Exception as e:
                logger.error(f"🚪❌ Error while waiting for server to close: {e}")
            finally:
                self._server = None

        # short pause so OS can release the file handle
        await asyncio.sleep(0.1)

        # remove socket file if it still exists
        if self.path and os.path.exists(self.path):
            try:
                os.unlink(self.path)
                logger.debug(f"🚪✅ Removed socket file: {self.path}")
            except OSError as e:
                logger.error(f"🚪❌ Could not remove socket file {self.path}: {e}")
                raise TransportError(f"Failed to remove socket file: {e}")

        self.endpoint = None
        self._closing = False
        logger.debug("🚪 close() completed for UnixSocketTransport.")
