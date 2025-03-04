#!/usr/bin/env python3
# pyvider/rpcplugin/transport/unix.py

import asyncio
import errno
import os
import socket
import stat
import sys
import time
from contextlib import suppress

import attrs

from pyvider.rpcplugin.client.connection import ClientConnection
from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.transport.base import RPCPluginTransport


@attrs.define(frozen=False, slots=True)
class UnixSocketTransport(RPCPluginTransport):
    """
    Unix domain socket transport compatible with Go plugin implementation.
    
    Fixed for Go-Python interoperability with specialized handling for:
    - Socket path normalization (supporting unix:, unix:/, unix:///)
    - File permission handling (0777 for cross-process access)
    - Proper socket state verification and cleanup
    - Robust connection tracking and shutdown
    """

    path: str | None = attrs.field(default=None)
    _server: asyncio.AbstractServer | None = attrs.field(init=False, default=None)
    _writer: asyncio.StreamWriter | None = attrs.field(init=False, default=None)
    _reader: asyncio.StreamReader | None = attrs.field(init=False, default=None)
    endpoint: str | None = attrs.field(init=False, default=None)

    _connections: set[ClientConnection] = attrs.field(init=False, factory=set)
    _running: bool = attrs.field(init=False, default=False)
    _closing: bool = attrs.field(init=False, default=False)
    _lock: asyncio.Lock = attrs.field(init=False, factory=asyncio.Lock)

    _transport_name: str = "unix"

    def __attrs_post_init__(self):
        """Initialize transport state and possibly normalize path."""
        if not self.path:
            # Generate ephemeral path if none provided
            import tempfile
            import uuid
            self.path = os.path.join(
                tempfile.gettempdir(), f"pyvider-{uuid.uuid4()}.sock"
            )
            logger.debug(f"📞🚀 Generated ephemeral Unix socket path: {self.path}")
        else:
            # Normalize path if it has a unix: prefix
            self.path = self._normalize_path(self.path)

        self._server_ready = asyncio.Event()
        logger.debug(f"📞🚀 UnixSocketTransport initialized with path={self.path}")

    def _normalize_path(self, path: str) -> str:
        """Normalize Unix socket path, handling various formats."""
        # Handle unix:, unix:/, unix:// prefixes
        if path.startswith("unix:"):
            path = path[5:]  # Remove 'unix:'
            # Handle additional slashes
            while path.startswith("/") and not path.startswith("//"):
                path = path[1:]
                
        logger.debug(f"📞🚀 Normalized path: {path}")
        return path

    async def _check_socket_in_use(self) -> bool:
        """Check if socket is already in use by another process."""
        if not self.path or not os.path.exists(self.path):
            return False
            
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            logger.debug(f"📞🔍 Checking if socket {self.path} is in use")
            sock.connect(self.path)
            logger.debug(f"📞🔍❌ Socket {self.path} is in use")
            sock.close()
            return True
        except (ConnectionRefusedError, FileNotFoundError):
            logger.debug(f"📞🔍✅ Socket {self.path} is available")
            return False
        except OSError as e:
            if e.errno in (errno.ENOENT, errno.ECONNREFUSED):
                logger.debug(f"📞🔍✅ Socket {self.path} is available (after OSError)")
                return False
            logger.error(f"📞🔍❌ Error checking socket: {e}")
            return False
        finally:
            try:
                sock.close()
            except:
                pass

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle client connections with proper tracking."""
        peer_info = writer.get_extra_info("peername") or "unknown"
        logger.debug(f"📞🤝🚀 New client connection from {peer_info}")

        conn = ClientConnection(
            reader=reader, writer=writer, remote_addr=str(peer_info)
        )
        
        try:
            async with self._lock:
                self._connections.add(conn)
                logger.debug(f"📞📥✅ Added connection to pool: {conn.remote_addr}")

            while self._running and not conn.is_closed:
                data = await conn.receive_data()
                if not data:
                    logger.debug(f"📞📥⚠️ No data received from {peer_info}, closing connection")
                    break
                    
                logger.debug(f"📞📥✅ Received data from {peer_info}: {len(data)} bytes")
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
            await conn.close()
            logger.debug(f"📞🔒✅ Closed connection from {peer_info}")

    async def listen(self) -> str:
        """Start listening on Unix socket with cross-platform compatibility."""
        async with self._lock:
            if self._running:
                raise TransportError(f"Socket {self.path} is already running")

            # Check if socket file is in use
            socket_in_use = await self._check_socket_in_use()
            if socket_in_use:
                logger.error(f"📞🕹❌ Socket {self.path} already in use")
                raise TransportError(f"Socket {self.path} already in use")

            # Create directory if needed
            dir_path = os.path.dirname(self.path)
            if dir_path:
                os.makedirs(dir_path, exist_ok=True)

            # Remove stale socket file if it exists
            if os.path.exists(self.path):
                try:
                    os.unlink(self.path)
                    logger.debug(f"📞🕹✅ Removed stale socket file: {self.path}")
                    # Brief pause to ensure file system syncs
                    await asyncio.sleep(0.1)
                except OSError as e:
                    if e.errno != errno.ENOENT:  # Ignore if file doesn't exist
                        logger.error(f"📞🕹❌ Failed to remove stale socket: {e}")
                        raise TransportError(f"Failed to remove stale socket: {e}")

            try:
                logger.debug(f"📞🕹🚀 Creating Unix socket at {self.path}")
                self._server = await asyncio.start_unix_server(
                    self._handle_client, path=self.path
                )
                
                # Set world-writable permissions (crucial for Go interop)
                os.chmod(self.path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)  # 0777
                
                self._running = True
                self.endpoint = self.path
                logger.debug(f"📞🕹✅ Server listening on {self.path}")
                self._server_ready.set()
                return self.path
                
            except OSError as e:
                logger.error(f"📞🕹❌ Failed to create Unix socket: {e}")
                raise TransportError(f"Failed to create Unix socket: {e}")

    async def connect(self, endpoint: str) -> None:
        """Connect to Unix socket with robust path handling."""
        # Save original endpoint for logging
        orig_endpoint = endpoint
        
        # More robust normalization for Unix socket paths
        if endpoint.startswith("unix:"):
            # Handle various unix: prefix formats (unix:, unix:/, unix://)
            endpoint = endpoint[5:]
            while endpoint.startswith("/") and not endpoint.startswith("//"):
                endpoint = endpoint[1:]
        
        logger.debug(f"📞🤝🚀 Connecting to Unix socket at '{endpoint}' (from '{orig_endpoint}')")
        
        # Verify socket file exists with retries
        retries = 3
        for attempt in range(retries):
            if os.path.exists(endpoint):
                break
            if attempt < retries - 1:
                logger.debug(f"📞🤝⚠️ Socket file not found, retrying ({attempt+1}/{retries})") 
                await asyncio.sleep(0.5)  # Short delay between retries
        
        if not os.path.exists(endpoint):
            logger.error(f"📞🤝❌ Socket file does not exist: {endpoint}")
            raise TransportError(f"Socket {endpoint} does not exist")

        try:
            # Connect with timeout
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_unix_connection(endpoint),
                timeout=5.0
            )
            self.endpoint = endpoint
            logger.debug(f"📞🤝✅ Connected to Unix socket at {endpoint}")
        except Exception as e:
            logger.error(f"📞🤝❌ Failed to connect to Unix socket: {e}")
            raise TransportError(f"Failed to connect to Unix socket: {e}")

    async def close(self) -> None:
        """Close Unix socket transport with proper cleanup."""
        logger.debug(f"📞🔒🚀 Closing Unix socket transport at {self.path}")
        
        if self._closing:
            logger.debug("📞🔒 Already closing, skipping duplicate close")
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
            try:
                self._writer.close()
                await self._writer.wait_closed()
                logger.debug("📞🔒✅ Client writer closed")
            except Exception as e:
                logger.error(f"📞🔒⚠️ Error closing writer: {e}")
            finally:
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

        # Critical: small delay to ensure resources are released
        await asyncio.sleep(0.2)
        
        # Remove socket file
        if self.path and os.path.exists(self.path):
            try:
                # Ensure socket file is removed
                os.unlink(self.path)
                logger.debug(f"📞🔒✅ Removed socket file: {self.path}")
            except OSError as e:
                logger.error(f"📞🔒❌ Failed to remove socket file: {e}")
                raise TransportError(f"Failed to remove socket file: {e}")

        self.endpoint = None
        self._closing = False
        logger.debug("📞🔒✅ Unix socket transport closed completely")

### 🐍🏗️🔌
