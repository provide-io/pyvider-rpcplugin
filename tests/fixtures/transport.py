
# tests/fixtures/transport.py

import pytest
import pytest_asyncio

import asyncio

import os
import socket

from pyvider.telemetry import logger

from pyvider.rpcplugin.transport import (
    UnixSocketTransport,
)

from ..fixtures import *


class SocketStateMonitor:
    """Utility for monitoring socket state."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._active = False
        self._connections = 0
        self._lock = asyncio.Lock()

    @property
    def active(self) -> bool:
        return self._active

    @property
    def path(self) -> str:
        return self._path

    @property
    def connections(self) -> int:
        return self._connections

    async def exists(self) -> bool:
        """Check if the socket file exists."""
        return os.path.exists(self._path)

    async def is_connectable(self) -> bool:
        """Check if the socket is connectable (exists and accepting connections)."""
        return await self.check_state()

    async def check_state(self) -> bool:
        """Check current socket state with retries."""
        for attempt in range(3):  # Retry up to 3 times
            async with self._lock:
                try:
                    if not os.path.exists(self._path):
                        self._active = False
                        return False

                    # Check if it's a valid socket file
                    try:
                        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        sock.connect(self._path)
                        self._active = True
                        self._connections += 1
                        sock.close()
                        return True
                    except (ConnectionRefusedError, FileNotFoundError):
                        # Socket exists but nothing listening
                        if attempt < 2:  # Only sleep if we have more retries
                            await asyncio.sleep(0.2)  # Wait for socket to be ready
                            continue
                        self._active = False
                        return False
                    except OSError:
                        self._active = False
                        return False
                    finally:
                        try:
                            sock.close()
                        except (NameError, UnboundLocalError):
                            pass
                except Exception as e:
                    logger.error(f"Socket state check error: {e}")

            # Sleep between retries
            if attempt < 2:
                await asyncio.sleep(0.2)

        self._active = False
        return False

    async def wait_for_active(self, timeout: float = 3.0) -> bool:
        """Wait for socket to become active with regular checks."""
        end_time = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < end_time:
            if await self.check_state():
                return True
            await asyncio.sleep(0.1)
        return False

    async def wait_for_inactive(self, timeout: float = 3.0) -> bool:
        """Wait for socket to become inactive."""
        end_time = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < end_time:
            if not await self.check_state():
                return True
            await asyncio.sleep(0.1)
        return False

    async def cleanup(self) -> None:
        """Clean up the socket file."""
        if os.path.exists(self._path):
            try:
                # Attempt to make it writable first
                os.chmod(self._path, 0o770)
                os.unlink(self._path)
                logger.debug(f"Cleaned up socket file: {self._path}")
            except Exception as e:
                logger.warning(f"Error cleaning up socket file {self._path}: {e}")

@pytest_asyncio.fixture
async def socket_monitor():
    """Fixture providing socket state monitoring with proper cleanup."""
    monitors = []

    def create_monitor(path: str) -> SocketStateMonitor:
        monitor = SocketStateMonitor(path)
        monitors.append(monitor)
        return monitor

    yield create_monitor

    # Force cleanup of all monitored sockets
    for monitor in monitors:
        try:
            await monitor.cleanup()
        except Exception as e:
            logger.warning(f"Error during monitor cleanup for {monitor.path}: {e}")

    # Double check that all sockets are gone
    for monitor in monitors:
        if os.path.exists(monitor.path):
            try:
                # Final attempt with elevated permissions
                os.chmod(monitor.path, 0o770)
                os.unlink(monitor.path)
                logger.debug(f"Cleaned up leftover socket: {monitor.path}")
            except Exception as e:
                logger.error(f"Final cleanup failed for {monitor.path}: {e}")

@pytest_asyncio.fixture
async def unused_tcp_port() -> int:
    """Fixture to get an unused TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

@pytest_asyncio.fixture
async def unix_transport():

    logger.debug("unix_transport fixture invoked.")

    import tempfile

    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        sock_path = tmp.name

    logger.debug(f"Using socket at: {sock_path}")

    # sock_path=f"/tmp/pyvider_test_{os.getpid()}.sock"

    transport = UnixSocketTransport(path=sock_path)

    await transport.listen()
    logger.debug(
        f"DEBUG: Fixture initialized transport at {transport.path}, _server: {transport._server}"
    )
    # logger.debug(f"DEBUG: Initialized transport at {transport.path} of type {type(transport)}")

    logger.debug(f"DEBUG: Fixture setup complete: {transport.path}")
    try:
        yield transport
    finally:
        await transport.close()
        if os.path.exists(sock_path):
            logger.debug("DEBUG: removing sock_path")
            os.unlink(sock_path)
        logger.debug("DEBUG: Fixture cleanup complete")

@pytest_asyncio.fixture(scope="function")
async def unique_socket_path() -> str:
    """Generate a unique socket path that won't conflict between tests."""
    import uuid
    import tempfile

    # Use a shorter unique ID to avoid path length issues
    unique_id = uuid.uuid4().hex[:8]

    # Use tempfile.gettempdir() which handles platform differences
    temp_dir = tempfile.gettempdir()
    socket_path = os.path.join(temp_dir, f"pv_{unique_id}.sock")

    # Ensure path doesn't exist before starting
    if os.path.exists(socket_path):
        try:
            os.chmod(socket_path, 0o770)
            os.unlink(socket_path)
        except OSError as e:
            logger.warning(f"🧪⚠️ Failed to clean stale socket: {e}")

    logger.debug(f"🧪🔌 Created unique socket path: {socket_path}")
    yield socket_path

    # Cleanup after test
    if os.path.exists(socket_path):
        try:
            os.chmod(socket_path, 0o770)
            os.unlink(socket_path)
        except OSError as e:
            logger.warning(f"🧪⚠️ Cleanup failed for socket {socket_path}: {e}")

    # Allow event loop to process socket close events
    await asyncio.sleep(0.1)

@pytest.fixture(scope="function", autouse=True)
async def transport_cleanup():
    yield
    # Force cleanup of transport resources
    await asyncio.sleep(0.1)  # Allow any pending cleanups

# 🐍🏗🧪️
