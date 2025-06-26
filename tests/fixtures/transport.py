# tests/fixtures/transport.py

import pytest
import pytest_asyncio

import asyncio

import os
import socket
import sys # Added import
import tempfile # Added import
import uuid
from pathlib import Path  # Ensure Path is imported
from typing import AsyncGenerator

from pyvider.telemetry import logger

from pyvider.rpcplugin.transport import (
    UnixSocketTransport,
)


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
async def unix_transport(
    managed_unix_socket_path: str,
):  # Added managed_unix_socket_path
    logger.debug("unix_transport fixture invoked, now using managed_unix_socket_path.")

    sock_path = managed_unix_socket_path

    logger.debug(f"Using socket at: {sock_path}")

    transport = UnixSocketTransport(path=sock_path)

    await transport.listen()
    logger.debug(
        f"DEBUG: Fixture initialized transport at {transport.path}, _server active: {hasattr(transport, '_server') and transport._server is not None}"
    )

    logger.debug(
        f"DEBUG: Fixture setup complete for unix_transport with path: {transport.path}"
    )
    try:
        yield transport
    finally:
        logger.debug(
            f"DEBUG: Starting cleanup for unix_transport with path: {sock_path}"
        )
        await (
            transport.close()
        )  # transport.close() should handle unlinking its own path
        # Double check for safety, as managed_unix_socket_path also has a finalizer.
        if os.path.exists(sock_path):
            logger.warning(
                f"DEBUG: Socket file {sock_path} still exists after transport.close() in unix_transport. Attempting unlink."
            )
            try:
                os.unlink(sock_path)
                logger.debug(
                    f"DEBUG: Successfully unlinked {sock_path} in unix_transport finalizer."
                )
            except OSError as e:
                logger.error(
                    f"DEBUG: Error unlinking {sock_path} in unix_transport finalizer: {e}"
                )
        logger.debug(
            f"DEBUG: Fixture unix_transport cleanup complete for path: {sock_path}"
        )


@pytest_asyncio.fixture(scope="function")
async def managed_unix_socket_path(
    request: pytest.FixtureRequest,
    tmp_path: Path,
) -> AsyncGenerator[str, None]:
    socket_filename = f"p_{uuid.uuid4().hex[:6]}.s" # Keep the short unique filename

    if sys.platform == "darwin": # macOS
        # Use /tmp/ directly on macOS to ensure shorter paths
        base_dir = Path(tempfile.gettempdir()) # Use tempfile.gettempdir() for robustness
        # Ensure /tmp exists and is writable, though it usually is.
        try:
            # Check if base_dir (e.g. /tmp) exists, create if not (unlikely for /tmp)
            if not base_dir.exists():
                 base_dir.mkdir(parents=True, exist_ok=True)

            # Attempt to create a temporary file to check writability
            # This is a more reliable check than os.access on some systems/setups
            with tempfile.NamedTemporaryFile(dir=base_dir, prefix="pyvider-test-") as tf:
                pass # Successfully created and automatically deleted means writable
            socket_path_obj = base_dir / socket_filename
            log_base_path_info = f"/tmp (via tempfile.gettempdir(): {base_dir})"
        except (OSError, PermissionError) as e:
             # Fallback if /tmp is not writable or accessible as expected
             logger.warning(f"macOS base directory ('{base_dir}') not usable ({e!r}), falling back to tmp_path for socket.")
             socket_path_obj = tmp_path / socket_filename # tmp_path is a Path object
             log_base_path_info = f"tmp_path ({tmp_path})"
    else: # Other platforms
        socket_path_obj = tmp_path / socket_filename # tmp_path is a Path object
        log_base_path_info = f"tmp_path ({tmp_path})"

    socket_path = str(socket_path_obj)

    logger.debug(
        f"🧪🔌 Providing managed socket path: {socket_path} (OS: {sys.platform}, Base: {log_base_path_info})"
    )

    # Ensure the path does not exist before yielding (defensive)
    if os.path.exists(socket_path):
        logger.warning(
            f"⚠️ Stale socket path {socket_path} detected before test. Attempting removal."
        )
        try:
            os.unlink(socket_path)
        except OSError as e:
            logger.error(
                f"⚠️ Could not remove pre-existing stale socket at {socket_path}: {e}. Test may fail."
            )
            # Depending on strictness, could raise an error here or let the test proceed.

    async def finalizer():
        logger.debug(
            f"🧪🧹 MANAGED_SOCKET_PATH_FINALIZER: Finalizing managed socket path: {socket_path}"
        )  # Existing + emphasis
        await asyncio.sleep(0.05)
        if os.path.exists(socket_path):  # socket_path_obj should be used here
            try:
                os.chmod(socket_path, 0o777)  # Ensure permissions allow unlink
                os.unlink(
                    socket_path
                )  # socket_path_obj.unlink(missing_ok=True) is better
                logger.debug(f"✅ Successfully unlinked socket: {socket_path}")
            except OSError as e:
                logger.warning(
                    f"⚠️ Error unlinking socket {socket_path} in finalizer: {e}. This might affect subsequent tests if not cleaned."
                )
        else:
            logger.debug(
                f"ℹ️ Socket path {socket_path} already cleaned up or never created by this instance."
            )

    async def finalizer_coro(): # Renamed to avoid confusion if we bring back old finalizer name
        logger.debug(
            f"🧪🧹 MANAGED_SOCKET_PATH_FINALIZER (async_finalizer): Finalizing managed socket path: {socket_path}"
        )
        await asyncio.sleep(0.05) # Keep the sleep, it might be generally helpful
        if os.path.exists(socket_path):
            try:
                os.chmod(socket_path, 0o777)
                os.unlink(socket_path)
                logger.debug(f"✅ Successfully unlinked socket (async_finalizer): {socket_path}")
            except Exception as e: # Keep catching generic Exception
                logger.warning(
                    f"⚠️ Error unlinking socket {socket_path} in async_finalizer (type: {type(e).__name__}): {e}"
                )
        else:
            logger.debug(
                f"ℹ️ Socket path {socket_path} (async_finalizer) already cleaned or never created."
            )

    # Revert to using request.addfinalizer with asyncio.ensure_future
    # This was the structure before the StopIteration error appeared.
    request.addfinalizer(lambda: asyncio.ensure_future(finalizer_coro()))

    yield socket_path


@pytest.fixture(scope="function", autouse=True)
async def transport_cleanup():
    yield
    # Force cleanup of transport resources
    await asyncio.sleep(0.1)  # Allow any pending cleanups


### 🐍🏗🧪️
