# tests/fixtures/transport.py

import asyncio
import os
import socket
import sys
import tempfile
import uuid
from collections.abc import AsyncGenerator, Callable  # Added Callable
from pathlib import Path

import pytest_asyncio
from pytest import FixtureRequest  # Added FixtureRequest

from pyvider.rpcplugin.transport import (
    UnixSocketTransport,
)
from pyvider.telemetry import logger


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
        sock: socket.socket | None = None  # Initialize sock
        for attempt in range(3):  # Retry up to 3 times
            async with self._lock:
                try:
                    if not os.path.exists(self._path):
                        self._active = False
                        return False

                    try:
                        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        sock.connect(self._path)
                        self._active = True
                        self._connections += 1
                        return True  # Return immediately after successful connect
                    except (ConnectionRefusedError, FileNotFoundError):
                        if attempt < 2:
                            await asyncio.sleep(0.2)
                            continue
                        self._active = False
                        return False
                    except OSError:
                        self._active = False
                        return False
                    finally:
                        if sock:
                            sock.close()
                except Exception as e:
                    logger.error(f"Socket state check error: {e}")
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
                os.chmod(self._path, 0o770)  # nosec B103
                os.unlink(self._path)
                logger.debug(f"Cleaned up socket file: {self._path}")
            except Exception as e:
                logger.warning(f"Error cleaning up socket file {self._path}: {e}")


@pytest_asyncio.fixture
async def socket_monitor() -> AsyncGenerator[Callable[[str], SocketStateMonitor]]:
    """Fixture providing socket state monitoring with proper cleanup."""
    monitors: list[SocketStateMonitor] = []

    def create_monitor(path: str) -> SocketStateMonitor:
        monitor = SocketStateMonitor(path)
        monitors.append(monitor)
        return monitor

    yield create_monitor

    for monitor in monitors:
        try:
            await monitor.cleanup()
        except Exception as e:
            logger.warning(f"Error during monitor cleanup for {monitor.path}: {e}")

    for monitor in monitors:
        if os.path.exists(monitor.path):
            try:
                os.chmod(monitor.path, 0o770)  # nosec B103
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
) -> AsyncGenerator[UnixSocketTransport]:
    logger.debug("unix_transport fixture invoked, using managed_unix_socket_path.")
    sock_path = managed_unix_socket_path
    logger.debug(f"Using socket at: {sock_path}")

    transport = UnixSocketTransport(path=sock_path)
    await transport.listen()
    logger.debug(
        f"DEBUG: Fixture initialized transport at {transport.path}, "
        f"_server active: {hasattr(transport, '_server') and transport._server is not None}"
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
        await transport.close()
        if os.path.exists(sock_path):
            logger.warning(
                f"DEBUG: Socket file {sock_path} still exists after "
                f"transport.close() in unix_transport. Attempting unlink."
            )
            try:
                os.unlink(sock_path)
                logger.debug(
                    f"DEBUG: Successfully unlinked {sock_path} "
                    f"in unix_transport finalizer."
                )
            except OSError as e:
                logger.error(
                    f"DEBUG: Error unlinking {sock_path} "
                    f"in unix_transport finalizer: {e}"
                )
        logger.debug(
            f"DEBUG: Fixture unix_transport cleanup complete for path: {sock_path}"
        )


@pytest_asyncio.fixture(scope="function")
async def managed_unix_socket_path(
    request: FixtureRequest,  # Changed from pytest.FixtureRequest
    tmp_path: Path,
) -> AsyncGenerator[str]:
    socket_filename = f"p_{uuid.uuid4().hex[:6]}.s"
    log_base_path_info: str

    if sys.platform == "darwin":  # macOS
        base_dir = Path(tempfile.gettempdir())
        try:
            if not base_dir.exists():
                base_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                dir=base_dir, prefix="pyvider-test-"
            ):  # Removed 'as tf' as it was unused
                pass
            socket_path_obj = base_dir / socket_filename
            log_base_path_info = f"/tmp (via tempfile.gettempdir(): {base_dir})"
        except (OSError, PermissionError) as e:
            logger.warning(
                f"macOS base directory ('{base_dir}') not usable ({e!r}), "
                f"falling back to tmp_path for socket."
            )
            socket_path_obj = tmp_path / socket_filename
            log_base_path_info = f"tmp_path ({tmp_path})"
    else:  # Other platforms
        socket_path_obj = tmp_path / socket_filename
        log_base_path_info = f"tmp_path ({tmp_path})"

    socket_path = str(socket_path_obj)

    logger.debug(
        f"🧪🔌 Providing managed socket path: {socket_path} "
        f"(OS: {sys.platform}, Base: {log_base_path_info})"
    )

    if os.path.exists(socket_path):
        logger.warning(
            f"⚠️ Stale socket path {socket_path} detected before test. "
            f"Attempting removal."
        )
        try:
            os.unlink(socket_path)
        except OSError as e:
            logger.error(
                f"⚠️ Could not remove pre-existing stale socket at {socket_path}: {e}. "
                f"Test may fail."
            )

    async def finalizer_coro() -> None:
        logger.debug(
            f"🧪🧹 MANAGED_SOCKET_PATH_FINALIZER (async_finalizer): "
            f"Finalizing managed socket path: {socket_path}"
        )
        await asyncio.sleep(0.05)
        if os.path.exists(socket_path):
            try:
                os.chmod(socket_path, 0o777)  # nosec B103
                os.unlink(socket_path)
                logger.debug(
                    f"✅ Successfully unlinked socket (async_finalizer): {socket_path}"
                )
            except Exception as e:
                logger.warning(
                    f"⚠️ Error unlinking socket {socket_path} in async_finalizer "
                    f"(type: {type(e).__name__}): {e}"
                )
        else:
            logger.debug(
                f"ℹ️ Socket path {socket_path} (async_finalizer) "
                f"already cleaned or never created."
            )

    request.addfinalizer(lambda: asyncio.ensure_future(finalizer_coro()))

    yield socket_path


### 🐍🏗🧪️
