# tests/transport/unix/test_transport_unix_connect.py

import asyncio
import os
import stat  # Added import
import pytest
from provide.testkit.mocking import AsyncMock, MagicMock  # Added MagicMock

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport.unix.transport import UnixSocketTransport

# Fixtures will be available via tests.fixtures through conftest.py
from tests.fixtures.dummy import DummyReader, DummyWriter  # Re-added specific import
# from tests.fixtures.transport import managed_unix_socket_path


@pytest.mark.asyncio
async def test_unix_connect_success(monkeypatch, managed_unix_socket_path) -> None:
    sock_path = managed_unix_socket_path
    transport = UnixSocketTransport(path=sock_path)
    dummy_reader = DummyReader(b"dummy")  # From tests.fixtures import *
    dummy_writer = DummyWriter()  # From tests.fixtures import *

    # Mock pathlib.Path.exists to return True for sock_path
    original_path_exists = lambda self: self._drv + self._root + str(self._path) == sock_path
    monkeypatch.setattr(
        "pathlib.Path.exists",
        lambda self: True if str(self) == sock_path else False,
    )

    # Mock pathlib.Path.stat to return an object that makes stat.S_ISSOCK(mode) true
    mock_stat_obj = MagicMock()
    # S_IFSOCK (0o140000) ORed with permissions (e.g. 0o777)
    socket_st_mode = 0o140000 | 0o777
    mock_stat_obj.st_mode = socket_st_mode

    monkeypatch.setattr(
        "pathlib.Path.stat",
        lambda self: mock_stat_obj if str(self) == sock_path else self.__class__.stat(self),
    )

    # Mock stat.S_ISSOCK to correctly interpret our mocked st_mode
    # S_ISSOCK typically checks (mode & S_IFMT) == S_IFSOCK.
    # Our mock should return True if the mode is exactly our socket_st_mode,
    # otherwise, fall back to original S_ISSOCK for other modes.
    original_s_issock = stat.S_ISSOCK
    monkeypatch.setattr(
        stat,
        "S_ISSOCK",
        lambda mode_arg: True if mode_arg == socket_st_mode else original_s_issock(mode_arg),
    )

    monkeypatch.setattr(
        asyncio,
        "open_unix_connection",
        AsyncMock(return_value=(dummy_reader, dummy_writer)),
    )

    await transport.connect("unix:" + sock_path)
    assert transport._writer is dummy_writer
    # Cleanup is handled by managed_unix_socket_path fixture


@pytest.mark.asyncio
async def test_unix_connect_nonexistent(monkeypatch, tmp_path) -> None:
    sock_path = str(tmp_path / "nonexistent.sock")
    transport = UnixSocketTransport(path=sock_path)
    monkeypatch.setattr(os.path, "exists", lambda path: False)
    with pytest.raises(TransportError, match="does not exist"):
        await transport.connect("unix:" + sock_path)


@pytest.mark.asyncio
async def test_unix_connect_oserror(monkeypatch, tmp_path) -> None:
    sock_path = str(tmp_path / "error.sock")
    with open(sock_path, "w") as f:
        f.write("")
    transport = UnixSocketTransport(path=sock_path)
    monkeypatch.setattr(
        asyncio,
        "open_unix_connection",
        AsyncMock(side_effect=OSError("Connect failed")),
    )
    with pytest.raises(TransportError, match="Path exists but is not a socket"):
        await transport.connect("unix:" + sock_path)
    os.unlink(sock_path)


@pytest.mark.asyncio
async def test_unix_socket_connect_invalid_endpoint() -> None:
    """
    Test connecting to an invalid endpoint with UnixSocketTransport.
    """
    transport = UnixSocketTransport(path="/tmp/this/better/be/an/invalid/endpoint-!@#%!#$!@$")
    with pytest.raises(TransportError):
        await transport.connect("invalid_endpoint")


@pytest.mark.asyncio
async def test_unix_socket_connect_nonexistent_path() -> None:
    """
    Test that UnixSocketTransport.connect raises TransportError when connecting to a nonexistent path.
    """
    transport = UnixSocketTransport()
    with pytest.raises(TransportError):
        await transport.connect("/nonexistent/path/pyvider.sock")


@pytest.mark.asyncio
async def test_unix_connect_retries_on_path_not_exists(mocker, managed_unix_socket_path):
    transport = UnixSocketTransport(path=managed_unix_socket_path)

    # pathlib.Path.exists will return False once, then True for subsequent calls
    # Use a callable to avoid StopIteration when list is exhausted
    call_count = {"count": 0}

    def mock_exists(self):
        call_count["count"] += 1
        return call_count["count"] > 1

    mocker.patch("pathlib.Path.exists", mock_exists)

    # Mock stat to succeed after path "appears"
    mock_stat_result = MagicMock()
    mock_stat_result.st_mode = stat.S_IFSOCK
    mocker.patch("pathlib.Path.stat", return_value=mock_stat_result)

    # Mock open_unix_connection to succeed
    mock_reader, mock_writer = AsyncMock(spec=asyncio.StreamReader), AsyncMock(spec=asyncio.StreamWriter)
    mocker.patch("asyncio.open_unix_connection", return_value=(mock_reader, mock_writer))

    # Mock asyncio.sleep to avoid actual sleep
    mock_sleep = mocker.patch("asyncio.sleep", new_callable=AsyncMock)

    await transport.connect(
        managed_unix_socket_path
    )  # Use the path directly as it's normalized in __attrs_post_init__

    # Verify that sleep was called due to retry (path didn't exist on first check)
    mock_sleep.assert_called_once_with(0.5)
    assert transport.endpoint == managed_unix_socket_path
    await transport.close()


@pytest.mark.asyncio
async def test_unix_connect_stat_fails(mocker, managed_unix_socket_path):
    transport = UnixSocketTransport(path=managed_unix_socket_path)

    mocker.patch("pathlib.Path.exists", return_value=True)  # Path exists
    mocker.patch("pathlib.Path.stat", side_effect=OSError("stat failed"))  # stat call fails

    # This will also call normalize_unix_path, ensure it doesn't interfere or mock if needed
    # For this test, direct path usage is fine as normalize_unix_path is simple for absolute paths
    with pytest.raises(TransportError, match="Error checking socket status: stat failed"):
        await transport.connect(managed_unix_socket_path)
    await transport.close()


### 🐍🏗🧪️


# 🐍🔌🧪🪄
