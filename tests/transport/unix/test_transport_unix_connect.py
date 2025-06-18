# tests/transport/unix/test_transport_unix_connect.py

import asyncio
import os
import stat  # Added import
import pytest
from unittest.mock import AsyncMock, MagicMock  # Added MagicMock

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport.unix import UnixSocketTransport

# Fixtures will be available via tests.fixtures through conftest.py
from tests.fixtures.dummy import DummyReader, DummyWriter  # Re-added specific import
# from tests.fixtures.transport import managed_unix_socket_path


@pytest.mark.asyncio
async def test_unix_connect_success(monkeypatch, managed_unix_socket_path) -> None:
    sock_path = managed_unix_socket_path
    transport = UnixSocketTransport(path=sock_path)
    dummy_reader = DummyReader(b"dummy")  # From tests.fixtures import *
    dummy_writer = DummyWriter()  # From tests.fixtures import *

    # Mock os.path.exists to return True for sock_path
    original_os_path_exists = os.path.exists
    monkeypatch.setattr(
        "os.path.exists",
        lambda path_arg: True
        if path_arg == sock_path
        else original_os_path_exists(path_arg),
    )

    # Mock os.stat to return an object that makes stat.S_ISSOCK(mode) true
    mock_stat_obj = MagicMock()
    # S_IFSOCK (0o140000) ORed with permissions (e.g. 0o777)
    socket_st_mode = 0o140000 | 0o777
    mock_stat_obj.st_mode = socket_st_mode

    original_os_stat = os.stat
    # Ensure the mock handles the path argument correctly, and any other potential args like dir_fd
    monkeypatch.setattr(
        "os.stat",
        lambda path_arg, *args, **kwargs: mock_stat_obj
        if path_arg == sock_path
        else original_os_stat(path_arg, *args, **kwargs),
    )

    # Mock stat.S_ISSOCK to correctly interpret our mocked st_mode
    # S_ISSOCK typically checks (mode & S_IFMT) == S_IFSOCK.
    # Our mock should return True if the mode is exactly our socket_st_mode,
    # otherwise, fall back to original S_ISSOCK for other modes.
    original_s_issock = stat.S_ISSOCK
    monkeypatch.setattr(
        stat,
        "S_ISSOCK",
        lambda mode_arg: True
        if mode_arg == socket_st_mode
        else original_s_issock(mode_arg),
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
    transport = UnixSocketTransport(
        path="/tmp/this/better/be/an/invalid/endpoint-!@#%!#$!@$"
    )
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


### 🐍🏗🧪️
