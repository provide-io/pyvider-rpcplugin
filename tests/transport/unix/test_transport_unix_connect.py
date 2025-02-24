
# tests/transport/unix/test_transport_unix_connect.py

import asyncio
import errno
import os
import socket
import stat
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport.unix import UnixSocketTransport
from pyvider.rpcplugin.client.connection import ClientConnection

from tests.fixtures import *

@pytest.mark.asyncio
async def test_unix_connect_success(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "connect.sock")
    # Create the file so that os.path.exists returns True.
    with open(sock_path, "w") as f:
        f.write("")
    transport = UnixSocketTransport(path=sock_path)
    dummy_reader = DummyReader(b"dummy")
    dummy_writer = DummyWriter()
    monkeypatch.setattr(asyncio, "open_unix_connection", AsyncMock(return_value=(dummy_reader, dummy_writer)))
    await transport.connect("unix:" + sock_path)
    assert transport._writer is dummy_writer
    os.unlink(sock_path)

@pytest.mark.asyncio
async def test_unix_connect_nonexistent(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "nonexistent.sock")
    transport = UnixSocketTransport(path=sock_path)
    monkeypatch.setattr(os.path, "exists", lambda path: False)
    with pytest.raises(TransportError, match="does not exist"):
        await transport.connect("unix:" + sock_path)

@pytest.mark.asyncio
async def test_unix_connect_oserror(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "error.sock")
    with open(sock_path, "w") as f:
        f.write("")
    transport = UnixSocketTransport(path=sock_path)
    monkeypatch.setattr(asyncio, "open_unix_connection", AsyncMock(side_effect=OSError("Connect failed")))
    with pytest.raises(TransportError, match="Failed to connect to Unix socket"):
        await transport.connect("unix:" + sock_path)
    os.unlink(sock_path)

@pytest.mark.asyncio
async def test_unix_socket_connect_invalid_endpoint():
    """
    Test connecting to an invalid endpoint with UnixSocketTransport.
    """
    transport = UnixSocketTransport(path="/tmp/this/better/be/an/invalid/endpoint-!@#%!#$!@$")
    with pytest.raises(TransportError):
        await transport.connect("invalid_endpoint")

@pytest.mark.asyncio
async def test_unix_socket_connect_nonexistent_path():
    """
    Test that UnixSocketTransport.connect raises TransportError when connecting to a nonexistent path.
    """
    transport = UnixSocketTransport()
    with pytest.raises(TransportError):
        await transport.connect("/nonexistent/path/pyvider.sock")

################################################################################

@pytest.mark.asyncio
async def test_unix_connect_success(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "connect.sock")
    # Create the file so that os.path.exists returns True.
    with open(sock_path, "w") as f:
        f.write("")
    transport = UnixSocketTransport(path=sock_path)
    dummy_reader = DummyReader(b"dummy")
    dummy_writer = DummyWriter()
    monkeypatch.setattr(asyncio, "open_unix_connection", AsyncMock(return_value=(dummy_reader, dummy_writer)))
    await transport.connect("unix:" + sock_path)
    assert transport._writer is dummy_writer
    os.unlink(sock_path)

@pytest.mark.asyncio
async def test_unix_connect_nonexistent(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "nonexistent.sock")
    transport = UnixSocketTransport(path=sock_path)
    monkeypatch.setattr(os.path, "exists", lambda path: False)
    with pytest.raises(TransportError, match="does not exist"):
        await transport.connect("unix:" + sock_path)

@pytest.mark.asyncio
async def test_unix_connect_oserror(monkeypatch, tmp_path):
    sock_path = str(tmp_path / "error.sock")
    with open(sock_path, "w") as f:
        f.write("")
    transport = UnixSocketTransport(path=sock_path)
    monkeypatch.setattr(asyncio, "open_unix_connection", AsyncMock(side_effect=OSError("Connect failed")))
    with pytest.raises(TransportError, match="Failed to connect to Unix socket"):
        await transport.connect("unix:" + sock_path)
    os.unlink(sock_path)

################################################################################
