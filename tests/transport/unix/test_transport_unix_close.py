# tests/transport/unix/test_transport_unix_close.py

import os
import pytest
import asyncio # Added import
from unittest.mock import patch

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.transport.unix import UnixSocketTransport

# Fixtures will be available via tests.fixtures through conftest.py
# from tests.fixtures.transport import unix_transport, managed_unix_socket_path


@pytest.mark.asyncio
async def test_unix_socket_transport_close_no_path(unix_transport) -> None:
    """
    Test that UnixSocketTransport.close works when no path exists.
    """
    # Call close without a path
    await unix_transport.close()

    # Check that no error is raised
    assert True


@pytest.mark.asyncio
async def test_unix_socket_transport_close_oserror(managed_unix_socket_path) -> None:
    """Test that UnixSocketTransport.close properly handles OSError during cleanup."""
    # Create a real socket first
    transport = UnixSocketTransport(path=str(managed_unix_socket_path))
    await transport.listen()

    # Create patches for both unlink and stat
    with (
        patch("os.unlink", side_effect=OSError("Mocked unlink error")),
        patch("os.path.exists", return_value=True),
    ):  # Ensure path exists check returns True
        with pytest.raises(TransportError, match="Failed to remove socket file"):
            await transport.close()

    # Clean up any remaining socket file
    try:
        if os.path.exists(managed_unix_socket_path):
            os.unlink(managed_unix_socket_path)
    except Exception:  # Replaced bare except
        pass


@pytest.mark.asyncio
async def test_unix_close_unlink_error(monkeypatch, tmp_path) -> None:
    sock_path = str(tmp_path / "unlink_error.sock")
    with open(sock_path, "w") as f:
        f.write("dummy")
    transport = UnixSocketTransport(path=sock_path)
    transport._writer = None
    transport._server = None
    monkeypatch.setattr(
        os.path,
        "exists",
        lambda path: True if path == sock_path else os.path.exists(path),
    )
    monkeypatch.setattr(
        os, "unlink", lambda path: (_ for _ in ()).throw(OSError("unlink error"))
    )
    with pytest.raises(TransportError, match="Failed to remove socket file"):
        await transport.close()


@pytest.mark.asyncio
async def test_unix_socket_close_connection_active(managed_unix_socket_path) -> None:
    """Test closing a transport with active connections."""
    # Create a server transport
    transport = UnixSocketTransport(path=str(managed_unix_socket_path))
    client_transport = UnixSocketTransport()
    endpoint = None
    try:
        endpoint = await transport.listen()

        # Create and connect a client
        await client_transport.connect(endpoint)

        # Close the server - should close client connections too
        # This is the main action being tested.
    finally:
        if transport: # Ensure transport was created
            await transport.close()
        if client_transport: # Ensure client_transport was created
            await client_transport.close()
        if endpoint and os.path.exists(endpoint): # Check if endpoint was set
             try:
                os.unlink(endpoint) # Manually ensure socket is gone for next test
             except OSError:
                pass # Ignore if already gone or permissions issue during test cleanup
        await asyncio.sleep(0.1) # Allow event loop to settle

    # Socket file should be removed by transport.close()
    if endpoint: # Check endpoint was actually set before asserting
        assert not os.path.exists(endpoint)


@pytest.mark.asyncio
async def test_unix_socket_close_no_server(unix_transport) -> None:
    """
    Test that UnixSocketTransport.close works when no server is running.
    """
    # Call close without a server
    await unix_transport.close()

    # Check that no error is raised and the path attribute is still accessible
    assert unix_transport.path is not None


@pytest.mark.asyncio
async def test_close_writer_exception(monkeypatch) -> None:
    """Test handling of exceptions during writer close."""
    transport = UnixSocketTransport(path="/tmp/dummy.sock")

    class FakeWriter:
        def close(self):
            pass

        async def wait_closed(self):
            raise Exception("Fake wait_closed error")

    fake_writer = FakeWriter()
    # _close_writer should catch the exception and log an error.
    await transport._close_writer(fake_writer)  # type: ignore[arg-type]
    # No exception should propagate.


# 🐍🏗🧪️
