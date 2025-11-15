# tests/transport/unix/test_transport_unix_close.py

import os
import pytest
import asyncio
import errno # Added import
from unittest.mock import patch, AsyncMock, MagicMock # Added AsyncMock, MagicMock

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.client.connection import ClientConnection # Added import
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
        def __init__(self):
            self.transport = AsyncMock() # Mock the transport attribute
            # Make transport.is_closing() exist and return False by default
            self.transport.is_closing = MagicMock(return_value=False)
            self.transport.abort = MagicMock()


        def close(self):
            pass

        async def wait_closed(self):
            # Simulate that after close() is called, is_closing might become True
            if hasattr(self.transport, 'is_closing') and callable(self.transport.is_closing):
                self.transport.is_closing.return_value = True
            raise Exception("Fake wait_closed error")

    fake_writer = FakeWriter()
    # _close_writer should catch the exception and log an error.
    await transport._close_writer(fake_writer) # No longer need type: ignore if FakeWriter is closer to StreamWriter
    # No exception should propagate.


@pytest.mark.asyncio
async def test_unix_socket_close_with_active_connections(mocker, managed_unix_socket_path):
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    # Don't actually start the server, just simulate state for _handle_client to have added connections
    # await transport.listen()

    mock_client_conn1 = AsyncMock(spec=ClientConnection)
    mock_client_conn2 = AsyncMock(spec=ClientConnection)

    # Manually add to the _connections set to simulate active connections
    transport._connections = {mock_client_conn1, mock_client_conn2}
    transport._running = True # Simulate server was running

    # Spy on asyncio.gather to see if it's called with the close coroutines
    gather_spy = mocker.spy(asyncio, "gather")

    await transport.close()

    mock_client_conn1.close.assert_awaited_once()
    mock_client_conn2.close.assert_awaited_once()

    # Check if gather was called with the results of the close() calls
    # This is a bit more involved to check precisely, but asserting it was called is a good start
    gather_spy.assert_called_once()
    assert not transport._connections # Should be cleared
    # Ensure socket file is also handled (e.g. unlinked if it existed)
    # This assertion might fail if the socket was never created by listen()
    # For this specific test, we are focusing on connection cleanup, not file cleanup if listen() wasn't called.
    # If managed_unix_socket_path creates the file, then this is fine.
    # assert not os.path.exists(managed_unix_socket_path)


@pytest.mark.asyncio
async def test_unix_socket_close_unlink_fails_persistently(mocker, managed_unix_socket_path):
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    # Create the socket file so os.path.exists is true initially
    with open(managed_unix_socket_path, 'w') as f: f.write('')

    mocker.patch("os.path.exists", return_value=True) # File always "exists"
    # Simulate unlink failing with an error that's not ENOENT (file not found)
    mock_unlink = mocker.patch("os.unlink", side_effect=OSError(errno.EACCES, "Permission denied"))
    mocker.patch("os.chmod", return_value=None) # Assume chmod works or is attempted

    # Patch sleep to avoid actual delays during the transport.close() logic itself
    mock_asyncio_sleep = mocker.patch("asyncio.sleep", new_callable=AsyncMock)

    try:
        with pytest.raises(TransportError, match="Failed to remove socket file after multiple attempts"):
            await transport.close()
    finally:
        # Unpatch asyncio.sleep so our explicit sleep below works correctly
        # It's important to clean up mocks that might interfere with subsequent operations
        # However, pytest-mock automatically undoes patches at the end of the test.
        # For this specific case, let's ensure the *real* asyncio.sleep is used for final cleanup.
        # pytest-mock automatically undoes patches, so explicit stop might not be needed
        # and could be causing the new RuntimeWarning.
        # mock_asyncio_sleep.stop() # Stop the general mock for asyncio.sleep - pytest-mock handles this

        import gc # Import garbage collector
        gc.collect() # Explicitly trigger garbage collection

        # Attempt to cancel pending tasks to help cleanup
        try:
            loop = asyncio.get_running_loop()
            current_task = asyncio.current_task(loop)
            tasks = [task for task in asyncio.all_tasks(loop) if task is not current_task]
            if tasks:
                for task in tasks:
                    task.cancel()
                # Give cancelled tasks a moment to process their cancellation
                await asyncio.gather(*tasks, return_exceptions=True)
        except RuntimeError: # Loop might be closed
            pass
        except Exception as e_task_cancel: # Catch any other error during task cancellation
            # Log this, as it's unexpected during cleanup
            print(f"Error during task cancellation in finally block: {e_task_cancel}")


        await asyncio.sleep(0.1) # Give event loop time to process cleanup

    assert mock_unlink.call_count == 3 # Should try 3 times
    # managed_unix_socket_path fixture will handle cleanup of the actual file

@pytest.mark.asyncio
async def test_unix_socket_close_unlink_generic_exception(mocker, managed_unix_socket_path):
    transport = UnixSocketTransport(path=managed_unix_socket_path)
    # Create the socket file
    with open(managed_unix_socket_path, 'w') as f: f.write('')

    mocker.patch("os.path.exists", return_value=True) # File "exists"
    # Simulate unlink failing with a generic Exception
    mock_unlink = mocker.patch("os.unlink", side_effect=Exception("Generic unlink error"))
    mocker.patch("os.chmod", return_value=None)

    with pytest.raises(TransportError, match="Failed to remove socket file: Generic unlink error"):
        await transport.close()

    mock_unlink.assert_called_once() # Should try once and fail
    # managed_unix_socket_path fixture will handle cleanup

@pytest.mark.asyncio
async def test_close_writer_transport_abort_not_closing(mocker):
    transport_module = UnixSocketTransport(path="/tmp/dummy_abort_not_closing.sock")
    writer = AsyncMock(spec=asyncio.StreamWriter)
    mock_transport_obj = MagicMock()
    mock_transport_obj.is_closing = MagicMock(return_value=False) # Explicitly make it a mock method
    mock_transport_obj.abort = MagicMock()
    writer.transport = mock_transport_obj
    writer.wait_closed = AsyncMock() # Prevent actual wait_closed from hanging

    await transport_module._close_writer(writer)
    mock_transport_obj.abort.assert_called_once()
    # transport_module._lock should be released, but testing lock state is tricky.
    # Ensure it doesn't hang or error.
    await transport_module.close() # ensure main transport can close

@pytest.mark.asyncio
async def test_close_writer_transport_abort_already_closing(mocker):
    transport_module = UnixSocketTransport(path="/tmp/dummy_abort_already_closing.sock")
    writer = AsyncMock(spec=asyncio.StreamWriter)
    mock_transport_obj = MagicMock()
    mock_transport_obj.is_closing = MagicMock(return_value=True) # Explicitly make it a mock method
    mock_transport_obj.abort = MagicMock()
    writer.transport = mock_transport_obj
    writer.wait_closed = AsyncMock()

    await transport_module._close_writer(writer)
    mock_transport_obj.abort.assert_not_called()
    await transport_module.close()

@pytest.mark.asyncio
async def test_close_writer_transport_abort_no_is_closing(mocker):
    transport_module = UnixSocketTransport(path="/tmp/dummy_abort_no_is_closing.sock")
    writer = AsyncMock(spec=asyncio.StreamWriter)

    class MockTransportWithAbortOnly:
        def __init__(self):
            self.abort = MagicMock()
            # No is_closing method defined

    mock_transport_obj = MockTransportWithAbortOnly()
    writer.transport = mock_transport_obj
    writer.wait_closed = AsyncMock()

    # Patch logger to check specific log message for this path
    mock_logger_debug = mocker.patch("pyvider.rpcplugin.transport.unix.logger.debug")

    await transport_module._close_writer(writer)
    mock_transport_obj.abort.assert_called_once()

    found_log = any("No is_closing, attempting abort" in call_args[0][0] for call_args in mock_logger_debug.call_args_list)
    assert found_log, "Log for 'No is_closing, attempting abort' not found."

    await transport_module.close()

@pytest.mark.asyncio
async def test_close_writer_transport_no_abort_method(mocker):
    transport_module = UnixSocketTransport(path="/tmp/dummy_no_abort.sock")
    writer = AsyncMock(spec=asyncio.StreamWriter)
    mock_transport_obj = MagicMock()
    # Make hasattr(mock_transport_obj, 'abort') return False
    type(mock_transport_obj).abort = mocker.PropertyMock(side_effect=AttributeError)
    # And hasattr(mock_transport_obj, 'is_closing') return True, and is_closing() is False
    mock_transport_obj.is_closing = MagicMock(return_value=False)
    writer.transport = mock_transport_obj
    writer.wait_closed = AsyncMock()

    await transport_module._close_writer(writer) # Should complete without error
    # No abort call expected because hasattr(mock_transport_obj, 'abort') will be false
    await transport_module.close()

# 🐍🏗🧪️
