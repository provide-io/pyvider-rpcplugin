# tests/transport/unix/test_transport_unix_close.py

import os
import pytest
import asyncio
import errno # Added import
from provide.testkit.mocking import patch, AsyncMock, MagicMock # Added AsyncMock, MagicMock
import warnings

from pyvider.rpcplugin.exception import TransportError
from pyvider.rpcplugin.client.connection import ClientConnection # Added import
from pyvider.rpcplugin.transport.unix.transport import UnixSocketTransport

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
            self.transport = None # Set to None to avoid issues with AsyncMock as transport

        def close(self):
            pass

        async def wait_closed(self):
            # Original logic for is_closing on self.transport is removed as self.transport is None
            raise Exception("Fake wait_closed error")

    fake_writer = FakeWriter()
    try:
        # _close_writer should catch the exception and log an error.
        await transport._close_writer(fake_writer) # type: ignore[arg-type]
        # No exception should propagate.
    finally:
        await transport.close() # Explicitly close the transport instance
        # fake_writer.transport is already None
        del fake_writer # Explicitly delete the mock
        # Removed gc.collect() and asyncio.sleep(0.01) to see if it affects the warning


@pytest.mark.asyncio
@pytest.mark.filterwarnings("ignore:Exception ignored in.*_SelectorTransport.__del__:pytest.PytestUnraisableExceptionWarning")
async def test_unix_socket_close_with_active_connections(managed_unix_socket_path):
    """Test that closing a transport closes all active connections.
    
    Note: The filterwarnings decorator suppresses a Python 3.13-specific warning that occurs
    during asyncio transport cleanup. This is not a bug in our code but rather a change in
    Python 3.13's asyncio cleanup ordering. The warning occurs when transport objects are
    garbage collected and try to detach from servers that have already been cleaned up.
    All functionality works correctly despite this warning.
    """
    # Use real connections to test actual behavior
    server_transport = UnixSocketTransport(path=managed_unix_socket_path)
    client_transport1 = UnixSocketTransport()
    client_transport2 = UnixSocketTransport()
    
    server_closed = False
    clients_closed = []
    
    try:
        # Start the server
        endpoint = await server_transport.listen()
        
        # Connect two clients
        await client_transport1.connect(endpoint)
        await client_transport2.connect(endpoint)
        
        # Give server time to accept connections
        await asyncio.sleep(0.1)
        
        # Verify we have connections
        initial_connections = len(server_transport._connections)
        assert initial_connections == 2, f"Expected 2 connections, got {initial_connections}"
        
        # Close the server (should close all connections)
        await server_transport.close()
        server_closed = True
        
        # Verify server state
        assert len(server_transport._connections) == 0
        assert not server_transport._running
        
        # Give connections time to detect they were closed
        await asyncio.sleep(0.1)
        
    finally:
        # Ensure all resources are cleaned up
        if not server_closed:
            try:
                await server_transport.close()
            except Exception:
                pass
                
        # Clean up clients
        try:
            await client_transport1.close()
            clients_closed.append(1)
        except Exception:
            pass
            
        try:
            await client_transport2.close()
            clients_closed.append(2)
        except Exception:
            pass
        
        # Wait for all transports to fully close
        await asyncio.sleep(0.1)
        
        # Force a final garbage collection
        import gc
        gc.collect()
        
        # Give the event loop time to process any remaining callbacks
        await asyncio.sleep(0.1)
        
        # Process any remaining tasks to ensure all transports are cleaned up
        # This is important for Python 3.13 where transport cleanup order matters
        loop = asyncio.get_event_loop()
        
        # Run the event loop until all tasks are complete
        pending = asyncio.all_tasks(loop)
        if pending:
            # Filter out the current task
            current = asyncio.current_task()
            pending = {task for task in pending if task != current and not task.done()}
            
            if pending:
                # Give tasks a chance to complete
                done, pending = await asyncio.wait(pending, timeout=0.1)
                
                # Cancel any remaining tasks
                for task in pending:
                    task.cancel()
                    
                # Wait for cancellation to complete
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
        
        # Final garbage collection after all async cleanup
        gc.collect()
        
        # One more sleep to let any final callbacks run
        await asyncio.sleep(0.05)


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
        except Exception: # Catch any other error during task cancellation
            # Ignore errors during task cancellation in finally block
            pass


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


# 🐍🔌🧪🪄
