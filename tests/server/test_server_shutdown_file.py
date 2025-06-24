import asyncio
import os
import tempfile
from pathlib import Path
import contextlib

import pytest
from unittest.mock import AsyncMock

from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from pyvider.rpcplugin.types import HandlerT, ServerT
from pyvider.telemetry import logger
from pyvider.rpcplugin.transport import UnixSocketTransport

class DummyHandler:
    pass

class DummyProtocol(RPCPluginProtocol[ServerT, HandlerT]):
    async def get_grpc_descriptors(self) -> tuple[None, str]:
        return None, "dummy_service_name"

    async def add_to_server(self, server: ServerT, handler: HandlerT) -> None:
        pass

@pytest.fixture
def temp_shutdown_file():
    with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
        path = tmpfile.name
    if os.path.exists(path):
        os.unlink(path)
    yield Path(path)
    if os.path.exists(path):
        os.unlink(path)

@pytest.mark.asyncio
async def test_server_shuts_down_on_file_creation(temp_shutdown_file, mocker):
    shutdown_file_path_str = str(temp_shutdown_file)
    mocker.patch.object(rpcplugin_config, 'shutdown_file_path', return_value=shutdown_file_path_str)
    
    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)

    # FIX: Use a side_effect to robustly set attributes that _negotiate_handshake would set.
    async def mock_negotiate_side_effect():
        server._protocol_version = 1
        server._transport_name = "unix"
        server._transport = UnixSocketTransport(path="/tmp/dummy_for_shutdown_test.sock")
    
    mocker.patch.object(server, '_negotiate_handshake', side_effect=mock_negotiate_side_effect)

    mocker.patch.object(server, '_register_signal_handlers')
    mocker.patch.object(server, '_setup_server', new_callable=AsyncMock)
    mocker.patch('sys.stdout.buffer.write')
    mocker.patch('sys.stdout.buffer.flush')

    serve_task = asyncio.create_task(server.serve())
    try:
        await asyncio.sleep(0.2)
        
        assert server._shutdown_watcher_task is not None, "Shutdown watcher task not started"

        with open(shutdown_file_path_str, "w") as f:
            f.write("shutdown")

        await asyncio.wait_for(serve_task, timeout=5.0)
        
        assert server._serving_future.done(), "Server's serving future was not done after shutdown."

    finally:
        if not serve_task.done():
            serve_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await serve_task

@pytest.mark.asyncio
async def test_watch_shutdown_file_cancelled(tmp_path, mocker):
    shutdown_file = tmp_path / "shutdown_cancel.file"
    # Configure server to use the shutdown file
    mocker.patch("pyvider.rpcplugin.server.rpcplugin_config.shutdown_file_path", return_value=str(shutdown_file))

    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)
    server._shutdown_file_path = str(shutdown_file) # Ensure it's set directly

    # Mock sleep to make the watcher loop quickly for the test
    original_sleep = asyncio.sleep
    # Using a side effect to allow the first sleep in the loop to proceed briefly, then cancel.
    sleep_calls = 0
    async def sleep_side_effect(delay):
        nonlocal sleep_calls
        sleep_calls += 1
        if sleep_calls > 1: # After the first actual sleep(1) in the loop
            # Subsequent calls to sleep (e.g. sleep(5) in except) will be very short
            return await original_sleep(0.001)
        return await original_sleep(delay)

    mocker.patch("asyncio.sleep", side_effect=sleep_side_effect)

    watcher_task = asyncio.create_task(server._watch_shutdown_file())

    await asyncio.sleep(0.01) # Let task start and hit the first sleep attempt

    assert watcher_task.cancel() # Request cancellation

    # Await the task; it should complete because it catches CancelledError
    try:
        await asyncio.wait_for(watcher_task, timeout=0.5)
    except asyncio.TimeoutError:
        pytest.fail("Watcher task did not complete after cancellation")

    assert watcher_task.done()
    assert watcher_task.exception() is None # Should have handled CancelledError and exited cleanly
    assert not server._shutdown_event.is_set()

@pytest.mark.asyncio
async def test_watch_shutdown_file_os_path_exists_raises_exception(tmp_path, mocker):
    shutdown_file = tmp_path / "shutdown_exists_exception.file"
    mocker.patch("pyvider.rpcplugin.server.rpcplugin_config.shutdown_file_path", return_value=str(shutdown_file))
    mock_logger_error = mocker.patch("pyvider.rpcplugin.server.logger.error")

    protocol = DummyProtocol()
    handler = DummyHandler()
    server = RPCPluginServer(protocol=protocol, handler=handler)
    server._shutdown_file_path = str(shutdown_file)

    # Mock os.path.exists to raise an exception
    mocker.patch("os.path.exists", side_effect=Exception("Test os.path.exists error"))
    # Mock sleep to make the loop run multiple times quickly if the error is caught and looped
    mock_sleep = mocker.patch("pyvider.rpcplugin.server.asyncio.sleep", new_callable=AsyncMock)


    watcher_task = asyncio.create_task(server._watch_shutdown_file())

    # Wait for the mocked sleep to be called, indicating the loop is running and hitting the error
    # The loop structure is: try { os.path.exists -> error } except { log; sleep(5) }
    # So, after the error, sleep(5) (mocked) should be called.
    await asyncio.sleep(0.01) # Small delay for task to start

    # Try to wait for sleep to be called a couple of times to ensure the loop runs
    for _ in range(10): # Try up to 10 * 0.01s = 0.1s
        if mock_sleep.call_count >= 2: # Wait for at least 2 calls to the mocked sleep(5)
            break
        await asyncio.sleep(0.01)

    assert mock_logger_error.called
    found_log = False
    for call_args_tuple in mock_logger_error.call_args_list:
        args, _ = call_args_tuple
        if args and "Error in shutdown file watcher: Test os.path.exists error" in args[0]:
            found_log = True
            break
    assert found_log, f"Expected log for os.path.exists error not found. Logs: {mock_logger_error.call_args_list}"

    watcher_task.cancel()
    with contextlib.suppress(asyncio.CancelledError, Exception): # Suppress errors as task might be already done or cancelled
      await watcher_task
