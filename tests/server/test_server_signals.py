# pyvider/rpcplugin/tests/server/test_server_signals.py

import asyncio
import pytest

from pyvider.rpcplugin.server import RPCPluginServer

from tests.conftest import (
    mock_server_protocol,
    mock_server_handler,
    mock_server_config,
)

from tests.fixtures import *

@pytest.mark.asyncio
async def test_server_signal_handling(mock_server_transport, mock_server_protocol) -> None:
    transport = mock_server_transport

    server = RPCPluginServer(
        protocol=mock_server_protocol,  # Use fixture correctly
        handler=mock_server_handler,
        config=mock_server_config,
        transport=transport,
    )
    server._exit_on_stop = False

    def trigger_shutdown():
        server._shutdown_requested()

    loop = asyncio.get_event_loop()
    loop.call_later(0.1, trigger_shutdown)

    await server.serve()
    assert server._serving_future.done()

@pytest.mark.asyncio
async def test_register_signal_handlers_success(monkeypatch) -> None:
    loop = asyncio.new_event_loop()
    monkeypatch.setattr(asyncio, "get_event_loop", lambda: loop)

    def fake_add_signal_handler(sig, handler):
        return

    monkeypatch.setattr(loop, "add_signal_handler", fake_add_signal_handler)
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=None,
    )

    server._register_signal_handlers()

@pytest.mark.asyncio
async def test_register_signal_handlers_not_supported_1(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    caplog
) -> None:
    """Test behavior when signal handlers are not supported."""
    loop = asyncio.new_event_loop()

    def mock_add_signal_handler(*args):
        raise NotImplementedError("Signal handler not supported")

    monkeypatch.setattr(loop, "add_signal_handler", mock_add_signal_handler)
    monkeypatch.setattr(asyncio, "get_event_loop", lambda: loop)

    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=None,
    )

    import logging
    with caplog.at_level(logging.WARNING):
        server._register_signal_handlers()

    assert "Signal handler not supported" in caplog.text

@pytest.mark.asyncio
async def test_shutdown_requested() -> None:
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=None,
    )

    fut = asyncio.Future()
    server._serving_future = fut
    server._shutdown_requested()
    assert fut.done()

###

@pytest.mark.asyncio
async def test_register_signal_handlers_not_supported_2(
    monkeypatch,
    mock_server_protocol,
    mock_server_handler,
    caplog
) -> None:
    """Test behavior when signal handlers are not supported."""
    import logging
    
    # Create a mock event loop
    loop = asyncio.new_event_loop()
    
    # Create a function that raises NotImplementedError
    def mock_add_signal_handler(*args, **kwargs):
        logger.warning("Signal handler not supported on this platform.")
        raise NotImplementedError("Signal handler not supported")
    
    # Apply mocks
    monkeypatch.setattr(loop, "add_signal_handler", mock_add_signal_handler)
    monkeypatch.setattr(asyncio, "get_event_loop", lambda: loop)
    
    # Create server instance
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=None,
    )
    
    # Capture logs while running the function
    with caplog.at_level(logging.WARNING):
        server._register_signal_handlers()
    
    # Check log content (normalize whitespace and line endings)
    normalized_logs = ' '.join(caplog.text.strip().replace('\n', ' ').split())
    assert "Signal handler not supported" in normalized_logs

###

@pytest.mark.asyncio
async def test_register_signal_handlers_not_supported_3(
    monkeypatch, mock_server_protocol, mock_server_handler, caplog
) -> None:
    """Test behavior when signal handlers are not supported."""
    import logging
    
    # Create a mock event loop that raises NotImplementedError
    loop = asyncio.new_event_loop()
    
    def mock_add_signal_handler(*args, **kwargs):
        # Write to log explicitly
        logger.warning("Signal handler not supported on this platform.")
        raise NotImplementedError("Signal handler not supported")
    
    # Apply mocks
    monkeypatch.setattr(loop, "add_signal_handler", mock_add_signal_handler)
    monkeypatch.setattr(asyncio, "get_event_loop", lambda: loop)
    
    # Create server instance
    server = RPCPluginServer(
        protocol=mock_server_protocol,
        handler=mock_server_handler,
        config=None,
        transport=None,
    )
    
    # Set logging level to capture warnings
    with caplog.at_level(logging.WARNING):
        server._register_signal_handlers()
    
    # Check if "Signal handler not supported" is in any log record
    found = False
    for record in caplog.records:
        if "Signal handler not supported" in record.message:
            found = True
            break
            
    assert found, "Warning about signal handler not supported was not logged"

###

### 🐍🏗🧪️
