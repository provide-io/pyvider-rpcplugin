# pyvider/rpcplugin/tests/transport/test_connection.py

import asyncio
import gc
import pytest

from pyvider.rpcplugin.client.connection import ClientConnection
from tests.fixtures.dummy import DummyReader, DummyWriter # Import added

from tests.fixtures import * # Keep for other fixtures if used by other tests


@pytest.fixture
def connection(dummy_reader, dummy_writer):
    # Create a ClientConnection with dummy streams.
    return ClientConnection(
        reader=dummy_reader, writer=dummy_writer, remote_addr="127.0.0.1"
    )

@pytest.mark.asyncio
async def test_is_closed_initial(connection, dummy_writer) -> None:
    # Initially, _closed is False and writer.is_closing() returns False.
    assert connection.is_closed is False

@pytest.mark.asyncio
async def test_is_closed_when_closed_flag(connection) -> None:
    # When _closed flag is True, is_closed should return True.
    connection._closed = True
    assert connection.is_closed is True

@pytest.mark.asyncio
async def test_is_closed_when_writer_closing(connection, dummy_writer) -> None:
    # When writer.is_closing() returns True, is_closed should return True.
    dummy_writer.closed = True
    assert connection.is_closed is True

@pytest.mark.asyncio
async def test_update_metrics(connection) -> None:
    # Start with zero metrics.
    connection.bytes_sent = 0
    connection.bytes_received = 0
    connection.update_metrics(bytes_sent=10, bytes_received=20)
    assert connection.bytes_sent == 10
    assert connection.bytes_received == 20

@pytest.mark.asyncio
async def test_send_data_normal() -> None: # Removed fixtures
    local_dummy_reader = DummyReader() # Default empty reader
    local_dummy_writer = DummyWriter()
    conn = ClientConnection(reader=local_dummy_reader, writer=local_dummy_writer, remote_addr="127.0.0.1")
    
    data = b"hello"
    await conn.send_data(data)
    
    assert local_dummy_writer.data == data
    assert conn.bytes_sent == len(data)

@pytest.mark.asyncio
async def test_send_data_when_closed(connection) -> None:
    # Mark connection as closed so that send_data should raise ConnectionError.
    connection._closed = True
    with pytest.raises(
        ConnectionError, match="Attempted to send data on closed connection"
    ):
        await connection.send_data(b"data")

@pytest.mark.asyncio
async def test_send_data_oserror(monkeypatch, connection) -> None:
    # Simulate an OSError in writer.drain.
    async def fake_drain():
        raise OSError("Fake drain error")

    monkeypatch.setattr(connection.writer, "drain", fake_drain)
    with pytest.raises(OSError, match="Fake drain error"):
        await connection.send_data(b"data")

@pytest.mark.asyncio
async def test_receive_data_normal() -> None: # Removed fixtures
    test_bytes = b"test data"
    local_dummy_reader = DummyReader(data=test_bytes) # Initialize with data
    local_dummy_writer = DummyWriter()
    conn = ClientConnection(reader=local_dummy_reader, writer=local_dummy_writer, remote_addr="127.0.0.1")
    
    # No need to set dummy_reader.data as it's set on init
    result = await conn.receive_data()
    
    assert result == test_bytes
    assert conn.bytes_received == len(test_bytes)

@pytest.mark.asyncio
async def test_receive_data_when_closed(connection) -> None:
    # Mark connection as closed so that receive_data raises ConnectionError.
    connection._closed = True
    with pytest.raises(
        ConnectionError, match="Attempted to receive data on closed connection"
    ):
        await connection.receive_data()

@pytest.mark.asyncio
async def test_receive_data_oserror(monkeypatch, connection) -> None:
    # Simulate an OSError in reader.read.
    async def fake_read(size: int):
        raise OSError("Fake read error")

    monkeypatch.setattr(connection.reader, "read", fake_read)
    with pytest.raises(OSError, match="Fake read error"):
        await connection.receive_data()

@pytest.mark.asyncio
async def test_close_normal(connection, dummy_writer) -> None:
    # Ensure close() properly marks connection as closed and calls writer.close().
    connection._closed = False
    await connection.close()
    assert connection._closed is True
    # Calling close() again should return immediately (idempotence).
    await connection.close()

@pytest.mark.asyncio
async def test_close_writer_error(monkeypatch, connection, dummy_writer, caplog) -> None:
    # Simulate an error during writer.wait_closed.
    async def fake_wait_closed():
        raise Exception("Fake wait_closed error")

    monkeypatch.setattr(dummy_writer, "wait_closed", fake_wait_closed)
    # Close should catch the exception and log an error.
    await connection.close()
    assert connection._closed is True

@pytest.mark.asyncio
async def test_del_warning(caplog, capsys) -> None:
    # Create a ClientConnection without calling close.
    # Ensure local dummy instances are used here too if this test relies on specific dummy behavior
    local_dummy_writer = DummyWriter()
    local_dummy_reader = DummyReader() # Or asyncio.StreamReader() if that's more appropriate for this specific test's goal
    
    conn = ClientConnection(
        reader=local_dummy_reader, writer=local_dummy_writer, remote_addr="127.0.0.1"
    )
    # Do not call close(), so __del__ should log a warning.
    del conn
    gc.collect()

    # Check that a warning about not being properly closed was logged.
    # Try both: either in captured log records or in stdout
    captured = capsys.readouterr()
    in_logs = any("was not properly closed" in record.message for record in caplog.records)
    in_stdout = "was not properly closed" in captured.out
    
    assert in_logs or in_stdout, "No warning about unclosed connection was found"
