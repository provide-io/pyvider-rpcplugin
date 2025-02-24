
# pyvider/rpcplugin/tests/transport/test_connection.py

import asyncio
import gc
import pytest

from pyvider.rpcplugin.client.connection import ClientConnection

# -------------------------------------------------------------------
# Dummy stream implementations for testing.
# -------------------------------------------------------------------
class DummyWriter:
    def __init__(self):
        self.closed = False
        self.data = bytearray()

    def write(self, data: bytes):
        self.data.extend(data)

    async def drain(self):
        # Simulate an immediate drain.
        await asyncio.sleep(0)

    def close(self):
        self.closed = True

    async def wait_closed(self):
        await asyncio.sleep(0)

    def is_closing(self) -> bool:
        return self.closed

class DummyReader:
    def __init__(self, data: bytes = b""):
        self.data = data
        self.called = False

    async def read(self, size: int):
        self.called = True
        return self.data

# -------------------------------------------------------------------
# Fixtures for DummyReader and DummyWriter.
# -------------------------------------------------------------------
@pytest.fixture
def dummy_writer():
    return DummyWriter()

@pytest.fixture
def dummy_reader():
    # Default dummy reader returns "test data".
    return DummyReader(b"test data")

@pytest.fixture
def connection(dummy_reader, dummy_writer):
    # Create a ClientConnection with dummy streams.
    return ClientConnection(
        reader=dummy_reader,
        writer=dummy_writer,
        remote_addr="127.0.0.1"
    )

# -------------------------------------------------------------------
# Test is_closed property.
# -------------------------------------------------------------------
def test_is_closed_initial(connection, dummy_writer):
    # Initially, _closed is False and writer.is_closing() returns False.
    assert connection.is_closed is False

def test_is_closed_when_closed_flag(connection):
    # When _closed flag is True, is_closed should return True.
    connection._closed = True
    assert connection.is_closed is True

def test_is_closed_when_writer_closing(connection, dummy_writer):
    # When writer.is_closing() returns True, is_closed should return True.
    dummy_writer.closed = True
    assert connection.is_closed is True

# -------------------------------------------------------------------
# Test update_metrics method.
# -------------------------------------------------------------------
def test_update_metrics(connection):
    # Start with zero metrics.
    connection.bytes_sent = 0
    connection.bytes_received = 0
    connection.update_metrics(bytes_sent=10, bytes_received=20)
    assert connection.bytes_sent == 10
    assert connection.bytes_received == 20

# -------------------------------------------------------------------
# Test send_data method.
# -------------------------------------------------------------------
@pytest.mark.asyncio
async def test_send_data_normal(connection, dummy_writer):
    # Test that send_data writes data and updates metrics.
    data = b"hello"
    await connection.send_data(data)
    # The dummy writer should have accumulated the data.
    assert dummy_writer.data == data
    # Metrics should be updated.
    assert connection.bytes_sent == len(data)

@pytest.mark.asyncio
async def test_send_data_when_closed(connection):
    # Mark connection as closed so that send_data should raise ConnectionError.
    connection._closed = True
    with pytest.raises(ConnectionError, match="Attempted to send data on closed connection"):
        await connection.send_data(b"data")

@pytest.mark.asyncio
async def test_send_data_oserror(monkeypatch, connection):
    # Simulate an OSError in writer.drain.
    async def fake_drain():
        raise OSError("Fake drain error")
    monkeypatch.setattr(connection.writer, "drain", fake_drain)
    with pytest.raises(OSError, match="Fake drain error"):
        await connection.send_data(b"data")

# -------------------------------------------------------------------
# Test receive_data method.
# -------------------------------------------------------------------
@pytest.mark.asyncio
async def test_receive_data_normal(connection, dummy_reader):
    # Test normal reception: dummy_reader returns preset data.
    test_bytes = b"response"
    dummy_reader.data = test_bytes
    result = await connection.receive_data()
    assert result == test_bytes
    # Metrics for bytes_received should be updated.
    assert connection.bytes_received == len(test_bytes)

@pytest.mark.asyncio
async def test_receive_data_when_closed(connection):
    # Mark connection as closed so that receive_data raises ConnectionError.
    connection._closed = True
    with pytest.raises(ConnectionError, match="Attempted to receive data on closed connection"):
        await connection.receive_data()

@pytest.mark.asyncio
async def test_receive_data_oserror(monkeypatch, connection):
    # Simulate an OSError in reader.read.
    async def fake_read(size: int):
        raise OSError("Fake read error")
    monkeypatch.setattr(connection.reader, "read", fake_read)
    with pytest.raises(OSError, match="Fake read error"):
        await connection.receive_data()

# -------------------------------------------------------------------
# Test close method.
# -------------------------------------------------------------------
@pytest.mark.asyncio
async def test_close_normal(connection, dummy_writer):
    # Ensure close() properly marks connection as closed and calls writer.close().
    connection._closed = False
    await connection.close()
    assert connection._closed is True
    # Calling close() again should return immediately (idempotence).
    await connection.close()

@pytest.mark.asyncio
async def test_close_writer_error(monkeypatch, connection, dummy_writer, caplog):
    # Simulate an error during writer.wait_closed.
    async def fake_wait_closed():
        raise Exception("Fake wait_closed error")
    monkeypatch.setattr(dummy_writer, "wait_closed", fake_wait_closed)
    # Close should catch the exception and log an error.
    await connection.close()
    assert connection._closed is True

# -------------------------------------------------------------------
# Test __del__ to ensure warning is logged if not properly closed.
# -------------------------------------------------------------------
def test_del_warning(caplog):
    # Create a ClientConnection without calling close.
    dummy_writer = DummyWriter()
    # For the reader, use a minimal dummy (can be an already created StreamReader).
    dummy_reader = asyncio.StreamReader()
    conn = ClientConnection(reader=dummy_reader, writer=dummy_writer, remote_addr="127.0.0.1")
    # Do not call close(), so __del__ should log a warning.
    del conn
    gc.collect()

    # Check that a warning about not being properly closed was logged.
    assert any("was not properly closed" in record.message for record in caplog.records)

