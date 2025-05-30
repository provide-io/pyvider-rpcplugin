# tests/client/test_connection.py
#
# Copyright (C) 2024 - All Rights Reserved
#
# This file is part of the PyVider RPCPlugin project.
#
# Any unauthorized use, reproduction, or distribution of this software
# is strictly prohibited without the express written permission of the copyright holder.
#

import asyncio
import gc
import pytest
import logging # Ensure this is imported

from pyvider.rpcplugin.client.connection import ClientConnection
from tests.fixtures.dummy import DummyReader, DummyWriter

# Assuming other tests might still use a general 'connection' fixture.
# If 'connection' fixture is not used by other tests in this file after this change,
# it could be removed or scoped more locally. For now, we'll keep it.
# from tests.fixtures import * # This was present, if not needed, can be removed.


@pytest.fixture
def connection_fixture(dummy_reader, dummy_writer): # Renamed to avoid clash if 'connection' is used elsewhere
    # Create a ClientConnection with dummy streams.
    return ClientConnection(
        reader=dummy_reader, writer=dummy_writer, remote_addr="127.0.0.1:fixture"
    )

@pytest.mark.asyncio
async def test_is_closed_initial(connection_fixture) -> None: # Used renamed fixture
    # Initially, _closed is False and writer.is_closing() returns False.
    assert connection_fixture.is_closed is False

@pytest.mark.asyncio
async def test_is_closed_when_closed_flag(connection_fixture) -> None: # Used renamed fixture
    # When _closed flag is True, is_closed should return True.
    connection_fixture._closed = True
    assert connection_fixture.is_closed is True

@pytest.mark.asyncio
async def test_is_closed_when_writer_closing(connection_fixture, dummy_writer) -> None: # Used renamed fixture
    # When writer.is_closing() returns True, is_closed should return True.
    dummy_writer.closed = True # Assuming dummy_writer has a 'closed' attribute used by its 'is_closing()'
    assert connection_fixture.is_closed is True

@pytest.mark.asyncio
async def test_update_metrics(connection_fixture) -> None: # Used renamed fixture
    # Start with zero metrics.
    connection_fixture.bytes_sent = 0
    connection_fixture.bytes_received = 0
    connection_fixture.update_metrics(bytes_sent=10, bytes_received=20)
    assert connection_fixture.bytes_sent == 10
    assert connection_fixture.bytes_received == 20

@pytest.mark.asyncio
async def test_send_data_normal() -> None:
    local_dummy_reader = DummyReader()
    local_dummy_writer = DummyWriter()
    conn = ClientConnection(reader=local_dummy_reader, writer=local_dummy_writer, remote_addr="127.0.0.1:send_normal")
    
    data = b"hello"
    await conn.send_data(data)
    
    assert local_dummy_writer.data == data # Assumes DummyWriter stores last written data this way
    assert conn.bytes_sent == len(data)
    await conn.close() # Cleanly close

@pytest.mark.asyncio
async def test_send_data_when_closed() -> None:
    conn = ClientConnection(reader=DummyReader(), writer=DummyWriter(), remote_addr="127.0.0.1:send_closed")
    conn._closed = True # Mark connection as closed
    with pytest.raises(
        ConnectionError, match="Attempted to send data on closed connection"
    ):
        await conn.send_data(b"data")
    # No explicit close needed as it was manually marked _closed and not truly opened

@pytest.mark.asyncio
async def test_send_data_oserror(monkeypatch) -> None:
    conn = ClientConnection(reader=DummyReader(), writer=DummyWriter(), remote_addr="127.0.0.1:send_oserror")
    async def fake_drain():
        raise OSError("Fake drain error")

    monkeypatch.setattr(conn.writer, "drain", fake_drain)
    with pytest.raises(OSError, match="Fake drain error"):
        await conn.send_data(b"data")
    await conn.close() # Cleanly close

@pytest.mark.asyncio
async def test_receive_data_normal() -> None:
    test_bytes = b"test data"
    local_dummy_reader = DummyReader(data=test_bytes)
    local_dummy_writer = DummyWriter()
    conn = ClientConnection(reader=local_dummy_reader, writer=local_dummy_writer, remote_addr="127.0.0.1:recv_normal")
    
    result = await conn.receive_data()
    
    assert result == test_bytes
    assert conn.bytes_received == len(test_bytes)
    await conn.close() # Cleanly close

@pytest.mark.asyncio
async def test_receive_data_when_closed() -> None:
    conn = ClientConnection(reader=DummyReader(), writer=DummyWriter(), remote_addr="127.0.0.1:recv_closed")
    conn._closed = True # Mark connection as closed
    with pytest.raises(
        ConnectionError, match="Attempted to receive data on closed connection"
    ):
        await conn.receive_data()
    # No explicit close needed

@pytest.mark.asyncio
async def test_receive_data_oserror(monkeypatch) -> None:
    conn = ClientConnection(reader=DummyReader(), writer=DummyWriter(), remote_addr="127.0.0.1:recv_oserror")
    async def fake_read(size: int): # Make sure signature matches StreamReader.read
        raise OSError("Fake read error")

    monkeypatch.setattr(conn.reader, "read", fake_read) # Patch 'read' not 'readexactly' unless that's what receive_data uses
    with pytest.raises(OSError, match="Fake read error"):
        await conn.receive_data()
    await conn.close() # Cleanly close

@pytest.mark.asyncio
async def test_close_normal(connection_fixture) -> None: # Used renamed fixture
    # Ensure close() properly marks connection as closed and calls writer.close().
    # connection_fixture starts with _closed = False
    assert connection_fixture._closed is False
    await connection_fixture.close()
    assert connection_fixture._closed is True
    # Calling close() again should return immediately (idempotence).
    await connection_fixture.close()


@pytest.mark.asyncio
async def test_close_writer_error(monkeypatch, connection_fixture, dummy_writer, caplog) -> None: # Used renamed fixture
    # Simulate an error during writer.wait_closed.
    async def fake_wait_closed():
        raise Exception("Fake wait_closed error")

    # dummy_writer here is the one used by connection_fixture
    monkeypatch.setattr(dummy_writer, "wait_closed", fake_wait_closed)
    
    # Close should catch the exception and log an error.
    # The logger used in ClientConnection is from pyvider.telemetry
    # caplog by default captures from root logger. If ClientConnection's logger does not propagate, this might need adjustment.
    # Assuming standard propagation for now.
    
    # Set caplog level for the specific logger if needed, or ensure it captures WARNING
    # For example: caplog.set_level(logging.ERROR, logger="pyvider.rpcplugin.client.connection")

    await connection_fixture.close()
    assert connection_fixture._closed is True
    
    # Check for the specific error log from ClientConnection.close()
    found_log = False
    expected_message_part = "Error during writer.wait_closed()" # Based on ClientConnection.close() implementation
    for record in caplog.records:
        if record.levelno == logging.ERROR and expected_message_part in record.message:
            found_log = True
            break
    assert found_log, f"Expected error log containing '{expected_message_part}' not found. Logs: {[(r.levelname, r.message) for r in caplog.records]}"


@pytest.mark.asyncio
async def test_del_warning(caplog) -> None:
    specific_remote_addr = "127.0.0.1:test_del_specific_addr"

    def create_and_del_conn_inner():
        # This function creates the connection and then it goes out of scope
        # when the function returns, making it eligible for garbage collection.
        # Using fresh DummyReader/Writer for this specific test's lifecycle
        conn_obj = ClientConnection(
            reader=DummyReader(), 
            writer=DummyWriter(), 
            remote_addr=specific_remote_addr
        )
        # Do not call conn_obj.close()
        # print(f"Created conn_obj with id: {id(conn_obj)} for {conn_obj.remote_addr}") # Debugging line

    create_and_del_conn_inner()
    
    # Attempt to force garbage collection.
    gc.collect()
    gc.collect() 
    
    await asyncio.sleep(0.01) 

    found_warning = False
    # Debug: Print all captured log records to see what's available
    # print(f"Number of records captured by caplog for test_del_warning: {len(caplog.records)}")
    # for record_idx, record_debug in enumerate(caplog.records):
    #    print(f"Caplog Record {record_idx}: LEVEL={record_debug.levelno}, NAME={record_debug.name}, MSG='{record_debug.message}'")

    for record in caplog.records:
        if record.levelno == logging.WARNING and \
           "was not properly closed" in record.message and \
           specific_remote_addr in record.message:
            found_warning = True
            break
    
    assert found_warning, f"No warning about unclosed connection for '{specific_remote_addr}' was found in logs. Captured logs: {[(r.levelname, r.message) for r in caplog.records]}"

# 🐍🏗️🔌
