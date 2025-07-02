# pyvider/rpcplugin/tests/transport/test_connection.py

import asyncio
import gc
from typing import Any, cast
from unittest.mock import MagicMock, patch

import pytest
from pytest import MonkeyPatch

from pyvider.rpcplugin.client.connection import ClientConnection
from tests.fixtures.dummy import DummyReader, DummyWriter  # Import added


@pytest.fixture
def connection(
    dummy_reader: DummyReader, dummy_writer: DummyWriter
) -> ClientConnection:  # Add types to fixture args
    # Create a ClientConnection with dummy streams using cast.
    return ClientConnection(
        reader=cast(asyncio.StreamReader, dummy_reader),
        writer=cast(asyncio.StreamWriter, dummy_writer),
        remote_addr="127.0.0.1",
    )


@pytest.mark.asyncio
async def test_is_closed_initial(
    connection: ClientConnection, dummy_writer: DummyWriter
) -> None:
    # Initially, _closed is False and writer.is_closing() returns False.
    assert connection.is_closed is False


@pytest.mark.asyncio
async def test_is_closed_when_closed_flag(connection: ClientConnection) -> None:
    # When _closed flag is True, is_closed should return True.
    connection._closed = True
    assert connection.is_closed is True


@pytest.mark.asyncio
async def test_is_closed_when_writer_closing(
    connection: ClientConnection, dummy_writer: DummyWriter
) -> None:
    # When writer.is_closing() returns True, is_closed should return True.
    dummy_writer.closed = True
    assert connection.is_closed is True


@pytest.mark.asyncio
async def test_update_metrics(connection: ClientConnection) -> None:
    # Start with zero metrics.
    connection.bytes_sent = 0
    connection.bytes_received = 0
    connection.update_metrics(bytes_sent=10, bytes_received=20)
    assert connection.bytes_sent == 10
    assert connection.bytes_received == 20


@pytest.mark.asyncio
async def test_send_data_normal() -> None:  # Removed fixtures
    local_dummy_reader = DummyReader()  # Default empty reader
    local_dummy_writer = DummyWriter()
    conn = ClientConnection(
        reader=cast(asyncio.StreamReader, local_dummy_reader),
        writer=cast(asyncio.StreamWriter, local_dummy_writer),
        remote_addr="127.0.0.1",
    )

    data = b"hello"
    await conn.send_data(data)

    assert local_dummy_writer.data == data
    assert conn.bytes_sent == len(data)


@pytest.mark.asyncio
async def test_send_data_when_closed(connection: ClientConnection) -> None:
    # Mark connection as closed so that send_data should raise ConnectionError.
    connection._closed = True
    with pytest.raises(
        ConnectionError, match="Attempted to send data on closed connection"
    ):
        await connection.send_data(b"data")


@pytest.mark.asyncio
async def test_send_data_oserror(
    monkeypatch: MonkeyPatch, connection: ClientConnection
) -> None:
    # Simulate an OSError in writer.drain.
    async def fake_drain() -> None:
        raise OSError("Fake drain error")

    monkeypatch.setattr(connection.writer, "drain", fake_drain)
    with pytest.raises(OSError, match="Fake drain error"):
        await connection.send_data(b"data")


@pytest.mark.asyncio
async def test_receive_data_normal() -> None:  # Removed fixtures
    test_bytes = b"test data"
    local_dummy_reader = DummyReader(data=test_bytes)  # Initialize with data
    local_dummy_writer = DummyWriter()
    conn = ClientConnection(
        reader=cast(asyncio.StreamReader, local_dummy_reader),
        writer=cast(asyncio.StreamWriter, local_dummy_writer),
        remote_addr="127.0.0.1",
    )

    # No need to set dummy_reader.data as it's set on init
    result = await conn.receive_data()

    assert result == test_bytes
    assert conn.bytes_received == len(test_bytes)


@pytest.mark.asyncio
async def test_receive_data_when_closed(connection: ClientConnection) -> None:
    # Mark connection as closed so that receive_data raises ConnectionError.
    connection._closed = True
    with pytest.raises(
        ConnectionError, match="Attempted to receive data on closed connection"
    ):
        await connection.receive_data()


@pytest.mark.asyncio
async def test_receive_data_oserror(
    monkeypatch: MonkeyPatch, connection: ClientConnection
) -> None:
    # Simulate an OSError in reader.read.
    async def fake_read(size: int) -> None:
        raise OSError("Fake read error")

    monkeypatch.setattr(connection.reader, "read", fake_read)
    with pytest.raises(OSError, match="Fake read error"):
        await connection.receive_data()


@pytest.mark.asyncio
async def test_close_normal(
    connection: ClientConnection, dummy_writer: DummyWriter
) -> None:
    # Ensure close() properly marks connection as closed and calls writer.close().
    connection._closed = False
    await connection.close()
    assert connection._closed is True
    # Calling close() again should return immediately (idempotence).
    await connection.close()


@pytest.mark.asyncio
async def test_close_writer_error(
    monkeypatch: MonkeyPatch,
    connection: ClientConnection,
    dummy_writer: DummyWriter,
    caplog: Any,
) -> None:
    # Simulate an error during writer.wait_closed.
    async def fake_wait_closed() -> None:
        raise Exception("Fake wait_closed error")

    monkeypatch.setattr(dummy_writer, "wait_closed", fake_wait_closed)
    # Close should catch the exception and log an error.
    await connection.close()
    assert connection._closed is True


@pytest.mark.asyncio
async def test_del_warning() -> None:
    local_dummy_writer = DummyWriter()
    local_dummy_reader = DummyReader()

    conn = ClientConnection(
        reader=cast(asyncio.StreamReader, local_dummy_reader),
        writer=cast(asyncio.StreamWriter, local_dummy_writer),
        remote_addr="127.0.0.1",
    )

    assert not conn.is_closed, (
        "Connection should not be considered closed before explicit close or __del__ "  # noqa: E501
        "for this test"
    )
    remote_addr = conn.remote_addr

    # Patch logger.warning in pyvider.rpcplugin.client.connection
    with patch(
        "pyvider.rpcplugin.client.connection.logger.warning", new_callable=MagicMock
    ) as mock_log_warning:
        del conn
        gc.collect()
        # For __del__ to be called reliably, especially with asyncio components,
        # it often needs a bit more than just gc.collect().
        # Giving the event loop a chance to run any pending tasks that might
        # be holding onto the object or involved in its cleanup is important.
        await asyncio.sleep(0.01)  # Allow event loop/GC a moment

        expected_message = f"Connection to {remote_addr} was not properly closed"

        # New assertion:
        found_expected_call = False
        for call_item in mock_log_warning.call_args_list:
            # call_item is a unittest.mock.call object. Access its positional args via call_item[0] or call_item.args # noqa: E501
            logged_message = call_item[0][0]  # First positional argument of the call
            if logged_message == expected_message:
                found_expected_call = True
                break

        assert found_expected_call, (
            f"Expected warning message '{expected_message}' not found in logger calls. "
            f"Actual calls: {mock_log_warning.call_args_list}"
        )
