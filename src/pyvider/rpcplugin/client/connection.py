#
# src/pyvider/rpcplugin/client/connection.py
#

"""
Client Connection Management.

This module defines the `ClientConnection` class, responsible for managing
the state and I/O operations of a single client connection within the
Pyvider RPC Plugin system. It includes metrics tracking and supports
dependency injection for I/O functions to facilitate testing.
"""

import asyncio
from collections.abc import (
    Awaitable,
)
from collections.abc import (
    Callable as AbcCallable,
)
from typing import Any  # Added for __eq__ type hint

from attrs import define, field

from pyvider.telemetry import logger

# Type aliases for dependency-injected I/O functions using collections.abc
SendFuncType = AbcCallable[[bytes], Awaitable[None]]
ReceiveFuncType = AbcCallable[[int], Awaitable[bytes]]


@define(slots=True, frozen=False)
class ClientConnection:
    """
    Represents an active client connection with associated metrics and state.

    This class wraps the asyncio StreamReader and StreamWriter with additional
    functionality for tracking metrics and managing connection state. It now
    supports dependency injection for its I/O functions, allowing tests or
    alternative implementations to override the default behavior.

    Attributes:
        reader: Stream for reading client data.
        writer: Stream for writing responses.
        remote_addr: Remote address of the client.
        bytes_sent: Total bytes sent over this connection.
        bytes_received: Total bytes received over this connection.
        send_func: Callable used to send data; defaults to _default_send.
        receive_func: Callable used to receive data; defaults to _default_receive.
    """

    reader: asyncio.StreamReader = field()
    writer: asyncio.StreamWriter = field()
    remote_addr: str = field()
    bytes_sent: int = field(default=0)
    bytes_received: int = field(default=0)
    _closed: bool = field(default=False, init=False)
    send_func: SendFuncType | None = field(default=None)
    receive_func: ReceiveFuncType | None = field(default=None)

    def __attrs_post_init__(self) -> None:
        """Post-initialization hook to set default I/O functions if not provided."""
        if self.send_func is None:
            self.send_func = self._default_send
        if self.receive_func is None:
            self.receive_func = self._default_receive

    @property
    def is_closed(self) -> bool:
        """Check if the connection is closed."""
        return self._closed or self.writer.is_closing()

    def update_metrics(self, bytes_sent: int = 0, bytes_received: int = 0) -> None:
        """
        Update connection metrics.

        Args:
            bytes_sent: Number of bytes sent.
            bytes_received: Number of bytes received.
        """
        self.bytes_sent += bytes_sent
        self.bytes_received += bytes_received
        logger.debug(
            f"Updated metrics for {self.remote_addr}",
            extra={
                "total_sent": self.bytes_sent,
                "total_received": self.bytes_received,
            },
        )

    async def _default_send(self, data: bytes) -> None:
        """
        Default send function: writes data to the writer and updates metrics.

        Args:
            data: Bytes to send.

        Raises:
            OSError: If an error occurs during sending.
        """
        try:
            self.writer.write(data)
            await self.writer.drain()
            self.update_metrics(bytes_sent=len(data))
            logger.debug(f"Sent data to {self.remote_addr}", extra={"bytes": len(data)})
        except OSError as e:
            logger.error(
                f"Error sending data to {self.remote_addr}", extra={"error": str(e)}
            )
            raise

    async def _default_receive(self, size: int = 16384) -> bytes:
        """
        Default receive function: reads data from the reader and updates metrics.

        Args:
            size: Maximum number of bytes to receive.

        Returns:
            Received data as bytes.

        Raises:
            OSError: If an error occurs during receiving.
        """
        try:
            data = await self.reader.read(size)
            if data:
                self.update_metrics(bytes_received=len(data))
                logger.debug(
                    f"Received data from {self.remote_addr}", extra={"bytes": len(data)}
                )
            return data
        except OSError as e:
            logger.error(
                f"Error receiving data from {self.remote_addr}", extra={"error": str(e)}
            )
            raise

    async def send_data(self, data: bytes) -> None:
        """
        Send data over the connection using the injected send_func.

        Args:
            data: Bytes to send.

        Raises:
            ConnectionError: If the connection is closed.
        """
        if self.is_closed:
            raise ConnectionError("Attempted to send data on closed connection")
        if self.send_func is None:
            # This should ideally not be reached if __attrs_post_init__ ran.
            raise RuntimeError(
                "send_func was not initialized. This should not happen if "
                "__attrs_post_init__ ran correctly."
            )
        await self.send_func(data)

    async def receive_data(self, size: int = 16384) -> bytes:
        """
        Receive data from the connection using the injected receive_func.

        Args:
            size: Maximum number of bytes to receive.

        Returns:
            Received data as bytes.

        Raises:
            ConnectionError: If the connection is closed.
        """
        if self.is_closed:
            raise ConnectionError("Attempted to receive data on closed connection")
        if self.receive_func is None:
            # This should ideally not be reached if __attrs_post_init__ ran.
            raise RuntimeError(
                "receive_func was not initialized. This should not happen if "
                "__attrs_post_init__ ran correctly."
            )
        return await self.receive_func(size)

    async def close(self) -> None:
        """
        Close the connection and clean up resources.

        This method is idempotent and can be safely called multiple times.
        """
        if self._closed:
            return

        logger.debug(f"Closing connection to {self.remote_addr}")
        self._closed = True

        if not self.writer.is_closing():
            try:
                self.writer.close()
                await self.writer.wait_closed()
                logger.debug(f"Connection to {self.remote_addr} closed successfully")
            except Exception as e:
                logger.error(
                    f"Error while closing connection to {self.remote_addr}",
                    extra={"error": str(e)},
                )

    def __del__(self) -> None:
        """
        Ensure resources are cleaned up.

        Note: Raising exceptions in __del__ is generally discouraged; a warning
              is logged instead.
        """
        if not self._closed and hasattr(self, "writer"):
            logger.warning(f"Connection to {self.remote_addr} was not properly closed")

    def __hash__(self) -> int:
        return hash((id(self), self.remote_addr))

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, ClientConnection):
            return NotImplemented
        return id(self) == id(other)


# 🐍🏗️🔌
