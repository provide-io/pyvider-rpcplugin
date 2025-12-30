#
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""gRPC Service Implementations for Pyvider RPC Plugin.

This module provides the Python implementations for the standard gRPC services
defined in the common go-plugin protocol:
- GRPCBrokerService: For managing brokered subchannels.
- GRPCStdioService: For streaming stdin/stdout/stderr.
- GRPCControllerService: For controlling the plugin lifecycle (e.g., shutdown).

It also includes helper classes like `SubchannelConnection` and a registration
function to add these services to a gRPC server."""

import asyncio
from collections.abc import AsyncIterator
import os
import traceback
from typing import Any

from attrs import define, field
from google.protobuf import empty_pb2  # Use google.protobuf.empty_pb2
import grpc  # For gRPC context type hint
from provide.foundation import logger, resilient

from pyvider.rpcplugin.defaults import DEFAULT_PROCESS_WAIT_TIME
from pyvider.rpcplugin.protocol.grpc_broker_pb2 import ConnInfo
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import (
    GRPCBrokerServicer,
    add_GRPCBrokerServicer_to_server,
)
from pyvider.rpcplugin.protocol.grpc_controller_pb2 import Empty as CEmpty
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import (
    GRPCControllerServicer,
    add_GRPCControllerServicer_to_server,
)
from pyvider.rpcplugin.protocol.grpc_stdio_pb2 import StdioData
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import (
    GRPCStdioServicer,
    add_GRPCStdioServicer_to_server,
)


class BrokerError(Exception):
    pass


@define(slots=True)
class SubchannelConnection:
    """
    Represents a brokered subchannel for plugin-to-plugin communication.

    In the go-plugin architecture, subchannels allow plugins to establish
    secondary communication channels for callbacks, additional services,
    or plugin-to-plugin communication. Each subchannel has a unique ID
    and network address.

    Attributes:
        conn_id: Unique identifier for this subchannel connection.
        address: Network address for the subchannel (format depends on transport).
        is_open: Whether the subchannel is currently open and available.

    Example:
        ```python
        subchannel = SubchannelConnection(
            conn_id=1,
            address="127.0.0.1:9000"
        )
        await subchannel.open()
        # Subchannel now ready for communication
        await subchannel.close()
        ```
    """

    conn_id: int = field()
    address: str = field()
    is_open: bool = field(default=False, init=False)

    async def open(self) -> None:
        """
        Open the subchannel for communication.

        This method establishes the subchannel connection and marks it as
        available for use. In a real implementation, this would involve
        network setup or IPC channel creation.

        Side Effects:
            Sets is_open to True after successful opening.
        """
        logger.debug("Opening subchannel", conn_id=self.conn_id, address=self.address)
        await asyncio.sleep(0.05)  # simulate
        self.is_open = True

    async def close(self) -> None:
        """
        Close the subchannel and release resources.

        This method closes the subchannel connection and marks it as
        unavailable. Resources associated with the subchannel are released.

        Side Effects:
            Sets is_open to False after closing.
        """
        await asyncio.sleep(0.05)
        self.is_open = False


class GRPCBrokerService(GRPCBrokerServicer):
    """
    Implementation of the gRPC Broker logic.

    This matches the StartStream(...) signature in `grpc_broker.proto`, which
    transmits a stream of ConnInfo messages in both directions.
    In go-plugin, the plugin side uses:
    'StartStream(stream ConnInfo) returns (stream ConnInfo)'
    to set up a subchannel for callbacks or bridging. We'll do a simplified
    version here.
    """

    def __init__(self) -> None:
        # We hold subchannel references here.
        self._subchannels: dict[int, SubchannelConnection] = {}

    async def StartStream(
        self,
        request_iterator: AsyncIterator[ConnInfo],
        context: grpc.aio.ServicerContext[ConnInfo, ConnInfo],
    ) -> AsyncIterator[ConnInfo]:
        """
        Handles the bidirectional stream for broker connections.

        This gRPC method allows the client and server to exchange `ConnInfo`
        messages to manage subchannels for additional services or callbacks.

        Args:
            request_iterator: An async iterator yielding incoming `ConnInfo`
                              messages from the client.
            context: The gRPC request context.

        Yields:
            Outgoing `ConnInfo` messages to the client.
        """
        incoming: ConnInfo | None = None  # Initialize to avoid unbound variable in exception handler
        try:  # Outer try for iterator errors
            async for incoming in request_iterator:
                sub_id = incoming.service_id
                try:  # Inner try for processing each item
                    logger.debug(
                        "Broker received subchannel request",
                        sub_id=sub_id,
                        network=incoming.network,
                        address=incoming.address,
                    )

                    if incoming.knock.knock:  # Request to open/ensure channel
                        if sub_id in self._subchannels and self._subchannels[sub_id].is_open:
                            yield ConnInfo(
                                service_id=sub_id,
                                network=incoming.network,
                                address=incoming.address,
                                knock=ConnInfo.Knock(knock=False, ack=True, error=""),
                            )
                        else:  # New subchannel request or existing but not open
                            subchan = SubchannelConnection(sub_id, incoming.address)
                            await subchan.open()
                            self._subchannels[sub_id] = subchan
                            yield ConnInfo(
                                service_id=sub_id,
                                network=incoming.network,
                                address=incoming.address,
                                knock=ConnInfo.Knock(knock=False, ack=True, error=""),
                            )
                    elif sub_id in self._subchannels:
                        await self._subchannels[sub_id].close()
                        del self._subchannels[sub_id]
                        yield ConnInfo(  # Ack the close
                            service_id=sub_id,
                            knock=ConnInfo.Knock(knock=False, ack=True, error=""),
                        )
                    else:
                        yield ConnInfo(
                            service_id=sub_id,
                            knock=ConnInfo.Knock(knock=False, ack=True, error="Channel not found"),
                        )
                except Exception as ex_inner:
                    err_str_inner = f"Broker error processing item for sub_id {sub_id}: {ex_inner}"
                    logger.error(
                        "Broker error processing subchannel item",
                        sub_id=sub_id,
                        error=str(ex_inner),
                        trace=traceback.format_exc(),
                    )
                    yield ConnInfo(
                        service_id=sub_id,
                        knock=ConnInfo.Knock(knock=False, ack=False, error=err_str_inner),
                    )
                    # Crucial: process next item, don't fall into ex_outer
                    continue
        except Exception as ex_outer:
            outer_error_sub_id = getattr(incoming, "service_id", 0) if incoming is not None else 0
            err_str_outer = (
                "Broker stream error from client iterator for sub_id "
                f"{outer_error_sub_id} (outer loop): {ex_outer}"
            )
            try:
                yield ConnInfo(
                    service_id=0,
                    knock=ConnInfo.Knock(knock=False, ack=False, error=err_str_outer),
                )
            except Exception as ex_yield:
                logger.error("Failed to yield broker error response", error=str(ex_yield))


_SENTINEL = object()  # Module-level sentinel


class GRPCStdioService(GRPCStdioServicer):
    """
    Implementation of plugin stdio streaming.
    """

    def __init__(self) -> None:
        self._message_queue: asyncio.Queue[Any] = asyncio.Queue()  # Allow Any for sentinel
        self._shutdown = False

    async def put_line(self, line: bytes, is_stderr: bool = False) -> None:
        """
        Adds a line of data (stdout or stderr) to the message queue for streaming.

        Args:
            line: The bytes data of the line.
            is_stderr: True if the line is from stderr, False for stdout.
        """
        try:
            data = StdioData(channel=StdioData.STDERR if is_stderr else StdioData.STDOUT, data=line)
            await self._message_queue.put(data)
        except Exception:
            pass  # Empty block

    async def _next_queue_item(self, done: asyncio.Event) -> StdioData | None:
        if not self._message_queue.empty():
            try:
                item = self._message_queue.get_nowait()
            except asyncio.QueueEmpty:  # pragma: no cover - defensive
                item = None
            else:
                self._message_queue.task_done()
                if item is _SENTINEL:
                    return None
                logger.debug(
                    "Stdio queue item retrieved (fast path)",
                    channel=item.channel,
                    data_preview=item.data[:20],
                )
                return item  # type: ignore[no-any-return]

        get_task = asyncio.create_task(self._message_queue.get(), name="StdioGetMessage")
        wait_task = asyncio.create_task(done.wait(), name="StdioDoneWait")

        try:
            completed, _ = await asyncio.wait([get_task, wait_task], return_when=asyncio.FIRST_COMPLETED)

            if get_task in completed:
                item = get_task.result()
                self._message_queue.task_done()
                if item is _SENTINEL:
                    return None
                logger.debug(
                    "Stdio queue item retrieved (async path)",
                    channel=item.channel,
                    data_preview=item.data[:20],
                )
                return item  # type: ignore[no-any-return]

            if wait_task in completed and wait_task.result():
                if not get_task.done():
                    get_task.cancel()
                return None
        finally:
            if not get_task.done():
                get_task.cancel()
            wait_task.cancel()

        return None

    async def _drain_queue(self) -> AsyncIterator[StdioData]:
        while not self._message_queue.empty():
            try:
                item = self._message_queue.get_nowait()
            except asyncio.QueueEmpty:  # pragma: no cover - defensive
                break
            self._message_queue.task_done()
            if item is _SENTINEL:
                continue
            logger.debug(
                "Stdio queue item drained",
                channel=item.channel,
                data_preview=item.data[:20],
            )
            yield item

    async def _stream_items(self, done: asyncio.Event) -> AsyncIterator[StdioData]:
        while not self._shutdown and not done.is_set():
            try:
                item = await self._next_queue_item(done)
            except Exception:  # pragma: no cover - defensive path for queue errors
                await asyncio.sleep(DEFAULT_PROCESS_WAIT_TIME)
                continue

            if item is None:
                break
            yield item

        if self._shutdown or not self._message_queue.empty():
            logger.debug(
                "Draining stdio queue",
                queue_size=self._message_queue.qsize(),
            )
            async for remaining in self._drain_queue():
                yield remaining

    async def StreamStdio(
        self, request: empty_pb2.Empty, context: grpc.aio.ServicerContext[empty_pb2.Empty, StdioData]
    ) -> AsyncIterator[StdioData]:
        """Streams STDOUT/STDERR lines to the caller."""

        done = asyncio.Event()

        def on_rpc_done(_: Any) -> None:
            done.set()

        context.add_done_callback(on_rpc_done)  # type: ignore[arg-type]

        async for item in self._stream_items(done):
            yield item

    def shutdown(self) -> None:
        # Note: `shutdown` is a reserved keyword in some contexts,
        # but here it's a method name.
        self._shutdown = True
        # Put sentinel into the queue to unblock .get()
        try:
            self._message_queue.put_nowait(_SENTINEL)
        except asyncio.QueueFull:  # pragma: no cover
            logger.warning("Message queue full during shutdown, cannot add sentinel")


class GRPCControllerService(GRPCControllerServicer):
    """
    Implements the GRPCController service for plugin lifecycle management.
    Specifically, it handles the Shutdown RPC to gracefully terminate the plugin.
    """

    def __init__(self, shutdown_event: asyncio.Event, stdio_service: GRPCStdioService) -> None:
        """
        Initializes the GRPCControllerService.

        Args:
            shutdown_event: An asyncio.Event to signal plugin shutdown.
            stdio_service: The GRPCStdioService instance to also shutdown.
        """
        self._shutdown_event = shutdown_event or asyncio.Event()
        self._stdio_service = stdio_service

    @resilient(
        context={"operation": "controller_shutdown", "component": "protocol"},
        log_errors=True,
    )
    async def Shutdown(self, request: CEmpty, context: grpc.aio.ServicerContext[CEmpty, CEmpty]) -> CEmpty:
        """
        Handles the Shutdown RPC request from the client.

        This method signals other plugin components to shut down gracefully
        and then initiates the process termination.

        Args:
            request: The Empty request message (from grpc_controller.proto).
            context: The gRPC request context.

        Returns:
            An Empty response message.
        """
        self._stdio_service.shutdown()
        self._shutdown_event.set()

        self._shutdown_task = asyncio.create_task(self._delayed_shutdown())
        return CEmpty()

    async def _delayed_shutdown(self) -> None:
        """Allow RPC response to complete before actual shutdown."""
        await asyncio.sleep(0.1)
        if hasattr(os, "kill") and hasattr(os, "getpid"):
            try:
                import signal

                os.kill(os.getpid(), signal.SIGTERM)
            except Exception:
                import sys

                sys.exit(0)  # Fallback exit
        else:
            import sys

            sys.exit(0)


def register_protocol_service(server: grpc.aio.Server, shutdown_event: asyncio.Event) -> None:
    """Registers all standard gRPC services for the plugin."""
    stdio_service = GRPCStdioService()
    broker_service = GRPCBrokerService()
    controller_service = GRPCControllerService(shutdown_event, stdio_service)

    add_GRPCStdioServicer_to_server(stdio_service, server)  # type: ignore[no-untyped-call]
    add_GRPCBrokerServicer_to_server(broker_service, server)  # type: ignore[no-untyped-call]
    add_GRPCControllerServicer_to_server(controller_service, server)  # type: ignore[no-untyped-call]


# 🐍🔌📞🔚
