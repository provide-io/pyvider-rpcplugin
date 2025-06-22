#
# src/pyvider/rpcplugin/protocol/service.py
#

"""
gRPC Service Implementations for Pyvider RPC Plugin.

This module provides the Python implementations for the standard gRPC services
defined in the common go-plugin protocol:
- GRPCBrokerService: For managing brokered subchannels.
- GRPCStdioService: For streaming stdin/stdout/stderr.
- GRPCControllerService: For controlling the plugin lifecycle (e.g., shutdown).

It also includes helper classes like `SubchannelConnection` and a registration
function to add these services to a gRPC server.
"""

import asyncio
import os
import traceback
from collections.abc import AsyncIterator
from typing import Any

import grpc  # For gRPC context type hint
from attrs import define, field
from google.protobuf import empty_pb2  # Use google.protobuf.empty_pb2

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
from pyvider.telemetry import logger


class BrokerError(Exception):
    pass


@define(slots=True)
class SubchannelConnection:
    """
    Represents a single 'brokered' subchannel. The go-plugin host
    can request to open or dial it. We store an ID, connection state, etc.
    """

    conn_id: int = field()
    address: str = field()
    is_open: bool = field(default=False, init=False)

    async def open(self) -> None:
        logger.debug(
            f"🔌🔍✅ SubchannelConnection.open() => Opening subchannel {self.conn_id} "
            f"at {self.address}"
        )
        await asyncio.sleep(0.05)  # simulate
        self.is_open = True

    async def close(self) -> None:
        logger.debug(
            f"🔌🔒✅ SubchannelConnection.close() => Closing subchannel {self.conn_id}"
        )
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
        context: grpc.aio.ServicerContext,
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
        logger.debug(
            "🔌📡🚀 GRPCBrokerService.StartStream => Began broker sub-stream "
            "(bidirectional)."
        )
        try:  # Outer try for iterator errors
            async for incoming in request_iterator:
                sub_id = incoming.service_id
                try:  # Inner try for processing each item
                    logger.debug(
                        "🔌📡🔍 Received ConnInfo: service_id="
                        f"{sub_id}, network='{incoming.network}', "
                        f"address='{incoming.address}'"
                    )

                    if incoming.knock.knock:  # Request to open/ensure channel
                        if (
                            sub_id in self._subchannels
                            and self._subchannels[sub_id].is_open
                        ):
                            logger.debug(
                                f"🔌📡⚠️ Subchannel ID {sub_id} already exists "
                                "and is open."
                            )
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
                            logger.debug(
                                f"🔌📡✅ Opened new subchannel {sub_id}, returning ack."
                            )
                            yield ConnInfo(
                                service_id=sub_id,
                                network=incoming.network,
                                address=incoming.address,
                                knock=ConnInfo.Knock(knock=False, ack=True, error=""),
                            )
                    else:  # Request to close channel (knock=False)
                        if sub_id in self._subchannels:
                            logger.debug(f"🔌📡🛑 Closing subchannel {sub_id}.")
                            await self._subchannels[sub_id].close()
                            del self._subchannels[sub_id]
                            yield ConnInfo(  # Ack the close
                                service_id=sub_id,
                                knock=ConnInfo.Knock(knock=False, ack=True, error=""),
                            )
                        else:
                            logger.warning(
                                "🔌📡⚠️ Request to close non-existent subchannel "
                                f"{sub_id}."
                            )
                            yield ConnInfo(
                                service_id=sub_id,
                                knock=ConnInfo.Knock(
                                    knock=False, ack=True, error="Channel not found"
                                ),
                            )
                except Exception as ex_inner:
                    err_str_inner = (
                        f"Broker error processing item for sub_id {sub_id}: {ex_inner}"
                    )
                    logger.error(
                        f"🔌📡❌ {err_str_inner}",
                        extra={"trace": traceback.format_exc()},
                    )
                    yield ConnInfo(
                        service_id=sub_id,
                        knock=ConnInfo.Knock(
                            knock=False, ack=False, error=err_str_inner
                        ),
                    )
                    # Crucial: process next item, don't fall into ex_outer
                    continue
        except Exception as ex_outer:
            outer_error_sub_id = (
                getattr(incoming, "service_id", 0) if "incoming" in locals() else 0
            )
            err_str_outer = (
                "Broker stream error from client iterator for sub_id "
                f"{outer_error_sub_id} (outer loop): {ex_outer}"
            )
            logger.error(
                f"🔌📡❌ {err_str_outer}", extra={"trace": traceback.format_exc()}
            )
            try:
                yield ConnInfo(
                    service_id=0,
                    knock=ConnInfo.Knock(knock=False, ack=False, error=err_str_outer),
                )
            except Exception as e_yield_fail:
                logger.error(
                    "🔌📡❌ Failed to yield error message after client iterator error: "
                    f"{e_yield_fail}"
                )

        logger.debug(
            "🔌📡🛑 GRPCBrokerService.StartStream => stream processing "
            "potentially ended."
        )


class GRPCStdioService(GRPCStdioServicer):
    """
    Implementation of plugin stdio streaming.
    """

    def __init__(self) -> None:
        self._message_queue: asyncio.Queue[StdioData] = asyncio.Queue()
        self._shutdown = False

    async def put_line(self, line: bytes, is_stderr: bool = False) -> None:
        """
        Adds a line of data (stdout or stderr) to the message queue for streaming.

        Args:
            line: The bytes data of the line.
            is_stderr: True if the line is from stderr, False for stdout.
        """
        try:
            data = StdioData(
                channel=StdioData.STDERR if is_stderr else StdioData.STDOUT, data=line
            )
            await self._message_queue.put(data)
        except Exception as e:
            logger.error(f"🔌📝❌ Error putting line in queue: {e}")

    async def StreamStdio(
        self, request: empty_pb2.Empty, context: grpc.aio.ServicerContext
    ) -> AsyncIterator[StdioData]:
        """Streams STDOUT/STDERR lines to the caller."""
        logger.debug(
            "🔌📝✅ GRPCStdioService.StreamStdio => started. Streaming lines to host."
        )

        done = asyncio.Event()

        # Revert to simpler signature if ctx not used, to satisfy mypy on callback type
        def on_rpc_done(_: Any) -> None:
            logger.debug(
                "🔌📝 GRPCStdioService.StreamStdio.on_rpc_done called "
                "(client disconnected or call ended)."
            )
            done.set()

        context.add_done_callback(on_rpc_done)  # type: ignore[arg-type]

        logger.debug(
            "🔌📝 GRPCStdioService: Entering StreamStdio while loop "
            f"(shutdown={self._shutdown}, done={done.is_set()})"
        )

        get_task: asyncio.Task[StdioData] | None = None
        done_wait_task: asyncio.Task[bool] | None = None

        while not self._shutdown and not done.is_set():
            try:
                get_task = asyncio.create_task(
                    self._message_queue.get(), name="StdioGetMessage"
                )
                done_wait_task = asyncio.create_task(done.wait(), name="StdioDoneWait")

                completed, pending = await asyncio.wait(
                    [get_task, done_wait_task], return_when=asyncio.FIRST_COMPLETED
                )

                should_break_loop = done_wait_task in completed

                if get_task in completed:
                    try:
                        data_item = get_task.result()
                        self._message_queue.task_done()
                        logger.debug(
                            "🔌📝✅ GRPCStdioService: Dequeued item: "
                            f"{data_item.channel}, {data_item.data[:20]!r}"
                        )
                        yield data_item
                        await asyncio.sleep(0)
                    except asyncio.CancelledError:
                        logger.debug(
                            "🔌📝 GRPCStdioService.StreamStdio: get_task was cancelled."
                        )

                tasks_to_await_cleanup_pending = []
                for task_to_cancel in pending:
                    if not task_to_cancel.done():
                        task_to_cancel.cancel()
                        tasks_to_await_cleanup_pending.append(task_to_cancel)

                if tasks_to_await_cleanup_pending:
                    await asyncio.gather(
                        *tasks_to_await_cleanup_pending, return_exceptions=True
                    )
                    logger.debug(
                        "🔌📝 GRPCStdioService.StreamStdio: Cleaned up "
                        f"{len(tasks_to_await_cleanup_pending)} pending tasks."
                    )

                if should_break_loop:
                    logger.debug(
                        "🔌📝 GRPCStdioService.StreamStdio: 'done' event set or "
                        "task cancelled, exiting loop."
                    )
                    break
            except asyncio.CancelledError:
                logger.debug(
                    "🔌📝🛑 GRPCStdioService.StreamStdio task itself was cancelled."
                )
                # Further cleanup of get_task/done_wait_task if they exist
                # (omitted for brevity as it's similar to below)
                break
            except Exception as e:
                logger.error(
                    f"🔌📝❌ Error in StreamStdio loop: {e}",
                    extra={"trace": traceback.format_exc()},
                )
                # Further cleanup
                break
        # Final cleanup (simplified)
        all_tasks = [t for t in [get_task, done_wait_task] if t and not t.done()]
        if all_tasks:
            for t in all_tasks:
                t.cancel()
            await asyncio.gather(*all_tasks, return_exceptions=True)

        logger.debug(
            "🔌📝🛑 GRPCStdioService.StreamStdio => exited main loop. "
            f"shutdown={self._shutdown}, done.is_set()={done.is_set()}"
        )

        if self._shutdown or not self._message_queue.empty():
            logger.debug(
                "🔌📝 GRPCStdioService.StreamStdio: Draining remaining "
                f"{self._message_queue.qsize()} items from queue..."
            )
            while not self._message_queue.empty():
                try:
                    data_item = self._message_queue.get_nowait()
                    self._message_queue.task_done()
                    logger.debug(
                        "🔌📝✅ GRPCStdioService: Draining item: "
                        f"{data_item.channel}, {data_item.data[:20]!r}"
                    )
                    yield data_item
                    await asyncio.sleep(0)
                except asyncio.QueueEmpty:
                    logger.debug(
                        "🔌📝 GRPCStdioService.StreamStdio: Queue empty during drain."
                    )
                    break
                except Exception as e_drain:
                    logger.error(
                        f"🔌📝❌ Error draining queue: {e_drain}",
                        extra={"trace": traceback.format_exc()},
                    )
                    break
        logger.debug("🔌📝 GRPCStdioService.StreamStdio: Stream truly ending.")

    def shutdown(self) -> None:
        # Note: `shutdown` is a reserved keyword in some contexts,
        # but here it's a method name.
        logger.debug("🔌📝⚠️ GRPCStdioService => marking service as shutdown")
        self._shutdown = True


class GRPCControllerService(GRPCControllerServicer):
    """
    Implements the GRPCController service for plugin lifecycle management.
    Specifically, it handles the Shutdown RPC to gracefully terminate the plugin.
    """

    def __init__(
        self, shutdown_event: asyncio.Event, stdio_service: GRPCStdioService
    ) -> None:
        """
        Initializes the GRPCControllerService.

        Args:
            shutdown_event: An asyncio.Event to signal plugin shutdown.
            stdio_service: The GRPCStdioService instance to also shutdown.
        """
        self._shutdown_event = shutdown_event or asyncio.Event()
        self._stdio_service = stdio_service

    async def Shutdown(
        self, request: CEmpty, context: grpc.aio.ServicerContext
    ) -> CEmpty:
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
        logger.debug(
            "🔌🛑✅ GRPCControllerService.Shutdown => plugin shutdown requested."
        )
        self._stdio_service.shutdown()
        self._shutdown_event.set()

        asyncio.create_task(self._delayed_shutdown())
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


def register_protocol_service(
    server: grpc.aio.Server, shutdown_event: asyncio.Event
) -> None:
    """Registers all standard gRPC services for the plugin."""
    stdio_service = GRPCStdioService()
    broker_service = GRPCBrokerService()
    controller_service = GRPCControllerService(shutdown_event, stdio_service)

    add_GRPCStdioServicer_to_server(stdio_service, server)
    add_GRPCBrokerServicer_to_server(broker_service, server)
    add_GRPCControllerServicer_to_server(controller_service, server)

    logger.debug(
        "🔌 ProtocolService => Registered GRPCStdio, GRPCBroker, GRPCController."
    )


# 🐍🏗️🔌
