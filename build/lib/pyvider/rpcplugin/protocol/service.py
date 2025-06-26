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

import os
import asyncio
import traceback
from typing import Any # Added for type hinting

from attrs import define, field

from pyvider.telemetry import logger
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
    Represents a single 'brokered' subchannel. The go-plugin host
    can request to open or dial it. We store an ID, connection state, etc.
    """
    conn_id: int = field()
    address: str = field()
    is_open: bool = field(default=False, init=False)

    async def open(self) -> None:
        logger.debug(
            f"🔌🔍✅ SubchannelConnection.open() => Opening subchannel {self.conn_id} at {self.address}"
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
    Implementation of the gRPC Broker logic. This matches the StartStream(...) signature in
    `grpc_broker.proto`, which transmits a stream of ConnInfo messages in both directions.

    In go-plugin, the plugin side uses 'StartStream(stream ConnInfo) returns (stream ConnInfo)'
    to set up a subchannel for callbacks or bridging. We'll do a simplified version here.
    """

    def __init__(self) -> None:
        # We hold subchannel references here.
        self._subchannels: dict[int, SubchannelConnection] = {}

    async def StartStream(self, request_iterator: Any, context: Any) -> Any: # Type hints for gRPC params
        """
        Handles the bidirectional stream for broker connections.

        This gRPC method allows the client and server to exchange `ConnInfo`
        messages to manage subchannels for additional services or callbacks.

        Args:
            request_iterator: An async iterator yielding incoming `ConnInfo` messages from the client.
            context: The gRPC request context.

        Yields:
            Outgoing `ConnInfo` messages to the client.
        """
        logger.debug(
            "🔌📡🚀 GRPCBrokerService.StartStream => Began broker sub-stream (bidirectional)."
        )
        try: # Outer try for iterator errors
            async for incoming in request_iterator:
                sub_id = incoming.service_id # Get sub_id early for use in error messages if needed
                try: # Inner try for processing each item
                    logger.debug(
                        f"🔌📡🔍 Received ConnInfo: service_id={sub_id}, network='{incoming.network}', address='{incoming.address}'"
                    )

                    if incoming.knock.knock: # Request to open/ensure channel
                        if sub_id in self._subchannels and self._subchannels[sub_id].is_open:
                            logger.debug(f"🔌📡⚠️ Subchannel ID {sub_id} already exists and is open.")
                            yield ConnInfo(
                                service_id=sub_id,
                                network=incoming.network,
                                address=incoming.address,
                                knock=ConnInfo.Knock(knock=False, ack=True, error=""),
                            )
                        else: # New subchannel request or existing but not open
                            subchan = SubchannelConnection(sub_id, incoming.address)
                            # Attempt to open the subchannel
                            await subchan.open() # This might raise BrokerError or other exceptions
                            self._subchannels[sub_id] = subchan # Add to dict ONLY after successful open
                            logger.debug(f"🔌📡✅ Opened new subchannel {sub_id}, returning ack.")
                            yield ConnInfo(
                                service_id=sub_id,
                                network=incoming.network,
                                address=incoming.address,
                                knock=ConnInfo.Knock(knock=False, ack=True, error=""),
                            )
                    else: # Request to close channel (knock=False)
                        if sub_id in self._subchannels:
                            logger.debug(f"🔌📡🛑 Closing subchannel {sub_id}.")
                            await self._subchannels[sub_id].close()
                            del self._subchannels[sub_id]
                            yield ConnInfo( # Ack the close
                                service_id=sub_id,
                                knock=ConnInfo.Knock(knock=False, ack=True, error=""),
                            )
                        else:
                            logger.warning(f"🔌📡⚠️ Request to close non-existent subchannel {sub_id}.")
                            yield ConnInfo( # Ack the close attempt, even if not found
                                service_id=sub_id,
                                knock=ConnInfo.Knock(knock=False, ack=True, error="Channel not found"),
                            )
                except Exception as ex_inner:
                    # 'sub_id' is defined from the line 'sub_id = incoming.service_id' before this try block.
                    err_str_inner = f"Broker error processing item for sub_id {sub_id}: {ex_inner}"
                    logger.error(f"🔌📡❌ {err_str_inner}", extra={"trace": traceback.format_exc()})
                    yield ConnInfo(
                        service_id=sub_id,
                        knock=ConnInfo.Knock(knock=False, ack=False, error=err_str_inner),
                    )
                    continue # Crucial to process next item and not fall into ex_outer for this specific error
        except Exception as ex_outer: # Catch errors from the request_iterator itself (e.g., client disconnect)
            # Ensure sub_id is defined for the log, default if not (e.g. error before sub_id is parsed)
            # For ex_outer, sub_id might not be in current scope if error happened early in `async for`
            outer_error_sub_id = getattr(incoming, 'service_id', 0) if 'incoming' in locals() else 0
            err_str_outer = f"Broker stream error from client iterator for sub_id {outer_error_sub_id} (outer loop): {ex_outer}"
            logger.error(
                f"🔌📡❌ {err_str_outer}", extra={"trace": traceback.format_exc()}
            )
            try:
                yield ConnInfo(
                    service_id=0, # No specific incoming item to get ID from
                    knock=ConnInfo.Knock(knock=False, ack=False, error=err_str_outer),
                )
            except Exception as e_yield_fail:
                logger.error(f"🔌📡❌ Failed to yield error message after client iterator error: {e_yield_fail}")

        logger.debug("🔌📡🛑 GRPCBrokerService.StartStream => stream processing potentially ended.")


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

    async def StreamStdio(self, request, context):
        """Streams STDOUT/STDERR lines to the caller."""
        logger.debug(
            "🔌📝✅ GRPCStdioService.StreamStdio => started. Streaming lines to host."
        )
        
        done = asyncio.Event()
        
        # FIX: Corrected on_rpc_done signature
        def on_rpc_done(_ignored_arg: Any): # Accepts one argument
            logger.debug("🔌📝 GRPCStdioService.StreamStdio.on_rpc_done called (client disconnected or call ended).") # Modified log
            done.set()
        
        context.add_done_callback(on_rpc_done) # gRPC context callback
        
        logger.debug(f"🔌📝 GRPCStdioService: Entering StreamStdio while loop (shutdown={self._shutdown}, done={done.is_set()})")

        get_task: asyncio.Task | None = None
        done_wait_task: asyncio.Task | None = None

        while not self._shutdown and not done.is_set():
            try:
                get_task = asyncio.create_task(self._message_queue.get(), name="StdioGetMessage")
                done_wait_task = asyncio.create_task(done.wait(), name="StdioDoneWait")

                completed, pending = await asyncio.wait(
                    [get_task, done_wait_task], return_when=asyncio.FIRST_COMPLETED
                )

                # Default to breaking if done_wait_task completed
                should_break_loop = done_wait_task in completed

                if get_task in completed:
                    try:
                        data_item = get_task.result()
                        self._message_queue.task_done()
                        logger.debug(f"🔌📝✅ GRPCStdioService: Dequeued item: {data_item.channel}, {data_item.data[:20]}")
                        yield data_item
                        await asyncio.sleep(0) # Allow consumer to process the item
                    except asyncio.CancelledError: # If get_task was cancelled by done_wait_task completing first
                        logger.debug("🔌📝 GRPCStdioService.StreamStdio: get_task was cancelled.")
                        # If done_wait_task also completed (which it should have to cancel get_task), loop will break

                # Cancel any pending tasks
                for task_to_cancel in pending:
                    task_to_cancel.cancel()
                    # Optionally, await the cancellation with suppress to ensure cleanup
                    # try:
                    #     await task_to_cancel
                    # except asyncio.CancelledError:
                    #     pass

                if should_break_loop: # If done_wait_task was the one that completed
                    logger.debug("🔌📝 GRPCStdioService.StreamStdio: 'done' event was set or task cancelled, exiting loop.")
                    break

            except asyncio.CancelledError:
                logger.debug("🔌📝🛑 GRPCStdioService.StreamStdio task itself was cancelled.")
                if get_task and not get_task.done():
                    get_task.cancel()
                if done_wait_task and not done_wait_task.done():
                    done_wait_task.cancel()
                break
            except Exception as e:
                logger.error(
                    f"🔌📝❌ Error in StreamStdio loop: {e}",
                    extra={"trace": traceback.format_exc()},
                )
                if get_task and not get_task.done():
                    get_task.cancel()
                if done_wait_task and not done_wait_task.done():
                    done_wait_task.cancel()
                break

        # Final cleanup of any lingering tasks (defensive)
        if get_task and not get_task.done():
            get_task.cancel()
        if done_wait_task and not done_wait_task.done():
            done_wait_task.cancel()

        logger.debug(f"🔌📝🛑 GRPCStdioService.StreamStdio => exited main loop. shutdown={self._shutdown}, done.is_set()={done.is_set()}")

        # Drain any remaining items from the queue if service was shut down
        # but client is potentially still connected (or to ensure all sent items are yielded)
        if self._shutdown or not self._message_queue.empty(): # Drain if shutdown or if items are there
            logger.debug(f"🔌📝 GRPCStdioService.StreamStdio: Draining remaining {self._message_queue.qsize()} items from queue...")
            while not self._message_queue.empty():
                try:
                    data_item = self._message_queue.get_nowait()
                    self._message_queue.task_done()
                    logger.debug(f"🔌📝✅ GRPCStdioService: Draining item: {data_item.channel}, {data_item.data[:20]}")
                    yield data_item
                    await asyncio.sleep(0)  # Allow consumer to process
                except asyncio.QueueEmpty:
                    logger.debug("🔌📝 GRPCStdioService.StreamStdio: Queue empty during drain.")
                    break
                except Exception as e_drain:
                    logger.error(f"🔌📝❌ Error draining queue: {e_drain}", extra={"trace": traceback.format_exc()})
                    break
        logger.debug("🔌📝 GRPCStdioService.StreamStdio: Stream truly ending.")

    def shutdown(self) -> None:
        logger.debug("🔌📝⚠️ GRPCStdioService => marking service as shutdown")
        self._shutdown = True

    # Note: `shutdown` is a reserved keyword in some contexts, but here it's a method name.
    # Consider renaming if it causes confusion, though it's descriptive.


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
        self._shutdown_event = shutdown_event or asyncio.Event() # Ensure an event is always present
        self._stdio_service = stdio_service

    async def Shutdown(self, request: CEmpty, context: Any) -> CEmpty: # Type hints for gRPC params
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
            except Exception: # pylint: disable=broad-except
                import sys
                sys.exit(0) # Fallback exit
        else:
            import sys
            sys.exit(0)


def register_protocol_service(server, shutdown_event: asyncio.Event) -> None:
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
