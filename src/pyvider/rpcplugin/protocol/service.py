#
# pyvider/rpcplugin/protocol/service.py
#

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

    async def StartStream(self, request_iterator, context):
        """
        StartStream is a bidirectional streaming RPC. Each side can send
        'ConnInfo' messages. We'll interpret them to open or close subchannels.
        """
        logger.debug(
            "🔌📡🚀 GRPCBrokerService.StartStream => Began broker sub-stream (bidirectional)."
        )
        try: # Outer try for iterator errors
            async for incoming in request_iterator:
                try: # Inner try for processing each item
                    logger.debug(
                        f"🔌📡🔍 Received ConnInfo: service_id={incoming.service_id}, network='{incoming.network}', address='{incoming.address}'"
                    )

                    if incoming.knock.knock:
                        sub_id = incoming.service_id
                        ack_response = False  # Default ack to False for knock requests
                        error_message = ""

                        if sub_id in self._subchannels:
                            logger.warning(
                                f"🔌📡⚠️ Subchannel ID {sub_id} already in _subchannels. Treating as successful re-knock/ack."
                            )
                            # If subchannel already exists, this implies successful setup previously or a re-knock.
                            ack_response = True
                        else:
                            subchan = SubchannelConnection(sub_id, incoming.address)
                            try:
                                await subchan.open()
                                self._subchannels[sub_id] = subchan # Add to dict ONLY after successful open
                                ack_response = True
                                logger.debug(f"🔌📡✅ Successfully opened and registered subchannel {sub_id}.")
                            except Exception as e_open:
                                error_message = f"Failed to open subchannel {sub_id}: {str(e_open)}"
                                logger.error(f"🔌📡❌ {error_message}", extra={"trace": traceback.format_exc()})
                                # ack_response remains False, error_message is set

                        outgoing = ConnInfo(
                            service_id=sub_id,
                            network=incoming.network,
                            address=incoming.address,
                            knock=ConnInfo.Knock(
                                knock=False, # This is a response to a knock
                                ack=ack_response,
                                error=error_message,
                            ),
                        )
                        logger.debug(
                            f"🔌📡✅ Responding to knock for subchannel {sub_id}: ack={ack_response}, error='{error_message}'. Details: {outgoing}"
                        )
                        yield outgoing
                    else: # This is a close request for a subchannel (knock=False implicitly)
                        sub_id = incoming.service_id
                        closed_ack_response = False
                        closed_error_message = ""
                        if sub_id in self._subchannels:
                            logger.debug(f"🔌📡🛑 Closing subchannel {sub_id}.")
                            try:
                                await self._subchannels[sub_id].close()
                                closed_ack_response = True # Successfully processed close request
                            except Exception as e_close:
                                closed_error_message = f"Error closing subchannel {sub_id}: {str(e_close)}"
                                logger.error(f"🔌📡❌ {closed_error_message}", extra={"trace": traceback.format_exc()})
                            finally:
                                # Remove from tracking regardless of close success, as intent was to close.
                                del self._subchannels[sub_id]
                        else:
                            closed_error_message = f"Attempted to close non-existent subchannel {sub_id}."
                            logger.warning(f"🔌📡⚠️ {closed_error_message}")
                            # ack remains False as subchannel wasn't found to be closed.

                        outgoing = ConnInfo(
                            service_id=sub_id,
                            knock=ConnInfo.Knock(knock=False, ack=closed_ack_response, error=closed_error_message),
                        )
                        yield outgoing

                except Exception as ex_item_processing:
                    # This catches unexpected errors during the processing of 'incoming' item,
                    # outside of the specific open/close logic handled above.
                    error_str_item = f"Broker error processing incoming item: {str(ex_item_processing)}"
                    logger.error(f"🔌📡❌ {error_str_item}", extra={"trace": traceback.format_exc()})
                    # Attempt to yield an error message specific to this failed item processing.
                    # Ensure 'incoming' is available or handle if not (e.g. if error occurred before 'incoming' was fully received/parsed)
                    current_service_id = getattr(incoming, 'service_id', 0) # Default to 0 if service_id is not accessible
                    yield ConnInfo(
                        service_id=current_service_id,
                        knock=ConnInfo.Knock(knock=False, ack=False, error=error_str_item),
                    )
        except Exception as ex_iterator: # Catch errors from the request_iterator itself (e.g., client disconnects abruptly)
            error_str_iterator = f"Broker stream error from client iterator: {str(ex_iterator)}"
            logger.error(
                f"🔌📡❌ {error_str_iterator}", extra={"trace": traceback.format_exc()}
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
        """Feed lines to the queue."""
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
        
        context.add_done_callback(on_rpc_done)
        
        logger.debug(f"🔌📝 GRPCStdioService: Entering StreamStdio while loop (shutdown={self._shutdown}, done={done.is_set()})")

        get_task = None
        done_wait_task = None # Renamed for clarity

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
                if get_task and not get_task.done(): get_task.cancel()
                if done_wait_task and not done_wait_task.done(): done_wait_task.cancel()
                break
            except Exception as e:
                logger.error(
                    f"🔌📝❌ Error in StreamStdio loop: {e}",
                    extra={"trace": traceback.format_exc()},
                )
                if get_task and not get_task.done(): get_task.cancel()
                if done_wait_task and not done_wait_task.done(): done_wait_task.cancel()
                break

        # Final cleanup of any lingering tasks (defensive)
        if get_task and not get_task.done(): get_task.cancel()
        if done_wait_task and not done_wait_task.done(): done_wait_task.cancel()

        logger.debug("🔌📝 GRPCStdioService: Main loop exited. Attempting to drain remaining queue items.")
        while True:
            try:
                # Use get_nowait() for non-blocking check during drain phase.
                data_item = self._message_queue.get_nowait()
                self._message_queue.task_done()
                logger.debug(f"🔌📝✅ GRPCStdioService: Draining item: {data_item.channel}, {data_item.data[:20]}")
                yield data_item
            except asyncio.QueueEmpty:
                logger.debug("🔌📝 GRPCStdioService: Queue is empty, drain complete.")
                break
            except Exception as e_drain:
                logger.error(f"🔌📝❌ Error during queue drain: {e_drain}", extra={"trace": traceback.format_exc()})
                break

        logger.debug(f"🔌📝🛑 GRPCStdioService.StreamStdio => stopping. Reason: shutdown={self._shutdown}, done.is_set()={done.is_set()}")

    def shutdown(self) -> None:
        logger.debug("🔌📝⚠️ GRPCStdioService => marking service as shutdown")
        self._shutdown = True


class GRPCControllerService(GRPCControllerServicer):
    """
    Controller for plugin lifecycle (Shutdown).
    """

    def __init__(
        self, shutdown_event: asyncio.Event, stdio_service: GRPCStdioService
    ) -> None:
        self._shutdown_event = shutdown_event
        self._stdio_service = stdio_service

    async def Shutdown(self, request, context):
        """Handles plugin shutdown request."""
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
