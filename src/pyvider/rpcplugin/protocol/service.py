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
                        if sub_id in self._subchannels:
                            logger.debug(
                                f"🔌📡⚠️ Subchannel ID {sub_id} already in _subchannels."
                            )
                        else:
                            subchan = SubchannelConnection(sub_id, incoming.address)
                            self._subchannels[sub_id] = subchan
                            await subchan.open()

                        outgoing = ConnInfo(
                            service_id=sub_id,
                            network=incoming.network,
                            address=incoming.address,
                            knock=ConnInfo.Knock(
                                knock=False,
                                ack=True,
                                error="",
                            ),
                        )
                        logger.debug(
                            f"🔌📡✅ Opening subchannel {sub_id}, returning ack. {outgoing}"
                        )
                        yield outgoing

                    else:
                        sub_id = incoming.service_id
                        if sub_id in self._subchannels:
                            logger.debug(f"🔌📡🛑 Closing subchannel {sub_id}.")
                            await self._subchannels[sub_id].close()
                            del self._subchannels[sub_id]
                        outgoing = ConnInfo(
                            service_id=sub_id,
                            knock=ConnInfo.Knock(knock=False, ack=True, error=""),
                        )
                        yield outgoing

                except Exception as ex_inner: # Catch errors processing an item (renamed ex to ex_inner)
                    err_str_inner = f"Broker error processing item: {ex_inner}"
                    logger.error(
                        f"🔌📡❌ {err_str_inner}", extra={"trace": traceback.format_exc()}
                )
                yield ConnInfo(
                    service_id=getattr(incoming, 'service_id', 0), # Use incoming service_id if available
                    knock=ConnInfo.Knock(knock=False, ack=False, error=err_str),
                )
        except Exception as ex_outer: # Catch errors from the request_iterator itself
            err_str_outer = f"Broker stream error from client iterator: {ex_outer}"
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

        get_task = None # Initialize task variables
        done_task = None

        while not self._shutdown and not done.is_set():
            try:
                # Create tasks for getting from queue and waiting for done event
                get_task = asyncio.create_task(self._message_queue.get(), name="StdioGetMessage")
                done_task = asyncio.create_task(done.wait(), name="StdioDoneWait")

                completed, pending = await asyncio.wait(
                    [get_task, done_task], return_when=asyncio.FIRST_COMPLETED
                )

                if done_task in completed:
                    logger.debug("🔌📝 GRPCStdioService.StreamStdio: 'done' event was set, exiting loop.")
                    if get_task and not get_task.done(): # If get_task is still pending
                        get_task.cancel() # Cancel it
                    break # Exit the while loop

                # If get_task is in completed (it must be, if done_task wasn't)
                data_item = get_task.result() # Get result from completed get_task
                self._message_queue.task_done()
                logger.debug(f"🔌📝✅ GRPCStdioService: Dequeued item: {data_item.channel}, {data_item.data[:20]}")
                yield data_item

            except asyncio.CancelledError: # If the StreamStdio task itself is cancelled
                logger.debug("🔌📝🛑 GRPCStdioService.StreamStdio task was cancelled.")
                if get_task and not get_task.done():
                    get_task.cancel()
                if done_task and not done_task.done():
                    done_task.cancel()
                break
            except Exception as e:
                logger.error(
                    f"🔌📝❌ Error in StreamStdio loop: {e}", # Changed log message slightly
                    extra={"trace": traceback.format_exc()},
                )
                if get_task and not get_task.done(): # Cleanup tasks on other exceptions too
                    get_task.cancel()
                if done_task and not done_task.done():
                    done_task.cancel()
                break
            finally:
                # Ensure tasks are cancelled if loop iteration ends for any reason other than break
                # (e.g. if we added a continue, which we don't have here)
                # This finally might be redundant if all exit paths (break) handle task cancellation.
                # However, if we were to await pending tasks here, it could also lead to hangs.
                # For now, cancellation in except blocks is the primary mechanism.
                pass

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
