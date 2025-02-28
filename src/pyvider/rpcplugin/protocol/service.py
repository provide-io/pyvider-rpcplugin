#!/usr/bin/env python3
# src/pyvider/rpcplugin/protocol/service.py

import asyncio
import traceback

from pyvider.rpcplugin.logger import logger
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


class SubchannelConnection:
    """
    Represents a single 'brokered' subchannel. The go-plugin host
    can request to open or dial it. We store an ID, connection state, etc.
    """

    def __init__(self, conn_id: int, address: str) -> None:
        self.conn_id = conn_id
        self.address = address
        self.is_open = False

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
        self._subchannels = {}

    async def StartStream(self, request_iterator, context):
        """
        StartStream is a bidirectional streaming RPC. Each side can send
        'ConnInfo' messages. We'll interpret them to open or close subchannels.
        """
        # Note: Because this is an async generator, you read from `request_iterator`
        # and optionally yield responses. Some advanced use-cases might do a real
        # 'broker mux' with synchronous channels. Here, we do a simplified approach.

        logger.debug(
            "🔌📡🚀 GRPCBrokerService.StartStream => Began broker sub-stream (bidirectional)."
        )

        # We'll produce responses as we handle each incoming message.
        async for incoming in request_iterator:
            try:
                logger.debug(
                    f"🔌📡🔍 Received ConnInfo: service_id={incoming.service_id}, network='{incoming.network}', address='{incoming.address}'"
                )

                # If we see 'knock.knock==True' then the host is requesting a subchannel open.
                if incoming.knock.knock:
                    # Attempt to open or create a subchannel.
                    sub_id = incoming.service_id
                    if sub_id in self._subchannels:
                        # Already exists, maybe just re-open or error out
                        logger.debug(
                            f"🔌📡⚠️ Subchannel ID {sub_id} already in _subchannels."
                        )
                    else:
                        # Create a new subchannel
                        subchan = SubchannelConnection(sub_id, incoming.address)
                        self._subchannels[sub_id] = subchan
                        await subchan.open()

                    # Send back a response with knock.ack=True
                    outgoing = ConnInfo(
                        service_id=sub_id,
                        network=incoming.network,
                        address=incoming.address,
                        knock=ConnInfo.Knock(
                            knock=False,  # we are responding
                            ack=True,
                            error="",
                        ),
                    )
                    logger.debug(
                        f"🔌📡✅ Opening subchannel {sub_id}, returning ack. {outgoing}"
                    )
                    yield outgoing

                else:
                    # Possibly a close request or just a no-op
                    sub_id = incoming.service_id
                    if sub_id in self._subchannels:
                        logger.debug(f"🔌📡🛑 Closing subchannel {sub_id}.")
                        await self._subchannels[sub_id].close()
                        del self._subchannels[sub_id]
                    # Return ack again
                    outgoing = ConnInfo(
                        service_id=sub_id,
                        knock=ConnInfo.Knock(knock=False, ack=True, error=""),
                    )
                    yield outgoing

            except Exception as ex:
                err_str = f"Broker error: {ex}"
                logger.error(
                    f"🔌📡❌ {err_str}", extra={"trace": traceback.format_exc()}
                )
                yield ConnInfo(
                    service_id=0,
                    knock=ConnInfo.Knock(knock=False, ack=False, error=err_str),
                )

        logger.debug("🔌📡🛑 GRPCBrokerService.StartStream => stream closed by client.")
        return


class GRPCStdioService(GRPCStdioServicer):
    """
    Implementation of plugin stdio streaming. Typically you want to capture
    plugin’s stdout/stderr and send it back to the host. We'll show a simplified
    approach. In real usage, you might run a background task collecting logs.
    """

    def __init__(self) -> None:
        # We keep an internal queue for all outgoing lines.
        self._message_queue = asyncio.Queue()
        self._shutdown = False

    async def put_line(self, line: bytes, is_stderr=False) -> None:
        """
        Public method: feed lines to the queue from somewhere else in your code,
        or from a logging handler that writes to the queue.
        """
        try:
            data = StdioData(
                channel=StdioData.STDERR if is_stderr else StdioData.STDOUT, data=line
            )
            await self._message_queue.put(data)
        except Exception as e:
            # Log but don't propagate to prevent crashing the service
            logger.error(f"🔌📝❌ Error putting line in queue: {e}")

    async def StreamStdio(self, request, context):
        """
        Streams STDOUT/STDERR lines to the caller.
        The host (go-plugin) typically calls this once at startup, then reads forever.
        """
        logger.debug(
            "🔌📝✅ GRPCStdioService.StreamStdio => started. Streaming lines to host."
        )
        # Use context.cancelled() instead of context.is_active() which doesn't exist
        while not self._shutdown and not context.cancelled():
            try:
                # Wait up to 2s for a new line; if none, we yield a short idle.
                data_item = await asyncio.wait_for(
                    self._message_queue.get(), timeout=2.0
                )
                yield data_item
            except TimeoutError:
                continue
            except Exception as e:
                logger.error(
                    f"🔌📝❌ Error streaming lines: {e}",
                    extra={"trace": traceback.format_exc()},
                )
                break

        logger.debug(
            "🔌📝🛑 GRPCStdioService.StreamStdio => stopping, either shutdown or context done."
        )
        return

    async def XStreamStdio(self, request, context):
        """
        Streams STDOUT/STDERR lines to the caller.
        The host (go-plugin) typically calls this once at startup, then reads forever.
        """
        logger.debug(
            "🔌📝✅ GRPCStdioService.StreamStdio => started.  Streaming lines to host."
        )
        while not self._shutdown and not context.is_active():
            try:
                # Wait up to 2s for a new line; if none, we yield a short idle.
                data_item = await asyncio.wait_for(
                    self._message_queue.get(), timeout=2.0
                )
                yield data_item
            except TimeoutError:
                continue
            except Exception as e:
                logger.error(
                    f"🔌📝❌ Error streaming lines: {e}",
                    extra={"trace": traceback.format_exc()},
                )
                break

        logger.debug(
            "🔌📝🛑 GRPCStdioService.StreamStdio => stopping, either shutdown or context done."
        )
        return

    def shutdown(self) -> None:
        logger.debug("🔌📝⚠️ GRPCStdioService => marking service as shutdown")
        self._shutdown = True


class GRPCControllerService(GRPCControllerServicer):
    """
    A simple Controller that can handle plugin lifecycle calls (Shutdown, Ping, etc.).
    You can add additional calls to replicate go-plugin’s “Ping” or “Health” checks.
    """

    def __init__(
        self, shutdown_event: asyncio.Event, stdio_service: GRPCStdioService
    ) -> None:
        self._shutdown_event = shutdown_event
        self._stdio_service = stdio_service

    async def Shutdown(self, request, context):
        """
        In go-plugin’s approach, calling 'Shutdown()' on the plugin triggers the plugin to exit.
        """
        logger.debug(
            "🔌🛑✅ GRPCControllerService.Shutdown => plugin shutdown requested."
        )
        self._stdio_service.shutdown()
        self._shutdown_event.set()
        # Return an empty object
        return CEmpty()

#
# Combine them: a convenience function that registers all services with the gRPC server.
#
def register_protocol_service(server, shutdown_event: asyncio.Event) -> None:
    """
    This function is called by your `server.py` to attach all the needed gRPC services.
    """
    # Create the “shared” Stdio service instance
    stdio_service = GRPCStdioService()

    # Initialize the broker + controller
    broker_service = GRPCBrokerService()
    controller_service = GRPCControllerService(shutdown_event, stdio_service)

    # Register them on the server
    add_GRPCStdioServicer_to_server(stdio_service, server)
    add_GRPCBrokerServicer_to_server(broker_service, server)
    add_GRPCControllerServicer_to_server(controller_service, server)

    logger.debug(
        "🔌 ProtocolService => Registered GRPCStdio, GRPCBroker, GRPCController with gRPC server."
    )

    # You might want to return references to the services for feeding data etc.
    # e.g. return (stdio_service, broker_service, controller_service)
