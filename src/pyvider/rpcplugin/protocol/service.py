
# pyvider/rpcplugin/protocol/service.py

import asyncio
from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.exception import HandshakeError

# Import generated classes from pb2_grpc modules
from pyvider.rpcplugin.protocol.grpc_stdio_pb2_grpc import GRPCStdioServicer, add_GRPCStdioServicer_to_server
from pyvider.rpcplugin.protocol.grpc_broker_pb2_grpc import GRPCBrokerServicer, add_GRPCBrokerServicer_to_server
from pyvider.rpcplugin.protocol.grpc_controller_pb2_grpc import GRPCControllerServicer, add_GRPCControllerServicer_to_server
from google.protobuf.empty_pb2 import Empty

class ProtocolService(GRPCStdioServicer, GRPCBrokerServicer, GRPCControllerServicer):
    """
    Implements the gRPC services for stdio, broker, and controller.
    """

    def __init__(self, shutdown_event: asyncio.Event):
        self._setup_complete = asyncio.Event()
        self._stream_active = True
        self._shutdown_event = shutdown_event
        self._message_queue = asyncio.Queue()
        self._active_streams = set()  # Track active stream IDs

    # GRPCStdio method
    async def StreamStdio(self, request, context):
        stream_id = id(context)
        self._active_streams.add(stream_id)
        logger.debug(f"🔌📡✅ StreamStdio started [Stream ID: {stream_id}]")
        try:
            # Instead of iterating over 'context', use an internal loop.
            while not self._shutdown_event.is_set():
                try:
                    message = await asyncio.wait_for(self._message_queue.get(), timeout=5.0)
                except asyncio.TimeoutError:
                    continue
                yield message  # Echo the message back
        except Exception as e:
            logger.error(f"🔌📡❌ StreamStdio error: {e}")
            raise
        finally:
            self._active_streams.discard(stream_id)
            logger.debug(f"🔌📡🛑 StreamStdio closed [Stream ID: {stream_id}]")
            await self.handle_shutdown()

    # GRPCBroker method
    async def StartStream(self, request_iterator, context):
        stream_id = request_iterator.stream_id or f"stream-{id(context)}"
        logger.debug(f"🔌📡✅ StartStream initiated [Stream ID: {stream_id}]")
        try:
            await asyncio.wait_for(self._setup_complete.wait(), timeout=2.0)
            self._active_streams.add(stream_id)
            return Empty()
        except asyncio.TimeoutError:
            logger.error(f"🔌📡❌ Timeout waiting for StreamStdio setup [Stream ID: {stream_id}]")
            context.set_code(14)  # UNAVAILABLE
            context.set_details('Timeout waiting for StreamStdio setup')
            raise
        except Exception as e:
            logger.error(f"🔌📡❌ StartStream error: {e}")
            context.set_code(13)  # INTERNAL
            context.set_details(f'Internal error: {e}')
            raise

    # GRPCController method
    async def Shutdown(self, request, context):
        logger.debug("🔌🛑✅ Shutdown initiated for plugin")
        self._stream_active = False
        self._shutdown_event.set()
        for stream_id in list(self._active_streams):
            self._active_streams.discard(stream_id)
            logger.debug(f"🔌📡🛑 Terminated active stream [Stream ID: {stream_id}]")
        # Insert additional shutdown logic as needed.
        return Empty()

    async def StopStream(self, request, context):
        stream_id = request.stream_id or "unknown"
        logger.debug(f"🔌📡🛑 StopStream received for [Stream ID: {stream_id}]")
        if stream_id in self._active_streams:
            self._active_streams.discard(stream_id)
            logger.debug(f"🔌📡✅ Stopped stream [Stream ID: {stream_id}]")
        else:
            logger.warning(f"🔌📡⚠️ Attempted to stop nonexistent stream [Stream ID: {stream_id}]")
        return Empty()

    async def handle_shutdown(self, force: bool = False):
        self._stream_active = False
        if force:
            while not self._message_queue.empty():
                try:
                    self._message_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
        await asyncio.sleep(0.1)

# Integration example:
def register_protocol_service(server, shutdown_event: asyncio.Event) -> None:
    service = ProtocolService(shutdown_event)
    add_GRPCStdioServicer_to_server(service, server)
    add_GRPCBrokerServicer_to_server(service, server)
    add_GRPCControllerServicer_to_server(service, server)
    logger.debug("🔌 ProtocolService registered with gRPC server.")
