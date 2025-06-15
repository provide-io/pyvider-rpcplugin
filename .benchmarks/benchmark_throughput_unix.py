import asyncio
import time
import os
import sys
from pathlib import Path
import grpc # For potential status codes

# Adjust path to import from examples/demo and src
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
examples_demo_path = project_root / "examples/demo"
src_path = project_root / "src"

# Add paths for imports
if str(examples_demo_path) not in sys.path:
    sys.path.insert(0, str(examples_demo_path))
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))


# Protocol / gRPC imports from examples/demo
try:
    import echo_pb2
    import echo_pb2_grpc
    # create_servicer_class is not found, so it will be removed.
    # We will make the handler inherit from the gRPC servicer directly.
except ImportError as e:
    print(f"Error importing demo protocol files or pyvider.rpcplugin: {e}")
    print(f"Please ensure examples/demo content (echo_pb2.py, echo_pb2_grpc.py) is available at {examples_demo_path}")
    print(f"and pyvider.rpcplugin is available at {src_path}.")
    sys.exit(1)

from pyvider.rpcplugin import plugin_server, plugin_protocol # Import plugin_protocol
from pyvider.rpcplugin.transport import UnixSocketTransport
from pyvider.telemetry import logger # Removed setup_logging

# --- Handler Definition ---
# The handler should inherit from the generated gRPC Servicer class
class EchoServiceHandlerImpl(echo_pb2_grpc.EchoServiceServicer):
    async def Echo(self, request: echo_pb2.EchoRequest, context):
        return echo_pb2.EchoReply(message=f"echo: {request.message}")

    async def EchoStream(self, request_iterator, context):
        async for request in request_iterator:
            yield echo_pb2.EchoReply(message=f"stream echo: {request.message}")

# --- Server Setup ---
async def run_server(socket_path, ready_event, stop_event):
    handler_instance = EchoServiceHandlerImpl()

    protocol_instance = plugin_protocol(
        service_name="EchoService", # Matches the service name in echo.proto
        descriptor_module=echo_pb2, # For service reflection/descriptors
        servicer_add_fn=echo_pb2_grpc.add_EchoServiceServicer_to_server
    )

    server_instance = plugin_server(
        protocol=protocol_instance,
        handler=handler_instance,
        transport="unix", # Correct argument for transport type
        transport_path=socket_path # Correct argument for Unix socket path
    )

    logger.info(f"Server starting on {socket_path}")
    server_ready_event_set_internally = False
    server_task = None
    try:
        async def serve_wrapper():
            nonlocal server_ready_event_set_internally
            try:
                # Attempt to set ready just before blocking serve call
                if not ready_event.is_set():
                    ready_event.set()
                    server_ready_event_set_internally = True
                    logger.info("Server signaled ready from serve_wrapper.")
                await server_instance.serve()
            except asyncio.CancelledError:
                logger.info("Server serve_wrapper task explicitly cancelled.")
            except Exception as e:
                logger.error(f"Server serve_wrapper error: {e}", exc_info=True)
                if not ready_event.is_set(): # If error before ready, signal it too
                    ready_event.set()
            finally:
                logger.info("Server serve_wrapper stopped.")

        server_task = asyncio.create_task(serve_wrapper())

        # Backup signal if server starts/fails extremely fast
        await asyncio.sleep(0.05)
        if not ready_event.is_set() and not server_ready_event_set_internally :
            ready_event.set()
            logger.info("Server signaled ready (fallback).")

        await stop_event.wait()
        logger.info("Stop event received, shutting down server...")

    except Exception as e:
        logger.error(f"Outer server run error: {e}", exc_info=True)
        if not ready_event.is_set():
            ready_event.set() # Ensure client part is unblocked if server fails to start
    finally:
        if server_task and not server_task.done():
            logger.info("Requesting server_instance.stop()")
            await server_instance.stop() # Graceful stop
            logger.info("Cancelling server_task.")
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                logger.info("Server_task successfully cancelled after stop.")
        logger.info("Server run_server function finished.")


# --- Client Setup ---
async def run_client_direct_transport(socket_path, num_requests):
    channel = None
    actual_requests_made = 0
    try:
        channel = grpc.aio.insecure_channel(f"unix://{socket_path}")
        await asyncio.wait_for(channel.channel_ready(), timeout=2.0) # Wait for channel to be ready
        stub = echo_pb2_grpc.EchoServiceStub(channel)
        logger.info(f"Client connected to {socket_path} via direct gRPC channel")

        start_time = time.perf_counter()

        for i in range(num_requests):
            actual_requests_made = i + 1
            request = echo_pb2.EchoRequest(message=f"hello {i}")
            try:
                response = await stub.Echo(request, timeout=0.5) # Short timeout for individual req
                if not response or not response.message:
                    logger.warning(f"Received empty/invalid response for request {i}")
            except grpc.aio.AioRpcError as e:
                logger.error(f"RPC error on request {i}: {e.details()} (code: {e.code()})")
                if e.code() in (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED):
                    logger.error("Server seems unavailable or request timed out. Stopping client benchmark.")
                    break

            if (i + 1) % 10000 == 0:
                logger.info(f"Sent {i + 1} requests...")

        end_time = time.perf_counter()

        total_time = end_time - start_time
        rps = 0
        # Calculate RPS based on actual requests made, especially if loop broke early
        requests_processed = actual_requests_made
        if total_time > 0:
            rps = requests_processed / total_time
        elif requests_processed > 0 : # Avoid division by zero if time is too small
            rps = float('inf') # Effectively infinite if time was zero for some requests
        else: # No requests and no time
            rps = 0


        logger.info("--- Unix Socket Throughput Benchmark (Direct gRPC Channel) ---")
        logger.info(f"Socket: {socket_path}")
        logger.info(f"Target Requests: {num_requests}")
        logger.info(f"Actual Requests Made: {actual_requests_made}")
        logger.info(f"Total Time: {total_time:.3f} seconds")
        logger.info(f"Requests/Second (RPS): {rps:.2f}")

        return rps
    except asyncio.TimeoutError:
        logger.error("Client failed to connect to server (channel not ready).")
        return 0
    except Exception as e:
        logger.error(f"Client error: {e}", exc_info=True)
        return 0
    finally:
        if channel:
            await channel.close()
            logger.info("Client channel closed.")


# --- Main Execution ---
async def main_benchmark():
    socket_path = f"/tmp/benchmark_throughput_pyvider_{os.getpid()}.sock"
    num_requests = 50000

    if os.path.exists(socket_path):
        try:
            os.remove(socket_path)
        except OSError as e:
            logger.warning(f"Could not remove old socket {socket_path}: {e}.")

    server_ready_event = asyncio.Event()
    server_stop_event = asyncio.Event() # Event to signal server to stop

    server_task = asyncio.create_task(run_server(socket_path, server_ready_event, server_stop_event))

    logger.info("Waiting for server to be ready...")
    try:
        await asyncio.wait_for(server_ready_event.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        logger.error("Server did not become ready in time. Aborting benchmark.")
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            logger.info("Server task cancelled due to timeout.")
        return

    if not os.path.exists(socket_path) and not server_task.done(): # Check if server task is already done (e.g. crashed)
        logger.error(f"Server did not create socket file at {socket_path} and task is not done. Aborting client.")
        server_stop_event.set() # Try to signal server to stop
        await asyncio.sleep(0.1) # Give a moment for stop signal
        if not server_task.done():
            server_task.cancel()
        try: await server_task
        except asyncio.CancelledError: pass
        return

    logger.info("Server reported ready. Starting client...")
    await asyncio.sleep(0.2)

    actual_rps = 0
    try:
        actual_rps = await run_client_direct_transport(socket_path, num_requests)
    except Exception as e:
        logger.error(f"Client run failed: {e}", exc_info=True)
    finally:
        logger.info("Client finished. Signaling server to stop...")
        server_stop_event.set()

        try:
            await asyncio.wait_for(server_task, timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning("Server did not stop gracefully in time. Forcibly cancelling task.")
            if not server_task.done(): # Check if not already cancelled
                server_task.cancel()
                try: await server_task
                except asyncio.CancelledError: pass
        except asyncio.CancelledError:
             logger.info("Server task was already cancelled (e.g. from inner exception).")


        if os.path.exists(socket_path):
            logger.debug(f"Cleaning up socket file: {socket_path}")
            try:
                os.remove(socket_path)
            except OSError as e:
                logger.warning(f"Error removing socket file {socket_path} during cleanup: {e}")

    target_rps = 50000
    if actual_rps >= target_rps:
        logger.info(f"SUCCESS: Achieved {actual_rps:.2f} RPS (Target: {target_rps}+ RPS)")
    else:
        logger.warning(f"PERFORMANCE NOTE: Achieved {actual_rps:.2f} RPS (Target: {target_rps}+ RPS).")

if __name__ == "__main__":
    log_level_env = os.getenv("PYVIDER_BENCHMARK_LOG_LEVEL", "INFO").upper()
    # setup_logging is removed. The logger should work with default config
    # and respect PLUGIN_LOG_LEVEL or PYVIDER_LOG_LEVEL if set,
    # or use its own default (likely INFO).
    # The pyvider.telemetry.logger is already configured by the library's __init__ or when config is loaded.
    logger.info(f"Starting Unix Domain Socket Throughput Benchmark with log level {log_level_env} (Note: effective level depends on Pyvider global config)...")
    asyncio.run(main_benchmark())
    logger.info("Benchmark finished.")
