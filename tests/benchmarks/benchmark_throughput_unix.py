import asyncio
import time
import os
import sys
from pathlib import Path
import grpc # For potential status codes

# Adjust path to import from examples/demo and src
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent.parent # Adjusted as script is now in tests/benchmarks
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
except ImportError as e:
    print(f"Error importing demo protocol files or pyvider.rpcplugin: {e}")
    print(f"Please ensure examples/demo content (echo_pb2.py, echo_pb2_grpc.py) is available at {examples_demo_path}")
    print(f"and pyvider.rpcplugin is available at {src_path}.")
    sys.exit(1)

from pyvider.rpcplugin import plugin_server, plugin_protocol
from pyvider.telemetry import logger

# --- Handler Definition ---
class EchoServiceHandlerImpl(echo_pb2_grpc.EchoServiceServicer):
    async def Echo(self, request: echo_pb2.EchoRequest, context):
        return echo_pb2.EchoResponse(reply=f"echo: {request.message}")

    async def EchoStream(self, request_iterator, context):
        async for request in request_iterator:
            yield echo_pb2.EchoResponse(reply=f"stream echo: {request.message}")

# --- Server Setup ---
async def run_server(socket_path, ready_event, stop_event):
    handler_instance = EchoServiceHandlerImpl()

    protocol_instance = plugin_protocol(
        service_name="EchoService",
        descriptor_module=echo_pb2,
        servicer_add_fn=echo_pb2_grpc.add_EchoServiceServicer_to_server
    )

    server_instance = plugin_server(
        protocol=protocol_instance,
        handler=handler_instance,
        transport="unix",
        transport_path=socket_path
    )

    logger.info(f"Server starting on {socket_path}")
    server_ready_event_set_internally = False
    server_task = None
    try:
        async def serve_wrapper():
            nonlocal server_ready_event_set_internally
            try:
                if not ready_event.is_set():
                    ready_event.set()
                    server_ready_event_set_internally = True
                    logger.info("Server signaled ready from serve_wrapper.")
                await server_instance.serve()
            except asyncio.CancelledError:
                logger.info("Server serve_wrapper task explicitly cancelled.")
            except Exception as e:
                logger.error(f"Server serve_wrapper error: {e}", exc_info=True)
                if not ready_event.is_set():
                    ready_event.set()
            finally:
                logger.info("Server serve_wrapper stopped.")

        server_task = asyncio.create_task(serve_wrapper())

        await asyncio.sleep(0.05)
        if not ready_event.is_set() and not server_ready_event_set_internally :
            ready_event.set()
            logger.info("Server signaled ready (fallback).")

        await stop_event.wait()
        logger.info("Stop event received, shutting down server...")

    except Exception as e:
        logger.error(f"Outer server run error: {e}", exc_info=True)
        if not ready_event.is_set():
            ready_event.set()
    finally:
        if server_task and not server_task.done():
            logger.info("Requesting server_instance.stop()")
            await server_instance.stop()
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
    # batch_size = 1000 # Original batch size for Unix script, use 500 for the note in READINESS
    batch_size = 500 # Setting to 500 to match desired state for READINESS note
    total_processed_successfully = 0

    try:
        channel = grpc.aio.insecure_channel(f"unix://{socket_path}")
        await asyncio.wait_for(channel.channel_ready(), timeout=2.0)
        stub = echo_pb2_grpc.EchoServiceStub(channel)
        logger.info(f"Client connected to {socket_path} via direct gRPC channel. Batch size: {batch_size}")

        start_time = time.perf_counter()

        main_loop_iterations = 0
        while actual_requests_made < num_requests:
            tasks = []
            requests_in_this_batch_count = 0

            remaining_requests = num_requests - actual_requests_made
            current_batch_size = min(batch_size, remaining_requests)

            for i in range(current_batch_size):
                request_index = actual_requests_made + i
                request = echo_pb2.EchoRequest(message=f"hello {request_index}")
                tasks.append(stub.Echo(request, timeout=2.0))
                requests_in_this_batch_count += 1

            if not tasks:
                break

            try:
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                for res_item in responses:
                    if isinstance(res_item, echo_pb2.EchoResponse) and res_item.reply:
                        total_processed_successfully += 1
                    elif isinstance(res_item, grpc.aio.AioRpcError):
                        e = res_item
                        logger.error(f"RPC error in batch: {e.details()} (code: {e.code()})")
                        if e.code() in (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.INTERNAL):
                             logger.critical(f"Critical RPC error {e.code()}, stopping client.")
                             actual_requests_made = num_requests + 1
                             break
                    elif isinstance(res_item, Exception):
                        logger.error(f"Non-RPC exception in batch processing: {res_item}", exc_info=res_item)
                    else:
                        logger.warning(f"Received unexpected response type: {type(res_item)}")

                if actual_requests_made >= num_requests + 1:
                    break
            except Exception as e:
                logger.error(f"Error in asyncio.gather or subsequent processing: {e}", exc_info=True)
                break

            actual_requests_made += requests_in_this_batch_count
            main_loop_iterations += 1

            # Log more frequently if num_requests is small, otherwise approx 10 times.
            log_interval = max(1, (num_requests // batch_size) // 10)
            if main_loop_iterations % log_interval == 0:
                logger.info(f"Completed {main_loop_iterations} batches ({actual_requests_made} requests attempted, {total_processed_successfully} successful)...")

        end_time = time.perf_counter()
        total_time = end_time - start_time

        rps = 0
        if total_time > 0:
            rps = total_processed_successfully / total_time
        elif total_processed_successfully > 0:
            rps = float('inf')

        logger.info("--- Unix Socket Throughput Benchmark (Direct gRPC Channel) ---")
        logger.info(f"Socket: {socket_path}")
        logger.info(f"Target Requests: {num_requests}")
        logger.info(f"Actual Requests Made (attempted): {actual_requests_made if actual_requests_made <= num_requests else num_requests}")
        logger.info(f"Total Successfully Processed: {total_processed_successfully}")
        logger.info(f"Total Time: {total_time:.3f} seconds")
        logger.info(f"Requests/Second (RPS) (based on successful): {rps:.2f}")

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
    server_stop_event = asyncio.Event()

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

    # This check is for Unix sockets, will be removed/adapted for TCP script
    if not os.path.exists(socket_path) and not server_task.done():
        logger.error(f"Server did not create socket file at {socket_path} and task is not done. Aborting client.")
        server_stop_event.set()
        await asyncio.sleep(0.1)
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
            if not server_task.done():
                server_task.cancel()
                try: await server_task
                except asyncio.CancelledError: pass
        except asyncio.CancelledError:
             logger.info("Server task was already cancelled.")


        if os.path.exists(socket_path): # This check is for Unix sockets
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
    logger.info(f"Starting Unix Domain Socket Throughput Benchmark with effective log level (influenced by Pyvider global config)...")
    asyncio.run(main_benchmark())
    logger.info("Benchmark finished.")
