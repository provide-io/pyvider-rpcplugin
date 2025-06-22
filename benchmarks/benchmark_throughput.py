import sys
from pathlib import Path

# Ensure examples directory and examples/demo are in path
# THIS BLOCK MUST BE AT THE VERY TOP OF THE FILE
benchmarks_dir = Path(__file__).resolve().parent
project_root = benchmarks_dir.parent
examples_path = project_root / "examples"
demo_path = examples_path / "demo"
if str(demo_path) not in sys.path:
    sys.path.insert(0, str(demo_path))
if str(examples_path) not in sys.path:
    sys.path.insert(0, str(examples_path))
if str(project_root) not in sys.path:  # /app
    sys.path.insert(0, str(project_root))
# END OF SYS.PATH MANIPULATION

import asyncio
import os
import time

import echo_pb2
import echo_pb2_grpc

from pyvider.rpcplugin import plugin_client, plugin_protocol, plugin_server


# Define a handler compatible with the Echo service
class BenchmarkEchoHandler(echo_pb2_grpc.EchoService):
    async def Echo(self, request, context):
        return echo_pb2.EchoResponse(
            reply=f"Echo: {request.message}"
        )  # Corrected response type and field


async def run_server_async(
    protocol, handler, address_url, ready_event, actual_socket_path
):
    transport_type, _ = address_url.split("://", 1)
    kwargs = {"protocol": protocol, "handler": handler, "transport": transport_type}
    if transport_type == "unix":
        kwargs["transport_path"] = actual_socket_path
    elif transport_type == "tcp":
        host, port_str = _.split(":")
        kwargs["host"] = host
        kwargs["port"] = int(port_str)

    server = plugin_server(**kwargs)
    print(f"Server starting with args: {kwargs}")
    asyncio.get_event_loop().call_soon(ready_event.set)
    try:
        await server.serve()
    except asyncio.CancelledError:
        print(f"Server at {address_url} stopping...")
        await server.stop()
        print(f"Server at {address_url} stopped.")
        raise
    except Exception as e:
        print(f"Server at {address_url} crashed: {e}")
        if not ready_event.is_set():
            ready_event.set()
        raise


async def run_client_throughput(
    protocol_for_client, num_requests, dummy_server_script_path
):
    # protocol_for_client is not directly used by plugin_client to create rpc attribute.
    # We will create the stub manually using client._channel.
    client = plugin_client(
        server_path=dummy_server_script_path,
        # protocol=protocol_for_client # This argument is not used by RPCPluginClient to create .rpc
    )

    rps = 0
    echo_stub = None
    try:
        print(
            f"Client starting with dummy handshaker '{dummy_server_script_path}' for throughput test..."
        )
        await client.start()
        print(
            "Client connected (handshake via dummy, actual transport to server's socket)."
        )

        if client._channel is None:
            raise RuntimeError(
                "Client channel is None after start(). Cannot create stub."
            )
        echo_stub = echo_pb2_grpc.EchoServiceStub(
            client._channel
        )  # Corrected Stub name

        payload = echo_pb2.EchoRequest(message="Benchmark")

        start_time = time.perf_counter()
        for _ in range(num_requests):
            await echo_stub.Echo(payload)  # Use the manually created stub
        end_time = time.perf_counter()

        duration = end_time - start_time
        rps = num_requests / duration if duration > 0 else float("inf")
        print(
            f"Throughput: {rps:.2f} req/s ({num_requests} requests in {duration:.4f}s)"
        )

    except Exception as e:
        print(f"Client throughput test failed: {e}")
        import traceback

        traceback.print_exc()
    finally:
        print("Client shutting down...")
        if hasattr(client, "_controller_stub") and client._controller_stub:
            try:
                await client.shutdown_plugin()
                print("Client shutdown_plugin called.")
            except Exception as e_shutdown:
                print(f"Error during client.shutdown_plugin(): {e_shutdown}")
        try:
            await client.close()
            print("Client closed.")
        except Exception as e_close:
            print(f"Error during client.close(): {e_close}")
    return rps


async def main():
    protocol = plugin_protocol(
        service_name="Echo",
        descriptor_module=echo_pb2,
        servicer_add_fn=echo_pb2_grpc.add_EchoServiceServicer_to_server,
    )
    handler = BenchmarkEchoHandler()

    socket_path = "/tmp/bench_tp_echo.sock"
    address_url = f"unix://{socket_path}"
    dummy_handshaker_script = str(benchmarks_dir / "dummy_handshaker.sh")

    if os.path.exists(socket_path):
        os.remove(socket_path)

    server_ready_event = asyncio.Event()
    server_task = asyncio.create_task(
        run_server_async(
            protocol, handler, address_url, server_ready_event, socket_path
        )
    )

    # Store results
    results = {}
    try:
        await asyncio.wait_for(server_ready_event.wait(), timeout=5.0)
        print("Server is ready. Starting throughput test...")
        results["throughput_rps"] = await run_client_throughput(
            protocol, 10000, dummy_handshaker_script
        )
    except TimeoutError:
        print("Server did not become ready in time.")
        results["throughput_rps"] = "ERROR: Server timeout"
    except Exception as e:
        print(f"An error occurred during main execution: {e}")
        results["throughput_rps"] = f"ERROR: {e}"
        import traceback

        traceback.print_exc()
    finally:
        print("Benchmark finished. Stopping server...")
        if not server_task.done():
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                print("Server task was cancelled as expected.")

        if os.path.exists(socket_path):
            try:
                os.remove(socket_path)
                print(f"Cleaned up socket: {socket_path}")
            except OSError as e:
                print(f"Error removing socket file {socket_path}: {e}")

    print("\n--- Benchmark Results ---")
    print(f"Throughput: {results.get('throughput_rps', 'N/A')}")
    print("Throughput benchmark finished.")


if __name__ == "__main__":
    asyncio.run(main())
