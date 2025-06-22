import statistics  # Moved here
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


class BenchmarkEchoHandler(echo_pb2_grpc.EchoService):
    async def Echo(self, request, context):
        return echo_pb2.EchoResponse(reply=f"Echo: {request.message}")


async def run_server_async(
    protocol, handler, address_url, ready_event, actual_socket_path_or_port
):
    transport_type, path_or_host_port = address_url.split("://", 1)
    kwargs = {"protocol": protocol, "handler": handler, "transport": transport_type}
    if transport_type == "unix":
        kwargs["transport_path"] = actual_socket_path_or_port
    elif transport_type == "tcp":
        # Ensure host is explicit if not localhost for clarity, though default is 127.0.0.1
        host_part = (
            path_or_host_port.split(":")[0] if ":" in path_or_host_port else "localhost"
        )
        kwargs["host"] = host_part
        kwargs["port"] = int(actual_socket_path_or_port)

    server = plugin_server(**kwargs)
    print(
        f"Server starting with args: {kwargs}"
    )  # This will print the handshake string to server's stdout
    asyncio.get_event_loop().call_soon(ready_event.set)
    try:
        await server.serve()
    except asyncio.CancelledError:
        print(f"Server at {address_url} stopping...")
        if hasattr(server, "stop"):
            await server.stop()  # Ensure graceful shutdown
        print(f"Server at {address_url} stopped.")
        raise
    except Exception as e:
        print(f"Server at {address_url} crashed: {e}")
        if not ready_event.is_set():
            ready_event.set()
        raise


async def measure_connection_time(protocol, dummy_server_script_path, num_iterations):
    timings = []
    print(
        f"Measuring connection time for {num_iterations} iterations using {dummy_server_script_path}..."
    )
    for i in range(num_iterations):
        print(f"Connection test iteration {i + 1}/{num_iterations} starting...")
        client = plugin_client(
            server_path=dummy_server_script_path,
        )
        try:
            start_time = time.perf_counter()
            print(f"Iter {i + 1}: Calling client.start()...")
            await client.start()
            end_time = time.perf_counter()
            timings.append((end_time - start_time) * 1000)  # milliseconds
            print(f"Iter {i + 1}: Connected in {(end_time - start_time) * 1000:.2f}ms.")
        except Exception as e:
            print(f"Iter {i + 1}: Connection attempt failed: {e}")
            # import traceback
            # traceback.print_exc()
        finally:
            print(f"Iter {i + 1}: Cleaning up client...")
            if hasattr(client, "_controller_stub") and client._controller_stub:
                try:
                    print(f"Iter {i + 1}: Calling shutdown_plugin...")
                    await client.shutdown_plugin()
                    print(f"Iter {i + 1}: shutdown_plugin finished.")
                except Exception as e_shut:
                    print(f"Iter {i + 1}: Error in shutdown_plugin: {e_shut}")
            try:
                print(f"Iter {i + 1}: Calling client.close()...")
                await client.close()
                print(f"Iter {i + 1}: client.close() finished.")
            except Exception as e_close:
                print(f"Iter {i + 1}: Error in client.close(): {e_close}")
            print(f"Iter {i + 1}: Client cleanup done.")
    return timings


async def main_test_address(
    protocol,
    handler,
    address_url,
    actual_socket_path_or_port,
    dummy_handshaker_content_generator,
):
    dummy_handshaker_script_path = str(benchmarks_dir / "dummy_cs_handshaker.sh")

    with open(dummy_handshaker_script_path, "w") as f:
        f.write(dummy_handshaker_content_generator(actual_socket_path_or_port))
    os.chmod(dummy_handshaker_script_path, 0o755)

    if address_url.startswith("unix://") and os.path.exists(
        str(actual_socket_path_or_port)
    ):
        try:
            os.remove(str(actual_socket_path_or_port))
        except OSError:
            pass  # Ignore if already removed or not found

    server_ready_event = asyncio.Event()
    server_task = asyncio.create_task(
        run_server_async(
            protocol,
            handler,
            address_url,
            server_ready_event,
            actual_socket_path_or_port,
        )
    )

    connection_timings = []
    num_iterations = 10  # Reduced iterations for testing
    try:
        print(f"Waiting for server {address_url} to be ready...")
        await asyncio.wait_for(
            server_ready_event.wait(), timeout=10.0
        )  # Increased server ready timeout slightly
        print(
            f"Server for {address_url} is ready. Running client connection speed tests for {num_iterations} iterations..."
        )
        connection_timings = await measure_connection_time(
            protocol, dummy_handshaker_script_path, num_iterations
        )
    except TimeoutError:
        print(f"Server for {address_url} did not become ready.")
    except Exception as e:
        print(f"Error during test for {address_url}: {e}")
        import traceback

        traceback.print_exc()
    finally:
        print(f"Stopping server for {address_url}...")
        if not server_task.done():
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                print(f"Server task for {address_url} was cancelled as expected.")

        if address_url.startswith("unix://") and os.path.exists(
            str(actual_socket_path_or_port)
        ):
            try:
                os.remove(str(actual_socket_path_or_port))
                print(f"Cleaned up socket: {actual_socket_path_or_port}")
            except OSError as e:
                print(f"Error removing socket file {actual_socket_path_or_port}: {e}")
        if os.path.exists(dummy_handshaker_script_path):
            try:
                os.remove(dummy_handshaker_script_path)
                print(f"Cleaned up dummy handshaker: {dummy_handshaker_script_path}")
            except OSError as e:
                print(
                    f"Error removing dummy handshaker {dummy_handshaker_script_path}: {e}"
                )

    if connection_timings:
        print(
            f"Connection Speed for {address_url}: Avg={statistics.mean(connection_timings):.2f}ms, Med={statistics.median(connection_timings):.2f}ms, Min={min(connection_timings):.2f}ms, Max={max(connection_timings):.2f}ms from {len(connection_timings)} samples"
        )
    else:
        print(f"Connection Speed for {address_url}: No successful connections.")
    return connection_timings


def get_unix_dummy_handshaker_content(socket_path):
    return f'#!/bin/bash\necho "1|1|unix|{socket_path}|grpc|"'


def get_tcp_dummy_handshaker_content(port):  # port is int here
    return f'#!/bin/bash\necho "1|1|tcp|127.0.0.1:{port}|grpc|"'


async def main():
    protocol = plugin_protocol(
        service_name="Echo",
        descriptor_module=echo_pb2,
        servicer_add_fn=echo_pb2_grpc.add_EchoServiceServicer_to_server,
    )
    handler = BenchmarkEchoHandler()

    results = {"unix": [], "tcp": []}

    unix_socket_path = "/tmp/bench_cs_echo.sock"
    unix_address = f"unix://{unix_socket_path}"
    print("\n--- Testing Unix Socket Connection Speed ---")
    results["unix"] = await main_test_address(
        protocol,
        handler,
        unix_address,
        unix_socket_path,
        get_unix_dummy_handshaker_content,
    )

    tcp_port = 50052
    tcp_address = f"tcp://localhost:{tcp_port}"
    print("\n--- Testing TCP Socket Connection Speed ---")
    results["tcp"] = await main_test_address(
        protocol, handler, tcp_address, tcp_port, get_tcp_dummy_handshaker_content
    )

    print("\n--- Benchmark Results ---")
    if results["unix"]:
        print(
            f"Unix Connection Speed: Avg={statistics.mean(results['unix']):.2f}ms, Med={statistics.median(results['unix']):.2f}ms"
        )
    else:
        print("Unix Connection Speed: No successful connections.")
    if results["tcp"]:
        print(
            f"TCP Connection Speed: Avg={statistics.mean(results['tcp']):.2f}ms, Med={statistics.median(results['tcp']):.2f}ms"
        )
    else:
        print("TCP Connection Speed: No successful connections.")
    print("\nConnection speed benchmark finished.")


if __name__ == "__main__":
    asyncio.run(main())
