# long-running
# Test for high concurrent connections
# long-running
# long-running
import asyncio
import os
import sys
from pathlib import Path  # Import Path

# Add demo directory to sys.path to find echo_pb2 and echo_pb2_grpc
# Ensure examples directory and examples/demo are in path
# THIS BLOCK MUST BE AT THE VERY TOP OF THE FILE
benchmarks_dir = Path(__file__).resolve().parent
# project_root should be /app, which is two levels up from tests/benchmarks
project_root = benchmarks_dir.parent.parent
examples_path = project_root / "examples"
demo_path = examples_path / "demo"

if str(demo_path) not in sys.path:
    sys.path.insert(0, str(demo_path))
if str(examples_path) not in sys.path:
    sys.path.insert(0, str(examples_path))
if str(project_root) not in sys.path:  # /app
    sys.path.insert(0, str(project_root))
# END OF SYS.PATH MANIPULATION

import echo_pb2
import echo_pb2_grpc

from pyvider.rpcplugin import plugin_client, plugin_protocol, plugin_server


class EchoHandler(echo_pb2_grpc.EchoServiceServicer):  # Corrected: EchoServiceServicer
    async def Echo(self, request, context):
        return echo_pb2.EchoResponse(reply=f"Echo: {request.message}")


async def run_server(protocol_def, handler, server_address_str, ready_event):
    print(f"Server starting at {server_address_str}")
    # server_address_str is like "unix:///tmp/bench_cc_echo.sock"
    # plugin_server uses transport and transport_path (or host/port for tcp)
    transport_type, actual_path_or_host_port = server_address_str.split("://", 1)

    kwargs_for_server = {
        "protocol": protocol_def,
        "handler": handler,
        "transport": transport_type,
    }
    if transport_type == "unix":
        kwargs_for_server["transport_path"] = actual_path_or_host_port
    elif transport_type == "tcp":
        host, port_str = actual_path_or_host_port.split(":")
        kwargs_for_server["host"] = host
        kwargs_for_server["port"] = int(port_str)

    server = plugin_server(**kwargs_for_server)
    print(f"Server instance created with args: {kwargs_for_server}")
    asyncio.get_event_loop().call_soon(ready_event.set)
    try:
        await server.serve()
    except asyncio.CancelledError:
        print(f"Server at {server_address_str} cancelled.")
        if hasattr(server, "stop"):  # Ensure server has stop method
            await server.stop()
        print(f"Server at {server_address_str} fully stopped after cancel.")
    except Exception as e:
        print(f"Server at {server_address_str} crashed: {type(e).__name__} - {e}")
        if not ready_event.is_set():  # If server crashes before ready, unblock main
            ready_event.set()
        raise
    finally:  # This finally might not be reached if serve() is truly blocking until cancel
        print(f"Server at {server_address_str} (in run_server finally block).")


async def client_task(
    client_id, protocol_def, dummy_handshaker_path, server_connect_address_str
):
    # server_connect_address_str is the full URI like "unix:///tmp/bench_cc_echo.sock"
    # dummy_handshaker_path is the path to the script that outputs the handshake string.

    client = plugin_client(server_path=dummy_handshaker_path, protocol=protocol_def)
    stub = None
    try:
        # print(f"Client {client_id}: Starting...")
        # The client.start() will use the handshake from dummy_handshaker_path to get the
        # actual connection URI (which should be server_connect_address_str).
        await client.start()  # CORRECTED: No override_channel_target
        # print(f"Client {client_id}: Connected.")

        if client._channel is None:
            print(f"Client {client_id}: FAILED - Channel is None after start.")
            return False

        stub = echo_pb2_grpc.EchoServiceStub(client._channel)

        payload = echo_pb2.EchoRequest(message=f"Client {client_id}")
        await stub.Echo(payload)
        # print(f"Client {client_id}: RPC call successful.")
        return True
    except Exception as e:
        print(f"Client {client_id} failed: {type(e).__name__} - {e}")
        # import traceback
        # traceback.print_exc()
        return False
    finally:
        # print(f"Client {client_id}: Shutting down...")
        if hasattr(client, "is_started") and client.is_started:
            if hasattr(client, "_controller_stub") and client._controller_stub:
                try:
                    await client.shutdown_plugin()
                except Exception:
                    pass
            try:
                await client.close()
            except Exception:
                pass
        # print(f"Client {client_id}: Closed.")


async def main():
    actual_protocol_def = plugin_protocol(
        "EchoService",  # Service name should match what's in .proto
        echo_pb2,
        echo_pb2_grpc.add_EchoServiceServicer_to_server,
    )
    handler = EchoHandler()

    socket_path = "/tmp/bench_high_cc_echo.sock"  # Changed socket path
    server_address_uri = (
        f"unix://{socket_path}"  # Used by server and for dummy handshaker output
    )

    dummy_handshaker_script_path = str(
        benchmarks_dir / "dummy_high_cc_echo_handshaker.sh"
    )  # Changed script name

    # Configure the dummy handshaker to output the correct socket path for this test
    handshake_line_for_dummy = f"1|1|unix|{socket_path}|grpc|"
    with open(dummy_handshaker_script_path, "w") as f:
        f.write("#!/bin/bash\n")
        f.write(f"echo '{handshake_line_for_dummy}'\n")
    os.chmod(dummy_handshaker_script_path, 0o755)
    print(
        f"Dummy high concurrency handshaker {dummy_handshaker_script_path} configured to output: {handshake_line_for_dummy}"
    )

    if os.path.exists(socket_path):
        print(f"Removing existing socket: {socket_path}")
        os.remove(socket_path)

    ready_event = asyncio.Event()
    # Pass the full URI to run_server, it will parse it.
    server_task = asyncio.create_task(
        run_server(actual_protocol_def, handler, server_address_uri, ready_event)
    )

    results_summary = {"successful": 0, "failed": 0, "error": "None"}
    try:
        print(f"Waiting for server for {server_address_uri} to be ready...")
        await asyncio.wait_for(ready_event.wait(), timeout=10.0)
        print("Server is ready. Starting high concurrency clients...")

        num_concurrent_clients = 1000  # Increased number of clients
        # Client tasks use the dummy handshaker. The server_address_uri is not directly used by client_task
        # if the dummy handshaker is correctly pointing to the server's socket.
        tasks = [
            client_task(
                i, actual_protocol_def, dummy_handshaker_script_path, server_address_uri
            )
            for i in range(num_concurrent_clients)
        ]

        client_run_results = await asyncio.gather(*tasks, return_exceptions=True)

        successful_calls = 0
        for i, r_exc in enumerate(client_run_results):
            if isinstance(r_exc, bool) and r_exc:
                successful_calls += 1
            elif isinstance(r_exc, Exception):
                print(
                    f"Client task {i} resulted in exception during gather: {type(r_exc).__name__} - {r_exc}"
                )
            # else: it was False from the task (already printed error in task)

        results_summary["successful"] = successful_calls
        results_summary["failed"] = num_concurrent_clients - successful_calls

        print(
            f"High Concurrency Test: {successful_calls}/{num_concurrent_clients} clients made successful calls."
        )

    except TimeoutError:
        print("Server did not become ready in time.")
        results_summary["error"] = "Server Timeout for High Concurrency Test"
    except Exception as e:
        print(f"Error during main high concurrency execution: {type(e).__name__} - {e}")
        import traceback

        traceback.print_exc()
        results_summary["error"] = str(e)
    finally:
        print("High Concurrency benchmark: Main section finished. Stopping server...")
        if not server_task.done():
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                print("Server task was successfully cancelled.")
            except Exception as e_srv_stop:
                print(f"Exception during server task await after cancel: {e_srv_stop}")

        if os.path.exists(socket_path):
            try:
                os.remove(socket_path)
                print(f"Cleaned up socket: {socket_path}")
            except OSError as e:
                print(f"Error removing socket file {socket_path}: {e}")
        # dummy_high_cc_echo_handshaker.sh is reused, so not deleting it here.

    print("\n--- Benchmark High Concurrency Results ---")
    print(
        f"High Concurrent Clients: Successful Calls={results_summary['successful']}, Failed/Not True={results_summary['failed']}, Overall Error='{results_summary.get('error', 'None')}'"
    )
    print("High Concurrency benchmark script finished.")


if __name__ == "__main__":
    asyncio.run(main())
