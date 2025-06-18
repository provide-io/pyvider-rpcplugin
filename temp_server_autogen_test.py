import asyncio
import sys # Import sys for sys.exit
import os # For cleanup
from pyvider.rpcplugin import plugin_server, create_basic_protocol
from pyvider.rpcplugin.exception import SecurityError, TransportError # Import specific exceptions
from pyvider.telemetry import logger # For seeing logs, though this script might not show them directly in output

# Ensure default PLUGIN_AUTO_MTLS=True is used.
# Do NOT call configure() to change it or set cert paths.

class MyHandler:
    async def MyMethod(self, request, context):
        return type("MyResponse", (), {"message": f"Request received: {getattr(request, 'data', 'no data')}"})()

async def main():
    protocol = create_basic_protocol()
    server = plugin_server(
        protocol=protocol,
        handler=MyHandler(),
        transport="unix",
        transport_path="/tmp/pyvider_autogen_final_test.sock"
    )
    print("Attempting to start server with auto-generated self-signed server certificate...")

    server_task = None
    try:
        async def run_server():
            try:
                print("Server task: calling server.serve()")
                await server.serve()
                print("Server task: server.serve() completed (should not happen if blocking).")
            except Exception as e_serve:
                print(f"Server task: EXCEPTION during server.serve(): {type(e_serve).__name__}: {e_serve}")
                if isinstance(e_serve, (RuntimeError, TransportError, SecurityError)):
                     raise

        server_task = asyncio.create_task(run_server())

        print("Main task: Waiting for server to become ready (or fail)...")
        await asyncio.wait_for(server.wait_for_server_ready(timeout=5.0), timeout=6.0)
        print("Main task: Server reported as ready!")
        print("TEST PASSED: Server started successfully with auto-generated certificate.")

    except RuntimeError as re:
        print(f"TEST FAILED: RuntimeError caught: {re}")
        if "Invalid cert chain file" in str(re) or "Handshaker factory creation failed" in str(re) or "Failed to bind to address" in str(re):
            print("Reason: Likely related to gRPC compatibility with the auto-generated certificate.")
        sys.exit(1)
    except TransportError as te:
        print(f"TEST FAILED: TransportError caught: {te}")
        if "AF_UNIX path too long" in str(te):
            print("Reason: AF_UNIX path too long error.")
        sys.exit(1)
    except SecurityError as se:
        print(f"TEST FAILED: Unexpected SecurityError caught: {se}")
        sys.exit(1)
    except asyncio.TimeoutError:
        if server_task and server_task.done() and server_task.exception():
            exc = server_task.exception()
            print(f"TEST FAILED: Server task failed with {type(exc).__name__}: {exc} after timeout.")
            sys.exit(1)
        else:
            print("TEST FAILED: Timeout waiting for server to become ready. Server task might be running or failed silently.")
            sys.exit(1)
    except Exception as e:
        print(f"TEST FAILED: An unexpected error occurred: {type(e).__name__}: {e}")
        sys.exit(1)
    finally:
        print("Main task: Stopping server...")
        if hasattr(server, '_server') and server._server is not None:
            await server.stop()
            print("Main task: Server stop called.")
        else:
            print("Main task: Server object not found or not started, skipping stop.")
        if server_task and not server_task.done():
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                print("Main task: Server task cancelled.")
            except Exception as e_finally:
                print(f"Main task: Exception during server task cancellation in finally: {e_finally}")
        elif server_task and server_task.done() and server_task.exception():
            print(f"Main task: Server task had an unhandled exception: {server_task.exception()}")

        socket_path = "/tmp/pyvider_autogen_final_test.sock"
        if os.path.exists(socket_path):
            try:
                os.remove(socket_path)
                print(f"Manually removed socket file: {socket_path}")
            except OSError as e_sock:
                print(f"Error removing socket file {socket_path}: {e_sock}")

if __name__ == "__main__":
    asyncio.run(main())
    print("Test script finished main execution successfully (implies success if no sys.exit(1) was called).")
