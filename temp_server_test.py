import asyncio
import sys # Added for sys.exit
import os # Added for os.path.exists and os.remove
from pyvider.rpcplugin import plugin_server, create_basic_protocol
# configure is not imported as we want to test default behavior.
from pyvider.rpcplugin.exception import SecurityError # Import for specific catch
from pyvider.telemetry import logger # For seeing logs, though this script might not show them directly in output

# Ensure default PLUGIN_AUTO_MTLS=True is used. Do NOT call configure() to change it.

class MyHandler:
    async def MyMethod(self, request, context):
        return type("MyResponse", (), {"message": f"Request received: {getattr(request, 'data', 'no data')}"})()

async def main():
    protocol = create_basic_protocol()
    # Start server with default config (expecting auto-generated cert if fix works)
    # Use a known path for clarity
    server = plugin_server(
        protocol=protocol,
        handler=MyHandler(),
        transport="unix",
        transport_path="/tmp/pyvider_autotest.sock" # Using a potentially shorter path
    )
    print("Attempting to start server with auto-mTLS (expecting auto-generation)...")
    server_task = None
    try:
        # server.serve() is blocking. We'll run it in a task and cancel it shortly.
        # This is to check if it starts up without the SecurityError.
        async def run_server_briefly():
            try:
                print("Server starting...")
                await server.serve()
                print("Server started and was serving (this line might not be reached if it blocks indefinitely).")
            except asyncio.CancelledError:
                print("Server task cancelled as planned.")
            except SecurityError as se_inner:
                # This is if serve() itself directly raises it before even blocking
                print(f"TEST FAILED (from run_server_briefly): SecurityError caught: {se_inner}")
                raise # Propagate to outer handler
            except Exception as e_inner:
                print(f"Server task failed with other error (from run_server_briefly): {e_inner}")
                if "AF_UNIX path too long" in str(e_inner):
                    print("ENCOUNTERED AF_UNIX PATH TOO LONG ERROR (from run_server_briefly)")
                # For this test, only SecurityError is a failure.
                # However, if it fails for other reasons, the test isn't truly testing the intended logic.
                # So, let's re-raise to see the error in the subtask output.
                raise

        server_task = asyncio.create_task(run_server_briefly())

        # Let the server attempt to start for a short period.
        # If SecurityError due to certs occurs, it's usually very early in `serve()`.
        await asyncio.sleep(2.0) # Give it a couple of seconds to start up or fail early

        if server_task.done():
            # If task is done, it might have exited due to an error. We retrieve exception to check.
            exc = server_task.exception()
            if exc:
                # This will be caught by the outer try/except if it's SecurityError
                # or will print if it's another error.
                raise exc # Re-raise to be caught by outer handler.
            else:
                print("Server task completed surprisingly early without apparent error.")
        else:
            print("Server task still running, seems SecurityError was not raised on startup.")
            print("This indicates the auto-generation logic likely worked or was bypassed appropriately.")
            print("TEST PASSED: No immediate SecurityError during server startup.")

    except SecurityError as se:
        print(f"TEST FAILED (from outer main): SecurityError caught: {se}")
        # To ensure the subtask runner sees this as a failure:
        # Option 1: raise se (will be caught by the final except block)
        # Option 2: sys.exit(1) (done in the __main__ block)
        raise # Re-raise to be caught by the __main__ block's specific handler
    except Exception as e:
        print(f"Server startup or brief run failed with other error (from outer main): {e}")
        if "AF_UNIX path too long" in str(e):
            print("ENCOUNTERED AF_UNIX PATH TOO LONG ERROR (from outer main)")
        # For this test, only SecurityError is the hard failure criteria.
        # Other errors should be noted but might not mean the *specific fix* failed.
        # However, if it fails for other reasons, the test is inconclusive for the SecurityError.
        # Let's make it fail the subtask to be safe if any error occurs.
        print("Treating other errors also as a test failure for clarity.")
        raise # Re-raise to be caught by the __main__ block
    finally:
        if server_task and not server_task.done():
            print("Stopping server task (finally block)...")
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                print("Server task successfully cancelled in finally block.")
            except Exception as e_finally:
                print(f"Exception during server task cancellation in finally: {e_finally}")

        # Explicitly stop the server resource if it was initialized
        # This is important because server.serve() might have been cancelled
        # but the server object still holds resources (like the socket file).
        if hasattr(server, '_transport') and server._transport is not None: # Check if server object was fully initialized
            print("Ensuring server transport is closed.")
            await server.stop() # server.stop() is idempotent and handles internal state.

        # Clean up socket file manually if it exists, as server.stop() might not always get it
        # if the server didn't fully start or was cancelled abruptly.
        socket_path = "/tmp/pyvider_autotest.sock"
        if os.path.exists(socket_path):
            try:
                os.remove(socket_path)
                print(f"Manually removed socket file: {socket_path}")
            except OSError as e_sock:
                print(f"Error removing socket file {socket_path}: {e_sock}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
        print("Test script finished main execution successfully.")
        # If we reach here without a SecurityError, the specific test passed.
    except SecurityError:
        print("TEST SCRIPT FAILED due to SecurityError propagation.")
        sys.exit(1) # Explicitly exit with error code for the subtask runner
    except Exception as e:
        print(f"Test script caught other unhandled exception: {e}")
        sys.exit(1) # Fail for other errors too, to be safe
