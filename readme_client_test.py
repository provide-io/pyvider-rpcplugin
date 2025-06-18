import asyncio
import grpc

async def run_client():
    socket_path = "/tmp/pyvider_quickstart.sock" # Same path as in server
    target = f"unix:{socket_path}"
    channel = None
    try:
        print(f"Attempting to connect to server at {target}...")
        # For a server script not launched by the client, connect directly using grpc.aio
        channel = grpc.aio.insecure_channel(target)

        # Setting a timeout for channel_ready according to the README example
        await asyncio.wait_for(channel.channel_ready(), timeout=5.0)
        print(f"Successfully connected to {target}")

        # Note: The BasicProtocol used by the Quick Start server is for connectivity tests.
        # It doesn't expose 'MyMethod' via standard gRPC stubs.
        # To call custom methods, define a .proto file and use generated stubs.
        # For this example, just connecting successfully demonstrates the server is up.
        # The README example implies we don't make an actual RPC call here.

    except asyncio.TimeoutError:
        print(f"Timeout: Failed to connect to {target} within 5 seconds.")
    except grpc.aio.AioRpcError as e:
        print(f"gRPC Error during connection: {e.code()} - {e.details()}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if channel:
            print("Closing gRPC channel.")
            await channel.close()

if __name__ == "__main__":
    asyncio.run(run_client())
