import asyncio
import grpc

async def main():
    socket_path = "/tmp/readme_test.sock"
    target = f"unix:{socket_path}"
    channel = None
    try:
        print(f"Attempting to connect to server at {target}...")
        channel = grpc.aio.insecure_channel(target)

        # Wait for the channel to be ready for a short period
        try:
            await asyncio.wait_for(channel.channel_ready(), timeout=5.0)
            print(f"Successfully connected to {target}")
            # In a real scenario with a defined service, you'd create a stub here.
            # For BasicProtocol, just connecting is the main test.
        except asyncio.TimeoutError:
            print(f"Timeout: Failed to connect to {target} within 5 seconds.")
            return # Exit if connection failed
        except grpc.aio.AioRpcError as e:
            print(f"gRPC Error during connection: {e.code()} - {e.details()}")
            return

        print("Client connected, now closing.")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if channel:
            print("Closing gRPC channel.")
            await channel.close()
            print("Channel closed.")

if __name__ == "__main__":
    asyncio.run(main())
