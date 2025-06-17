import asyncio
from pyvider.rpcplugin import plugin_server, create_basic_protocol

# 1. Define your service handler (implement your RPC methods)
class MyHandler:
    async def MyMethod(self, request, context):
        # Process request and return a response object
        # For this minimal example, we return a simple object.
        # In practice, this would be a protobuf message.
        return type("MyResponse", (), {"message": f"Request received: {getattr(request, 'data', 'no data')}"})()

# This is your main async function
async def main():
    # 2. Create a basic protocol (uses a default service definition)
    protocol = create_basic_protocol()

    # 3. Create the plugin server with your handler
    # Forcing a known socket path for the client to connect to
    server = plugin_server(protocol=protocol, handler=MyHandler(), transport="unix", transport_path="/tmp/readme_test.sock")

    # 4. Start the server (this will run indefinitely until stopped)
    print("Starting server on /tmp/readme_test.sock")
    await server.serve()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server shutting down...")
