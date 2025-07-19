import asyncio
from pyvider.rpcplugin import plugin_server, create_basic_protocol, configure

# Dummy handler for testing
class MyApiRefHandler:
    async def SomeMethod(self, request, context): # Method name doesn't matter for basic protocol
        return type("MyResponse", (), {"message": "API Ref Test"})()

async def main():
    # Configure for insecure test
    configure(PLUGIN_AUTO_MTLS=False)

    # Create protocol (using basic for simplicity, as no pb2 files are available here)
    protocol = create_basic_protocol()

    # Create server (based on "Basic Server Setup" example in API ref)
    server = plugin_server(
        protocol=protocol,
        handler=MyApiRefHandler(),
        transport="unix", # Using unix for simplicity, instead of TCP from example
        transport_path="/tmp/api_ref_server.sock" # Specific path
    )
    print("API Ref Test Server starting on /tmp/api_ref_server.sock")

    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5) # Let server start

    print("API Ref Test Server supposedly running. Will stop now.")
    await server.stop()
    await server_task
    print("API Ref Test Server stopped.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        import os
        if os.path.exists("/tmp/api_ref_server.sock"):
            os.remove("/tmp/api_ref_server.sock")
