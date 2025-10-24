# Basic Echo Service Example

This example demonstrates a fundamental client-server RPC interaction using `pyvider-rpcplugin`. It's perfect for learning the basics of plugin development.

## Overview

The Echo service provides a simple unary RPC pattern:
- **Unary RPC** - Client sends a message, server echoes it back

This is implemented in two files:
- `examples/echo_server.py` - Plugin server implementation
- `examples/echo_client.py` - Client that launches and communicates with the server

## Service Definition

The service is defined in `examples/proto/echo.proto`:

```protobuf
syntax = "proto3";

package echo;

service EchoService {
  // Simple echo - returns the input message
  rpc Echo(EchoRequest) returns (EchoResponse);
}

message EchoRequest {
  string message = 1;
}

message EchoResponse {
  string reply = 1;
}
```

## Server Implementation

The server (`examples/echo_server.py`) implements three key components:

### 1. Service Handler

```python
class EchoHandler(echo_pb2_grpc.EchoServiceServicer):
    async def Echo(
        self, request: echo_pb2.EchoRequest, context: grpc.aio.ServicerContext
    ) -> echo_pb2.EchoResponse:
        logger.info(f"Handler: Received Echo request: '{request.message}'")
        reply_message = f"Server echoed: {request.message}"
        return echo_pb2.EchoResponse(reply=reply_message)
```

The handler processes incoming Echo requests and returns responses.

### 2. Protocol Wrapper

```python
class EchoProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        return echo_pb2_grpc, "echo.EchoService"

    async def add_to_server(self, server: Any, handler: Any) -> None:
        echo_pb2_grpc.add_EchoServiceServicer_to_server(handler, server)
        logger.info("EchoService handler registered with gRPC server.")
```

The protocol wrapper tells pyvider-rpcplugin how to register the service with gRPC.

### 3. Server Initialization

```python
async def main() -> None:
    logger.info("Starting Echo Plugin Server...")

    handler = EchoHandler()
    echo_protocol_instance = cast(TypesRPCPluginProtocol, EchoProtocol())

    server: RPCPluginServer = plugin_server(
        protocol=echo_protocol_instance,
        handler=handler,
    )

    await server.serve()
```

The server uses the `plugin_server()` factory function for easy setup.

## Client Implementation

The client (`examples/echo_client.py`) implements:

### 1. Client Class

```python
class EchoClient:
    def __init__(self, server_script_path: str) -> None:
        self.server_script_path = server_script_path
        self.client_config = {
            "env": {
                "PLUGIN_MAGIC_COOKIE_KEY": rpcplugin_config.plugin_magic_cookie_key,
                "PLUGIN_MAGIC_COOKIE_VALUE": rpcplugin_config.plugin_magic_cookie_value,
                "PLUGIN_LOG_LEVEL": rpcplugin_config.plugin_log_level,
                "PLUGIN_AUTO_MTLS": str(rpcplugin_config.plugin_auto_mtls).lower(),
            }
        }

    async def start(self) -> bool:
        self._client = RPCPluginClient(
            command=[sys.executable, self.server_script_path],
            config=self.client_config,
        )
        await self._client.start()
        self._stub = echo_pb2_grpc.EchoServiceStub(self._client.grpc_channel)
        return True
```

### 2. Making RPC Calls

```python
async def call_echo(self, message: str) -> str | None:
    request = echo_pb2.EchoRequest(message=message)
    response = await self._stub.Echo(request)
    return response.reply
```

## Running the Example

From the project root directory:

```bash
python examples/echo_client.py
```

The client will automatically:
1. Launch `echo_server.py` as a subprocess
2. Perform the handshake protocol
3. Establish a gRPC connection
4. Make Echo RPC calls
5. Clean up and terminate the server

### Expected Output

```
2025-01-15 10:30:45.123 [info     ] Client will use server script: .../examples/echo_server.py
2025-01-15 10:30:45.200 [info     ] Starting Echo Plugin Server...
2025-01-15 10:30:45.201 [info     ] EchoService handler registered with gRPC server
2025-01-15 10:30:45.250 [info     ] Client started and connected successfully
2025-01-15 10:30:45.251 [info     ] Sending Echo request to server: 'Hello from pyvider client!'
2025-01-15 10:30:45.252 [info     ] Handler: Received Echo request: 'Hello from pyvider client!'
2025-01-15 10:30:45.253 [info     ] Received Echo reply from server: 'Server echoed: Hello from pyvider client!'
```

## Key Concepts Demonstrated

### 1. Plugin Architecture
- Server runs as independent subprocess
- Client manages server lifecycle
- Clean separation of concerns

### 2. Foundation Integration
- Structured logging with `provide.foundation.logger`
- Configuration via environment variables
- Type-safe configuration access

### 3. gRPC Integration
- Protocol Buffer message definitions
- Async/await RPC patterns
- Stub-based client calls

### 4. Security
- Magic cookie authentication during handshake
- Environment-based configuration
- Process isolation

## Common Issues

### Server Not Found
If you get "Could not find echo_server.py":
```bash
# Make sure you're running from project root
cd /path/to/pyvider-rpcplugin
python examples/echo_client.py
```

### Import Errors
If you get "ModuleNotFoundError":
- The `example_utils.configure_for_example()` call should handle path setup
- Ensure you're running from the project root directory

### Connection Timeout
If the client times out:
- Check the server logs for errors
- Verify no other process is using the socket/port
- Try increasing timeout: `await asyncio.wait_for(self._client.start(), timeout=30.0)`

## Next Steps

### Learn More Patterns
- **[Echo Intermediate](echo-intermediate.md)** - Add streaming RPC patterns
- **[Echo Advanced](echo-advanced.md)** - Bidirectional streaming, error handling, monitoring

### Explore Other Examples
- **[Direct Connection Example](../guide/client/direct-connections.md)** - Connect to existing server
- **[Security Example](security-mtls-example.md)** - Add mTLS encryption
- **[Production Example](production-config-example.md)** - Production-ready configuration

### Study Core Concepts
- **[RPC Architecture](../guide/concepts/rpc-architecture.md)** - Understanding the plugin model
- **[Transport Configuration](../guide/concepts/transports.md)** - Unix sockets vs TCP
- **[Security Model](../guide/concepts/security.md)** - Authentication and encryption

## Source Code

- Server: `examples/echo_server.py`
- Client: `examples/echo_client.py`
- Protocol: `examples/proto/echo.proto`
