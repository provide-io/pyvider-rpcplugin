# Quick Start Examples

Focused code examples demonstrating specific pyvider-rpcplugin features in 15-30 lines. Perfect for quickly understanding core concepts and getting started.

=== "Basic Client"

    **Complexity**: 🟢 Beginner | **Lines**: ~20 | **Source**: `examples/short/basic_client.py`

    A minimal client that connects to a plugin server - demonstrates the absolute basics of launching and connecting to a plugin subprocess.

    ```python
    #!/usr/bin/env python3
    """
    Minimal plugin client example (20 lines).
    Shows the absolute basics of connecting to a plugin server.
    """
    import asyncio
    import sys
    from pathlib import Path
    from pyvider.rpcplugin import plugin_client
    from provide.foundation import logger


    async def main():
        """Connect to plugin server."""
        server_path = Path(__file__).parent / "basic_server.py"
        client = plugin_client(command=[sys.executable, str(server_path)])

        logger.info("Connecting to server...")
        await client.start()
        logger.info(f"Connected! Channel: {client.grpc_channel}")

        await client.close()


    if __name__ == "__main__":
        asyncio.run(main())
    ```

    ### Key Points

    - **`plugin_client()`** creates a client that handles plugin subprocess lifecycle automatically
    - **`command` parameter** specifies how to launch the plugin server (Python interpreter + script path)
    - **`await client.start()`** launches subprocess, waits for handshake, establishes gRPC connection
    - **`client.grpc_channel`** provides access to the gRPC channel for making RPC calls
    - **`await client.close()`** gracefully shuts down the plugin subprocess

    ### Alternative: Manual Cleanup

    For cases where you need manual control:

    ```python
    async def main():
        client = plugin_client(command=["python", "my_server.py"])

        try:
            await client.start()
            print("Connected to plugin!")
            # Use client...
        finally:
            await client.close()
            print("Shutdown complete")
    ```

    **Note**: The context manager pattern is recommended as it ensures cleanup even if exceptions occur.

=== "Basic Server"

    **Complexity**: 🟢 Beginner | **Lines**: ~15 | **Source**: `examples/short/basic_server.py`

    A minimal plugin server demonstrating the absolute basics - just 15 lines to create a working RPC plugin server.

    ```python
    #!/usr/bin/env python3
    """
    Minimal plugin server example (15 lines).
    Shows the absolute basics of creating a plugin server.
    """
    import asyncio
    from pyvider.rpcplugin import plugin_protocol, plugin_server
    from provide.foundation import logger


    async def main():
        """Run minimal plugin server."""
        protocol = plugin_protocol()  # Basic protocol
        handler = object()  # Dummy handler
        server = plugin_server(protocol=protocol, handler=handler)

        logger.info("Starting minimal server...")
        await server.serve()


    if __name__ == "__main__":
        asyncio.run(main())
    ```

    ### Key Points

    - **`plugin_protocol()`** creates a basic protocol implementation (no custom RPC methods)
    - **`plugin_server()`** factory creates a fully configured server with sensible defaults
    - **`object()` as handler** - For this minimal example, no custom handler is needed
    - **Foundation `logger`** provides structured logging (not `print()`)
    - **`server.serve()`** handles entire server lifecycle: transport setup, handshake, request serving

=== "Health Checks"

    **Complexity**: 🟢 Beginner | **Lines**: ~20 | **Source**: `examples/short/health_check.py`

    A minimal plugin server with gRPC health check service enabled - perfect for production deployments with Kubernetes or other monitoring systems.

    ```python
    #!/usr/bin/env python3
    """
    Server with health check enabled (20 lines).
    Demonstrates enabling the gRPC health check service.
    """
    import asyncio
    from pyvider.rpcplugin import plugin_protocol, plugin_server, configure
    from provide.foundation import logger


    async def main():
        """Run server with health checks."""
        # Enable health check service
        configure(health_service_enabled=True)

        protocol = plugin_protocol()
        handler = object()
        server = plugin_server(protocol=protocol, handler=handler)

        logger.info("Starting server with health checks enabled...")
        await server.serve()


    if __name__ == "__main__":
        asyncio.run(main())
    ```

    ### Key Points

    - **`configure(health_service_enabled=True)`** enables the gRPC Health Checking Protocol
    - **Automatic health service** - no custom health logic required for basic health checks
    - **Standard gRPC protocol** - compatible with Kubernetes liveness/readiness probes
    - **Production-focused** - health checks are essential for container orchestration

    ### Testing Health Status

    Query health status with `grpc_health_probe`:

    ```bash
    grpc_health_probe -addr=localhost:50051 -service=your.ServiceName
    ```

=== "Rate Limiting"

    **Complexity**: 🟢 Beginner | **Lines**: ~25 | **Source**: `examples/short/rate_limiting.py`

    A server with automatic rate limiting using token bucket algorithm - protects your service from being overwhelmed by too many requests.

    ```python
    #!/usr/bin/env python3
    """
    Server with rate limiting (25 lines).
    Demonstrates enabling request rate limiting.
    """
    import asyncio
    from pyvider.rpcplugin import plugin_protocol, plugin_server, configure
    from provide.foundation import logger


    async def main():
        """Run server with rate limiting."""
        # Enable rate limiting: 100 requests/sec, burst capacity 200
        configure(
            rate_limit_enabled=True,
            rate_limit_requests_per_second=100.0,
            rate_limit_burst_capacity=200
        )

        protocol = plugin_protocol()
        handler = object()
        server = plugin_server(protocol=protocol, handler=handler)

        logger.info("Starting server with rate limiting: 100 req/s...")
        await server.serve()


    if __name__ == "__main__":
        asyncio.run(main())
    ```

    ### Key Points

    - **`configure(rate_limit_enabled=True)`** enables automatic server-side rate limiting
    - **`rate_limit_requests_per_second`** sets sustained request rate (100 req/s in this example)
    - **`rate_limit_burst_capacity`** allows temporary bursts above sustained rate (200 tokens)
    - **Token bucket algorithm** - uses Foundation's `TokenBucketRateLimiter` under the hood
    - **Automatic rejection** - requests exceeding limits get `RESOURCE_EXHAUSTED` gRPC status

    ### Client Handling

    Implement exponential backoff for rate limit errors:

    ```python
    for attempt in range(max_retries):
        try:
            return await stub.MyMethod(request)
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.RESOURCE_EXHAUSTED:
                await asyncio.sleep(2 ** attempt)
                continue
            raise
    ```

=== "TCP Transport"

    **Complexity**: 🟢 Beginner | **Lines**: ~20 | **Source**: `examples/short/tcp_transport.py`

    A plugin server using TCP sockets instead of Unix domain sockets - essential for Windows compatibility and network communication.

    ```python
    #!/usr/bin/env python3
    """
    Server with TCP transport (20 lines).
    Demonstrates using TCP instead of Unix sockets.
    """
    import asyncio
    from pyvider.rpcplugin import plugin_protocol, plugin_server
    from provide.foundation import logger


    async def main():
        """Run server with TCP transport."""
        protocol = plugin_protocol()
        handler = object()

        # Use TCP transport on port 50051
        server = plugin_server(
            protocol=protocol,
            handler=handler,
            transport="tcp",
            port=50051
        )

        logger.info("Starting server with TCP transport on port 50051...")
        await server.serve()


    if __name__ == "__main__":
        asyncio.run(main())
    ```

    ### Key Points

    - **`transport="tcp"`** specifies TCP socket transport instead of Unix domain sockets
    - **`port=50051`** sets the TCP port (use `port=0` for automatic port assignment)
    - **Windows compatibility** - TCP works on all platforms (Unix sockets not available on Windows)
    - **Network communication** - TCP allows plugin communication across network boundaries
    - **Automatic handshake** - client detects TCP endpoint from handshake output

    ### Securing TCP

    Always use mTLS with TCP transport:

    ```python
    configure(
        auto_mtls=True,
        server_cert="file:///path/to/server.crt",
        server_key="file:///path/to/server.key",
        ca_cert="file:///path/to/ca.crt"
    )
    ```

=== "Custom Protocol"

    **Complexity**: 🟡 Intermediate | **Lines**: ~30 | **Source**: `examples/short/custom_protocol.py`

    A server implementing a custom protocol - shows how to extend `RPCPluginProtocol` for your own gRPC services.

    ```python
    #!/usr/bin/env python3
    """
    Custom protocol example (30 lines).
    Shows how to create a custom protocol wrapper.
    """
    import asyncio
    from typing import Any
    from pyvider.rpcplugin import plugin_server
    from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
    from provide.foundation import logger


    class CustomProtocol(RPCPluginProtocol):
        """Custom protocol implementation."""

        async def get_grpc_descriptors(self) -> tuple[Any, str]:
            """Return gRPC descriptors."""
            return None, "custom.MyService"

        async def add_to_server(self, server: Any, handler: Any) -> None:
            """Register services with gRPC server."""
            logger.info("Custom protocol registered")


    async def main():
        """Run server with custom protocol."""
        protocol = CustomProtocol()
        handler = object()
        server = plugin_server(protocol=protocol, handler=handler)

        logger.info("Starting server with custom protocol...")
        await server.serve()


    if __name__ == "__main__":
        asyncio.run(main())
    ```

    ### Key Points

    - **Extend `RPCPluginProtocol`** to create custom protocol implementations
    - **`get_grpc_descriptors()`** returns the gRPC module and service name for your Protocol Buffers
    - **`add_to_server()`** registers your custom gRPC servicer with the server
    - **Production pattern** - for real services, implement full Protocol Buffer integration

    ### Complete Protocol Pattern

    For a real service with Protocol Buffers:

    ```python
    import my_service_pb2_grpc

    class MyServiceProtocol(RPCPluginProtocol):
        async def get_grpc_descriptors(self) -> tuple[Any, str]:
            return my_service_pb2_grpc, "mypackage.MyService"

        async def add_to_server(self, server: Any, handler: Any) -> None:
            my_service_pb2_grpc.add_MyServiceServicer_to_server(handler, server)
            logger.info("MyService registered with gRPC server")
    ```

## Learning Path

### Beginner Track
1. **Basic Server + Client** - Understand the core plugin lifecycle
2. **Health Checks** - Add production monitoring capability
3. **Rate Limiting** - Protect your service from overload
4. **Echo Example** - Build a complete service with RPC methods

### Intermediate Track
1. **TCP Transport** - Cross-platform and network communication
2. **Custom Protocol** - Integrate your own gRPC services
3. **Echo Streaming** - Implement streaming patterns
4. **Error Handling** - Build robust client/server error handling

### Advanced Track
1. **Production Configuration** - mTLS, resource limits, tuning
2. **Performance Optimization** - Profiling and optimization techniques
3. **Custom Middleware** - Implement interceptors and middleware
4. **Observability** - Telemetry, metrics, and distributed tracing

## Next Steps

### Explore Complete Examples
- **[Echo Service Example](echo-example.md)** - Complete RPC service from basic to production
- **[Examples Index](index.md)** - Full list of available examples

### Study Core Concepts
- **[RPC Architecture](../guide/concepts/rpc-architecture/)** - Understanding the plugin model
- **[Transport Configuration](../guide/concepts/transports.md)** - Unix sockets vs TCP
- **[Security Model](../guide/concepts/security.md)** - Authentication and encryption

### Build Production Services
- **[Server Guide](../guide/server/)** - Server-side patterns and optimization
- **[Client Guide](../guide/client/)** - Client-side patterns and error handling
- **[Security Guide](../guide/security/)** - Comprehensive mTLS setup
- **[Configuration Guide](../guide/config/)** - Production deployment patterns

## Running Examples

From the project root:

```bash
# Install dependencies
uv sync

# Run basic client (launches basic_server.py automatically)
python examples/short/basic_client.py

# Run health check server
python examples/short/health_check.py

# Run rate limited server
python examples/short/rate_limiting.py

# Run TCP transport server
python examples/short/tcp_transport.py

# Run custom protocol server
python examples/short/custom_protocol.py
```

## Common Issues

### Import Errors
If you get "ModuleNotFoundError":
- Ensure you're running from the project root directory
- Run `uv sync` to install dependencies

### Connection Issues
If client can't connect to server:
- Check server logs for errors
- Verify no other process is using the socket/port
- Try increasing connection timeout

### Transport Not Working
If TCP transport fails:
- Check firewall allows the port
- Verify port is not already in use: `lsof -i :50051`
- Try a different port or use `port=0` for automatic assignment

## Source Code

All quick start examples are in the repository:

```
examples/short/
├── basic_client.py      # Minimal client connection
├── basic_server.py      # Minimal server setup
├── health_check.py      # Health check implementation
├── rate_limiting.py     # Rate limiting example
├── tcp_transport.py     # TCP transport configuration
└── custom_protocol.py   # Custom protocol example
```
