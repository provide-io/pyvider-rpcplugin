# Examples

Practical examples and code snippets demonstrating common Pyvider RPC Plugin patterns and use cases.

## Quick Reference

| Example | Description | Complexity |
|---------|-------------|------------|
| [Basic Plugin](#basic-plugin) | Minimal plugin server and client | 🟢 Beginner |
| [Echo Service](#echo-service) | Complete RPC service with custom methods | 🟢 Beginner |

## Basic Plugin

The simplest possible plugin demonstrating core concepts.

### Plugin Server (`basic_plugin.py`)

```python
#!/usr/bin/env python3
"""Basic plugin server example."""
import asyncio
from pyvider.rpcplugin import plugin_server, plugin_protocol
from provide.foundation import logger

class BasicHandler:
    """Simple handler with no custom RPC methods."""
    
    def __init__(self):
        logger.info("🔌 Basic handler initialized")
        logger.info("Foundation logging active for structured output")

async def main():
    """Main server function."""
    logger.info("🚀 Starting basic plugin server...")
    
    # Use default protocol (no custom RPC methods)
    protocol = plugin_protocol()
    handler = BasicHandler()
    
    # Create and start server
    server = plugin_server(protocol=protocol, handler=handler)
    
    try:
        await server.serve()  # Blocks until shutdown
        logger.info("Basic plugin server finished")
    except KeyboardInterrupt:
        logger.info("Basic plugin server stopped by user")
    except Exception as e:
        logger.error(f"Basic plugin server error: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())
```

### Host Application (`basic_client.py`)

```python
#!/usr/bin/env python3
"""Basic client that launches and connects to plugin."""
import asyncio
import sys
from pathlib import Path
from pyvider.rpcplugin import plugin_client
from pyvider.rpcplugin.exception import RPCPluginError
from provide.foundation import logger

async def main():
    """Main client function."""
    logger.info("🏠 Starting basic client...")

    # Define plugin command
    plugin_path = Path(__file__).parent / "basic_plugin.py"
    plugin_command = [sys.executable, str(plugin_path)]

    try:
        logger.info("🚀 Launching basic plugin...")

        # Use async context manager for automatic cleanup
        async with plugin_client(command=plugin_command) as client:
            # Start the plugin
            await client.start()

            logger.info("✅ Connected to plugin successfully!")
            logger.info("💡 Plugin is running and ready (no custom RPC methods)")

            # Keep connection alive briefly
            await asyncio.sleep(2)
            logger.info("🎉 Basic example completed!")

        # Client automatically closed on context exit
        logger.info("🔌 Shutdown complete")

    except RPCPluginError as e:
        logger.error(f"❌ Plugin error: {e.message}")
        if e.hint:
            logger.error(f"💡 Hint: {e.hint}")
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())
```

### Run the Example

```bash
python basic_client.py
```

Expected output:
```
2024-01-15 10:30:45.123 [info     ] 🏠 Starting basic client...
2024-01-15 10:30:45.124 [info     ] 🚀 Launching basic plugin...
2024-01-15 10:30:45.200 [info     ] 🚀 Starting basic plugin server...
2024-01-15 10:30:45.201 [info     ] 🔌 Basic handler initialized
2024-01-15 10:30:45.250 [info     ] ✅ Connected to plugin successfully!
2024-01-15 10:30:45.251 [info     ] 💡 Plugin is running and ready (no custom RPC methods)
2024-01-15 10:30:47.252 [info     ] 🎉 Basic example completed!
2024-01-15 10:30:47.253 [info     ] 🔌 Shutting down...
2024-01-15 10:30:47.254 [info     ] Shutdown complete
```

## Echo Service

Complete RPC service with Protocol Buffers and custom methods.

!!! note "Simplified vs. Actual Examples"
    The examples below are **simplified for teaching purposes** to clearly demonstrate core concepts. The actual runnable files in `examples/echo_server.py` and `examples/echo_client.py` include additional production-ready patterns such as:

    - `example_utils.configure_for_example()` for path setup
    - Detailed environment variable handling
    - Class-based client implementation with comprehensive error handling
    - Additional comments and logging

    **To run the actual examples:**
    ```bash
    # From project root
    python examples/echo_client.py
    ```

    The simplified examples below are perfect for understanding the framework. Use the actual files when you need production-ready patterns.

### Protocol Definition (`echo.proto`)

```protobuf
syntax = "proto3";
package echo;

message EchoRequest {
    string message = 1;
    int32 count = 2;
}

message EchoResponse {
    string reply = 1;
    int32 processed_count = 2;
}

service EchoService {
    rpc Echo(EchoRequest) returns (EchoResponse);
    rpc ReverseEcho(EchoRequest) returns (EchoResponse);
}
```

### Generate Python Code

```bash
python -m grpc_tools.protoc \
    -I. \
    --python_out=. \
    --grpc_python_out=. \
    --pyi_out=. \
    echo.proto
```

### Echo Server (`echo_server.py`)

```python
#!/usr/bin/env python3
"""Echo service plugin server."""
import asyncio
from typing import Any
import grpc
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from provide.foundation import logger

# Import generated Protocol Buffer code
from echo_pb2 import EchoRequest, EchoResponse
from echo_pb2_grpc import EchoServiceServicer, add_EchoServiceServicer_to_server
import echo_pb2_grpc

class EchoHandler(EchoServiceServicer):
    """Echo service implementation."""
    
    async def Echo(
        self, 
        request: EchoRequest, 
        context: grpc.aio.ServicerContext
    ) -> EchoResponse:
        """Simple echo method."""
        logger.info(f"📨 Echo request: '{request.message}' (count: {request.count})")
        
        reply = f"Echo: {request.message}"
        response = EchoResponse(reply=reply, processed_count=request.count)
        
        logger.info(f"📤 Echo response: '{reply}'")
        return response
    
    async def ReverseEcho(
        self, 
        request: EchoRequest, 
        context: grpc.aio.ServicerContext
    ) -> EchoResponse:
        """Reverse echo method."""
        logger.info(f"🔄 Reverse echo request: '{request.message}'")
        
        reversed_message = request.message[::-1]
        reply = f"Reversed: {reversed_message}"
        response = EchoResponse(reply=reply, processed_count=request.count)
        
        logger.info(f"📤 Reverse echo response: '{reply}'")
        return response

class EchoProtocol(RPCPluginProtocol):
    """Echo service protocol implementation."""
    
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        return echo_pb2_grpc, "echo.EchoService"
    
    def get_method_type(self, method_name: str) -> str:
        if method_name in ["Echo", "ReverseEcho"]:
            return "unary_unary"
        return "unary_unary"  # Default
    
    async def add_to_server(self, server: Any, handler: Any) -> None:
        add_EchoServiceServicer_to_server(handler, server)
        logger.info("✅ Echo service registered")

async def main():
    """Main server function."""
    logger.info("🚀 Starting Echo plugin server...")
    
    # Create handler and protocol
    handler = EchoHandler()
    protocol = EchoProtocol()
    
    # Create and start server
    server = plugin_server(protocol=protocol, handler=handler)
    
    try:
        await server.serve()
        logger.info("Echo server finished")
    except KeyboardInterrupt:
        logger.info("Echo server stopped by user")
    except Exception as e:
        logger.error(f"Echo server error: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())
```

### Echo Client (`echo_client.py`)

```python
#!/usr/bin/env python3
"""Echo service client."""
import asyncio
import sys
from pathlib import Path
from pyvider.rpcplugin import plugin_client
from pyvider.rpcplugin.exception import RPCPluginError
from provide.foundation import logger

# Import generated Protocol Buffer code
from echo_pb2 import EchoRequest
from echo_pb2_grpc import EchoServiceStub

async def main():
    """Main client function."""
    logger.info("🏠 Starting Echo client...")

    # Define plugin command
    plugin_path = Path(__file__).parent / "echo_server.py"
    plugin_command = [sys.executable, str(plugin_path)]

    try:
        logger.info("🚀 Launching Echo plugin...")

        # Use async context manager for automatic cleanup
        async with plugin_client(command=plugin_command) as client:
            # Start the plugin
            await client.start()

            logger.info("✅ Connected to Echo plugin!")

            # Create gRPC stub for making RPC calls
            stub = EchoServiceStub(client.grpc_channel)

            # Test messages
            messages = [
                ("Hello, Plugin!", 1),
                ("How are you doing?", 2),
                ("This is a test message", 3),
                ("Goodbye!", 4),
            ]

            for message, count in messages:
                logger.info(f"📨 Sending Echo: '{message}'")

                # Make Echo RPC call
                echo_request = EchoRequest(message=message, count=count)
                echo_response = await stub.Echo(echo_request)

                logger.info(f"📤 Received: '{echo_response.reply}' (processed: {echo_response.processed_count})")

                # Make ReverseEcho RPC call
                logger.info(f"🔄 Sending Reverse Echo: '{message}'")
                reverse_response = await stub.ReverseEcho(echo_request)

                logger.info(f"📤 Received: '{reverse_response.reply}' (processed: {reverse_response.processed_count})")
                logger.info("---")

            logger.info("🎉 All Echo calls completed successfully!")

        # Client automatically closed on context exit
        logger.info("🔌 Shutdown complete")

    except RPCPluginError as e:
        logger.error(f"❌ Plugin error: {e.message}")
        if e.hint:
            logger.error(f"💡 Hint: {e.hint}")
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())
```

## Additional Resources

For more advanced patterns and production use cases:

- **[Security Guide](../guide/security/index.md)** - Complete mTLS setup and security patterns
- **[Advanced Topics](../guide/advanced/index.md)** - Performance tuning, custom protocols, telemetry
- **[Production Configuration](../guide/config/production.md)** - Deployment best practices
- **[Server Guide](../guide/server/index.md)** - Server-side patterns and optimization
- **[Client Guide](../guide/client/index.md)** - Client-side patterns and error handling

## More Examples

### Available Examples

The `examples/` directory contains additional working examples:

- **[Echo Service Examples](echo-basic.md)** - Complete RPC service with streaming patterns (basic, intermediate, and advanced)
- **Short Examples** (see navigation menu) - Focused 15-30 line examples for specific features

### Running Examples

All examples are available in the `examples/` directory of the repository:

```bash
# Clone the repository
git clone https://github.com/provide-io/pyvider-rpcplugin.git
cd pyvider-rpcplugin

# Install dependencies
uv sync

# Run quick start example
python examples/quick_start_client.py

# Run echo service example
python examples/echo_client.py

# Run secure mTLS example
python examples/security_mtls_example.py

# Run telemetry demo
python examples/telemetry_demo.py
```

### Example Structure

Examples are organized in a flat structure with descriptive names:

```
examples/
├── quick_start_client.py           # Basic client launching dummy_server.py
├── dummy_server.py                  # Minimal plugin server
├── echo_client.py                   # Echo service client (class-based, production-ready)
├── echo_server.py                   # Echo service server (comprehensive)
├── e2e_greeter_client.py            # End-to-end greeter client
├── e2e_greeter_server.py            # End-to-end greeter server
├── advanced_plugin_example.py       # Advanced plugin patterns
├── security_mtls_example.py         # mTLS security patterns
├── transport_options_demo.py        # Transport configuration
├── telemetry_demo.py                # Telemetry integration
├── async_patterns_demo.py           # Advanced async patterns
├── error_handling_demo.py           # Error handling patterns
├── custom_protocols_demo.py         # Custom protocol concepts
├── performance_tuning_concepts.py   # Performance optimization
├── production_config_discussion.py  # Production deployment discussion
├── direct_client_connection.py      # Direct connection patterns
├── client_setup_concepts.py         # Client setup patterns
├── server_setup_concepts.py         # Server setup patterns
├── example_utils.py                 # Shared utilities for examples
├── run_all_examples.py              # Script to run all examples
├── proto/                           # Protocol Buffer definitions
│   ├── echo.proto                   # Echo service definition
│   └── greeter.proto                # Greeter service definition
└── short/                           # Short focused examples (15-30 lines)
    ├── basic_client.py              # Minimal client connection
    ├── basic_server.py              # Minimal server setup
    ├── health_check.py              # Health check implementation
    ├── rate_limiting.py             # Rate limiting example
    ├── tcp_transport.py             # TCP transport configuration
    └── custom_protocol.py           # Custom protocol example
```

### Contributing Examples

We welcome contributions of new examples! Please:

1. Follow the established structure and naming conventions
2. Include comprehensive documentation and comments
3. Add appropriate error handling and logging
4. Test examples on multiple platforms
5. Submit a pull request with your example

### Getting Help

If you have questions about the examples:

- Check the [User Guide](../guide/index.md) for detailed concepts
- Review the [API Reference](../reference/index.md) for technical details
- Report issues on [GitHub](https://github.com/provide-io/pyvider-rpcplugin/issues)
- Join discussions in [GitHub Discussions](https://github.com/provide-io/pyvider-rpcplugin/discussions)