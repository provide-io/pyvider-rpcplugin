# Examples

Practical examples and code snippets demonstrating common Pyvider RPC Plugin patterns and use cases.

## Quick Reference

| Example | Description | Complexity |
|---------|-------------|------------|
| [Basic Plugin](#basic-plugin) | Minimal plugin server and client | 🟢 Beginner |
| [Echo Service](#echo-service) | Complete RPC service with custom methods | 🟢 Beginner |
| [Secure Plugin](#secure-plugin) | mTLS authentication and encryption | 🟡 Intermediate |
| [Streaming Data](#streaming-data) | Server and client streaming patterns | 🟡 Intermediate |
| [Error Recovery](#error-recovery) | Robust error handling and retry logic | 🟡 Intermediate |
| [Plugin Pool](#plugin-pool) | Connection pooling and load balancing | 🔴 Advanced |
| [Custom Transport](#custom-transport) | Custom transport implementation | 🔴 Advanced |
| [Production Setup](#production-setup) | Complete production deployment | 🔴 Advanced |

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
    
    client = None
    try:
        logger.info("🚀 Launching basic plugin...")
        
        # Create and connect to plugin
        client = plugin_client(command=plugin_command)
        await client.start()
        
        logger.info("✅ Connected to plugin successfully!")
        logger.info("💡 Plugin is running and ready (no custom RPC methods)")
        
        # Keep connection alive briefly
        await asyncio.sleep(2)
        logger.info("🎉 Basic example completed!")
        
    except RPCPluginError as e:
        logger.error(f"❌ Plugin error: {e.message}")
        if e.hint:
            logger.error(f"💡 Hint: {e.hint}")
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)
    finally:
        if client:
            logger.info("🔌 Shutting down...")
            await client.close()
            logger.info("Shutdown complete")

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
    
    client = None
    try:
        logger.info("🚀 Launching Echo plugin...")
        
        # Create and connect to plugin
        client = plugin_client(command=plugin_command)
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
        
    except RPCPluginError as e:
        logger.error(f"❌ Plugin error: {e.message}")
        if e.hint:
            logger.error(f"💡 Hint: {e.hint}")
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}", exc_info=True)
    finally:
        if client:
            logger.info("🔌 Shutting down...")
            await client.close()
            logger.info("Shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())
```

## Secure Plugin

Demonstrates mTLS authentication and encrypted communication.

### Secure Server (`secure_server.py`)

```python
#!/usr/bin/env python3
"""Secure plugin server with mTLS."""
import asyncio
import os
import tempfile
from pathlib import Path
from pyvider.rpcplugin import plugin_server, plugin_protocol, configure
from pyvider.rpcplugin.crypto import Certificate
from provide.foundation import logger

class SecureHandler:
    """Secure handler demonstrating security features."""
    
    def __init__(self):
        logger.info("🔒 Secure handler initialized")

async def setup_certificates(temp_dir: Path) -> tuple[str, str, str]:
    """Set up mTLS certificates."""
    logger.info("🔑 Generating mTLS certificates...")
    
    # Generate CA certificate
    ca_cert = Certificate.create_ca(
        common_name="Secure Plugin CA",
        organization_name="Example Corp",
        validity_days=1
    )
    
    # Generate server certificate
    server_cert = Certificate.create_signed_certificate(
        ca_certificate=ca_cert,
        common_name="secure-plugin-server",
        alt_names=["localhost", "127.0.0.1"],
        is_client_cert=False,
        validity_days=1
    )
    
    # Save certificates to temporary files
    ca_file = temp_dir / "ca.crt"
    server_cert_file = temp_dir / "server.crt"
    server_key_file = temp_dir / "server.key"
    
    ca_file.write_text(ca_cert.cert)
    server_cert_file.write_text(server_cert.cert)
    server_key_file.write_text(server_cert.key)
    
    logger.info(f"📁 Certificates saved to {temp_dir}")
    
    return str(ca_file), str(server_cert_file), str(server_key_file)

async def main():
    """Main secure server function."""
    logger.info("🔒 Starting secure plugin server...")
    
    # Create temporary directory for certificates
    with tempfile.TemporaryDirectory(prefix="secure_plugin_") as temp_dir:
        temp_path = Path(temp_dir)
        
        # Set up certificates
        ca_file, server_cert_file, server_key_file = await setup_certificates(temp_path)
        
        # Configure mTLS
        os.environ.update({
            "PLUGIN_AUTO_MTLS": "true",
            "PLUGIN_SERVER_CERT": f"file://{server_cert_file}",
            "PLUGIN_SERVER_KEY": f"file://{server_key_file}",
            "PLUGIN_CLIENT_ROOT_CERTS": f"file://{ca_file}",
        })
        
        # Create secure server
        protocol = plugin_protocol()
        handler = SecureHandler()
        server = plugin_server(protocol=protocol, handler=handler)
        
        try:
            logger.info("🔒 Starting secure server with mTLS...")
            await server.serve()
            logger.info("Secure server finished")
        except KeyboardInterrupt:
            logger.info("Secure server stopped by user")
        except Exception as e:
            logger.error(f"Secure server error: {e}", exc_info=True)

if __name__ == "__main__":
    asyncio.run(main())
```

### Secure Client (`secure_client.py`)

```python
#!/usr/bin/env python3
"""Secure client with mTLS."""
import asyncio
import sys
import tempfile
from pathlib import Path
from pyvider.rpcplugin import plugin_client, configure
from pyvider.rpcplugin.crypto import Certificate
from pyvider.rpcplugin.exception import RPCPluginError
from provide.foundation import logger

async def setup_client_certificates(temp_dir: Path):
    """Set up client mTLS certificates."""
    logger.info("🔑 Setting up client certificates...")
    
    # Generate same CA as server (in real usage, share CA cert)
    ca_cert = Certificate.create_ca(
        common_name="Secure Plugin CA",
        organization_name="Example Corp",
        validity_days=1
    )
    
    # Generate client certificate
    client_cert = Certificate.create_signed_certificate(
        ca_certificate=ca_cert,
        common_name="secure-plugin-client",
        is_client_cert=True,
        validity_days=1
    )
    
    # Configure client mTLS using PEM strings
    configure(
        auto_mtls=True,
        client_cert=client_cert.cert,      # PEM string
        client_key=client_cert.key,        # PEM string
        server_root_certs=ca_cert.cert,    # Trust server certs from this CA
        magic_cookie_key="SECURE_PLUGIN_COOKIE",
        magic_cookie="ultra-secure-token-456"
    )
    
    # Return server certificates for plugin subprocess
    server_cert = Certificate.create_signed_certificate(
        ca_certificate=ca_cert,
        common_name="secure-plugin-server",
        alt_names=["localhost", "127.0.0.1"],
        is_client_cert=False,
        validity_days=1
    )
    
    # Save server certificates for plugin
    ca_file = temp_dir / "ca.crt"
    server_cert_file = temp_dir / "server.crt"
    server_key_file = temp_dir / "server.key"
    
    ca_file.write_text(ca_cert.cert)
    server_cert_file.write_text(server_cert.cert)
    server_key_file.write_text(server_cert.key)
    
    return {
        "PLUGIN_AUTO_MTLS": "true",
        "PLUGIN_SERVER_CERT": f"file://{server_cert_file}",
        "PLUGIN_SERVER_KEY": f"file://{server_key_file}",
        "PLUGIN_CLIENT_ROOT_CERTS": f"file://{ca_file}",
        "SECURE_PLUGIN_COOKIE": "ultra-secure-token-456",
        "PLUGIN_MAGIC_COOKIE_KEY": "SECURE_PLUGIN_COOKIE",
        "PLUGIN_MAGIC_COOKIE_VALUE": "ultra-secure-token-456"
    }

async def main():
    """Main secure client function."""
    logger.info("🔒 Starting secure client...")
    
    # Create temporary directory for certificates
    with tempfile.TemporaryDirectory(prefix="secure_client_") as temp_dir:
        temp_path = Path(temp_dir)
        
        # Set up client certificates and get server environment
        server_env = await setup_client_certificates(temp_path)
        
        # Define plugin command
        plugin_path = Path(__file__).parent / "secure_server.py"
        plugin_command = [sys.executable, str(plugin_path)]
        
        client = None
        try:
            logger.info("🚀 Launching secure plugin...")
            
            # Create client with server environment
            client = plugin_client(
                command=plugin_command,
                config={"env": server_env}
            )
            
            await client.start()  # mTLS handshake happens here
            
            logger.info("✅ Secure connection established!")
            logger.info("🔒 All communication is now encrypted with mTLS")
            
            # Connection is ready for encrypted RPC calls
            await asyncio.sleep(2)
            logger.info("🎉 Secure example completed!")
            
        except RPCPluginError as e:
            logger.error(f"❌ Secure plugin error: {e.message}")
            if e.hint:
                logger.error(f"💡 Hint: {e.hint}")
        except Exception as e:
            logger.error(f"❌ Unexpected error: {e}", exc_info=True)
        finally:
            if client:
                logger.info("🔒 Shutting down secure connection...")
                await client.close()
                logger.info("Secure shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())
```

## More Examples

### Available Examples

The following additional examples are available in the repository:

- **[Streaming Data](streaming.md)** - Server and client streaming patterns
- **[Error Recovery](error-recovery.md)** - Robust error handling and retry logic  
- **[Plugin Pool](plugin-pool.md)** - Connection pooling and load balancing
- **[Custom Transport](custom-transport.md)** - Custom transport implementation
- **[Production Setup](production-setup.md)** - Complete production deployment
- **[Testing Strategies](testing.md)** - Unit and integration testing patterns
- **[Performance Benchmarks](benchmarks.md)** - Performance testing and optimization

### Running Examples

All examples are available in the `examples/` directory of the repository:

```bash
# Clone the repository
git clone https://github.com/provide-io/pyvider-rpcplugin.git
cd pyvider-rpcplugin

# Install dependencies
pip install -e .

# Run basic example
python examples/basic/basic_client.py

# Run echo service example  
python examples/echo/echo_client.py

# Run secure example
python examples/security/secure_client.py
```

### Example Structure

Each example follows a consistent structure:

```
examples/
├── basic/
│   ├── basic_client.py      # Host application
│   ├── basic_plugin.py      # Plugin server
│   └── README.md            # Example documentation
├── echo/
│   ├── echo.proto           # Protocol definition
│   ├── echo_pb2.py          # Generated messages
│   ├── echo_pb2_grpc.py     # Generated services
│   ├── echo_client.py       # Host application
│   ├── echo_server.py       # Plugin server
│   └── README.md            # Example documentation
└── security/
    ├── secure_client.py     # Secure host application
    ├── secure_server.py     # Secure plugin server
    └── README.md            # Security example docs
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

- Check the [User Guide](../guide/) for detailed concepts
- Review the [API Reference](../api/) for technical details  
- Report issues on [GitHub](https://github.com/provide-io/pyvider-rpcplugin/issues)
- Join discussions in [GitHub Discussions](https://github.com/provide-io/pyvider-rpcplugin/discussions)