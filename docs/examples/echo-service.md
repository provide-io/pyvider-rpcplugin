# Echo Service Example

This example demonstrates a basic RPC service that echoes messages back to clients. It's perfect for learning the fundamentals of the Pyvider RPC Plugin framework.

## Overview

The Echo service provides:

- **Unary RPC** - Simple request-response echo
- **Server streaming** - Stream multiple echo responses
- **Client streaming** - Collect messages and echo back
- **Bidirectional streaming** - Real-time echo conversation

## Service Definition

First, define the service in Protocol Buffers:

**echo.proto**
```protobuf
syntax = "proto3";

package echo;

service EchoService {
  // Simple echo - returns the input message
  rpc Echo(EchoRequest) returns (EchoResponse);
  
  // Server streaming - returns multiple echo responses  
  rpc ServerStreamEcho(EchoRequest) returns (stream EchoResponse);
  
  // Client streaming - collects messages and returns summary
  rpc ClientStreamEcho(stream EchoRequest) returns (EchoResponse);
  
  // Bidirectional streaming - real-time echo conversation
  rpc BidirectionalEcho(stream EchoRequest) returns (stream EchoResponse);
}

message EchoRequest {
  string message = 1;
  string client_id = 2;
  int64 timestamp = 3;
}

message EchoResponse {
  string message = 1;
  string server_id = 2;
  int64 timestamp = 3;
  int32 sequence = 4;
}
```

Generate Python code:
```bash
python -m grpc_tools.protoc --python_out=. --grpc_python_out=. echo.proto
```

## Server Implementation

**echo_service.py**
```python
import asyncio
import time
import uuid
from typing import AsyncIterator
import grpc
from grpc.aio import ServicerContext

from echo_pb2 import EchoRequest, EchoResponse
from echo_pb2_grpc import EchoServiceServicer
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin import RPCPluginProtocol
from provide.foundation import logger

class EchoServiceHandler(EchoServiceServicer):
    """Echo service implementation."""
    
    def __init__(self):
        self.server_id = str(uuid.uuid4())[:8]
        self.request_count = 0
        logger.info("Echo service started", extra={"server_id": self.server_id})
    
    async def Echo(
        self, 
        request: EchoRequest, 
        context: ServicerContext
    ) -> EchoResponse:
        """Simple echo implementation."""
        self.request_count += 1
        
        logger.info("Echo request received", extra={
            "client_id": request.client_id, 
            "message": request.message
        })
        
        # Simulate some processing time
        await asyncio.sleep(0.1)
        
        response = EchoResponse(
            message=f"Echo: {request.message}",
            server_id=self.server_id,
            timestamp=int(time.time() * 1000),
            sequence=self.request_count
        )
        
        return response
    
    async def ServerStreamEcho(
        self, 
        request: EchoRequest, 
        context: ServicerContext
    ) -> AsyncIterator[EchoResponse]:
        """Server streaming echo - sends multiple responses."""
        logger.info("Server stream echo started", extra={
            "client_id": request.client_id,
            "message": request.message
        })
        
        # Send 5 echo responses with delay
        for i in range(5):
            if context.cancelled():
                logger.info("Client cancelled server stream")
                break
            
            response = EchoResponse(
                message=f"Echo #{i+1}: {request.message}",
                server_id=self.server_id,
                timestamp=int(time.time() * 1000),
                sequence=i + 1
            )
            
            yield response
            
            # Wait before next response
            await asyncio.sleep(1)
        
        logger.info("Server stream echo completed")
    
    async def ClientStreamEcho(
        self, 
        request_iterator: AsyncIterator[EchoRequest], 
        context: ServicerContext
    ) -> EchoResponse:
        """Client streaming echo - collects messages and responds."""
        messages = []
        client_id = None
        
        async for request in request_iterator:
            if client_id is None:
                client_id = request.client_id
                logger.info("Starting client stream", extra={"client_id": client_id})
            
            messages.append(request.message)
            logger.debug("Received message", extra={"message": request.message})
        
        # Create summary response
        summary = f"Received {len(messages)} messages: {', '.join(messages)}"
        
        response = EchoResponse(
            message=summary,
            server_id=self.server_id,
            timestamp=int(time.time() * 1000),
            sequence=len(messages)
        )
        
        logger.info("Client stream completed", extra={"client_id": client_id})
        return response
    
    async def BidirectionalEcho(
        self, 
        request_iterator: AsyncIterator[EchoRequest], 
        context: ServicerContext
    ) -> AsyncIterator[EchoResponse]:
        """Bidirectional streaming echo - real-time conversation."""
        sequence = 0
        
        async for request in request_iterator:
            sequence += 1
            
            logger.debug("Bidirectional echo received", extra={
                "client_id": request.client_id,
                "message": request.message
            })
            
            # Echo back immediately
            response = EchoResponse(
                message=f"Echo: {request.message}",
                server_id=self.server_id,
                timestamp=int(time.time() * 1000),
                sequence=sequence
            )
            
            yield response
            
            # Check for special commands
            if request.message.lower() == "ping":
                # Respond with pong after a delay
                await asyncio.sleep(0.5)
                pong_response = EchoResponse(
                    message="Pong!",
                    server_id=self.server_id,
                    timestamp=int(time.time() * 1000),
                    sequence=sequence + 1
                )
                yield pong_response
                sequence += 1


class EchoProtocol(RPCPluginProtocol):
    """Echo service protocol."""
    
    async def get_grpc_descriptors(self):
        """Return gRPC module and service name."""
        import echo_pb2_grpc
        return echo_pb2_grpc, "echo.EchoService"
    
    async def add_to_server(self, server, handler):
        """Add service to gRPC server."""
        from echo_pb2_grpc import add_EchoServiceServicer_to_server
        add_EchoServiceServicer_to_server(handler, server)
        logger.info("Echo service registered with gRPC server")


async def create_echo_server():
    """Create and configure echo server."""
    # Create handler and protocol
    handler = EchoServiceHandler()
    protocol = EchoProtocol()
    
    # Create plugin server using factory function
    server = plugin_server(protocol=protocol, handler=handler)
    
    return server


async def main():
    """Run the echo server."""
    # Foundation logging is automatically configured
    
    server = await create_echo_server()
    
    try:
        logger.info("Echo server starting...")
        await server.serve()  # Handles handshake and serving
        
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
    
    except Exception as e:
        logger.error("Server error", exc_info=True)


if __name__ == "__main__":
    asyncio.run(main())
```

## Client Implementation

**echo_client.py**
```python
import asyncio
import sys
import time
import uuid
from pathlib import Path
from typing import AsyncIterator

from echo_pb2 import EchoRequest, EchoResponse
from echo_pb2_grpc import EchoServiceStub
from pyvider.rpcplugin import plugin_client
from pyvider.rpcplugin.exception import RPCPluginError
from provide.foundation import logger

class EchoClient:
    """Echo service client."""
    
    def __init__(self, plugin_command: list[str]):
        self.client_id = str(uuid.uuid4())[:8]
        self.plugin_command = plugin_command
        self.client = None
        self.stub: EchoServiceStub | None = None
        logger.info("Echo client created", extra={"client_id": self.client_id})
    
    async def connect(self):
        """Connect to the plugin."""
        self.client = plugin_client(command=self.plugin_command)
        await self.client.start()
        self.stub = EchoServiceStub(self.client.grpc_channel)
        logger.info("Connected to echo plugin")
    
    async def simple_echo(self, message: str) -> EchoResponse:
        """Simple echo call."""
        if not self.stub:
            raise RuntimeError("Client not connected")
            
        request = EchoRequest(
            message=message,
            client_id=self.client_id,
            timestamp=int(time.time() * 1000)
        )
        
        logger.info("Sending echo request", extra={"message": message})
        
        try:
            response = await self.stub.Echo(request)
            logger.info("Received echo response", extra={"response": response.message})
            return response
        
        except Exception as e:
            logger.error("RPC call failed", exc_info=True)
            raise
    
    async def server_stream_echo(self, message: str) -> list[EchoResponse]:
        """Server streaming echo call."""
        if not self.stub:
            raise RuntimeError("Client not connected")
            
        request = EchoRequest(
            message=message,
            client_id=self.client_id,
            timestamp=int(time.time() * 1000)
        )
        
        logger.info("Starting server stream echo", extra={"message": message})
        responses = []
        
        try:
            async for response in self.stub.ServerStreamEcho(request):
                logger.info("Received stream response", extra={"response": response.message})
                responses.append(response)
            
            logger.info("Server stream completed", extra={"count": len(responses)})
            return responses
        
        except Exception as e:
            logger.error("Stream call failed", exc_info=True)
            raise
    
    async def client_stream_echo(self, messages: list[str]) -> EchoResponse:
        """Client streaming echo call."""
        if not self.stub:
            raise RuntimeError("Client not connected")
            
        logger.info("Starting client stream", extra={"message_count": len(messages)})
        
        async def request_generator() -> AsyncIterator[EchoRequest]:
            for message in messages:
                request = EchoRequest(
                    message=message,
                    client_id=self.client_id,
                    timestamp=int(time.time() * 1000)
                )
                logger.debug("Sending stream message", extra={"message": message})
                yield request
                await asyncio.sleep(0.5)  # Small delay between messages
        
        try:
            response = await self.stub.ClientStreamEcho(request_generator())
            logger.info("Client stream completed", extra={"response": response.message})
            return response
        
        except Exception as e:
            logger.error("Client stream failed", exc_info=True)
            raise
    
    async def bidirectional_echo(self, messages: list[str]) -> list[EchoResponse]:
        """Bidirectional streaming echo."""
        if not self.stub:
            raise RuntimeError("Client not connected")
            
        logger.info("Starting bidirectional echo", extra={"message_count": len(messages)})
        
        async def request_generator() -> AsyncIterator[EchoRequest]:
            for message in messages:
                request = EchoRequest(
                    message=message,
                    client_id=self.client_id,
                    timestamp=int(time.time() * 1000)
                )
                logger.debug("Sending bidirectional message", extra={"message": message})
                yield request
                await asyncio.sleep(1)
        
        responses = []
        
        try:
            async for response in self.stub.BidirectionalEcho(request_generator()):
                logger.info("Received bidirectional response", extra={"response": response.message})
                responses.append(response)
            
            logger.info("Bidirectional echo completed", extra={"count": len(responses)})
            return responses
        
        except Exception as e:
            logger.error("Bidirectional stream failed", exc_info=True)
            raise
    
    async def close(self):
        """Close client connection."""
        if self.client:
            await self.client.close()
        logger.info("Echo client closed")


async def demo_echo_client():
    """Demonstrate echo client functionality."""
    # Define plugin command  
    plugin_path = Path(__file__).parent / "echo_service.py"
    plugin_command = [sys.executable, str(plugin_path)]
    
    client = EchoClient(plugin_command)
    
    try:
        # Connect to plugin
        await client.connect()
        # Simple echo
        print("\n1. Simple Echo")
        response = await client.simple_echo("Hello, World!")
        print(f"Response: {response.message}")
        
        # Server streaming
        print("\n2. Server Streaming Echo")
        responses = await client.server_stream_echo("Stream test")
        for i, response in enumerate(responses):
            print(f"Stream response {i+1}: {response.message}")
        
        # Client streaming
        print("\n3. Client Streaming Echo")
        messages = ["Message 1", "Message 2", "Message 3"]
        response = await client.client_stream_echo(messages)
        print(f"Summary: {response.message}")
        
        # Bidirectional streaming
        print("\n4. Bidirectional Streaming Echo")
        messages = ["Hello", "ping", "Goodbye"]
        responses = await client.bidirectional_echo(messages)
        for i, response in enumerate(responses):
            print(f"Bidirectional response {i+1}: {response.message}")
    
    finally:
        await client.close()


async def main():
    """Run echo client demo."""
    # Foundation logging is automatically configured
    
    try:
        await demo_echo_client()
    except RPCPluginError as e:
        logger.error("Plugin error", extra={"error": str(e)})
        raise
    except Exception as e:
        logger.error("Demo failed", exc_info=True)
        raise


if __name__ == "__main__":
    asyncio.run(main())
```

## Interactive Client

**interactive_echo.py**
```python
import asyncio
import sys
from pathlib import Path
from echo_client import EchoClient
from provide.foundation import logger

class InteractiveEchoClient:
    """Interactive echo client for testing."""
    
    def __init__(self, plugin_command: list[str]):
        self.plugin_command = plugin_command
        self.client: EchoClient | None = None
        self.running = True
    
    async def start(self):
        """Start interactive session."""
        print("🔊 Interactive Echo Client")
        print("Commands: echo, stream, client-stream, bidi, quit")
        print("Example: echo Hello World")
        
        self.client = EchoClient(self.plugin_command)
        await self.client.connect()
        
        while self.running:
            try:
                command = await self._get_input("echo> ")
                await self._process_command(command.strip())
            
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            
            except Exception as e:
                print(f"Error: {e}")
    
    async def _get_input(self, prompt: str) -> str:
        """Get user input asynchronously."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, input, prompt)
    
    async def _process_command(self, command: str):
        """Process user command."""
        if not command:
            return
        
        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        if cmd == "quit" or cmd == "exit":
            self.running = False
        
        elif cmd == "echo":
            if not args:
                print("Usage: echo <message>")
                return
            
            response = await self.client.simple_echo(args)
            print(f"Server: {response.message}")
        
        elif cmd == "stream":
            if not args:
                print("Usage: stream <message>")
                return
            
            print("Receiving server stream...")
            responses = await self.client.server_stream_echo(args)
            print(f"Received {len(responses)} responses")
        
        elif cmd == "client-stream":
            print("Enter messages (empty line to finish):")
            messages = []
            
            while True:
                msg = await self._get_input("  > ")
                if not msg.strip():
                    break
                messages.append(msg)
            
            if messages:
                response = await self.client.client_stream_echo(messages)
                print(f"Server summary: {response.message}")
        
        elif cmd == "bidi":
            print("Enter messages for bidirectional stream (empty line to finish):")
            messages = []
            
            while True:
                msg = await self._get_input("  > ")
                if not msg.strip():
                    break
                messages.append(msg)
            
            if messages:
                responses = await self.client.bidirectional_echo(messages)
                print(f"Received {len(responses)} bidirectional responses")
        
        elif cmd == "help":
            self._show_help()
        
        else:
            print(f"Unknown command: {cmd}")
            self._show_help()
    
    def _show_help(self):
        """Show help message."""
        print("""
Available commands:
  echo <message>        - Simple echo
  stream <message>      - Server streaming echo
  client-stream         - Client streaming echo
  bidi                  - Bidirectional streaming echo
  help                  - Show this help
  quit                  - Exit client
        """)
    
    async def close(self):
        """Close client."""
        if self.client:
            await self.client.close()


async def main():
    """Run interactive echo client."""
    # Define plugin command
    plugin_path = Path(__file__).parent / "echo_service.py"
    plugin_command = [sys.executable, str(plugin_path)]
    
    client = InteractiveEchoClient(plugin_command)
    
    try:
        await client.start()
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
```

## Running the Example

### Plugin-Based Execution

With the pyvider-rpcplugin framework, the client automatically launches and manages the server process:

### 1. Run the Client Demo

```bash
# The client will automatically launch echo_service.py as a plugin
python echo_client.py
```

### 2. Interactive Testing

```bash
# Interactive client also manages the plugin automatically
python interactive_echo.py
```

### 3. Standalone Server Testing

For development/testing, you can run the server standalone:

```bash
# Set required environment for standalone mode
export PLUGIN_MAGIC_COOKIE="test_cookie_value"
python echo_service.py
```

## Testing

**test_echo_service.py**
```python
import pytest
import asyncio
from echo_service import EchoServiceHandler
from echo_pb2 import EchoRequest, EchoResponse

@pytest.fixture
async def echo_handler():
    """Create echo handler for testing."""
    return EchoServiceHandler()

@pytest.mark.asyncio
async def test_simple_echo(echo_handler):
    """Test simple echo functionality."""
    request = EchoRequest(
        message="test message",
        client_id="test-client",
        timestamp=1234567890
    )
    
    # Mock context
    class MockContext:
        def cancelled(self):
            return False
    
    response = await echo_handler.Echo(request, MockContext())
    
    assert response.message == "Echo: test message"
    assert response.server_id == echo_handler.server_id
    assert response.sequence == 1

@pytest.mark.asyncio
async def test_server_stream_echo(echo_handler):
    """Test server streaming echo."""
    request = EchoRequest(
        message="stream test",
        client_id="test-client",
        timestamp=1234567890
    )
    
    class MockContext:
        def cancelled(self):
            return False
    
    responses = []
    async for response in echo_handler.ServerStreamEcho(request, MockContext()):
        responses.append(response)
    
    assert len(responses) == 5
    assert all("stream test" in r.message for r in responses)

@pytest.mark.asyncio  
async def test_client_stream_echo(echo_handler):
    """Test client streaming echo."""
    messages = ["msg1", "msg2", "msg3"]
    
    async def request_generator():
        for msg in messages:
            yield EchoRequest(
                message=msg,
                client_id="test-client",
                timestamp=1234567890
            )
    
    class MockContext:
        pass
    
    response = await echo_handler.ClientStreamEcho(request_generator(), MockContext())
    
    assert "3 messages" in response.message
    assert all(msg in response.message for msg in messages)
```

Run tests:
```bash
# Install pytest if needed
pip install pytest pytest-asyncio

# Run tests
pytest test_echo_service.py -v
```

## Key Features Demonstrated

1. **Modern Plugin Architecture** - Uses pyvider-rpcplugin factory functions and protocol system
2. **Foundation Integration** - Proper use of Foundation's structured logging and configuration
3. **All RPC Patterns** - Unary, server streaming, client streaming, bidirectional streaming
4. **Modern Python Patterns** - Uses Python 3.11+ features and modern typing
5. **Proper Error Handling** - Plugin-aware error handling with structured logging
6. **Automatic Process Management** - Client manages plugin process lifecycle
7. **Protocol-Based Design** - Clean separation between protocol definition and business logic
8. **Async/Await Patterns** - Full async implementation throughout
9. **Resource Management** - Proper connection and resource cleanup
10. **Testing Framework** - Unit tests for service methods
11. **Interactive Testing** - Real-time testing interface
12. **Structured Logging** - Foundation-based logging with context

This echo service demonstrates the modern pyvider-rpcplugin patterns and provides a solid foundation for building production RPC services with proper plugin architecture, Foundation integration, and modern Python practices.

## Learning Path and Implementation Guides

### Next Steps for Implementation
- **[Server Development Guide](../guide/server/)** - Learn advanced server patterns, including async programming, health checks, and production deployment
- **[Transport Configuration](../guide/server/transports.md)** - Advanced transport configuration for performance and security optimization
- **[Security Implementation](../guide/security/)** - Add mTLS, certificate management, and authentication to your services

### Configuration and Production Readiness
- **[Configuration Guide](../guide/config/)** - Environment-driven configuration for development and production environments
- **[Production Configuration](../guide/config/production.md)** - Production-grade configuration patterns with security and performance optimization

### Understanding Core Concepts
- **[Transport Concepts](../guide/concepts/transports.md)** - Understand transport selection and performance characteristics
- **[Security Model](../guide/concepts/security.md)** - Learn about the layered security architecture used by the plugin system

### API References
- **[Configuration API](../api/config/)** - Programmatic configuration access and validation
- **[Server API](../api/server/)** - Complete server implementation API documentation