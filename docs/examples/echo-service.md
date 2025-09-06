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
import logging
from typing import AsyncIterator
import grpc
from grpc.aio import ServicerContext

from echo_pb2 import EchoRequest, EchoResponse
from echo_pb2_grpc import EchoServiceServicer, add_EchoServiceServicer_to_server
from pyvider.server import RPCPluginServer
from pyvider.config import ServerConfig, TransportConfig

logger = logging.getLogger(__name__)

class EchoServicer(EchoServiceServicer):
    """Echo service implementation."""
    
    def __init__(self):
        self.server_id = str(uuid.uuid4())[:8]
        self.request_count = 0
        logger.info(f"Echo service started with ID: {self.server_id}")
    
    async def Echo(
        self, 
        request: EchoRequest, 
        context: ServicerContext
    ) -> EchoResponse:
        """Simple echo implementation."""
        self.request_count += 1
        
        logger.info(f"Echo request from {request.client_id}: {request.message}")
        
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
        logger.info(f"Server stream echo from {request.client_id}: {request.message}")
        
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
                logger.info(f"Starting client stream from {client_id}")
            
            messages.append(request.message)
            logger.debug(f"Received message: {request.message}")
        
        # Create summary response
        summary = f"Received {len(messages)} messages: {', '.join(messages)}"
        
        response = EchoResponse(
            message=summary,
            server_id=self.server_id,
            timestamp=int(time.time() * 1000),
            sequence=len(messages)
        )
        
        logger.info(f"Client stream completed for {client_id}")
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
            
            logger.debug(f"Bidirectional echo from {request.client_id}: {request.message}")
            
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


async def create_echo_server():
    """Create and configure echo server."""
    # Configure server
    config = ServerConfig(
        transport=TransportConfig(
            host="localhost",
            port=50051,
            tls_enabled=False
        ),
        max_workers=10,
        log_level="INFO"
    )
    
    # Create server
    server = RPCPluginServer(config)
    
    # Add echo service
    echo_servicer = EchoServicer()
    server.add_service(echo_servicer)
    
    return server


async def main():
    """Run the echo server."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    server = await create_echo_server()
    
    try:
        await server.start()
        logger.info("Echo server started. Press Ctrl+C to stop.")
        
        # Keep server running
        while True:
            await asyncio.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
    
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
```

## Client Implementation

**echo_client.py**
```python
import asyncio
import time
import uuid
import logging
from typing import AsyncIterator
import grpc

from echo_pb2 import EchoRequest, EchoResponse
from echo_pb2_grpc import EchoServiceStub
from pyvider.client import RPCPluginClient
from pyvider.config import ClientConfig, TransportConfig

logger = logging.getLogger(__name__)

class EchoClient:
    """Echo service client."""
    
    def __init__(self, host: str = "localhost", port: int = 50051):
        self.client_id = str(uuid.uuid4())[:8]
        self.channel = grpc.aio.insecure_channel(f"{host}:{port}")
        self.stub = EchoServiceStub(self.channel)
        logger.info(f"Echo client created with ID: {self.client_id}")
    
    async def simple_echo(self, message: str) -> EchoResponse:
        """Simple echo call."""
        request = EchoRequest(
            message=message,
            client_id=self.client_id,
            timestamp=int(time.time() * 1000)
        )
        
        logger.info(f"Sending echo request: {message}")
        
        try:
            response = await self.stub.Echo(request)
            logger.info(f"Received echo response: {response.message}")
            return response
        
        except grpc.RpcError as e:
            logger.error(f"RPC call failed: {e.code()}: {e.details()}")
            raise
    
    async def server_stream_echo(self, message: str) -> list[EchoResponse]:
        """Server streaming echo call."""
        request = EchoRequest(
            message=message,
            client_id=self.client_id,
            timestamp=int(time.time() * 1000)
        )
        
        logger.info(f"Starting server stream echo: {message}")
        responses = []
        
        try:
            async for response in self.stub.ServerStreamEcho(request):
                logger.info(f"Received stream response: {response.message}")
                responses.append(response)
            
            logger.info(f"Server stream completed, received {len(responses)} responses")
            return responses
        
        except grpc.RpcError as e:
            logger.error(f"Stream call failed: {e.code()}: {e.details()}")
            raise
    
    async def client_stream_echo(self, messages: list[str]) -> EchoResponse:
        """Client streaming echo call."""
        logger.info(f"Starting client stream with {len(messages)} messages")
        
        async def request_generator() -> AsyncIterator[EchoRequest]:
            for message in messages:
                request = EchoRequest(
                    message=message,
                    client_id=self.client_id,
                    timestamp=int(time.time() * 1000)
                )
                logger.debug(f"Sending stream message: {message}")
                yield request
                await asyncio.sleep(0.5)  # Small delay between messages
        
        try:
            response = await self.stub.ClientStreamEcho(request_generator())
            logger.info(f"Client stream completed: {response.message}")
            return response
        
        except grpc.RpcError as e:
            logger.error(f"Client stream failed: {e.code()}: {e.details()}")
            raise
    
    async def bidirectional_echo(self, messages: list[str]) -> list[EchoResponse]:
        """Bidirectional streaming echo."""
        logger.info(f"Starting bidirectional echo with {len(messages)} messages")
        
        async def request_generator() -> AsyncIterator[EchoRequest]:
            for message in messages:
                request = EchoRequest(
                    message=message,
                    client_id=self.client_id,
                    timestamp=int(time.time() * 1000)
                )
                logger.debug(f"Sending bidirectional message: {message}")
                yield request
                await asyncio.sleep(1)
        
        responses = []
        
        try:
            async for response in self.stub.BidirectionalEcho(request_generator()):
                logger.info(f"Received bidirectional response: {response.message}")
                responses.append(response)
            
            logger.info(f"Bidirectional echo completed, received {len(responses)} responses")
            return responses
        
        except grpc.RpcError as e:
            logger.error(f"Bidirectional stream failed: {e.code()}: {e.details()}")
            raise
    
    async def close(self):
        """Close client connection."""
        await self.channel.close()
        logger.info("Echo client closed")


async def demo_echo_client():
    """Demonstrate echo client functionality."""
    client = EchoClient()
    
    try:
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
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        await demo_echo_client()
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
```

## Interactive Client

**interactive_echo.py**
```python
import asyncio
import logging
import sys
from typing import Any
from echo_client import EchoClient

logger = logging.getLogger(__name__)

class InteractiveEchoClient:
    """Interactive echo client for testing."""
    
    def __init__(self):
        self.client: EchoClient | None = None
        self.running = True
    
    async def start(self):
        """Start interactive session."""
        print("🔊 Interactive Echo Client")
        print("Commands: echo, stream, client-stream, bidi, quit")
        print("Example: echo Hello World")
        
        self.client = EchoClient()
        
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
    logging.basicConfig(level=logging.INFO)
    
    client = InteractiveEchoClient()
    
    try:
        await client.start()
    finally:
        await client.close()


if __name__ == "__main__":
    asyncio.run(main())
```

## Running the Example

### 1. Start the Server

```bash
# Terminal 1: Start echo server
python echo_service.py
```

### 2. Run the Client Demo

```bash
# Terminal 2: Run client demo
python echo_client.py
```

### 3. Interactive Testing

```bash
# Terminal 2: Run interactive client
python interactive_echo.py
```

## Testing

**test_echo_service.py**
```python
import pytest
import asyncio
from echo_service import EchoServicer
from echo_pb2 import EchoRequest, EchoResponse

@pytest.fixture
async def echo_servicer():
    """Create echo servicer for testing."""
    return EchoServicer()

@pytest.mark.asyncio
async def test_simple_echo(echo_servicer):
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
    
    response = await echo_servicer.Echo(request, MockContext())
    
    assert response.message == "Echo: test message"
    assert response.server_id == echo_servicer.server_id
    assert response.sequence == 1

@pytest.mark.asyncio
async def test_server_stream_echo(echo_servicer):
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
    async for response in echo_servicer.ServerStreamEcho(request, MockContext()):
        responses.append(response)
    
    assert len(responses) == 5
    assert all("stream test" in r.message for r in responses)

@pytest.mark.asyncio  
async def test_client_stream_echo(echo_servicer):
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
    
    response = await echo_servicer.ClientStreamEcho(request_generator(), MockContext())
    
    assert "3 messages" in response.message
    assert all(msg in response.message for msg in messages)
```

Run tests:
```bash
pytest test_echo_service.py -v
```

## Key Features Demonstrated

1. **All RPC Patterns** - Unary, server streaming, client streaming, bidirectional
2. **Error Handling** - Proper gRPC error handling and logging
3. **Async/Await** - Full async implementation throughout
4. **Resource Management** - Proper connection management
5. **Testing** - Unit tests for service methods
6. **Interactive Client** - Real-time testing interface
7. **Logging** - Comprehensive logging for debugging

This echo service provides a solid foundation for understanding RPC patterns and can be extended with additional features like authentication, rate limiting, and persistence.