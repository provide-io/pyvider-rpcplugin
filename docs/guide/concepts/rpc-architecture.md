# RPC Architecture

The Pyvider RPC Plugin system implements a robust RPC (Remote Procedure Call) architecture built on gRPC, designed for secure, high-performance communication between host applications and plugin processes.

## Overview

The RPC architecture follows a client-server model where:

- **Host Application** acts as the client, launching and communicating with plugins
- **Plugin Process** acts as the server, providing RPC services to the host
- **Communication** happens over Unix sockets or TCP with optional mTLS encryption
- **Protocol** uses gRPC with automatic service discovery and method routing

```
┌─────────────────────────────────────────────────────────────────┐
│ Host Application Process                                        │
│                                                                 │
│  ┌─────────────────┐                                           │
│  │ RPCPluginClient │                                           │
│  │                 │                                           │
│  │ ┌─────────────┐ │            gRPC/HTTP2                    │
│  │ │ Service     │ │ ◄─────────────────────────────────────┐  │
│  │ │ Stubs       │ │                                        │  │
│  │ └─────────────┘ │                                        │  │
│  │                 │                                        │  │
│  │ ┌─────────────┐ │                                        │  │
│  │ │ Transport   │ │                                        │  │
│  │ │ Layer       │ │                                        │  │
│  │ └─────────────┘ │                                        │  │
│  └─────────────────┘                                        │  │
└──────────────────────────────────────────────────────────────┼──┘
                                                               │
                                                               │
┌──────────────────────────────────────────────────────────────┼──┐
│ Plugin Process                                               │  │
│                                                              │  │
│  ┌─────────────────┐                                        │  │
│  │ RPCPluginServer │                                        │  │
│  │                 │                                        │  │
│  │ ┌─────────────┐ │                                        │  │
│  │ │ gRPC Server │ │ ◄──────────────────────────────────────┘  │
│  │ │             │ │                                           │
│  │ │ ┌─────────┐ │ │                                           │
│  │ │ │Service  │ │ │                                           │
│  │ │ │Handler  │ │ │                                           │
│  │ │ └─────────┘ │ │                                           │
│  │ └─────────────┘ │                                           │
│  │                 │                                           │
│  │ ┌─────────────┐ │                                           │
│  │ │ Transport   │ │                                           │
│  │ │ Layer       │ │                                           │
│  │ └─────────────┘ │                                           │
│  └─────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. gRPC Foundation

The architecture is built on **gRPC**, providing:

- **Protocol Buffers** for efficient serialization
- **HTTP/2** for multiplexed, bidirectional communication
- **Streaming Support** for real-time data flows
- **Built-in Load Balancing** and connection management
- **Rich Error Handling** with status codes and metadata

```python
# Example service definition (proto file)
syntax = "proto3";

package example;

service DataProcessor {
    // Unary RPC - single request, single response
    rpc ProcessData(DataRequest) returns (DataResponse);
    
    // Server streaming - single request, multiple responses
    rpc StreamResults(QueryRequest) returns (stream ResultItem);
    
    // Client streaming - multiple requests, single response
    rpc UploadData(stream DataChunk) returns (UploadResponse);
    
    // Bidirectional streaming - multiple requests and responses
    rpc InteractiveSession(stream SessionMessage) returns (stream SessionResponse);
}

message DataRequest {
    string data = 1;
    map<string, string> options = 2;
}

message DataResponse {
    string result = 1;
    int32 status_code = 2;
}
```

### 2. Service Discovery

The RPC architecture includes automatic service discovery:

```python
# Client automatically discovers available services
async with plugin_client(command=["python", "-m", "my_plugin"]) as client:
    # Available services are automatically exposed as attributes
    response = await client.data_processor.ProcessData(
        data="example",
        options={"format": "json"}
    )
```

### 3. Method Routing

gRPC provides automatic method routing and dispatching:

```python
# Server-side service implementation
class DataProcessorServicer:
    async def ProcessData(self, request, context):
        """Handle ProcessData RPC method."""
        logger.info(f"Processing data: {request.data}")
        
        # Business logic implementation
        result = await self.process_business_logic(request.data)
        
        return DataResponse(
            result=result,
            status_code=0
        )
    
    async def StreamResults(self, request, context):
        """Handle streaming RPC method."""
        for i in range(10):
            yield ResultItem(
                id=i,
                data=f"result_{i}",
                timestamp=time.time()
            )
            await asyncio.sleep(0.1)  # Simulate processing
```

### 4. Foundation Integration

The RPC architecture seamlessly integrates with Foundation for essential services:

```python
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from provide.foundation import logger, config
from provide.foundation.crypto import Certificate

class SecureDataProcessor:
    def __init__(self):
        # Foundation configuration
        self.config = config.get_config()
        
    async def ProcessData(self, request, context):
        # Foundation logging with structured context
        logger.info("Processing secure data", 
                   request_id=request.id, 
                   data_size=len(request.data))
        
        # Foundation crypto for data validation
        if self.config.validate_signatures:
            cert = Certificate.from_request(context)
            if not cert.is_valid():
                logger.warning("Invalid certificate", cert_id=cert.id)
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid certificate")
        
        result = await self.process_data(request.data)
        logger.info("Data processed successfully", result_size=len(result))
        
        return DataResponse(result=result, status_code=0)
```

**Foundation provides:**

- **Structured Logging**: Rich context and formatting for debugging and monitoring
- **Configuration Management**: Environment-aware settings with validation
- **Cryptography**: Certificate management, signing, and validation
- **Error Handling**: Comprehensive error boundaries and retry logic
- **Rate Limiting**: Token bucket implementation for request throttling

## Communication Patterns

### 1. Unary RPC (Request-Response)

Most common pattern for simple request-response operations:

```python
# Client side
async def simple_request():
    async with plugin_client(command=cmd) as client:
        response = await client.my_service.GetStatus()
        return response.status

# Server side  
class MyServiceServicer:
    async def GetStatus(self, request, context):
        return StatusResponse(
            status="healthy",
            uptime=self.get_uptime(),
            version="1.0.0"
        )
```

### 2. Server Streaming

Server sends multiple responses for a single client request:

```python
# Client side - receive stream
async def receive_stream():
    async with plugin_client(command=cmd) as client:
        async for item in client.my_service.StreamData(request):
            print(f"Received: {item.data}")

# Server side - send stream
class MyServiceServicer:
    async def StreamData(self, request, context):
        for i in range(request.count):
            yield DataItem(
                id=i,
                data=f"item_{i}",
                timestamp=time.time()
            )
            await asyncio.sleep(0.1)
```

### 3. Client Streaming

Client sends multiple requests, server responds with single response:

```python
# Client side - send stream
async def send_stream():
    async with plugin_client(command=cmd) as client:
        
        async def generate_requests():
            for i in range(100):
                yield DataChunk(
                    sequence=i,
                    data=f"chunk_{i}".encode()
                )
        
        response = await client.my_service.UploadData(generate_requests())
        return response.total_bytes

# Server side - receive stream
class MyServiceServicer:
    async def UploadData(self, request_iterator, context):
        total_bytes = 0
        async for chunk in request_iterator:
            total_bytes += len(chunk.data)
            # Process chunk
        
        return UploadResponse(total_bytes=total_bytes)
```

### 4. Bidirectional Streaming

Both client and server can send multiple messages:

```python
# Client side - interactive session
async def interactive_session():
    async with plugin_client(command=cmd) as client:
        
        async def send_messages():
            for i in range(10):
                yield SessionMessage(
                    id=i,
                    content=f"message_{i}"
                )
                await asyncio.sleep(1.0)
        
        async for response in client.my_service.Chat(send_messages()):
            print(f"Server says: {response.content}")

# Server side - handle interactive session
class MyServiceServicer:
    async def Chat(self, request_iterator, context):
        async for message in request_iterator:
            # Process incoming message
            response_content = await self.process_message(message.content)
            
            # Send response
            yield SessionResponse(
                id=message.id,
                content=response_content
            )
```

## Protocol Implementation

### Protocol Interface

The `RPCPluginProtocol` interface defines how services integrate with the server:

```python
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol

class MyProtocol(RPCPluginProtocol):
    service_name = "example.MyService"
    
    async def get_grpc_descriptors(self):
        """Return gRPC module and service name."""
        import my_service_pb2_grpc
        return my_service_pb2_grpc, "example.MyService"
    
    async def add_to_server(self, server, handler):
        """Register service with gRPC server."""
        from my_service_pb2_grpc import add_MyServiceServicer_to_server
        add_MyServiceServicer_to_server(handler, server)
    
    def get_method_type(self, method_name):
        """Return RPC method type for given method."""
        method_types = {
            "GetStatus": "unary_unary",
            "StreamData": "unary_stream", 
            "UploadData": "stream_unary",
            "Chat": "stream_stream"
        }
        return method_types.get(method_name, "unary_unary")
```

### Service Integration

Services are integrated through the protocol implementation:

```python
# Complete service setup
class MyServiceHandler:
    """Business logic implementation."""
    
    async def GetStatus(self, request, context):
        return StatusResponse(status="healthy")
    
    async def ProcessData(self, request, context):
        result = await self.business_logic(request.data)
        return DataResponse(result=result)

# Create server with service
server = plugin_server(
    protocol=MyProtocol(),
    handler=MyServiceHandler()
)
```

## Error Handling Architecture

### gRPC Status Codes

The architecture uses standard gRPC status codes for error handling:

```python
import grpc
from grpc import StatusCode

class MyServiceServicer:
    async def ProcessData(self, request, context):
        try:
            # Validate input
            if not request.data:
                context.set_code(StatusCode.INVALID_ARGUMENT)
                context.set_details("Data field is required")
                return DataResponse()
            
            # Process data
            result = await self.process(request.data)
            return DataResponse(result=result)
            
        except ValidationError as e:
            context.set_code(StatusCode.INVALID_ARGUMENT)
            context.set_details(str(e))
            return DataResponse()
            
        except PermissionError as e:
            context.set_code(StatusCode.PERMISSION_DENIED)
            context.set_details(str(e))
            return DataResponse()
            
        except Exception as e:
            logger.error("Unexpected error", exc_info=True)
            context.set_code(StatusCode.INTERNAL)
            context.set_details("Internal server error")
            return DataResponse()
```

### Client Error Handling

Clients handle gRPC errors through exceptions:

```python
import grpc

async def handle_rpc_errors():
    try:
        async with plugin_client(command=cmd) as client:
            response = await client.my_service.ProcessData(request)
            return response
            
    except grpc.aio.AioRpcError as e:
        if e.code() == grpc.StatusCode.INVALID_ARGUMENT:
            logger.error(f"Invalid request: {e.details()}")
        elif e.code() == grpc.StatusCode.PERMISSION_DENIED:
            logger.error(f"Permission denied: {e.details()}")
        elif e.code() == grpc.StatusCode.UNAVAILABLE:
            logger.error("Service unavailable, retrying...")
            # Implement retry logic
        else:
            logger.error(f"RPC error: {e.code()} - {e.details()}")
        raise
```

## Performance Architecture

### Connection Multiplexing

gRPC uses HTTP/2 for efficient connection multiplexing:

```python
# Single connection handles multiple concurrent RPCs
async def concurrent_requests():
    async with plugin_client(command=cmd) as client:
        # All requests share the same connection
        tasks = [
            client.my_service.ProcessData(f"data_{i}")
            for i in range(100)
        ]
        
        # Requests are automatically multiplexed
        results = await asyncio.gather(*tasks)
        return results
```

### Streaming Efficiency

Streaming RPCs provide efficient data transfer:

```python
# Efficient large data transfer
async def stream_large_dataset():
    async with plugin_client(command=cmd) as client:
        
        # Stream data without loading everything into memory
        async for chunk in client.my_service.StreamLargeData(request):
            await process_chunk_incrementally(chunk)
            # Memory usage remains constant
```

### Connection Pooling

For high-throughput scenarios, implement connection pooling:

```python
class ConnectionPool:
    def __init__(self, command, pool_size=10):
        self.command = command
        self.pool_size = pool_size
        self.connections = asyncio.Queue(maxsize=pool_size)
    
    async def initialize(self):
        for _ in range(self.pool_size):
            client = plugin_client(command=self.command)
            await client.start()
            await self.connections.put(client)
    
    async def get_connection(self):
        return await self.connections.get()
    
    async def return_connection(self, client):
        await self.connections.put(client)

# Usage with connection pooling
pool = ConnectionPool(["python", "-m", "my_plugin"], pool_size=20)
await pool.initialize()
```

## Security Architecture Integration

### Transport Layer Security

The RPC architecture integrates with the security model:

```python
# Automatic mTLS integration
os.environ.update({
    "PYVIDER_PLUGIN_AUTO_MTLS": "true",
    "PYVIDER_PLUGIN_SERVER_CERT": "file:///etc/ssl/server.pem",
    "PYVIDER_PLUGIN_SERVER_KEY": "file:///etc/ssl/server.key"
})

# gRPC automatically uses TLS for all communication
server = plugin_server(protocol=protocol, handler=handler)
```

### Authentication Integration

Magic cookie authentication happens at the transport layer before gRPC:

```python
# Authentication occurs during handshake, before gRPC communication
async def authenticated_rpc():
    # Magic cookie validated during connection establishment
    async with plugin_client(command=cmd) as client:
        # All RPC calls are automatically authenticated
        response = await client.my_service.SecureOperation(request)
        return response
```

## Architecture Benefits

### 1. Type Safety

Protocol Buffers provide compile-time type safety:

```python
# Types are automatically generated from .proto files
request = DataRequest(
    data="example",
    options={"key": "value"}  # Type-checked
)

response = await client.my_service.ProcessData(request)
# response.result is automatically typed as string
```

### 2. Versioning Support

gRPC provides built-in API versioning:

```python
# Forward/backward compatible service evolution
service DataProcessor {
    rpc ProcessDataV1(DataRequestV1) returns (DataResponseV1);
    rpc ProcessDataV2(DataRequestV2) returns (DataResponseV2);
}
```

### 3. Language Interoperability

gRPC enables polyglot plugin development:

```python
# Python client can communicate with any gRPC server
# Server could be implemented in Go, Java, C++, etc.
async with plugin_client(command=["./go-plugin-server"]) as client:
    response = await client.data_service.ProcessData(request)
```

### 4. Built-in Observability

gRPC provides built-in metrics and tracing:

```python
# Automatic request/response metrics
# - Request count, latency, error rates
# - Connection health and status
# - Streaming metrics (messages sent/received)
```

## Next Steps

- **[Protocols](protocols.md)** - Protocol definition and implementation patterns
- **[Handshake Process](handshake.md)** - Connection establishment and negotiation
- **[Transports](transports.md)** - Transport layer implementation details
- **[Security Model](security.md)** - Security architecture and patterns