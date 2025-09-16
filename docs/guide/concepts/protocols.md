# Protocols

Protocol definitions are the foundation of the Pyvider RPC Plugin system. They define the interface between clients and servers, specify available services and methods, and ensure type-safe communication across process boundaries.

## Overview

The protocol system provides:

- **gRPC Integration** - Built on Protocol Buffers for efficient, type-safe communication
- **Service Definition** - Clear specification of available RPC methods  
- **Type Safety** - Compile-time type checking and automatic code generation
- **Versioning Support** - Backward and forward compatibility for API evolution
- **Multi-language Support** - Protocol definitions work across programming languages

## Protocol Components

### 1. Protocol Buffers (.proto files)

Protocol definitions start with `.proto` files that define services and messages:

```protobuf
// example.proto
syntax = "proto3";

package example;

// Service definition
service DataProcessor {
    // Unary RPC - single request, single response
    rpc ProcessData(ProcessRequest) returns (ProcessResponse);
    
    // Server streaming - single request, multiple responses  
    rpc StreamResults(StreamRequest) returns (stream ResultItem);
    
    // Health check method
    rpc GetStatus(StatusRequest) returns (StatusResponse);
}

// Message definitions
message ProcessRequest {
    string data = 1;
    map<string, string> options = 2;
    repeated string tags = 3;
}

message ProcessResponse {
    string result = 1;
    int32 status_code = 2;
    double processing_time = 3;
}

message StreamRequest {
    string query = 1;
    int32 limit = 2;
}

message ResultItem {
    string id = 1;
    string data = 2;
    int64 timestamp = 3;
}

message StatusRequest {}

message StatusResponse {
    string status = 1;
    string version = 2;
    int64 uptime = 3;
}
```

### 2. Generated Code

Protocol Buffers compiler generates Python code from `.proto` files:

```python
# Generated files (automatic)
# example_pb2.py - Message classes
# example_pb2_grpc.py - Service classes and stubs

# Example generated message class
class ProcessRequest:
    def __init__(self, data: str = "", options: dict = None, tags: list = None):
        self.data = data
        self.options = options or {}
        self.tags = tags or []

# Example generated service stub
class DataProcessorStub:
    def __init__(self, channel):
        self.ProcessData = channel.unary_unary(
            '/example.DataProcessor/ProcessData',
            request_serializer=ProcessRequest.SerializeToString,
            response_deserializer=ProcessResponse.FromString,
        )
```

### 3. Protocol Implementation

The `RPCPluginProtocol` class integrates Protocol Buffers with the plugin system:

```python
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
import example_pb2_grpc

class DataProcessorProtocol(RPCPluginProtocol):
    """Protocol implementation for DataProcessor service."""
    
    service_name = "example.DataProcessor"
    
    async def get_grpc_descriptors(self):
        """Return gRPC module and service name for registration."""
        return example_pb2_grpc, "example.DataProcessor"
    
    async def add_to_server(self, server, handler):
        """Register service implementation with gRPC server."""
        example_pb2_grpc.add_DataProcessorServicer_to_server(handler, server)
    
    def get_method_type(self, method_name: str) -> str:
        """Return RPC method type for the given method."""
        method_types = {
            "ProcessData": "unary_unary",
            "StreamResults": "unary_stream", 
            "GetStatus": "unary_unary"
        }
        return method_types.get(method_name, "unary_unary")
```

### 4. Service Handler Implementation

Service handlers implement the actual business logic:

```python
import example_pb2
import example_pb2_grpc
from provide.foundation import logger

class DataProcessorHandler(example_pb2_grpc.DataProcessorServicer):
    """Implementation of DataProcessor service."""
    
    def __init__(self):
        self.start_time = time.time()
        logger.info("DataProcessor handler initialized")
    
    async def ProcessData(self, request, context):
        """Handle ProcessData RPC method."""
        logger.info(f"Processing data: {request.data}")
        
        try:
            # Validate request
            if not request.data:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("Data field is required")
                return example_pb2.ProcessResponse()
            
            # Process data with options
            start_time = time.time()
            result = await self._process_business_logic(
                data=request.data,
                options=dict(request.options),
                tags=list(request.tags)
            )
            processing_time = time.time() - start_time
            
            return example_pb2.ProcessResponse(
                result=result,
                status_code=0,
                processing_time=processing_time
            )
            
        except ValueError as e:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(str(e))
            return example_pb2.ProcessResponse(status_code=1)
            
        except Exception as e:
            logger.error(f"Processing error: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal processing error")
            return example_pb2.ProcessResponse(status_code=2)
    
    async def StreamResults(self, request, context):
        """Handle StreamResults streaming RPC method."""
        logger.info(f"Streaming results for query: {request.query}")
        
        try:
            results = await self._query_data(request.query, request.limit)
            
            for result in results:
                yield example_pb2.ResultItem(
                    id=result["id"],
                    data=result["data"],
                    timestamp=int(time.time())
                )
                
                # Allow for graceful cancellation
                if context.cancelled():
                    logger.info("Stream cancelled by client")
                    break
                    
        except Exception as e:
            logger.error(f"Streaming error: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
    
    async def GetStatus(self, request, context):
        """Handle GetStatus RPC method."""
        uptime = int(time.time() - self.start_time)
        
        return example_pb2.StatusResponse(
            status="healthy",
            version="1.0.0",
            uptime=uptime
        )
    
    async def _process_business_logic(self, data, options, tags):
        """Internal business logic implementation."""
        # Simulate processing
        await asyncio.sleep(0.1)
        
        # Apply options
        result = data.upper() if options.get("uppercase") else data
        
        # Add tags
        if tags:
            result = f"[{','.join(tags)}] {result}"
            
        return result
    
    async def _query_data(self, query, limit):
        """Internal data querying logic."""
        # Simulate database query
        results = []
        for i in range(min(limit, 10)):
            results.append({
                "id": f"item_{i}",
                "data": f"Result for '{query}' #{i}"
            })
            await asyncio.sleep(0.05)  # Simulate processing delay
        
        return results
```

## Protocol Usage Patterns

### 1. Basic Server Setup

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin import plugin_server

async def main():
    # Create server with custom protocol
    server = plugin_server(
        protocol=DataProcessorProtocol(),
        handler=DataProcessorHandler()
    )
    
    logger.info("DataProcessor server starting...")
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
```

### 2. Client Usage

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin import plugin_client
import example_pb2

async def main():
    client = plugin_client(command=["python", "data_processor_server.py"])
    
    async with client:
        # Create typed request
        request = example_pb2.ProcessRequest(
            data="Hello, World!",
            options={"uppercase": "true"},
            tags=["greeting", "example"]
        )
        
        # Make RPC call
        response = await client.data_processor.ProcessData(request)
        
        logger.info(f"Result: {response.result}")
        logger.info(f"Processing time: {response.processing_time:.3f}s")
        
        # Stream results
        stream_request = example_pb2.StreamRequest(
            query="test data",
            limit=5
        )
        
        logger.info("Streaming results...")
        async for item in client.data_processor.StreamResults(stream_request):
            logger.info(f"Received: {item.id} - {item.data}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Advanced Protocol Patterns

### 1. Multiple Services

A single protocol can support multiple services:

```protobuf
// multi_service.proto
service UserService {
    rpc CreateUser(CreateUserRequest) returns (User);
    rpc GetUser(GetUserRequest) returns (User);
}

service DataService {
    rpc StoreData(StoreRequest) returns (StoreResponse);
    rpc QueryData(QueryRequest) returns (QueryResponse);
}
```

```python
class MultiServiceProtocol(RPCPluginProtocol):
    """Protocol supporting multiple services."""
    
    service_name = "multi.Services"
    
    async def get_grpc_descriptors(self):
        return multi_service_pb2_grpc, "multi.Services"
    
    async def add_to_server(self, server, handler):
        # Register multiple services with the same handler
        multi_service_pb2_grpc.add_UserServiceServicer_to_server(handler, server)
        multi_service_pb2_grpc.add_DataServiceServicer_to_server(handler, server)

class MultiServiceHandler(
    multi_service_pb2_grpc.UserServiceServicer,
    multi_service_pb2_grpc.DataServiceServicer
):
    """Handler implementing multiple services."""
    
    async def CreateUser(self, request, context):
        # User service implementation
        pass
    
    async def StoreData(self, request, context):
        # Data service implementation  
        pass
```

### 2. Versioned APIs

Support multiple API versions in the same protocol:

```protobuf
// versioned_api.proto
service DataProcessorV1 {
    rpc Process(ProcessRequestV1) returns (ProcessResponseV1);
}

service DataProcessorV2 {
    rpc Process(ProcessRequestV2) returns (ProcessResponseV2);
    rpc BatchProcess(BatchProcessRequest) returns (BatchProcessResponse);
}
```

```python
class VersionedProtocol(RPCPluginProtocol):
    """Protocol supporting multiple API versions."""
    
    def __init__(self, version="v2"):
        self.version = version
        self.service_name = f"example.DataProcessor{version.upper()}"
    
    async def get_grpc_descriptors(self):
        return versioned_api_pb2_grpc, self.service_name
    
    async def add_to_server(self, server, handler):
        if self.version == "v1":
            versioned_api_pb2_grpc.add_DataProcessorV1Servicer_to_server(handler, server)
        elif self.version == "v2":
            versioned_api_pb2_grpc.add_DataProcessorV2Servicer_to_server(handler, server)
```

### 3. Streaming Patterns

Implement various streaming patterns:

```protobuf
service StreamingService {
    // Server streaming: single request, multiple responses
    rpc DownloadFile(DownloadRequest) returns (stream FileChunk);
    
    // Client streaming: multiple requests, single response  
    rpc UploadFile(stream FileChunk) returns (UploadResponse);
    
    // Bidirectional streaming: multiple requests and responses
    rpc Chat(stream ChatMessage) returns (stream ChatMessage);
}
```

```python
class StreamingHandler(streaming_pb2_grpc.StreamingServiceServicer):
    """Handler with streaming implementations."""
    
    async def DownloadFile(self, request, context):
        """Server streaming - send file in chunks."""
        file_path = request.file_path
        
        try:
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)  # 8KB chunks
                    if not chunk:
                        break
                    
                    yield streaming_pb2.FileChunk(
                        data=chunk,
                        sequence=chunk_num,
                        is_last=(len(chunk) < 8192)
                    )
                    chunk_num += 1
                    
        except FileNotFoundError:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"File not found: {file_path}")
    
    async def UploadFile(self, request_iterator, context):
        """Client streaming - receive file in chunks."""
        file_data = b""
        total_chunks = 0
        
        async for chunk in request_iterator:
            file_data += chunk.data
            total_chunks += 1
        
        # Save file
        file_path = f"/tmp/upload_{int(time.time())}.bin"
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        return streaming_pb2.UploadResponse(
            file_path=file_path,
            total_bytes=len(file_data),
            total_chunks=total_chunks
        )
    
    async def Chat(self, request_iterator, context):
        """Bidirectional streaming - interactive chat."""
        async for message in request_iterator:
            # Process incoming message
            response_text = await self.process_chat_message(message.text)
            
            # Send response
            yield streaming_pb2.ChatMessage(
                user="assistant",
                text=response_text,
                timestamp=int(time.time())
            )
```

## Protocol Development Workflow

### 1. Define Protocol

```bash
# 1. Write .proto file
cat > my_service.proto << EOF
syntax = "proto3";
package myservice;

service MyService {
    rpc DoSomething(Request) returns (Response);
}

message Request {
    string input = 1;
}

message Response {
    string output = 1;
}
EOF
```

### 2. Generate Code

```bash
# 2. Generate Python code from .proto file
python -m grpc_tools.protoc \
    --proto_path=. \
    --python_out=. \
    --grpc_python_out=. \
    my_service.proto

# Generated files:
# - my_service_pb2.py (message classes)
# - my_service_pb2_grpc.py (service classes)
```

### 3. Implement Protocol

```python
# 3. Implement protocol class
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
import my_service_pb2_grpc

class MyServiceProtocol(RPCPluginProtocol):
    service_name = "myservice.MyService"
    
    async def get_grpc_descriptors(self):
        return my_service_pb2_grpc, "myservice.MyService"
    
    async def add_to_server(self, server, handler):
        my_service_pb2_grpc.add_MyServiceServicer_to_server(handler, server)
```

### 4. Implement Handler

```python
# 4. Implement service handler
import my_service_pb2
import my_service_pb2_grpc

class MyServiceHandler(my_service_pb2_grpc.MyServiceServicer):
    async def DoSomething(self, request, context):
        # Business logic
        result = self.process(request.input)
        
        return my_service_pb2.Response(output=result)
```

### 5. Create Server

```python
# 5. Create server with protocol and handler
from pyvider.rpcplugin import plugin_server

server = plugin_server(
    protocol=MyServiceProtocol(),
    handler=MyServiceHandler()
)
```

## Protocol Best Practices

### 1. Message Design

```protobuf
// Good: Clear, extensible message design
message ProcessRequest {
    string data = 1;                    // Required data
    map<string, string> options = 2;    // Extensible options
    repeated string tags = 3;           // List of tags
    google.protobuf.Timestamp created = 4;  // Use well-known types
}

// Bad: Unclear, hard to extend
message ProcessRequest {
    string data = 1;
    string option1 = 2;  // Hard to extend
    string option2 = 3;  // Limited flexibility
}
```

### 2. Error Handling

```python
async def ProcessData(self, request, context):
    try:
        # Validate request
        if not request.data:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Missing required field: data")
            return ProcessResponse()
        
        # Business logic
        result = await self.process(request.data)
        
        return ProcessResponse(
            result=result,
            status=ProcessResponse.Status.SUCCESS
        )
        
    except PermissionError:
        context.set_code(grpc.StatusCode.PERMISSION_DENIED)
        context.set_details("Insufficient permissions")
        
    except Exception as e:
        logger.error("Processing failed", exc_info=True)
        context.set_code(grpc.StatusCode.INTERNAL)
        context.set_details("Internal error occurred")
    
    return ProcessResponse(status=ProcessResponse.Status.ERROR)
```

### 3. Service Documentation

```python
class DocumentedProtocol(RPCPluginProtocol):
    """
    Well-documented protocol implementation.
    
    This protocol provides data processing services with the following capabilities:
    - Synchronous data processing
    - Streaming result delivery
    - Health status monitoring
    
    Usage:
        protocol = DocumentedProtocol()
        handler = DocumentedHandler()
        server = plugin_server(protocol=protocol, handler=handler)
    """
    
    service_name = "documented.DataProcessor"
    
    async def get_grpc_descriptors(self):
        """Return gRPC descriptors for the DataProcessor service."""
        return documented_pb2_grpc, self.service_name
```

## Next Steps

- **[RPC Architecture](rpc-architecture.md)** - Understanding the complete RPC system
- **[Handshake Process](handshake.md)** - Connection establishment and protocol negotiation
- **[Server Development](../server/index.md)** - Implementing servers with custom protocols
- **[Custom Protocols](../advanced/custom-protocols.md)** - Advanced protocol development patterns