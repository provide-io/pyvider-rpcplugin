---
title: Protocol Definition
description: How to define gRPC service interfaces for Pyvider plugins
---

# Protocol Definition Guide

This guide explains how to define gRPC service interfaces for your Pyvider RPC Plugin system. The protocol definition is the contract between client and server—it defines what operations are available and how data is structured.

## Protocol Buffer Basics

Protocol Buffers (protobuf) is Google's language-neutral, platform-neutral, extensible mechanism for serializing structured data. With protobuf, you define your data structures and services in `.proto` files, then use the protobuf compiler to generate code in your preferred language.

### Creating a .proto File

Start by creating a `.proto` file that defines your service interface:

```protobuf
syntax = "proto3";  // Always use proto3 syntax
package example;    // Define a package name to avoid conflicts

// Service definition
service Calculator {
  // Simple unary RPC
  rpc Add(AddRequest) returns (AddResponse);
  
  // Server streaming RPC
  rpc GenerateFibonacci(FibRequest) returns (stream FibResponse);
  
  // Client streaming RPC
  rpc SumValues(stream SumRequest) returns (SumResponse);
  
  // Bidirectional streaming RPC
  rpc ProcessBatch(stream BatchRequest) returns (stream BatchResponse);
}

// Message definitions
message AddRequest {
  int32 a = 1;
  int32 b = 2;
}

message AddResponse {
  int32 result = 1;
}

message FibRequest {
  int32 count = 1;
}

message FibResponse {
  int32 value = 1;
  int32 position = 2;
}

message SumRequest {
  int32 value = 1;
}

message SumResponse {
  int32 sum = 1;
  int32 count = 2;
}

message BatchRequest {
  string operation = 1;
  repeated int32 values = 2;
}

message BatchResponse {
  string operation = 1;
  int32 result = 2;
  string status = 3;
}
```

This file defines a simple calculator service with four RPC methods demonstrating different communication patterns.

## RPC Method Types

Protocol Buffers support four types of RPC methods:

### 1. Unary RPC

The client sends a single request and gets a single response.

```protobuf
rpc Add(AddRequest) returns (AddResponse);
```

This is the simplest pattern—like asking a single question and getting a single answer.

### 2. Server Streaming RPC

The client sends a single request and gets a stream of responses.

```protobuf
rpc GenerateFibonacci(FibRequest) returns (stream FibResponse);
```

This is useful for returning large datasets or continuous updates—like asking for weather updates and getting a continuous feed.

### 3. Client Streaming RPC

The client sends a stream of requests and gets a single response.

```protobuf
rpc SumValues(stream SumRequest) returns (SumResponse);
```

This is useful for uploading data or sending commands in sequence—like sending a series of files and getting a single confirmation.

### 4. Bidirectional Streaming RPC

The client and server send streams of messages to each other.

```protobuf
rpc ProcessBatch(stream BatchRequest) returns (stream BatchResponse);
```

This is useful for real-time interactions like chat or complex workflows—like having a conversation where both sides can speak whenever they want.

## Message Definition Best Practices

When defining messages, follow these best practices:

1. **Use Appropriate Types**: Choose field types that match your data requirements. For example, use `int32` for standard integers, `int64` for large integers, and `string` for text.

2. **Field Numbering**: Each field in a message requires a unique number. Start from 1 and increment sequentially.

3. **Reserved Fields**: Mark deleted fields as reserved to prevent future reuse.

```protobuf
message ExampleMessage {
  reserved 2, 15, 9 to 11;    // Reserved field numbers
  reserved "foo", "bar";      // Reserved field names
  
  string name = 1;
  int32 id = 3;
}
```

4. **Nested Types**: Use nested types for logical grouping.

```protobuf
message SearchResponse {
  message Result {
    string url = 1;
    string title = 2;
    repeated string snippets = 3;
  }
  repeated Result results = 1;
}
```

5. **Enumerations**: Use enums for fields with a fixed set of values.

```protobuf
enum Status {
  UNKNOWN = 0;  // Always start enum with 0
  ACTIVE = 1;
  PENDING = 2;
  DELETED = 3;
}

message User {
  string name = 1;
  Status status = 2;
}
```

## Protocol Versioning

Design your protocol with versioning in mind:

1. **Never Change Field Numbers**: Once assigned, a field number should never be reused or changed.

2. **Add, Don't Modify**: Add new fields rather than modifying existing ones.

3. **Use Required vs. Optional**: In proto3, all fields are effectively optional. Design your code to handle missing fields gracefully.

4. **Service Versioning**: Include version information in the service name if making breaking changes.

```protobuf
service CalculatorV1 {
  // Original methods...
}

service CalculatorV2 {
  // New and improved methods...
}
```

Think of protocol versioning like designing a building with room for expansion—you can add new rooms, but you shouldn't tear down existing walls.

## Generating Python Code

After defining your `.proto` file, generate the Python code using the protobuf compiler:

```bash
# Install the required tools
pip install grpcio-tools

# Generate Python code
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. your_service.proto
```

This will create two Python files:
- `your_service_pb2.py`: Contains message classes
- `your_service_pb2_grpc.py`: Contains service classes

The generated code looks something like this (simplified):

```python
# your_service_pb2.py
class AddRequest(message.Message):
    __slots__ = ["a", "b"]
    A_FIELD_NUMBER = 1
    B_FIELD_NUMBER = 2
    # ...

# your_service_pb2_grpc.py
class CalculatorServicer(object):
    def Add(self, request, context):
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')
    # ...
```

## Implementing the RPCPluginProtocol

To use your generated code with Pyvider, implement the `RPCPluginProtocol`:

```python
from pyvider.rpcplugin.protocol import RPCPluginProtocol
import your_service_pb2
import your_service_pb2_grpc

class CalculatorProtocol(RPCPluginProtocol):
    """Protocol definition for the Calculator service."""
    
    def get_grpc_descriptors(self):
        """Return the protobuf descriptor and service name."""
        return your_service_pb2.DESCRIPTOR, "Calculator"
    
    def add_to_server(self, server, handler):
        """Add the service to a gRPC server."""
        your_service_pb2_grpc.add_CalculatorServicer_to_server(handler, server)
```

This protocol class tells Pyvider how to register your service with the gRPC server.

## Evolution and Backward Compatibility

When evolving your protocol over time, follow these guidelines to maintain backward compatibility:

1. **Add New Fields**: You can always add new fields to messages.
2. **Never Delete Fields**: Mark them as reserved instead.
3. **Never Change Field Types**: This can break existing code.
4. **Never Change Field Numbers**: Each field has a unique number that must be preserved.
5. **Add New Methods**: You can add new methods to services without breaking existing clients.

```protobuf
// Original version
message User {
  string name = 1;
  string email = 2;
}

// Evolved version
message User {
  string name = 1;
  string email = 2;
  string phone = 3;           // New field added
  reserved 4;                 // Field was added and then removed
  reserved "old_field";       // Field name that should never be reused
}
```

Think of your protocol as a contract with past and future versions of your software—changes should be additive and considerate of existing implementations.

## Best Practices

1. **Keep It Simple**: Design services with clear, focused responsibilities.
2. **Use Descriptive Names**: Service and method names should clearly indicate their purpose.
3. **Document Everything**: Add comments to explain complex fields or usage patterns.
4. **Plan for Versioning**: Structure your protocol to allow for future expansion.
5. **Consider Performance**: Be mindful of message size and complexity.
6. **Test with Mock Services**: Test your protocol with mock implementations before full deployment.

## Next Steps

Now that you understand how to define your protocol, you might want to explore:

- [Server Implementation](server-implementation.md) to implement your service
- [Client Implementation](client-implementation.md) to connect to your service
- [Application Integration](application-integration.md) to integrate plugins into your application
