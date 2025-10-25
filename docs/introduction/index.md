# Introduction to Pyvider RPC Plugin

**Path:** [Home](../index.md) → Introduction

## What is Pyvider RPC Plugin?

Pyvider RPC Plugin is an enterprise-grade RPC framework for building plugin systems in Python. It enables you to create high-performance, type-safe plugin architectures where plugins run as separate processes and communicate via gRPC.

## Key Concepts

### Plugin Architecture

In a plugin system:
- **Host Application**: Your main program that orchestrates plugins
- **Plugins**: Separate processes that provide specific functionality
- **RPC Communication**: Type-safe, high-performance communication between host and plugins

```
┌──────────────────┐         RPC          ┌──────────────────┐
│                  │◄──────────────────────►│                  │
│  Host Application│                        │     Plugin 1     │
│                  │◄──────────────────────►│                  │
└──────────────────┘         RPC          └──────────────────┘
         │                                           
         │                  RPC          ┌──────────────────┐
         └──────────────────────────────►│     Plugin 2     │
                                         └──────────────────┘
```

### Why Use Plugins?

**Process Isolation**: Plugins run in separate processes, preventing crashes from affecting the host

**Language Flexibility**: Write plugins in any language that supports gRPC

**Hot Reloading**: Update plugins without restarting the host application

**Security**: Plugins can run with different permissions than the host

**Scalability**: Distribute plugins across machines for horizontal scaling

## Core Features

### 🚀 Performance
- **Async-native**: Built on asyncio for maximum concurrency
- **Efficient Transports**: Unix domain sockets for local, TCP for network
- **Protocol Buffers**: Binary serialization for speed and size

### 🔒 Security
- **mTLS Support**: Mutual TLS authentication built-in
- **Process Isolation**: Plugins can't crash the host
- **Magic Cookies**: Handshake authentication for trusted connections

### 🛠️ Developer Experience
- **Type Safety**: Full type hints and IDE support
- **Foundation Integration**: Enterprise infrastructure included
- **Simple API**: `plugin_server()` and `plugin_client()` functions

### 🏗️ Production Ready
- **Health Checks**: gRPC health checking protocol
- **Rate Limiting**: Token bucket rate limiting
- **Structured Logging**: Foundation's logging system
- **Configuration**: Environment-based configuration

## How It Works

### 1. Define Your Service

Create a Protocol Buffer definition:

```protobuf
service MyService {
    rpc ProcessData(Request) returns (Response);
}
```

### 2. Implement the Server

```python
from pyvider.rpcplugin import plugin_server

class MyHandler:
    async def ProcessData(self, request, context):
        # Your business logic
        return Response(result="processed")

server = plugin_server(
    protocol=MyProtocol(),
    handler=MyHandler()
)
await server.serve()
```

### 3. Connect from Client

```python
from pyvider.rpcplugin import plugin_client

# Client automatically launches and manages plugin
async with plugin_client(command=["python", "plugin.py"]) as client:
    response = await client.ProcessData(request)
```

## Foundation Infrastructure

Pyvider RPC Plugin is built on [Foundation](foundation.md), which provides:

- **Configuration Management**: Type-safe, validated configuration
- **Structured Logging**: Consistent logging across all components
- **Cryptography**: Certificate management for mTLS
- **Rate Limiting**: Protect services from overload
- **Error Handling**: Consistent error patterns

This means you get enterprise-grade infrastructure automatically, without additional dependencies or configuration.

## Use Cases

### Microservices
Build service-oriented architectures with independent, scalable services.

### Data Processing Pipelines
Create modular data processing with specialized plugins for each stage.

### Extension Systems
Add plugin support to existing applications without major refactoring.

### Multi-Language Systems
Combine Python host applications with plugins written in Go, Rust, or other languages.

### Security-Sensitive Applications
Isolate untrusted code in separate processes with limited permissions.

## Comparison with Alternatives

| Feature | Pyvider RPC Plugin | REST APIs | Direct Import | Subprocess |
|---------|-------------------|-----------|---------------|------------|
| Type Safety | ✅ Full | ⚠️ Limited | ✅ Full | ❌ None |
| Performance | ✅ High | ⚠️ Medium | ✅ Highest | ⚠️ Medium |
| Process Isolation | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes |
| Cross-Language | ✅ Yes | ✅ Yes | ❌ No | ⚠️ Limited |
| Hot Reload | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes |
| Complexity | ⚠️ Medium | ⚠️ Medium | ✅ Low | ❌ High |

## Learning Path

1. **[Foundation Overview](foundation.md)** - Understand the infrastructure layer
2. **[Architecture](../development/architecture.md)** - Learn the system design
3. **[Getting Started](../getting-started/index.md)** - Build your first plugin
4. **[User Guide](../guide/index.md)** - Deep dive into features
5. **[API Reference](../reference/index.md)** - Detailed documentation

## Quick Example

Here's a complete working example to get you started:

```python
# server.py
import asyncio
from pyvider.rpcplugin import plugin_server, plugin_protocol

class EchoHandler:
    async def Echo(self, request, context):
        return {"message": f"Echo: {request.message}"}

async def main():
    server = plugin_server(
        protocol=plugin_protocol("EchoService"),
        handler=EchoHandler()
    )
    await server.serve()

asyncio.run(main())
```

```python
# client.py
import asyncio
from pyvider.rpcplugin import plugin_client

async def main():
    async with plugin_client(command=["python", "server.py"]) as client:
        response = await client.Echo(message="Hello!")
        print(response.message)  # "Echo: Hello!"

asyncio.run(main())
```

## Next Steps

Ready to dive deeper? Choose your path:

- **Understand the infrastructure**: Continue to [Foundation Overview](foundation.md)
- **Learn the architecture**: Jump to [Architecture](../development/architecture.md)
- **Start building**: Go to [Getting Started](../getting-started/index.md)

---

**Navigation:** [Home](../index.md) | [Next: Foundation](foundation.md)