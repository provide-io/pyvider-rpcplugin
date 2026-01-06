# Simple Custom RPC (Without Protocol Buffers)

This intermediate tutorial bridges the gap between the [Quick Start](quick-start.md) and the full [Protocol Buffers Plugin](first-plugin.md). Learn how to create custom RPC methods using plain Python before diving into protobuf complexity.

!!! info "Conceptual Tutorial"
    This is a **conceptual tutorial** designed to teach the principles of RPC plugin development. The example files referenced (`processor_service.py`, `simple_protocol.py`, `simple_server.py`, `simple_client.py`) are **not included in the examples/ directory**.

    **You can:**
    - Create these files yourself as a learning exercise
    - Use them as templates for your own custom RPC services
    - Skip to the [Echo Service Example](../examples/echo-example.md) for a complete, runnable example using Protocol Buffers

    **For working examples**, see:
    - [Echo Service](../examples/echo-example.md) - Complete RPC service with Protocol Buffers
    - [Examples Overview](../examples/index.md) - All runnable examples

**Navigation:** [Home](../index.md) → [Getting Started](index.md) → Simple Custom RPC

## What You'll Learn

- Create custom RPC methods without Protocol Buffers
- Use Python dataclasses for type-safe messages
- Understand the plugin protocol abstraction
- Prepare for Protocol Buffers implementation

## Prerequisites

- Completed [Quick Start](quick-start.md)
- Basic understanding of async Python
- Pyvider RPC Plugin installed

## Simple Data Processing Service

Let's build a data processing service using plain Python:

### Step 1: Define Your Service

Create `processor_service.py`:

```python
from dataclasses import dataclass
from typing import Any
from provide.foundation import logger

@dataclass
class ProcessRequest:
    """Request to process data."""
    data: str
    operation: str = "uppercase"

@dataclass  
class ProcessResponse:
    """Response with processed data."""
    result: str
    operation_applied: str
    success: bool = True

class DataProcessor:
    """Simple data processing service."""
    
    async def process(self, request: ProcessRequest) -> ProcessResponse:
        """Process data based on operation."""
        logger.info(f"Processing: {request.operation} on {len(request.data)} chars")
        
        try:
            if request.operation == "uppercase":
                result = request.data.upper()
            elif request.operation == "lowercase":
                result = request.data.lower()
            elif request.operation == "reverse":
                result = request.data[::-1]
            else:
                return ProcessResponse(
                    result="",
                    operation_applied=request.operation,
                    success=False
                )
            
            return ProcessResponse(
                result=result,
                operation_applied=request.operation,
                success=True
            )
            
        except Exception as e:
            logger.error(f"Processing failed: {e}")
            return ProcessResponse(
                result="",
                operation_applied=request.operation,
                success=False
            )
```

### Step 2: Create the Protocol Bridge

Create `simple_protocol.py`:

```python
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from typing import Any

class SimpleProtocol(RPCPluginProtocol):
    """Protocol bridge for simple Python RPC."""
    
    def __init__(self, service_name: str = "DataProcessor"):
        self.service_name = service_name
        self.handler = None
    
    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        """Return service descriptors (not using gRPC yet)."""
        # This would return actual gRPC descriptors in a real implementation
        return None, self.service_name
    
    async def add_to_server(self, server: Any, handler: Any) -> None:
        """Register handler with server."""
        self.handler = handler
        # In a real implementation, this would register with gRPC server
        logger.info(f"Registered {self.service_name} handler")
    
    async def call_method(self, method_name: str, request: Any) -> Any:
        """Route method calls to handler."""
        if hasattr(self.handler, method_name):
            method = getattr(self.handler, method_name)
            return await method(request)
        else:
            raise AttributeError(f"Method {method_name} not found")
```

### Step 3: Create the Server

Create `simple_server.py`:

```python
import asyncio
from pyvider.rpcplugin import plugin_server, configure
from provide.foundation import logger

# Import our service components
from processor_service import DataProcessor
from simple_protocol import SimpleProtocol

async def main():
    """Run the simple RPC server."""
    
    # Configure the plugin environment
    configure(
        magic_cookie="simple-processor",
        auto_mtls=False,  # Start simple, add security later
        handshake_timeout=10.0
    )
    
    # Create protocol and handler
    protocol = SimpleProtocol(service_name="DataProcessor")
    handler = DataProcessor()
    
    # Create and start server
    logger.info("Starting Simple RPC Server")
    server = plugin_server(
        protocol=protocol,
        handler=handler
    )
    
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
```

### Step 4: Create the Client

Create `simple_client.py`:

```python
import asyncio
import sys
from pathlib import Path
from pyvider.rpcplugin import plugin_client, configure
from provide.foundation import logger

# Import message types
from processor_service import ProcessRequest, ProcessResponse

async def main():
    """Connect to simple RPC server."""
    
    # Configure client
    configure(
        magic_cookie="simple-processor",
        handshake_timeout=10.0
    )
    
    # Define plugin command
    plugin_path = Path(__file__).parent / "simple_server.py"
    plugin_command = [sys.executable, str(plugin_path)]
    
    # Connect to plugin
    async with plugin_client(command=plugin_command) as client:
        logger.info("Connected to Simple RPC Server")
        
        # Make RPC calls using dataclasses
        operations = [
            ProcessRequest(data="Hello World", operation="uppercase"),
            ProcessRequest(data="PYTHON RPC", operation="lowercase"),
            ProcessRequest(data="Reverse Me", operation="reverse")
        ]
        
        for request in operations:
            # In real implementation, this would use gRPC channel
            # For now, we're demonstrating the pattern
            response = await client.protocol.call_method("process", request)
            
            logger.info(f"Request: {request.operation}('{request.data}')")
            logger.info(f"Response: '{response.result}' (success={response.success})")

if __name__ == "__main__":
    asyncio.run(main())
```

## Understanding the Bridge to Protocol Buffers

This simple example demonstrates the core concepts without Protocol Buffer complexity:

1. **Service Definition**: Your business logic in `DataProcessor`
2. **Message Types**: Using dataclasses instead of protobuf messages
3. **Protocol Bridge**: `SimpleProtocol` connects your service to the RPC framework
4. **Type Safety**: Python type hints provide IDE support and clarity

## Next Steps: Adding Protocol Buffers

When you're ready for production-grade RPC with cross-language support:

1. **Define `.proto` file**: Replace dataclasses with protobuf definitions
2. **Generate Python code**: Use `grpc_tools.protoc` to generate message classes
3. **Implement gRPC servicer**: Replace simple handler with gRPC servicer
4. **Use gRPC channel**: Replace simple calls with proper gRPC stubs

The structure remains the same - Protocol Buffers just add:
- Binary serialization for efficiency
- Cross-language compatibility
- Strict schema validation
- Streaming support

## Key Takeaways

- You can start with simple Python classes before learning Protocol Buffers
- The plugin architecture separates concerns: service, protocol, transport
- Foundation provides logging, configuration, and infrastructure automatically
- Type hints and dataclasses provide type safety without protobuf complexity

**Ready for Protocol Buffers?** Continue to [Build Your First Plugin](first-plugin.md)

---

**Navigation:** [Previous: Quick Start](quick-start.md) | [Next: First Plugin](first-plugin.md)