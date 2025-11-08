# Client Development

Master building robust plugin clients with Pyvider RPC Plugin. Learn connection management, error handling, retry logic, and advanced client patterns for production applications.

## Overview

Plugin clients connect to and communicate with plugin servers through secure, high-performance gRPC channels. The framework handles transport negotiation, authentication, service discovery, and connection lifecycle management.

## Quick Client Example

Here's a minimal plugin client to get you started:

```python
import asyncio
from pyvider.rpcplugin import plugin_client

async def main():
    # Connect to plugin server
    async with plugin_client(command=["python", "my_plugin.py"]) as client:
        # Server starts automatically and performs handshake
        
        # Call RPC methods through automatic service discovery
        response = await client.calculator.Add(a=5, b=3)
        print(f"Result: {response.result}")  # Result: 8
        
        # Multiple calls reuse the same connection
        response2 = await client.calculator.Multiply(a=4, b=7)
        print(f"Result: {response2.result}")  # Result: 28

if __name__ == "__main__":
    asyncio.run(main())
```

## Client Architecture

### Core Components

The plugin client consists of several integrated components:

```
┌─────────────────────────────────────────────────────────────────┐
│ Plugin Client                                                   │
│                                                                 │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │ Service         │ │ Connection      │ │ Process         │   │
│  │ Discovery       │ │ Management      │ │ Management      │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
│                                                                 │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐   │
│  │ gRPC Channel    │ │ Authentication  │ │ Error Handling  │   │
│  │ Management      │ │ & Security      │ │ & Retry Logic   │   │
│  └─────────────────┘ └─────────────────┘ └─────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Client Lifecycle

Understanding the client lifecycle helps with proper resource management:

1. **Process Launch** - Start plugin server subprocess
2. **Transport Discovery** - Negotiate optimal transport (Unix/TCP)
3. **Authentication** - Magic cookie validation and mTLS handshake
4. **Service Discovery** - Discover available gRPC services
5. **Channel Ready** - gRPC channel established for RPC calls
6. **Active Communication** - Normal RPC operations
7. **Graceful Shutdown** - Clean process termination and resource cleanup

```python
class ClientLifecycleExample:
    async def demonstrate_lifecycle(self):
        """Demonstrate complete client lifecycle."""
        
        # 1. Create client (no connection yet)
        client = plugin_client(command=["python", "calculator_plugin.py"])
        
        try:
            # 2. Start connection (launches process, performs handshake)
            await client.start()
            print("✅ Client connected and authenticated")
            
            # 3. Service discovery happens automatically
            available_services = client.get_available_services()
            print(f"📋 Available services: {available_services}")
            
            # 4. Make RPC calls
            result = await client.calculator.Add(a=10, b=5)
            print(f"🔢 Calculation result: {result.result}")
            
            # 5. Connection remains active for multiple calls
            for i in range(5):
                result = await client.calculator.Multiply(a=i, b=2)
                print(f"   {i} * 2 = {result.result}")
        
        finally:
            # 6. Clean shutdown
            await client.close()
            print("🔌 Client disconnected and process terminated")

# Usage
lifecycle_demo = ClientLifecycleExample()
await lifecycle_demo.demonstrate_lifecycle()
```

## Client Development Sections

### 📝 [Basic Client Setup](basic-setup/)
Learn the fundamentals of creating and configuring plugin clients:
- Client initialization and configuration
- Environment setup and validation
- Basic error handling patterns
- Development vs production setup

### 🔗 [Connection Management](connections/)
Master connection lifecycle and management:
- Connection establishment and teardown
- Connection pooling and reuse
- Health monitoring and reconnection
- Concurrent connection handling

### 🎯 [Direct Connections](direct-connections/)
Connect to existing plugin processes:
- Direct TCP/Unix socket connections
- Service registry integration
- Load balancing across multiple servers
- Connection discovery patterns

### 🔄 [Retry Logic](retry-logic/)
Implement resilient error handling and retry patterns:
- Exponential backoff retry strategies
- Circuit breaker patterns
- Timeout management
- Graceful degradation

## Service Discovery and Method Calling

### Automatic Service Discovery

The client automatically discovers available services during connection:

```python
async def explore_service_discovery():
    async with plugin_client(command=["python", "multi_service_plugin.py"]) as client:
        # Services are automatically available as attributes
        
        # List all available services
        services = client.get_available_services()
        print(f"Available services: {services}")
        # Output: ['calculator.Calculator', 'file.FileManager', 'health.Health']
        
        # Access services directly
        calc_result = await client.calculator.Add(a=1, b=2)
        file_info = await client.file_manager.GetFileInfo(path="/tmp/test.txt")
        health_status = await client.health.Check(service="")
        
        # Inspect service methods
        calc_methods = client.calculator.get_available_methods()
        print(f"Calculator methods: {calc_methods}")
        # Output: ['Add', 'Subtract', 'Multiply', 'Divide']
```

### Dynamic Service Access

For dynamic service access, use the service registry:

```python
async def dynamic_service_access():
    async with plugin_client(command=["python", "plugin.py"]) as client:
        # Get service by name
        service_name = "calculator.Calculator"
        if client.has_service(service_name):
            calc_service = client.get_service(service_name)
            result = await calc_service.Add(a=5, b=3)
        
        # Iterate through all services
        for service_name in client.get_available_services():
            service = client.get_service(service_name)
            methods = service.get_available_methods()
            print(f"Service {service_name} has methods: {methods}")
        
        # Call methods dynamically
        method_name = "Add"
        if client.calculator.has_method(method_name):
            result = await client.calculator.call_method(method_name, a=10, b=20)
            print(f"Dynamic call result: {result.result}")
```

## Error Handling and Resilience

### Comprehensive Error Handling

```python
import grpc
from pyvider.rpcplugin.exception import (
    RPCPluginError, TransportError, HandshakeError, 
    ProtocolError, SecurityError
)

async def robust_client_example():
    """Example of robust client with comprehensive error handling."""
    
    try:
        async with plugin_client(
            command=["python", "unreliable_plugin.py"],
            timeout=30.0,
            max_retries=3
        ) as client:
            
            # RPC call with specific error handling
            result = await client.calculator.Divide(a=10, b=0)
            
    except HandshakeError as e:
        print(f"🤝 Authentication failed: {e.message}")
        # Handle authentication issues
        
    except TransportError as e:
        print(f"🌐 Connection failed: {e.message}")
        # Handle network/transport issues
        
    except grpc.aio.AioRpcError as e:
        if e.code() == grpc.StatusCode.INVALID_ARGUMENT:
            print(f"❌ Invalid request: {e.details()}")
        elif e.code() == grpc.StatusCode.UNAVAILABLE:
            print(f"🔄 Service unavailable: {e.details()}")
        else:
            print(f"🚨 RPC error: {e.code()} - {e.details()}")
    
    except RPCPluginError as e:
        print(f"🔌 Plugin error: {e.message}")
        if e.hint:
            print(f"💡 Hint: {e.hint}")
    
    except Exception as e:
        print(f"💥 Unexpected error: {e}")

# Usage
await robust_client_example()
```

### Retry with Circuit Breaker

```python
import asyncio
import time
from typing import Callable, TypeVar, Any

T = TypeVar('T')

class CircuitBreakerClient:
    """Client with built-in circuit breaker pattern."""
    
    def __init__(self, command: list[str], failure_threshold: int = 3):
        self.command = command
        self.failure_threshold = failure_threshold
        self.failure_count = 0
        self.last_failure_time = 0
        self.circuit_open = False
        self.recovery_timeout = 60.0  # 60 seconds
        
    async def call_with_circuit_breaker(self, operation: Callable[[], T]) -> T:
        """Execute operation with circuit breaker protection."""
        
        # Check if circuit is open
        if self.circuit_open:
            if time.time() - self.last_failure_time < self.recovery_timeout:
                raise Exception("Circuit breaker is OPEN - requests blocked")
            else:
                # Try to close circuit
                self.circuit_open = False
                self.failure_count = 0
        
        try:
            # Execute operation
            result = await operation()
            
            # Reset failure count on success
            self.failure_count = 0
            return result
            
        except Exception as e:
            # Record failure
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            # Open circuit if threshold exceeded
            if self.failure_count >= self.failure_threshold:
                self.circuit_open = True
                print(f"🚫 Circuit breaker OPENED after {self.failure_count} failures")
            
            raise e
    
    async def reliable_rpc_call(self, service_method: str, **kwargs) -> Any:
        """Make RPC call with circuit breaker protection."""
        
        async def rpc_operation():
            async with plugin_client(command=self.command) as client:
                # Parse service and method
                service_name, method_name = service_method.split('.')
                service = getattr(client, service_name.lower())
                method = getattr(service, method_name)
                
                return await method(**kwargs)
        
        return await self.call_with_circuit_breaker(rpc_operation)

# Usage
circuit_client = CircuitBreakerClient(["python", "flaky_plugin.py"])

try:
    result = await circuit_client.reliable_rpc_call(
        "calculator.Add", 
        a=5, b=3
    )
    print(f"Result: {result.result}")
except Exception as e:
    print(f"Call failed: {e}")
```

## Concurrent Client Operations

### Multiple Concurrent Calls

```python
import asyncio
from typing import List, Dict, Any

async def concurrent_client_calls():
    """Demonstrate concurrent RPC calls from single client."""
    
    async with plugin_client(command=["python", "calculator.py"]) as client:
        # Create multiple concurrent operations
        tasks = [
            client.calculator.Add(a=i, b=i*2)
            for i in range(10)
        ]
        
        # Execute all calls concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"Call {i} failed: {result}")
            else:
                print(f"Call {i}: {i} + {i*2} = {result.result}")

async def batch_processing_client():
    """Process multiple items in batches with concurrent calls."""
    
    async with plugin_client(command=["python", "processor.py"]) as client:
        # Prepare batch data
        items = [f"item_{i}" for i in range(100)]
        batch_size = 10
        
        # Process in batches
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            
            # Create concurrent tasks for batch
            batch_tasks = [
                client.processor.ProcessItem(data=item)
                for item in batch
            ]
            
            # Execute batch concurrently
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            # Handle batch results
            successful = sum(1 for r in batch_results if not isinstance(r, Exception))
            failed = len(batch_results) - successful
            
            print(f"Batch {i//batch_size + 1}: {successful} successful, {failed} failed")

# Usage
await concurrent_client_calls()
await batch_processing_client()
```

### Connection Pool Management

```python
import asyncio
from typing import Optional
from contextlib import asynccontextmanager

class ClientPool:
    """Pool of plugin clients for high-throughput scenarios."""
    
    def __init__(self, command: list[str], pool_size: int = 5):
        self.command = command
        self.pool_size = pool_size
        self.pool = asyncio.Queue(maxsize=pool_size)
        self.active_clients = 0
        
    async def initialize(self):
        """Initialize the client pool."""
        for _ in range(self.pool_size):
            client = plugin_client(command=self.command)
            await client.start()
            await self.pool.put(client)
            self.active_clients += 1
    
    @asynccontextmanager
    async def acquire_client(self):
        """Acquire a client from the pool."""
        client = await self.pool.get()
        try:
            yield client
        finally:
            await self.pool.put(client)
    
    async def close_all(self):
        """Close all clients in the pool."""
        clients = []
        while not self.pool.empty():
            try:
                client = self.pool.get_nowait()
                clients.append(client)
            except asyncio.QueueEmpty:
                break
        
        # Close all clients
        for client in clients:
            await client.close()
        
        self.active_clients = 0

# Usage with high-throughput operations
async def high_throughput_example():
    """Example of high-throughput client operations."""
    
    pool = ClientPool(["python", "fast_processor.py"], pool_size=10)
    await pool.initialize()
    
    try:
        # Process many requests concurrently using pool
        async def process_request(request_id: int):
            async with pool.acquire_client() as client:
                return await client.processor.FastProcess(
                    request_id=request_id,
                    data=f"request_{request_id}"
                )
        
        # Launch 100 concurrent requests
        tasks = [process_request(i) for i in range(100)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Analyze results
        successful = sum(1 for r in results if not isinstance(r, Exception))
        print(f"Processed {successful}/100 requests successfully")
        
    finally:
        await pool.close_all()

# Usage
await high_throughput_example()
```

## Configuration and Best Practices

### Environment-Based Client Configuration

```python
import os
from dataclasses import dataclass

@dataclass
class ClientConfig:
    """Client configuration from environment."""
    
    # Connection settings
    command: list[str] = None
    timeout: float = float(os.environ.get("PLUGIN_CLIENT_TIMEOUT", "30.0"))
    max_retries: int = int(os.environ.get("PLUGIN_CLIENT_MAX_RETRIES", "3"))
    
    # Transport preferences
    preferred_transport: str = os.environ.get("PLUGIN_CLIENT_TRANSPORT", "auto")
    tcp_host: str = os.environ.get("PLUGIN_CLIENT_TCP_HOST", "127.0.0.1")
    tcp_port: int = int(os.environ.get("PLUGIN_CLIENT_TCP_PORT", "0"))
    
    # Security settings
    enable_mtls: bool = os.environ.get("PLUGIN_CLIENT_ENABLE_MTLS", "false").lower() == "true"
    client_cert: str | None = os.environ.get("PLUGIN_CLIENT_CERT")
    client_key: str | None = os.environ.get("PLUGIN_CLIENT_KEY")
    
    # Performance settings
    compression: str = os.environ.get("PLUGIN_CLIENT_COMPRESSION", "gzip")
    max_message_size: int = int(os.environ.get("PLUGIN_CLIENT_MAX_MESSAGE_SIZE", str(4*1024*1024)))
    
    def create_client(self, command: list[str] = None):
        """Create configured plugin client."""
        cmd = command or self.command
        if not cmd:
            raise ValueError("Command must be specified")
        
        client_kwargs = {
            "command": cmd,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "compression": self.compression,
            "max_message_size": self.max_message_size
        }
        
        # Add transport preferences
        if self.preferred_transport != "auto":
            client_kwargs["transport"] = self.preferred_transport
        
        # Add security settings
        if self.enable_mtls and self.client_cert and self.client_key:
            client_kwargs.update({
                "enable_mtls": True,
                "client_cert": self.client_cert,
                "client_key": self.client_key
            })
        
        return plugin_client(**client_kwargs)

# Usage
config = ClientConfig()
client = config.create_client(["python", "my_plugin.py"])
```

## Next Steps

Ready to dive deeper into client development? Choose your path:

1. **New to Plugin Clients?** Start with [Basic Client Setup](basic-setup/)
2. **Need Connection Management?** Check out [Connection Management](connections/)  
3. **Working with Existing Servers?** Explore [Direct Connections](direct-connections/)
4. **Building Resilient Clients?** Review [Retry Logic](retry-logic/)

Each section provides practical examples, error handling patterns, and production-ready implementations for building robust plugin clients.