# Basic Client Setup

Learn the fundamentals of creating and configuring plugin clients with comprehensive examples and best practices.

## Minimal Client

```python
import asyncio
from pyvider.rpcplugin import plugin_client

async def main():
    # Simple client with automatic lifecycle management
    async with plugin_client(command=["python", "calculator.py"]) as client:
        result = await client.calculator.Add(a=5, b=3)
        print(f"Result: {result.result}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Manual Client Lifecycle

```python
import asyncio
from pyvider.rpcplugin import plugin_client

async def manual_client_example():
    """Example of manual client lifecycle management."""
    
    # Create client (no connection yet)
    client = plugin_client(command=["python", "calculator.py"])
    
    try:
        # Start connection manually
        await client.start()
        print(" Client connected")
        
        # Use client
        result = await client.calculator.Add(a=10, b=5)
        print(f"Calculation: {result.result}")
        
    finally:
        # Always close client
        await client.close()
        print("= Client disconnected")

# Usage
await manual_client_example()
```

## Client Configuration

```python
from pyvider.rpcplugin import plugin_client

# Basic configuration
client = plugin_client(
    command=["python", "my_plugin.py"],
    timeout=30.0,                    # Connection timeout
    max_retries=3,                   # Retry attempts
    compression="gzip",              # Enable compression
    max_message_size=4*1024*1024     # 4MB max message size
)

# Transport-specific configuration
client = plugin_client(
    command=["python", "my_plugin.py"],
    transport="tcp",                 # Force TCP transport
    tcp_host="127.0.0.1",           # TCP host
    tcp_port=8080,                  # Specific TCP port
    enable_mtls=True,               # Enable mTLS security
    client_cert="client.pem",       # Client certificate
    client_key="client.key"         # Client private key
)
```

## Environment Configuration

```python
import os
from pyvider.rpcplugin import plugin_client

# Configure via environment variables
os.environ.update({
    "PLUGIN_CLIENT_TIMEOUT": "60.0",
    "PLUGIN_CLIENT_MAX_RETRIES": "5",
    "PLUGIN_CLIENT_TRANSPORT": "unix",
    "PLUGIN_CLIENT_COMPRESSION": "gzip"
})

# Client picks up environment configuration
client = plugin_client(command=["python", "my_plugin.py"])
```

## Error Handling

```python
import grpc
from pyvider.rpcplugin.exception import RPCPluginError, TransportError

async def robust_client():
    try:
        async with plugin_client(command=["python", "plugin.py"]) as client:
            result = await client.service.Method(param="value")
            return result
            
    except TransportError as e:
        print(f"Connection failed: {e.message}")
        # Handle connection issues
        
    except grpc.aio.AioRpcError as e:
        if e.code() == grpc.StatusCode.UNAVAILABLE:
            print("Service unavailable")
        else:
            print(f"RPC error: {e.code()} - {e.details()}")
    
    except RPCPluginError as e:
        print(f"Plugin error: {e.message}")
        if e.hint:
            print(f"Hint: {e.hint}")
```

## Service Discovery

```python
async def explore_services():
    async with plugin_client(command=["python", "multi_service.py"]) as client:
        # List available services
        services = client.get_available_services()
        print(f"Available services: {services}")
        
        # Check if specific service exists
        if client.has_service("calculator.Calculator"):
            result = await client.calculator.Add(a=1, b=2)
            print(f"Calculator result: {result.result}")
        
        # Get service methods
        if hasattr(client, 'calculator'):
            methods = client.calculator.get_available_methods()
            print(f"Calculator methods: {methods}")
```

## Development vs Production

### Development Setup
```python
def create_dev_client(command):
    return plugin_client(
        command=command,
        timeout=120.0,      # Long timeout for debugging
        max_retries=1,      # Fewer retries for faster failure
        enable_logging=True, # Detailed logging
        transport="tcp"     # Easier to debug than Unix sockets
    )
```

### Production Setup
```python
def create_prod_client(command):
    return plugin_client(
        command=command,
        timeout=30.0,       # Standard timeout
        max_retries=3,      # Reasonable retry count
        compression="gzip", # Enable compression
        transport="unix",   # Best performance
        enable_mtls=True,   # Security required
        max_message_size=10*1024*1024,  # 10MB limit
        keepalive_time=30.0 # Connection keepalive
    )
```

## Multiple Clients

```python
async def multiple_clients_example():
    """Example of using multiple clients concurrently."""
    
    # Create clients for different services
    calc_client = plugin_client(command=["python", "calculator.py"])
    file_client = plugin_client(command=["python", "file_service.py"])
    
    try:
        # Start all clients
        await calc_client.start()
        await file_client.start()
        
        # Use clients concurrently
        calc_task = calc_client.calculator.Add(a=5, b=3)
        file_task = file_client.file_manager.ListFiles(path="/tmp")
        
        # Wait for both operations
        calc_result, file_result = await asyncio.gather(calc_task, file_task)
        
        print(f"Calculation: {calc_result.result}")
        print(f"Files: {len(file_result.files)}")
        
    finally:
        # Close all clients
        await calc_client.close()
        await file_client.close()
```

## Client Factory Pattern

```python
from typing import Any
from dataclasses import dataclass

@dataclass
class ClientFactory:
    """Factory for creating configured clients."""
    
    default_timeout: float = 30.0
    default_retries: int = 3
    enable_compression: bool = True
    
    def create_client(self, command: list[str], **overrides) -> plugin_client:
        """Create client with factory defaults."""
        config = {
            "command": command,
            "timeout": self.default_timeout,
            "max_retries": self.default_retries,
            "compression": "gzip" if self.enable_compression else None
        }
        
        # Apply overrides
        config.update(overrides)
        
        return plugin_client(**config)
    
    def create_calculator_client(self):
        return self.create_client(["python", "calculator.py"])
    
    def create_file_client(self):
        return self.create_client(
            ["python", "file_service.py"],
            max_message_size=50*1024*1024  # Large files
        )
    
    def create_secure_client(self, command: list[str]):
        return self.create_client(
            command,
            enable_mtls=True,
            client_cert="client.pem",
            client_key="client.key"
        )

# Usage
factory = ClientFactory()
client = factory.create_calculator_client()
```

## Testing Clients

```python
import pytest
from unittest.mock import Mock, patch

@pytest.mark.asyncio
async def test_client_basic_connection():
    """Test basic client connection."""
    with patch('subprocess.Popen') as mock_popen:
        mock_popen.return_value.communicate.return_value = (b"", b"")
        
        async with plugin_client(command=["echo", "test"]) as client:
            # Client should be connected
            assert client.is_connected()

@pytest.mark.asyncio 
async def test_client_rpc_call():
    """Test RPC call through client."""
    # This would require a test plugin server
    async with plugin_client(command=["python", "test_plugin.py"]) as client:
        response = await client.echo.Echo(message="test")
        assert response.message == "Echo: test"

@pytest.mark.asyncio
async def test_client_error_handling():
    """Test client error handling."""
    with pytest.raises(TransportError):
        async with plugin_client(command=["nonexistent_command"]) as client:
            pass
```

## Next Steps

- **[Connection Management](connections.md)** - Master connection lifecycle
- **[Direct Connections](direct-connections.md)** - Connect to existing servers  
- **[Retry Logic](retry-logic.md)** - Build resilient clients