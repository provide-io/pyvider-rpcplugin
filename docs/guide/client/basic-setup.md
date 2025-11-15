# Basic Client Setup

Learn the fundamentals of creating and configuring plugin clients with comprehensive examples and best practices.

## Minimal Client

!!! note "Using gRPC Stubs"
    The client provides a `grpc_channel` for making RPC calls.
    You must use generated gRPC stubs - the client doesn't provide automatic service proxies.

```python
import asyncio
from pyvider.rpcplugin import plugin_client
# Import generated gRPC stub
from calculator_pb2_grpc import CalculatorStub
from calculator_pb2 import AddRequest

async def main():
    # Simple client with automatic lifecycle management
    async with plugin_client(command=["python", "calculator.py"]) as client:
        await client.start()

        # Create gRPC stub from client's channel
        stub = CalculatorStub(client.grpc_channel)

        # Make RPC call using stub
        request = AddRequest(a=5, b=3)
        result = await stub.Add(request)
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
        
        # Create gRPC stub and use client
        from calculator_pb2_grpc import CalculatorStub
        from calculator_pb2 import AddRequest

        stub = CalculatorStub(client.grpc_channel)
        request = AddRequest(a=10, b=5)
        result = await stub.Add(request)
        print(f"Calculation: {result.result}")
        
    finally:
        # Always close client
        await client.close()
        print("= Client disconnected")

# Usage
await manual_client_example()
```

## Client Configuration

!!! important "Configuration Methods"
    The `plugin_client()` factory only accepts `command` and `config` parameters. The `config` dict is used to pass environment variables to the **plugin subprocess**, not to configure the client itself.

    **Configuration Flow:**
    ```
    ┌─────────────────────────────┐        ┌─────────────────────────────┐
    │   Your Process (Client)     │        │  Plugin Subprocess (Server) │
    ├─────────────────────────────┤        ├─────────────────────────────┤
    │ Set environment variables:  │        │ Receives environment vars:  │
    │ - os.environ["PLUGIN_..."]  │        │ - From config={"env": ...}  │
    │ - PLUGIN_CLIENT_MAX_RETRIES │        │ - PLUGIN_LOG_LEVEL          │
    │ - PLUGIN_CONNECTION_TIMEOUT │        │ - PLUGIN_AUTO_MTLS          │
    │                             │        │ - PLUGIN_SERVER_PORT        │
    │ Configures CLIENT behavior  │  -->   │ Configures SERVER behavior  │
    └─────────────────────────────┘        └─────────────────────────────┘
    ```

    **To configure the CLIENT:** Set environment variables in your own process
    **To configure the PLUGIN:** Use `config={"env": {...}}`

### Configuring Client Behavior

Set environment variables in your process to configure client behavior:

```python
import os
from pyvider.rpcplugin import plugin_client

# Configure client retry behavior
os.environ["PLUGIN_CLIENT_MAX_RETRIES"] = "3"
os.environ["PLUGIN_CLIENT_RETRY_ENABLED"] = "true"
os.environ["PLUGIN_CONNECTION_TIMEOUT"] = "30.0"

# Configure transport preferences
os.environ["PLUGIN_CLIENT_TRANSPORTS"] = '["tcp", "unix"]'  # JSON list

# Configure gRPC message sizes
os.environ["PLUGIN_GRPC_MAX_RECEIVE_MESSAGE_SIZE"] = str(4*1024*1024)  # 4MB
os.environ["PLUGIN_GRPC_MAX_SEND_MESSAGE_SIZE"] = str(4*1024*1024)

# Configure client-side mTLS
os.environ["PLUGIN_CLIENT_CERT"] = "file:///path/to/client.crt"
os.environ["PLUGIN_CLIENT_KEY"] = "file:///path/to/client.key"

# Client automatically picks up these environment variables
client = plugin_client(command=["python", "my_plugin.py"])
```

### Configuring Plugin Subprocess

Use the `config` parameter to pass environment variables to the plugin:

```python
from pyvider.rpcplugin import plugin_client

# Pass environment variables to the plugin subprocess
client = plugin_client(
    command=["python", "my_plugin.py"],
    config={
        "env": {
            "PLUGIN_LOG_LEVEL": "DEBUG",
            "PLUGIN_AUTO_MTLS": "true",
            "MY_PLUGIN_API_KEY": "secret-key",
            "PLUGIN_SERVER_PORT": "8080",
        }
    }
)
```

## Error Handling

```python
import grpc
from pyvider.rpcplugin.exception import RPCPluginError, TransportError

async def robust_client() -> None:
    """Example of robust error handling in a client."""
    try:
        async with plugin_client(command=["python", "plugin.py"]) as client:
            await client.start()
            # Make RPC calls using gRPC stubs
            # stub = YourServiceStub(client.grpc_channel)
            # result = await stub.YourMethod(request)

    except TransportError as e:
        print(f"❌ Connection failed: {e.message}")
        # Handle connection issues

    except grpc.aio.AioRpcError as e:
        if e.code() == grpc.StatusCode.UNAVAILABLE:
            print("❌ Service unavailable")
        else:
            print(f"❌ RPC error: {e.code()} - {e.details()}")

    except RPCPluginError as e:
        print(f"❌ Plugin error: {e.message}")
        if e.hint:
            print(f"💡 Hint: {e.hint}")
```

## Service Discovery

!!! warning "Conceptual Example"
    The following example shows conceptual patterns for service discovery.
    In actual usage, you need to know your service's protocol definition
    and use the generated gRPC stubs directly.

```python
from calculator_pb2_grpc import CalculatorStub
from calculator_pb2 import AddRequest

async def explore_services():
    async with plugin_client(command=["python", "multi_service.py"]) as client:
        await client.start()

        # You must know which services are available
        # based on your .proto files and plugin implementation

        # Create stub for known service
        stub = CalculatorStub(client.grpc_channel)

        # Make RPC calls using the stub
        request = AddRequest(a=1, b=2)
        result = await stub.Add(request)
        print(f"Calculator result: {result.result}")

        # For multiple services, create multiple stubs
        # from file_pb2_grpc import FileServiceStub
        # file_stub = FileServiceStub(client.grpc_channel)
```

## Development vs Production

!!! important "Configuration Method"
    The `plugin_client()` factory only accepts `command` and `config` parameters.
    Configure client behavior via **environment variables** in your process.

    **Two-Level Configuration:**
    ```
    Host Process                Plugin Process
    ============                ==============
    os.environ["..."]    →      config={"env": {"..."}}
    (affects client)            (affects plugin server)
    ```

### Development Setup
```python
import os

def create_dev_client(command: list[str]):
    """Create client configured for development.

    Args:
        command: Command list to launch the plugin subprocess

    Returns:
        Configured RPCPluginClient instance
    """
    # Configure CLIENT behavior via environment variables
    os.environ["PLUGIN_CONNECTION_TIMEOUT"] = "120.0"  # Long timeout for debugging
    os.environ["PLUGIN_CLIENT_MAX_RETRIES"] = "1"  # Fewer retries
    os.environ["PLUGIN_LOG_LEVEL"] = "DEBUG"  # Detailed logging
    os.environ["PLUGIN_CLIENT_TRANSPORTS"] = '["tcp"]'  # TCP easier to debug

    # Pass environment to plugin subprocess
    return plugin_client(
        command=command,
        config={
            "env": {
                "PLUGIN_LOG_LEVEL": "DEBUG",
                "PLUGIN_AUTO_MTLS": "false",  # Disable mTLS for local dev
            }
        }
    )
```

### Production Setup
```python
import os

def create_prod_client(command: list[str]):
    """Create client configured for production.

    Args:
        command: Command list to launch the plugin subprocess

    Returns:
        Configured RPCPluginClient instance for production use
    """
    # Configure CLIENT behavior via environment variables
    os.environ["PLUGIN_CONNECTION_TIMEOUT"] = "30.0"
    os.environ["PLUGIN_CLIENT_MAX_RETRIES"] = "3"
    os.environ["PLUGIN_GRPC_MAX_RECEIVE_MESSAGE_SIZE"] = str(10*1024*1024)  # 10MB
    os.environ["PLUGIN_GRPC_MAX_SEND_MESSAGE_SIZE"] = str(10*1024*1024)
    os.environ["PLUGIN_GRPC_KEEPALIVE_TIME_MS"] = "30000"
    os.environ["PLUGIN_CLIENT_TRANSPORTS"] = '["unix", "tcp"]'  # Unix preferred

    # Configure CLIENT mTLS
    os.environ["PLUGIN_CLIENT_CERT"] = "file:///etc/plugin/client.crt"
    os.environ["PLUGIN_CLIENT_KEY"] = "file:///etc/plugin/client.key"

    # Pass environment to plugin subprocess
    return plugin_client(
        command=command,
        config={
            "env": {
                "PLUGIN_LOG_LEVEL": "INFO",
                "PLUGIN_AUTO_MTLS": "true",  # Enable mTLS for production
                "PLUGIN_RATE_LIMIT_ENABLED": "true",
            }
        }
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
import os
from dataclasses import dataclass
from pyvider.rpcplugin import plugin_client

@dataclass
class ClientFactory:
    """Factory for creating configured clients."""

    default_timeout: float = 30.0
    default_retries: int = 3
    log_level: str = "INFO"

    def _configure_client_environment(self):
        """Configure client behavior via environment variables."""
        os.environ["PLUGIN_CONNECTION_TIMEOUT"] = str(self.default_timeout)
        os.environ["PLUGIN_CLIENT_MAX_RETRIES"] = str(self.default_retries)
        os.environ["PLUGIN_LOG_LEVEL"] = self.log_level

    def create_client(
        self,
        command: list[str],
        plugin_env: dict[str, str] | None = None
    ) -> plugin_client:
        """Create client with factory defaults."""
        self._configure_client_environment()

        return plugin_client(
            command=command,
            config={"env": plugin_env or {}}
        )

    def create_calculator_client(self):
        return self.create_client(
            ["python", "calculator.py"],
            plugin_env={"PLUGIN_AUTO_MTLS": "false"}
        )

    def create_file_client(self):
        # Configure large message sizes for file transfers
        os.environ["PLUGIN_GRPC_MAX_RECEIVE_MESSAGE_SIZE"] = str(50*1024*1024)
        os.environ["PLUGIN_GRPC_MAX_SEND_MESSAGE_SIZE"] = str(50*1024*1024)

        return self.create_client(
            ["python", "file_service.py"],
            plugin_env={"PLUGIN_AUTO_MTLS": "false"}
        )

    def create_secure_client(self, command: list[str]):
        # Configure client-side mTLS
        os.environ["PLUGIN_CLIENT_CERT"] = "file:///path/to/client.pem"
        os.environ["PLUGIN_CLIENT_KEY"] = "file:///path/to/client.key"

        return self.create_client(
            command,
            plugin_env={
                "PLUGIN_AUTO_MTLS": "true",
                "PLUGIN_SERVER_CERT": "file:///path/to/server.crt",
            }
        )

# Usage
factory = ClientFactory(default_timeout=60.0, log_level="DEBUG")
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

- **[Connection Management](connections/)** - Master connection lifecycle
- **[Direct Connections](direct-connections/)** - Connect to existing servers  
- **[Retry Logic](retry-logic/)** - Build resilient clients