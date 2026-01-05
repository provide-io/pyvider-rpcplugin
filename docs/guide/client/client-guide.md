# Client Development Guide

Master building robust plugin clients with Pyvider RPC Plugin. Learn the fundamentals of client setup, configuration, and lifecycle management for production applications.

## Quick Start

Here's a minimal plugin client to get you started:

```python
import asyncio
from pyvider.rpcplugin import plugin_client
from calculator_pb2_grpc import CalculatorStub
from calculator_pb2 import AddRequest

async def main():
    # Connect to plugin server with automatic lifecycle management
    async with plugin_client(command=["python", "calculator.py"]) as client:
        await client.start()

        # Create gRPC stub from client's channel
        stub = CalculatorStub(client.grpc_channel)

        # Make RPC call
        request = AddRequest(a=5, b=3)
        result = await stub.Add(request)
        print(f"Result: {result.result}")  # Result: 8

if __name__ == "__main__":
    asyncio.run(main())
```

!!! note "Using gRPC Stubs"
    The client provides a `grpc_channel` for making RPC calls. You must use generated gRPC stubs - the client doesn't provide automatic service proxies.

## Client Architecture

=== "Core Components"

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

=== "Lifecycle"

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
            client = plugin_client(command=["python", "calculator.py"])

            try:
                # 2-4. Start connection (launches process, performs handshake, discovers services)
                await client.start()
                print("✅ Client connected and authenticated")

                # 5-6. Make RPC calls
                stub = CalculatorStub(client.grpc_channel)
                result = await stub.Add(AddRequest(a=10, b=5))
                print(f"🔢 Calculation result: {result.result}")

            finally:
                # 7. Clean shutdown
                await client.close()
                print("🔌 Client disconnected and process terminated")
    ```

## Client Patterns

=== "Context Manager (Recommended)"

    Automatic lifecycle management with context manager:

    ```python
    async def context_manager_example():
        """Recommended pattern for automatic cleanup."""

        async with plugin_client(command=["python", "calculator.py"]) as client:
            await client.start()

            # Use client
            stub = CalculatorStub(client.grpc_channel)
            result = await stub.Add(AddRequest(a=10, b=5))
            print(f"Result: {result.result}")

        # Client automatically closed on context exit
        print("Client disconnected")
    ```

=== "Manual Lifecycle"

    Manual control over client lifecycle:

    ```python
    async def manual_client_example():
        """Example of manual client lifecycle management."""

        # Create client (no connection yet)
        client = plugin_client(command=["python", "calculator.py"])

        try:
            # Start connection manually
            await client.start()
            print("✅ Client connected")

            # Use client
            stub = CalculatorStub(client.grpc_channel)
            result = await stub.Add(AddRequest(a=10, b=5))
            print(f"Calculation: {result.result}")

        finally:
            # Always close client
            await client.close()
            print("🔌 Client disconnected")
    ```

## Configuration

=== "Client Configuration"

    !!! important "Configuration Flow"
        **To configure the CLIENT:** Set environment variables in your own process

        **To configure the PLUGIN:** Use `config={"env": {...}}`

    Set environment variables in your process to configure client behavior:

    ```python
    import os
    from pyvider.rpcplugin import plugin_client

    # Configure client retry behavior
    os.environ["PLUGIN_CLIENT_MAX_RETRIES"] = "5"
    os.environ["PLUGIN_CONNECTION_TIMEOUT"] = "30"
    os.environ["PLUGIN_CLIENT_BACKOFF_MULTIPLIER"] = "2.0"

    # Create client (uses environment variables for client config)
    client = plugin_client(command=["python", "plugin.py"])
    ```

    **Available client environment variables:**
    - `PLUGIN_CLIENT_MAX_RETRIES` - Maximum connection retry attempts (default: 3)
    - `PLUGIN_CONNECTION_TIMEOUT` - Connection timeout in seconds (default: 10)
    - `PLUGIN_CLIENT_BACKOFF_MULTIPLIER` - Exponential backoff multiplier (default: 2.0)
    - `PLUGIN_CLIENT_BACKOFF_MAX` - Maximum backoff delay in seconds (default: 60)

=== "Plugin Configuration"

    Configure the plugin subprocess via `config` parameter:

    ```python
    from pyvider.rpcplugin import plugin_client

    # Configure plugin server behavior
    client = plugin_client(
        command=["python", "calculator.py"],
        config={
            "env": {
                # Plugin subprocess configuration
                "PLUGIN_LOG_LEVEL": "debug",
                "PLUGIN_AUTO_MTLS": "true",
                "PLUGIN_RATE_LIMIT_ENABLED": "true",
                "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": "100.0",
                "PLUGIN_HEALTH_SERVICE_ENABLED": "true",
            }
        }
    )

    await client.start()
    ```

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

=== "Security Configuration"

    Configure mTLS for secure communication:

    ```python
    import os

    # Configure client to verify server certificates
    os.environ["PLUGIN_CLIENT_VERIFY_SERVER"] = "true"
    os.environ["PLUGIN_CA_CERT"] = "file:///etc/ssl/certs/ca.crt"

    # Configure plugin server with certificates
    client = plugin_client(
        command=["python", "secure_plugin.py"],
        config={
            "env": {
                "PLUGIN_AUTO_MTLS": "true",
                "PLUGIN_SERVER_CERT": "file:///etc/ssl/certs/server.crt",
                "PLUGIN_SERVER_KEY": "file:///etc/ssl/private/server.key",
                "PLUGIN_CA_CERT": "file:///etc/ssl/certs/ca.crt",
            }
        }
    )

    await client.start()
    ```

## Advanced Patterns

### Multiple Service Clients

Manage multiple plugin connections:

```python
class MultiPluginClient:
    def __init__(self):
        self.plugins = {}

    async def add_plugin(self, name: str, command: list[str]):
        """Add a plugin connection."""
        client = plugin_client(command=command)
        await client.start()
        self.plugins[name] = client
        return client

    async def close_all(self):
        """Close all plugin connections."""
        for name, client in self.plugins.items():
            await client.close()
            print(f"Closed {name}")

# Usage
async def multi_plugin_example():
    manager = MultiPluginClient()

    try:
        # Add multiple plugins
        calc = await manager.add_plugin("calculator", ["python", "calc.py"])
        db = await manager.add_plugin("database", ["python", "db.py"])

        # Use plugins
        calc_stub = CalculatorStub(calc.grpc_channel)
        result = await calc_stub.Add(AddRequest(a=5, b=3))

    finally:
        await manager.close_all()
```

### Connection Pooling

Reuse connections efficiently:

```python
from typing import Dict
from asyncio import Lock

class ClientPool:
    def __init__(self, command: list[str], pool_size: int = 5):
        self.command = command
        self.pool_size = pool_size
        self.clients: list = []
        self.available: list = []
        self.lock = Lock()

    async def initialize(self):
        """Initialize connection pool."""
        for _ in range(self.pool_size):
            client = plugin_client(command=self.command)
            await client.start()
            self.clients.append(client)
            self.available.append(client)

    async def acquire(self):
        """Get a client from the pool."""
        async with self.lock:
            while not self.available:
                await asyncio.sleep(0.1)
            return self.available.pop()

    async def release(self, client):
        """Return a client to the pool."""
        async with self.lock:
            self.available.append(client)

    async def close_all(self):
        """Close all connections."""
        for client in self.clients:
            await client.close()

# Usage
async def pool_example():
    pool = ClientPool(command=["python", "calculator.py"], pool_size=5)
    await pool.initialize()

    try:
        # Acquire client from pool
        client = await pool.acquire()

        try:
            stub = CalculatorStub(client.grpc_channel)
            result = await stub.Add(AddRequest(a=10, b=5))
            print(f"Result: {result.result}")
        finally:
            # Return to pool
            await pool.release(client)

    finally:
        await pool.close_all()
```

## Best Practices

### 1. Always Use Context Managers

Prefer `async with` for automatic resource cleanup:

```python
# Good
async with plugin_client(command=["python", "plugin.py"]) as client:
    await client.start()
    # Use client

# Avoid
client = plugin_client(command=["python", "plugin.py"])
await client.start()
# Easy to forget cleanup
```

### 2. Configure Timeouts

Set appropriate timeouts for your use case:

```python
import os

# Short timeout for local plugins
os.environ["PLUGIN_CONNECTION_TIMEOUT"] = "5"

# Longer timeout for remote/slow plugins
os.environ["PLUGIN_CONNECTION_TIMEOUT"] = "30"
```

### 3. Handle Startup Failures

Always handle connection failures:

```python
from pyvider.rpcplugin.exception import TransportError, HandshakeError

try:
    async with plugin_client(command=["python", "plugin.py"]) as client:
        await client.start()
        # Use client
except (TransportError, HandshakeError) as e:
    logger.error(f"Failed to connect: {e.message}")
    # Implement fallback or retry logic
```

### 4. Clean Resource Management

Ensure proper cleanup even with exceptions:

```python
client = None
try:
    client = plugin_client(command=["python", "plugin.py"])
    await client.start()
    # Use client
except Exception as e:
    logger.error(f"Error: {e}")
    raise
finally:
    if client:
        await client.close()
```

## Troubleshooting

### Connection Issues

**Problem:** Client fails to connect to plugin

```python
# Check plugin process status
try:
    await client.start()
except TransportError as e:
    logger.error(f"Connection failed: {e.message}")
    # Check if plugin process actually started
    # Check logs for plugin subprocess errors
```

### Timeout Issues

**Problem:** Connection times out

```python
# Increase timeout for slow-starting plugins
os.environ["PLUGIN_CONNECTION_TIMEOUT"] = "60"

# Or check if plugin is actually responding
import subprocess
result = subprocess.run(["python", "plugin.py", "--version"], capture_output=True)
print(result.stdout)  # Verify plugin executable works
```

### Port Conflicts

**Problem:** Port already in use

```python
# Use automatic port assignment in plugin server
# In plugin server code:
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="tcp",
    port=0  # Automatic port assignment
)
```

## Next Steps

- **[Connection Resilience](resilience.md)** - Error handling, retry logic, health monitoring
- **[Direct Connections](direct-connections.md)** - Connect to existing servers
- **[Security Guide](../security/)** - mTLS configuration and authentication
- **[Examples](../../examples/)** - Complete working examples
