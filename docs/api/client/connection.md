# Client Connection API

The Client Connection API provides connection management for RPC plugin clients, handling plugin server processes, transport setup, and gRPC channel management.

## Overview

The pyvider-rpcplugin client connection system provides:

- **Process Management** - Automatic plugin server process lifecycle
- **Transport Negotiation** - Unix socket and TCP transport support
- **Handshake Protocol** - Secure connection establishment
- **Channel Management** - gRPC channel setup and cleanup
- **Error Handling** - Connection failures and recovery

## Core Classes

### `RPCPluginClient`

Main client class for connecting to RPC plugin servers.

```python
from pyvider.rpcplugin.client import RPCPluginClient
```

#### Constructor

```python
def __init__(
    self,
    command: list[str],
    config: dict[str, Any] | None = None
) -> None:
```

**Parameters:**
- `command` (list[str]): Command to start the plugin server process
- `config` (dict[str, Any] | None): Optional configuration dictionary

**Example:**
```python
# Basic client setup
client = RPCPluginClient(
    command=["python", "-m", "my_plugin.server"],
    config={
        "timeout": 30,
        "max_retries": 3
    }
)
```

#### Methods

##### `start`

```python
async def start(self) -> None:
```

Start the client and establish connection to plugin server.

**Raises:**
- `TransportError`: If connection cannot be established
- `HandshakeError`: If handshake fails
- `ProcessError`: If server process fails to start

**Example:**
```python
try:
    await client.start()
    print("Client connected successfully")
except Exception as e:
    print(f"Connection failed: {e}")
```

##### `stop`

```python
async def stop(self) -> None:
```

Stop the client and clean up resources.

**Example:**
```python
try:
    await client.stop()
    print("Client stopped successfully")
except Exception as e:
    print(f"Stop failed: {e}")
```

##### `is_running`

```python
def is_running(self) -> bool:
```

Check if the client is currently running and connected.

**Returns:**
- `bool`: True if client is running and connected

**Example:**
```python
if client.is_running():
    # Use the client for RPC calls
    response = await stub.SomeMethod(request)
else:
    print("Client not running")
```

#### Properties

##### `grpc_channel`

```python
@property
def grpc_channel(self) -> grpc.aio.Channel | None:
```

Get the gRPC channel for making RPC calls.

**Returns:**
- `grpc.aio.Channel | None`: The gRPC channel if connected, None otherwise

**Example:**
```python
channel = client.grpc_channel
if channel:
    stub = MyServiceStub(channel)
    response = await stub.MyMethod(request)
```

### `ClientConnection`

Low-level connection wrapper for stream I/O.

```python
from pyvider.rpcplugin.client.connection import ClientConnection
```

#### Constructor

```python
def __init__(
    self,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter
) -> None:
```

**Parameters:**
- `reader` (asyncio.StreamReader): Input stream
- `writer` (asyncio.StreamWriter): Output stream

#### Methods

##### `read_line`

```python
async def read_line(self) -> str:
```

Read a line from the input stream.

##### `write_line`

```python
async def write_line(self, line: str) -> None:
```

Write a line to the output stream.

##### `close`

```python
async def close(self) -> None:
```

Close the connection streams.

## Usage Examples

### Basic Client Usage

```python
import asyncio
from pyvider.rpcplugin.client import RPCPluginClient

async def main():
    # Create client
    client = RPCPluginClient(
        command=["python", "-m", "my_plugin.server"]
    )
    
    try:
        # Start client and connect
        await client.start()
        
        # Get gRPC channel
        channel = client.grpc_channel
        if channel:
            # Create service stub
            from my_plugin.service_pb2_grpc import MyServiceStub
            stub = MyServiceStub(channel)
            
            # Make RPC calls
            from my_plugin.service_pb2 import MyRequest
            request = MyRequest(message="Hello")
            response = await stub.SayHello(request)
            print(f"Response: {response.message}")
        
    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        # Clean up
        await client.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

### Client with Configuration

```python
import asyncio
from pyvider.rpcplugin.client import RPCPluginClient

async def main():
    # Client configuration
    config = {
        "connection_timeout": 30,
        "max_retries": 5,
        "retry_delay": 1.0,
        "environment": {
            "DEBUG": "1",
            "PLUGIN_LOG_LEVEL": "INFO"
        }
    }
    
    client = RPCPluginClient(
        command=["./my-plugin-server", "--port", "0"],
        config=config
    )
    
    try:
        await client.start()
        
        # Client is now ready for use
        if client.is_running():
            channel = client.grpc_channel
            # ... use channel for RPC calls
        
    finally:
        await client.stop()

asyncio.run(main())
```

### Context Manager Usage

```python
import asyncio
from contextlib import asynccontextmanager
from pyvider.rpcplugin.client import RPCPluginClient

@asynccontextmanager
async def plugin_client(command: list[str], config: dict = None):
    """Context manager for plugin client."""
    client = RPCPluginClient(command=command, config=config)
    try:
        await client.start()
        yield client
    finally:
        await client.stop()

async def main():
    async with plugin_client(["python", "-m", "my_plugin"]) as client:
        channel = client.grpc_channel
        if channel:
            # Use the client
            stub = MyServiceStub(channel)
            response = await stub.GetStatus()
            print(f"Status: {response.status}")

asyncio.run(main())
```

### Error Handling

```python
import asyncio
import logging
from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.exception import TransportError, HandshakeError

logger = logging.getLogger(__name__)

async def robust_client_setup(command: list[str], max_attempts: int = 3):
    """Set up client with retries."""
    
    for attempt in range(max_attempts):
        client = RPCPluginClient(command=command)
        
        try:
            await client.start()
            logger.info(f"Client connected on attempt {attempt + 1}")
            return client
            
        except TransportError as e:
            logger.warning(f"Transport error on attempt {attempt + 1}: {e}")
            await client.stop()
            
        except HandshakeError as e:
            logger.warning(f"Handshake error on attempt {attempt + 1}: {e}")
            await client.stop()
            
        except Exception as e:
            logger.error(f"Unexpected error on attempt {attempt + 1}: {e}")
            await client.stop()
        
        if attempt < max_attempts - 1:
            delay = 2 ** attempt  # Exponential backoff
            logger.info(f"Retrying in {delay} seconds...")
            await asyncio.sleep(delay)
    
    raise ConnectionError(f"Failed to connect after {max_attempts} attempts")

async def main():
    try:
        client = await robust_client_setup(["./my-plugin-server"])
        
        # Use client
        channel = client.grpc_channel
        # ... make RPC calls
        
    except ConnectionError as e:
        logger.error(f"Could not establish connection: {e}")
        return
    
    finally:
        if 'client' in locals():
            await client.stop()

asyncio.run(main())
```

### Multiple Clients

```python
import asyncio
from pyvider.rpcplugin.client import RPCPluginClient

async def create_client_pool(commands: list[list[str]]) -> list[RPCPluginClient]:
    """Create multiple clients for load distribution."""
    clients = []
    
    for command in commands:
        client = RPCPluginClient(command=command)
        try:
            await client.start()
            clients.append(client)
        except Exception as e:
            print(f"Failed to start client {command}: {e}")
            # Clean up partial clients
            for c in clients:
                await c.stop()
            raise
    
    return clients

async def round_robin_request(clients: list[RPCPluginClient], request_data):
    """Distribute requests across clients in round-robin fashion."""
    if not clients:
        raise ValueError("No clients available")
    
    # Simple round-robin (in real implementation, use atomic counter)
    import random
    client = random.choice([c for c in clients if c.is_running()])
    
    if not client:
        raise ConnectionError("No running clients available")
    
    channel = client.grpc_channel
    if channel:
        stub = MyServiceStub(channel)
        return await stub.ProcessRequest(request_data)
    
    raise ConnectionError("Client channel not available")

async def main():
    commands = [
        ["./plugin-server", "--instance", "1"],
        ["./plugin-server", "--instance", "2"],
        ["./plugin-server", "--instance", "3"],
    ]
    
    try:
        clients = await create_client_pool(commands)
        print(f"Started {len(clients)} clients")
        
        # Make distributed requests
        for i in range(10):
            request = MyRequest(id=i, data=f"request_{i}")
            response = await round_robin_request(clients, request)
            print(f"Request {i}: {response.result}")
        
    finally:
        # Clean up all clients
        if 'clients' in locals():
            for client in clients:
                await client.stop()

asyncio.run(main())
```

## Configuration Options

The client supports various configuration options passed via the `config` parameter:

### Connection Settings

```python
config = {
    # Connection timeouts
    "connection_timeout": 30,      # Seconds to wait for connection
    "handshake_timeout": 10,       # Seconds to wait for handshake
    
    # Retry settings  
    "max_retries": 3,              # Maximum connection attempts
    "retry_delay": 1.0,            # Base delay between retries
    "retry_exponential": True,     # Use exponential backoff
    
    # Process settings
    "process_timeout": 60,         # Seconds to wait for process start
    "kill_timeout": 5,             # Seconds to wait before force kill
    
    # Environment variables for server process
    "environment": {
        "DEBUG": "1",
        "PLUGIN_LOG_LEVEL": "INFO",
        "CUSTOM_CONFIG": "/path/to/config.json"
    }
}

client = RPCPluginClient(command=["./server"], config=config)
```

### TLS/Security Settings

```python
config = {
    # TLS configuration (when supported)
    "tls_enabled": True,
    "ca_cert_path": "/path/to/ca.pem",
    "client_cert_path": "/path/to/client.pem",
    "client_key_path": "/path/to/client-key.pem",
    "verify_hostname": True,
    
    # mTLS settings
    "mutual_tls": True,
    "cert_validation": "strict",   # strict, permissive, disabled
}
```

## Best Practices

### 1. Resource Management

Always use proper resource cleanup:

```python
# Good - explicit cleanup
client = RPCPluginClient(command=["./server"])
try:
    await client.start()
    # ... use client
finally:
    await client.stop()

# Better - context manager
async with plugin_client(["./server"]) as client:
    # ... use client
    # automatic cleanup on exit
```

### 2. Error Handling

Implement comprehensive error handling:

```python
try:
    await client.start()
except TransportError:
    # Handle transport/network issues
    pass
except HandshakeError:
    # Handle protocol/handshake issues  
    pass
except ProcessError:
    # Handle server process issues
    pass
except Exception:
    # Handle unexpected errors
    pass
```

### 3. Connection Monitoring

Monitor connection health:

```python
async def monitor_connection(client: RPCPluginClient):
    """Monitor client connection health."""
    while client.is_running():
        try:
            # Simple health check
            channel = client.grpc_channel
            if not channel:
                logger.warning("Client channel not available")
                break
                
            # You could implement a ping/health check RPC here
            await asyncio.sleep(30)  # Check every 30 seconds
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            break
    
    logger.info("Connection monitoring stopped")
```

### 4. Graceful Shutdown

Implement graceful shutdown handling:

```python
import signal
import asyncio

clients = []

async def shutdown_handler():
    """Gracefully shutdown all clients."""
    print("Shutting down clients...")
    
    for client in clients:
        try:
            await client.stop()
        except Exception as e:
            print(f"Error stopping client: {e}")
    
    print("Shutdown complete")

def setup_signal_handlers():
    """Setup signal handlers for graceful shutdown."""
    loop = asyncio.get_event_loop()
    
    for sig in [signal.SIGTERM, signal.SIGINT]:
        loop.add_signal_handler(
            sig, 
            lambda: asyncio.create_task(shutdown_handler())
        )
```

## Future Improvements

The following advanced connection management features are planned for future releases:

### Connection Pooling

Advanced connection pooling with:

- **Pool Size Management**: Configurable min/max connections
- **Connection Lifecycle**: Automatic creation and cleanup
- **Health Monitoring**: Per-connection health checks
- **Load Balancing**: Intelligent request distribution

```python
# Future API concept
pool = ConnectionPool(
    commands=[["./server1"], ["./server2"]],
    min_connections=2,
    max_connections=10,
    health_check_interval=30
)

async with pool.get_connection() as client:
    response = await client.call_method(request)
```

### Load Balancing Strategies

Multiple load balancing algorithms:

- **Round Robin**: Equal distribution across connections
- **Weighted Round Robin**: Priority-based distribution  
- **Least Connections**: Route to least busy connection
- **Performance-Based**: Route based on response times

```python
# Future API concept
balancer = LoadBalancer(
    strategy="least_connections",
    health_aware=True,
    sticky_sessions=True
)
```

### Circuit Breaker Pattern

Automatic failure detection and recovery:

- **Failure Thresholds**: Configurable failure rates
- **Circuit States**: Open/Closed/Half-Open states
- **Recovery Logic**: Automatic retry and recovery
- **Fallback Mechanisms**: Graceful degradation

```python
# Future API concept
circuit_breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=60,
    fallback_handler=fallback_function
)
```

### Service Discovery Integration

Dynamic service discovery:

- **Registry Integration**: Consul, etcd, Kubernetes
- **Health-Aware Discovery**: Filter unhealthy instances
- **Dynamic Reconfiguration**: Add/remove endpoints
- **Load-Aware Routing**: Consider service load

```python
# Future API concept
discovery = ServiceDiscovery(
    provider="kubernetes",
    service_name="my-plugin-service",
    namespace="default"
)

client_manager = ClientManager(discovery=discovery)
```

### Advanced Health Monitoring

Comprehensive health checking:

- **Custom Health Protocols**: Plugin-specific health checks
- **Dependency Monitoring**: Check external dependencies
- **Metrics Collection**: Connection performance metrics
- **Alerting Integration**: Health status notifications

## Quick Examples

For executable code samples:

- **[Basic Client](../../examples/short/basic-client.md)** - Simple connection setup
- **[TCP Transport](../../examples/short/tcp-transport.md)** - Network transport configuration

These features would significantly enhance the connection management capabilities for production deployments with high availability requirements.