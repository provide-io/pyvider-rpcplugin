# Client API

The Client API provides classes and functions for host applications to launch, manage, and communicate with plugin processes.

## Core Classes

### RPCPluginClient

The main client class that manages plugin lifecycle and RPC communication.

```python
from pyvider.rpcplugin.client import RPCPluginClient

client = RPCPluginClient(
    command=["python", "my_plugin.py"],
    config={"env": {"CUSTOM_VAR": "value"}}
)

await client.start()    # Launch and connect
# Use client.grpc_channel for RPC calls
await client.close()    # Shutdown
```

**Key Methods:**
- `start()` - Launch plugin and establish connection
- `close()` - Gracefully shutdown plugin and connection
- `is_started` - Check if client is connected
- `grpc_channel` - Access gRPC channel for making calls

### Factory Functions

#### plugin_client()

Convenience factory for creating configured clients:

```python
from pyvider.rpcplugin import plugin_client

# Launch executable
client = plugin_client(command=["python", "my_plugin.py"])

# Direct connection (plugin already running)
client = plugin_client(address="unix:///tmp/plugin.sock")

# Custom configuration
client = plugin_client(
    command=["python", "my_plugin.py"],
    config={
        "env": {"DEBUG": "1"},
        "timeout": 60.0
    }
)
```

## Client Lifecycle

### Startup Sequence

1. **Configuration Loading** - Read environment variables and config
2. **Plugin Launch** - Start plugin subprocess (if command provided)
3. **Handshake Reading** - Read connection details from plugin stdout
4. **Transport Connection** - Connect via Unix socket or TCP
5. **mTLS Negotiation** - Perform certificate exchange (if enabled)
6. **Channel Ready** - gRPC channel ready for method calls

### Connection Management

```python
async def managed_plugin_connection():
    client = None
    try:
        # Establish connection
        client = plugin_client(command=["python", "my_plugin.py"])
        await client.start()
        
        # Check connection status
        assert client.is_started
        
        # Use the connection
        stub = MyServiceStub(client.grpc_channel)
        response = await stub.MyMethod(request)
        
    finally:
        # Always cleanup
        if client:
            await client.close()
```

### Reconnection Handling

```python
class ResilientClient:
    def __init__(self, command: list[str]):
        self.command = command
        self.client = None
    
    async def ensure_connected(self):
        if not self.client or not self.client.is_started:
            if self.client:
                await self.client.close()
            
            self.client = plugin_client(command=self.command)
            await self.client.start()
    
    async def make_call(self, func):
        await self.ensure_connected()
        return await func(self.client.grpc_channel)
```

## Configuration

### Environment Variables

Key client configuration variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `PLUGIN_CLIENT_TIMEOUT` | Connection timeout (seconds) | `30.0` |
| `PLUGIN_HANDSHAKE_TIMEOUT` | Handshake timeout (seconds) | `30.0` |
| `PLUGIN_CLIENT_RETRY_COUNT` | Max retry attempts | `3` |
| `PLUGIN_CLIENT_RETRY_DELAY` | Retry delay (seconds) | `1.0` |
| `PLUGIN_AUTO_MTLS` | Enable mutual TLS | `false` |

### Programmatic Configuration

```python
from pyvider.rpcplugin import configure

configure(
    client_timeout=60.0,
    handshake_timeout=45.0,
    client_retry_count=5,
    client_retry_delay=2.0,
    auto_mtls=True
)
```

### Per-Client Configuration

```python
client = plugin_client(
    command=["python", "my_plugin.py"],
    config={
        "timeout": 120.0,           # Override default timeout
        "retry_count": 5,           # Custom retry behavior
        "env": {                    # Plugin environment variables
            "DEBUG": "1",
            "LOG_LEVEL": "DEBUG"
        },
        "cwd": "/path/to/plugin",   # Plugin working directory
        "auto_mtls": True           # Enable mTLS for this client
    }
)
```

## Connection Types

### Executable Plugin

Launch plugin as subprocess:

```python
# Python script
client = plugin_client(command=["python", "my_plugin.py"])

# Compiled binary  
client = plugin_client(command=["/usr/local/bin/my-plugin"])

# With arguments
client = plugin_client(command=["python", "my_plugin.py", "--debug"])

# Custom environment
client = plugin_client(
    command=["python", "my_plugin.py"],
    config={
        "env": {
            "PLUGIN_MODE": "production",
            "API_KEY": "secret-key"
        }
    }
)
```

### Direct Connection

Connect to already running plugin:

```python
# Unix socket
client = plugin_client(address="unix:///tmp/my-plugin.sock")

# TCP connection
client = plugin_client(address="tcp://127.0.0.1:8080")

# With mTLS
client = plugin_client(
    address="tcp://plugin.example.com:8443",
    config={"auto_mtls": True}
)
```

## Security Features

### mTLS Configuration

Enable mutual TLS authentication:

```python
# Environment variables
os.environ.update({
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_CLIENT_CERT": "file:///path/to/client.crt",
    "PLUGIN_CLIENT_KEY": "file:///path/to/client.key",
    "PLUGIN_SERVER_ROOT_CERTS": "file:///path/to/ca.crt"
})

client = plugin_client(command=["python", "my_plugin.py"])
```

### Certificate Management

```python
from pyvider.rpcplugin.crypto import Certificate

# Generate client certificate
ca_cert = Certificate.from_file("ca.crt")
client_cert = Certificate.create_signed_certificate(
    ca_certificate=ca_cert,
    common_name="my-client",
    is_client_cert=True
)

# Use with client
configure(
    auto_mtls=True,
    client_cert=client_cert.cert,    # PEM string
    client_key=client_cert.key,      # PEM string
    server_root_certs=ca_cert.cert   # Trust server certs from this CA
)
```

### Magic Cookie Validation

```python
# Custom magic cookie
configure(
    magic_cookie_key="MY_PLUGIN_TOKEN",
    magic_cookie="super-secret-value-123"
)

# Cookie automatically set in plugin environment
client = plugin_client(command=["python", "my_plugin.py"])
```

## RPC Communication

### Making Method Calls

```python
from my_service_pb2_grpc import MyServiceStub
from my_service_pb2 import MyRequest

async def call_plugin_method():
    client = plugin_client(command=["python", "my_plugin.py"])
    await client.start()
    
    try:
        # Create gRPC stub
        stub = MyServiceStub(client.grpc_channel)
        
        # Make RPC call
        request = MyRequest(message="Hello Plugin!")
        response = await stub.MyMethod(request)
        
        return response.result
        
    finally:
        await client.close()
```

### Streaming Calls

```python
async def streaming_example():
    client = plugin_client(command=["python", "streaming_plugin.py"])
    await client.start()
    
    try:
        stub = StreamingServiceStub(client.grpc_channel)
        
        # Server streaming
        async for response in stub.ServerStream(request):
            print(f"Received: {response.data}")
        
        # Client streaming
        async def request_generator():
            for i in range(10):
                yield StreamRequest(data=f"Message {i}")
        
        response = await stub.ClientStream(request_generator())
        
        # Bidirectional streaming
        async def bidirectional_generator():
            for i in range(5):
                yield BidirectionalRequest(data=f"Ping {i}")
        
        async for response in stub.BidirectionalStream(bidirectional_generator()):
            print(f"Pong: {response.data}")
            
    finally:
        await client.close()
```

## Error Handling

### Connection Errors

```python
from pyvider.rpcplugin.exception import (
    TransportError, HandshakeError, SecurityError
)

async def robust_client():
    try:
        client = plugin_client(command=["python", "my_plugin.py"])
        await client.start()
        
    except TransportError as e:
        logger.error(f"❌ Connection failed: {e}")
        # Maybe try different transport or retry
        
    except HandshakeError as e:
        logger.error(f"🤝 Handshake failed: {e}")
        # Check magic cookie or protocol version
        
    except SecurityError as e:
        logger.error(f"🔐 Security error: {e}")
        # Check certificates and mTLS configuration
```

### RPC Call Errors

```python
import grpc

async def handle_rpc_errors():
    try:
        response = await stub.MyMethod(request)
        return response
        
    except grpc.aio.AioRpcError as e:
        if e.code() == grpc.StatusCode.UNAVAILABLE:
            # Plugin temporarily unavailable
            logger.warning("Plugin unavailable, retrying...")
            await asyncio.sleep(1)
            return await stub.MyMethod(request)
            
        elif e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
            # Request timeout
            logger.error("Request timed out")
            raise TimeoutError("Plugin request timeout") from e
            
        else:
            # Other gRPC errors
            logger.error(f"RPC error: {e.code()} - {e.details()}")
            raise
```

## Performance Optimization

### Connection Pooling

```python
class PluginPool:
    def __init__(self, command: list[str], pool_size: int = 3):
        self.command = command
        self.pool_size = pool_size
        self.pool = asyncio.Queue(maxsize=pool_size)
        self.total_clients = 0
    
    async def get_client(self) -> RPCPluginClient:
        """Get a client from the pool."""
        if self.pool.empty() and self.total_clients < self.pool_size:
            # Create new client
            client = plugin_client(command=self.command)
            await client.start()
            self.total_clients += 1
            return client
        
        # Wait for available client
        return await self.pool.get()
    
    async def return_client(self, client: RPCPluginClient):
        """Return client to pool."""
        if client.is_started:
            await self.pool.put(client)
        else:
            # Replace broken client
            new_client = plugin_client(command=self.command)
            await new_client.start()
            await self.pool.put(new_client)

# Usage
plugin_pool = PluginPool(["python", "worker_plugin.py"], pool_size=5)

async def use_pooled_client():
    client = await plugin_pool.get_client()
    try:
        stub = WorkerServiceStub(client.grpc_channel)
        result = await stub.ProcessWork(work_request)
        return result
    finally:
        await plugin_pool.return_client(client)
```

### Channel Options

```python
# Configure gRPC channel options for performance
configure(
    grpc_options=[
        # Keep-alive settings
        ('grpc.keepalive_time_ms', 30000),
        ('grpc.keepalive_timeout_ms', 5000),
        ('grpc.keepalive_permit_without_calls', True),
        
        # Message size limits
        ('grpc.max_send_message_length', 64 * 1024 * 1024),
        ('grpc.max_receive_message_length', 64 * 1024 * 1024),
        
        # Connection settings
        ('grpc.http2.max_pings_without_data', 0),
        ('grpc.http2.min_time_between_pings_ms', 10000),
    ]
)
```

## Monitoring and Observability

### Client Metrics

```python
from provide.foundation import logger

class MonitoredClient:
    def __init__(self, command: list[str]):
        self.command = command
        self.client = None
        self.call_count = 0
        self.error_count = 0
        self.start_time = None
    
    async def start(self):
        self.start_time = time.time()
        self.client = plugin_client(command=self.command)
        await self.client.start()
        
        logger.info("📊 Client started", 
                   command=" ".join(self.command),
                   startup_time=time.time() - self.start_time)
    
    async def make_call(self, func):
        self.call_count += 1
        call_start = time.time()
        
        try:
            result = await func(self.client.grpc_channel)
            call_duration = time.time() - call_start
            
            logger.info("📈 RPC call completed",
                       call_count=self.call_count,
                       duration=call_duration,
                       success=True)
            
            return result
            
        except Exception as e:
            self.error_count += 1
            call_duration = time.time() - call_start
            
            logger.error("📉 RPC call failed",
                        call_count=self.call_count,
                        error_count=self.error_count,
                        duration=call_duration,
                        error=str(e))
            raise
```

### Health Monitoring

```python
async def monitor_plugin_health(client: RPCPluginClient):
    """Monitor plugin health continuously."""
    
    while client.is_started:
        try:
            # Check gRPC channel state
            state = client.grpc_channel.get_state()
            
            if state == grpc.ChannelConnectivity.READY:
                logger.debug("✅ Plugin connection healthy")
            elif state == grpc.ChannelConnectivity.TRANSIENT_FAILURE:
                logger.warning("⚠️ Plugin connection unstable")
            elif state == grpc.ChannelConnectivity.SHUTDOWN:
                logger.error("❌ Plugin connection closed")
                break
            
            # Optional: Make health check RPC
            # health_stub = grpc_health_v1.HealthStub(client.grpc_channel)
            # health_response = await health_stub.Check(
            #     grpc_health_v1.HealthCheckRequest()
            # )
            
        except Exception as e:
            logger.error(f"Health check error: {e}")
        
        await asyncio.sleep(30)  # Check every 30 seconds
```

## Example Implementations

### Basic Client

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin import plugin_client
from my_service_pb2_grpc import MyServiceStub
from my_service_pb2 import MyRequest

async def main():
    client = plugin_client(command=["python", "my_plugin.py"])
    
    try:
        await client.start()
        
        stub = MyServiceStub(client.grpc_channel)
        response = await stub.MyMethod(MyRequest(message="Hello!"))
        
        print(f"Response: {response.result}")
        
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

### Context Manager Client

```python
from contextlib import asynccontextmanager

@asynccontextmanager
async def plugin_connection(command: list[str]):
    """Context manager for plugin connections."""
    client = plugin_client(command=command)
    try:
        await client.start()
        yield client
    finally:
        await client.close()

# Usage
async def main():
    async with plugin_connection(["python", "my_plugin.py"]) as client:
        stub = MyServiceStub(client.grpc_channel)
        response = await stub.MyMethod(request)
        return response
```

## API Reference

### Classes

- [`RPCPluginClient`](client.md) - Main client implementation
- [`plugin_client()`](../factories.md#plugin_client) - Client factory function

### Related APIs

- **[Transport API](../transport/)** - Network transport implementations
- **[Configuration API](../config/)** - Client configuration management
- **[Exceptions API](../exceptions/)** - Client error handling
- **[Security](../security/)** - mTLS and authentication