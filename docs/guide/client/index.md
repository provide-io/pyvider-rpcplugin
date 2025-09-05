# Client Development

The Pyvider RPC Plugin client system provides a comprehensive solution for connecting to and communicating with plugin servers. This section covers everything you need to develop robust client applications that can launch plugins, manage connections, handle errors, and optimize performance.

## Overview

The client development framework provides:

- **Process Management** - Launch and manage plugin subprocess
- **Connection Handling** - Automatic connection with retry logic
- **Protocol Negotiation** - Version and transport negotiation
- **Resource Management** - Automatic cleanup of processes and connections
- **Error Recovery** - Comprehensive error handling with retry patterns
- **Performance Optimization** - Connection pooling and concurrent operations

```python
import asyncio
from pyvider.rpcplugin import plugin_client

async def main():
    # Create client that launches and connects to plugin
    client = plugin_client(command=["python", "-m", "my_plugin"])
    
    async with client:
        # Client automatically handles connection lifecycle
        response = await client.my_service.process_data("example")
        print(f"Result: {response}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Client Architecture

### Core Components

```
┌─────────────────┐
│ Client Application│
│                 │
└─────────┬───────┘
          │ creates
          ▼
┌─────────────────┐     ┌──────────────────┐
│ RPCPluginClient │────▶│ Plugin Process   │
│                 │     │ Management       │
│ ┌─────────────┐ │     └──────────────────┘
│ │ Connection  │ │              │
│ │ Manager     │ │              │ launches
│ └─────────────┘ │              ▼
│        │        │     ┌──────────────────┐
│        │        │     │ Plugin Server    │
│        │        │     │ (subprocess)     │
│        │        │     └──────────────────┘
└─────────┬───────┘              │
          │                      │ handshake
          │ connects              │
          ▼                      ▼
┌─────────────────┐     ┌──────────────────┐
│ gRPC Channel    │────▶│ Transport        │
│                 │     │ (Unix/TCP)       │
└─────────────────┘     └──────────────────┘
```

### Client Lifecycle

1. **Process Launch** - Start plugin subprocess with specified command
2. **Handshake Reading** - Read handshake string from plugin stdout  
3. **Transport Negotiation** - Select compatible transport (Unix/TCP)
4. **Connection Establishment** - Connect to plugin server endpoint
5. **Service Discovery** - Discover available RPC services
6. **Ready State** - Client ready for RPC calls
7. **Resource Cleanup** - Automatic cleanup on exit

## Development Sections

### 🚀 [Basic Client Setup](basic-setup.md)
Learn to create and configure plugin clients:
- Client creation and configuration
- Factory function usage  
- Basic connection patterns
- Simple examples

### 🔗 [Connection Management](connections.md)
Master client connection handling:
- Connection lifecycle
- Automatic retry logic
- Connection pooling patterns
- Resource management

### 🎯 [Direct Connections](direct-connections.md) 
Connect to existing plugin servers:
- Direct endpoint connection
- Bypass process management
- Integration with external servers
- Advanced connection patterns

### ⚠️ [Error Handling](error-handling.md)
Implement robust error handling:
- Exception hierarchy
- Recovery patterns
- Circuit breaker implementation
- Error logging and debugging

### 🔄 [Retry Logic](retry-logic.md)
Configure and customize retry behavior:
- Exponential backoff configuration
- Retry policies and limits
- Custom retry strategies
- Performance considerations

## Quick Start

### Basic Client

```python
#!/usr/bin/env python3
import asyncio
from pyvider.rpcplugin import plugin_client
from provide.foundation import logger

async def main():
    # Create client for plugin command
    client = plugin_client(command=["python", "-m", "my_plugin.server"])
    
    try:
        async with client:
            logger.info("✅ Connected to plugin server")
            
            # Make RPC calls
            response = await client.my_service.get_status()
            logger.info(f"📊 Server status: {response.status}")
            
            # Process data
            result = await client.my_service.process_data(
                data="example input",
                options={"format": "json"}
            )
            logger.info(f"📈 Processing result: {result}")
            
    except Exception as e:
        logger.error(f"❌ Client error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
```

### Production Client

```python
#!/usr/bin/env python3
import asyncio
import os
from pyvider.rpcplugin import plugin_client

async def main():
    # Configure for production
    os.environ.update({
        "PYVIDER_PLUGIN_CLIENT_RETRY_ENABLED": "true",
        "PYVIDER_PLUGIN_CLIENT_MAX_RETRIES": "5",
        "PYVIDER_PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": "120",
        "PYVIDER_PLUGIN_HANDSHAKE_TIMEOUT": "30.0",
        "PYVIDER_PLUGIN_CONNECTION_TIMEOUT": "60.0"
    })
    
    client = plugin_client(
        command=["python", "-m", "my_plugin.server"],
        config={
            "request_timeout": 30.0,
            "max_concurrent_requests": 10
        }
    )
    
    # Client includes:
    # - Automatic retry with exponential backoff
    # - Connection timeout handling
    # - Request timeout management
    # - Resource cleanup and process management
    
    async with client:
        # High-throughput concurrent operations
        tasks = []
        for i in range(100):
            task = client.my_service.process_item(f"item_{i}")
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        successes = [r for r in results if not isinstance(r, Exception)]
        errors = [r for r in results if isinstance(r, Exception)]
        
        logger.info(f"✅ Processed {len(successes)} items successfully")
        if errors:
            logger.warning(f"⚠️ {len(errors)} items failed")

if __name__ == "__main__":
    asyncio.run(main())
```

## Common Patterns

### Configuration-Based Client

```python
import os
from pyvider.rpcplugin import plugin_client

def create_configured_client(env="development"):
    """Create client with environment-specific configuration."""
    
    if env == "development":
        config = {
            "handshake_timeout": 5.0,
            "connection_timeout": 10.0,
            "max_retries": 2,
            "log_level": "DEBUG"
        }
        command = ["python", "-m", "my_plugin.dev_server"]
        
    elif env == "production":
        config = {
            "handshake_timeout": 30.0,
            "connection_timeout": 60.0, 
            "max_retries": 5,
            "retry_total_timeout": 120,
            "log_level": "INFO"
        }
        command = ["python", "-m", "my_plugin.server"]
        
    else:
        raise ValueError(f"Unknown environment: {env}")
    
    return plugin_client(command=command, config=config)

# Usage
env = os.getenv("ENVIRONMENT", "development")
client = create_configured_client(env)
```

### Batch Processing Client

```python
import asyncio
from pyvider.rpcplugin import plugin_client

async def batch_process_items(items, batch_size=10):
    """Process items in batches for optimal performance."""
    
    client = plugin_client(command=["python", "-m", "my_plugin.server"])
    
    async with client:
        results = []
        
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            logger.info(f"📦 Processing batch {i//batch_size + 1}")
            
            # Process batch concurrently
            batch_tasks = [
                client.my_service.process_item(item) 
                for item in batch
            ]
            
            batch_results = await asyncio.gather(
                *batch_tasks, 
                return_exceptions=True
            )
            
            results.extend(batch_results)
            
            # Optional: Add delay between batches to avoid overwhelming server
            if i + batch_size < len(items):
                await asyncio.sleep(0.1)
        
        return results

# Usage
items = [f"item_{i}" for i in range(100)]
results = await batch_process_items(items, batch_size=20)
```

### Connection Pool Client

```python
import asyncio
from collections.abc import AsyncContextManager
from pyvider.rpcplugin import plugin_client

class ClientPool:
    """Connection pool for high-throughput scenarios."""
    
    def __init__(self, command, pool_size=5):
        self.command = command
        self.pool_size = pool_size
        self.available_clients = asyncio.Queue(maxsize=pool_size)
        self.all_clients = []
        self.closed = False
    
    async def initialize(self):
        """Initialize all clients in the pool."""
        for i in range(self.pool_size):
            client = plugin_client(command=self.command)
            await client.start()
            self.all_clients.append(client)
            await self.available_clients.put(client)
            logger.info(f"📡 Initialized client {i+1}/{self.pool_size}")
    
    async def get_client(self) -> AsyncContextManager:
        """Get an available client from the pool."""
        if self.closed:
            raise RuntimeError("Client pool is closed")
        
        client = await self.available_clients.get()
        return ClientContextManager(client, self)
    
    async def return_client(self, client):
        """Return client to the pool."""
        if not self.closed:
            await self.available_clients.put(client)
    
    async def close(self):
        """Close all clients in the pool."""
        self.closed = True
        for client in self.all_clients:
            try:
                await client.stop()
            except Exception as e:
                logger.warning(f"⚠️ Error closing client: {e}")

class ClientContextManager:
    def __init__(self, client, pool):
        self.client = client
        self.pool = pool
    
    async def __aenter__(self):
        return self.client
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.pool.return_client(self.client)

# Usage
async def use_client_pool():
    pool = ClientPool(command=["python", "-m", "my_plugin"], pool_size=10)
    await pool.initialize()
    
    try:
        # Use clients from pool
        tasks = []
        for i in range(50):
            async def process_with_pool_client(item_id):
                async with pool.get_client() as client:
                    return await client.my_service.process_item(f"item_{item_id}")
            
            tasks.append(process_with_pool_client(i))
        
        results = await asyncio.gather(*tasks)
        return results
        
    finally:
        await pool.close()
```

## Configuration Reference

### Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PYVIDER_PLUGIN_CLIENT_RETRY_ENABLED` | `true` | Enable connection retry |
| `PYVIDER_PLUGIN_CLIENT_MAX_RETRIES` | `3` | Maximum retry attempts |
| `PYVIDER_PLUGIN_CLIENT_INITIAL_BACKOFF_MS` | `500` | Initial backoff delay |
| `PYVIDER_PLUGIN_CLIENT_MAX_BACKOFF_MS` | `5000` | Maximum backoff delay |
| `PYVIDER_PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S` | `60` | Total retry timeout |
| `PYVIDER_PLUGIN_HANDSHAKE_TIMEOUT` | `10.0` | Handshake timeout seconds |
| `PYVIDER_PLUGIN_CONNECTION_TIMEOUT` | `30.0` | Connection timeout seconds |

**[📖 Complete Configuration Reference](../config/)**

## Examples and Resources

### Working Examples
- **[ch02_quick_start_client.py](../../examples/ch02_quick_start_client.py)** - Basic client patterns
- **[ch06_client_setup_concepts.py](../../examples/ch06_client_setup_concepts.py)** - Client configuration  
- **[ch07_echo_client.py](../../examples/ch07_echo_client.py)** - Complete echo client implementation
- **[ch08_direct_client_connection.py](../../examples/ch08_direct_client_connection.py)** - Direct connection patterns
- **[ch15_e2e_client.py](../../examples/ch15_e2e_client.py)** - Production client example

### Related Documentation
- **[API Reference](../../api/client/)** - Complete client API documentation
- **[Configuration Guide](../config/)** - Environment and configuration setup
- **[Error Handling Guide](error-handling.md)** - Error handling and recovery patterns
- **[Examples Overview](../../getting-started/examples.md)** - All available examples

## Next Steps

1. **[Start with Basic Setup](basic-setup.md)** - Learn client fundamentals
2. **[Master Connection Management](connections.md)** - Handle connection lifecycle  
3. **[Implement Error Handling](error-handling.md)** - Build robust error recovery
4. **[Configure Retry Logic](retry-logic.md)** - Optimize retry behavior
5. **[Use Direct Connections](direct-connections.md)** - Connect to existing servers