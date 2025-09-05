# RPCPluginClient API

The `RPCPluginClient` class provides the client-side interface for communicating with Pyvider RPC Plugin servers. It handles the complete lifecycle of plugin connections including process management, secure communication, and service interaction.

## Overview

The client follows a sophisticated lifecycle pattern: subprocess launch → handshake negotiation → secure channel establishment → service stub creation → ongoing communication → graceful shutdown. It includes automatic retry logic, comprehensive error handling, and support for both Unix socket and TCP transport protocols.

## Quick Start

```python
from pyvider.rpcplugin.client import RPCPluginClient

# Create and start a client
async def run_client():
    client = RPCPluginClient(
        command=["python", "-m", "my_plugin_server"]
    )
    
    async with client:
        # Client is automatically started and will be closed on exit
        # Use client.grpc_channel for your protocol-specific stubs
        my_stub = MyServiceStub(client.grpc_channel)
        response = await my_stub.MyMethod(request)
        print(f"Response: {response}")
```

## Factory Function Usage

The recommended way to create clients is using the `plugin_client` factory:

```python
from pyvider.rpcplugin.factories import plugin_client

# Basic client
client = plugin_client(
    command=["./my-plugin-server"]
)

# Client with configuration overrides
client = plugin_client(
    command=["python", "-m", "my_plugin"],
    config={
        "env": {
            "PLUGIN_LOG_LEVEL": "DEBUG",
            "MY_PLUGIN_CONFIG": "production"
        }
    },
    auto_connect=False  # Don't attempt immediate connection
)

await client.start()
```

## Configuration Options

Client behavior is controlled through environment variables and config overrides:

### Connection Configuration

```bash
export PLUGIN_CONNECTION_TIMEOUT=30.0  # Connection timeout in seconds
export PLUGIN_HANDSHAKE_TIMEOUT=10.0   # Handshake timeout in seconds
```

### Retry Configuration

```bash
export PLUGIN_CLIENT_RETRY_ENABLED=true
export PLUGIN_CLIENT_MAX_RETRIES=3
export PLUGIN_CLIENT_INITIAL_BACKOFF_MS=500
export PLUGIN_CLIENT_MAX_BACKOFF_MS=5000
export PLUGIN_CLIENT_RETRY_JITTER_MS=100
export PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S=60
```

### Security Configuration

**Magic Cookie Authentication**:
```bash
export PLUGIN_MAGIC_COOKIE_KEY="MY_PLUGIN_COOKIE"
export PLUGIN_MAGIC_COOKIE_VALUE="super-secret-value"
```

**Automatic mTLS**:
```bash
export PLUGIN_AUTO_MTLS=true
export PLUGIN_CLIENT_CERT="file:///path/to/client.crt"  # Optional manual cert
export PLUGIN_CLIENT_KEY="file:///path/to/client.key"   # Optional manual key
export PLUGIN_CLIENT_ROOT_CERTS="file:///path/to/ca.crt"  # Server CA
```

## Client Lifecycle

### 1. Construction and Configuration

```python
from pyvider.rpcplugin.client import RPCPluginClient

# Direct construction
client = RPCPluginClient(
    command=["python", "-m", "my_plugin_server"],
    config={
        "env": {
            "PLUGIN_LOG_LEVEL": "DEBUG"
        }
    }
)
```

During construction, the client:
- Stores command and configuration parameters
- Initializes internal state and events
- Prepares for process management

### 2. Client Startup Process

The `start()` method orchestrates the complete connection process:

```python
await client.start()
```

This method performs:

1. **Certificate Setup**: If auto-mTLS is enabled, loads or generates client certificates
2. **Process Launch**: Starts the plugin server subprocess with environment configuration
3. **Handshake Negotiation**: 
   - Reads handshake response from plugin stdout
   - Parses transport type, address, protocol version, server certificate
   - Establishes the appropriate transport connection
4. **Secure Channel Creation**: Creates gRPC channel with TLS/mTLS if configured
5. **Service Stub Initialization**: Sets up standard gRPC stubs (stdio, broker, controller)
6. **Background Task Startup**: Begins streaming plugin logs

### 3. Service Communication

After startup, use the gRPC channel for service-specific communication:

```python
# Access the gRPC channel for custom stubs
if client.grpc_channel:
    my_service_stub = MyServiceStub(client.grpc_channel)
    
    # Make RPC calls
    response = await my_service_stub.GetInfo(request)
    
    # Stream-based communication
    async for item in my_service_stub.StreamData(request):
        process_item(item)
```

### 4. Graceful Shutdown

```python
# Request plugin shutdown
await client.shutdown_plugin()

# Clean up client resources
await client.close()

# Or use context manager for automatic cleanup
async with client:
    # Your code here
    pass  # Client automatically shuts down and closes
```

## Advanced Usage

### Custom Process Configuration

```python
client = RPCPluginClient(
    command=["./my-plugin", "--config", "/path/to/config.yaml"],
    config={
        "env": {
            # Plugin-specific environment
            "PLUGIN_LOG_LEVEL": "DEBUG",
            "PLUGIN_DATA_DIR": "/tmp/plugin-data",
            # Standard configuration
            "PLUGIN_AUTO_MTLS": "true",
            "PLUGIN_CONNECTION_TIMEOUT": "45.0",
        }
    }
)
```

### Retry Behavior Customization

```python
# Disable retries for debugging
client = RPCPluginClient(
    command=["./my-plugin"],
    config={
        "env": {
            "PLUGIN_CLIENT_RETRY_ENABLED": "false"
        }
    }
)

# Aggressive retry settings
client = RPCPluginClient(
    command=["./unreliable-plugin"],
    config={
        "env": {
            "PLUGIN_CLIENT_RETRY_ENABLED": "true",
            "PLUGIN_CLIENT_MAX_RETRIES": "10",
            "PLUGIN_CLIENT_INITIAL_BACKOFF_MS": "100",
            "PLUGIN_CLIENT_MAX_BACKOFF_MS": "2000",
            "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": "120",
        }
    }
)
```

### Connection Monitoring

```python
# Monitor connection events
client = RPCPluginClient(command=["./my-plugin"])

# Wait for handshake completion
try:
    await client.start()
    await asyncio.wait_for(
        client._handshake_complete_event.wait(), 
        timeout=10.0
    )
    print("Handshake successful!")
except asyncio.TimeoutError:
    print("Handshake timed out")
except Exception as e:
    print(f"Connection failed: {e}")
```

### Broker Subchannel Usage

For plugins that support multiple services:

```python
# Open a subchannel for additional service
await client.open_broker_subchannel(
    sub_id=123,
    address="127.0.0.1:50052"
)

# The broker handles the subchannel lifecycle
# You can then create stubs for services on that subchannel
```

## Error Handling

### Connection Error Types

```python
from pyvider.rpcplugin.exception import (
    HandshakeError,
    TransportError,
    SecurityError,
    ProtocolError
)

try:
    await client.start()
except HandshakeError as e:
    print(f"Handshake failed: {e.message}")
    if e.hint:
        print(f"Hint: {e.hint}")
except TransportError as e:
    print(f"Transport error: {e.message}")
except SecurityError as e:
    print(f"Security/TLS error: {e.message}")
except ProtocolError as e:
    print(f"Protocol error: {e.message}")
```

### Common Issues and Solutions

**Plugin process fails to start**:
- Verify command path and executable permissions
- Check plugin dependencies and environment
- Review plugin logs for startup errors

**Handshake timeout**:
- Increase `PLUGIN_HANDSHAKE_TIMEOUT`
- Check plugin stdout for handshake output
- Verify plugin implements the handshake protocol correctly

**TLS/mTLS errors**:
- Verify certificate paths and permissions
- Check certificate validity and format
- Ensure client and server certificate configurations match

**Connection refused**:
- Check if plugin server is listening on the expected address
- Verify firewall and network configuration for TCP transport
- For Unix sockets, check socket file permissions

### Retry Logic and Recovery

```python
async def robust_client_connection():
    """Client with comprehensive error handling and recovery."""
    client = None
    try:
        client = RPCPluginClient(
            command=["./my-plugin"],
            config={
                "env": {
                    # Enable retries with reasonable settings
                    "PLUGIN_CLIENT_RETRY_ENABLED": "true",
                    "PLUGIN_CLIENT_MAX_RETRIES": "5",
                    "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": "60",
                }
            }
        )
        
        await client.start()
        
        # Client is ready for use
        yield client
        
    except HandshakeError as e:
        logger.error(f"Failed to establish connection: {e.message}")
        if "process exited" in e.message:
            logger.error("Plugin process crashed during startup")
        raise
        
    except TransportError as e:
        logger.error(f"Transport error: {e.message}")
        raise
        
    finally:
        if client:
            try:
                await client.shutdown_plugin()
            except Exception as e:
                logger.warning(f"Error during shutdown: {e}")
            finally:
                await client.close()
```

## Production Deployment

### Resource Management

```python
import asyncio
import signal
from contextlib import asynccontextmanager

class PluginManager:
    """Production-grade plugin client manager."""
    
    def __init__(self, command: list[str]):
        self.command = command
        self.client = None
        self.shutdown_event = asyncio.Event()
    
    async def start(self):
        """Start the plugin client with production configuration."""
        self.client = RPCPluginClient(
            command=self.command,
            config={
                "env": {
                    # Production settings
                    "PLUGIN_AUTO_MTLS": "true",
                    "PLUGIN_CONNECTION_TIMEOUT": "30.0",
                    "PLUGIN_CLIENT_RETRY_ENABLED": "true",
                    "PLUGIN_CLIENT_MAX_RETRIES": "3",
                    "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": "90",
                }
            }
        )
        
        # Setup signal handling
        def handle_signal():
            self.shutdown_event.set()
        
        signal.signal(signal.SIGTERM, lambda s, f: handle_signal())
        signal.signal(signal.SIGINT, lambda s, f: handle_signal())
        
        await self.client.start()
        
    async def run(self):
        """Main application loop."""
        try:
            await self.start()
            
            # Your application logic here
            my_stub = MyServiceStub(self.client.grpc_channel)
            
            while not self.shutdown_event.is_set():
                try:
                    # Perform RPC operations
                    response = await asyncio.wait_for(
                        my_stub.SomeMethod(request),
                        timeout=5.0
                    )
                    # Process response
                    await asyncio.sleep(1.0)
                    
                except asyncio.TimeoutError:
                    logger.warning("RPC call timed out")
                except Exception as e:
                    logger.error(f"RPC call failed: {e}")
                    await asyncio.sleep(5.0)  # Backoff on error
                    
        finally:
            await self.shutdown()
    
    async def shutdown(self):
        """Graceful shutdown with timeout."""
        if self.client:
            try:
                await asyncio.wait_for(
                    self.client.shutdown_plugin(),
                    timeout=10.0
                )
            except asyncio.TimeoutError:
                logger.warning("Plugin shutdown timed out")
            except Exception as e:
                logger.error(f"Error during shutdown: {e}")
            finally:
                await self.client.close()

# Usage
async def main():
    manager = PluginManager(["./my-production-plugin"])
    await manager.run()

if __name__ == "__main__":
    asyncio.run(main())
```

### Health Monitoring

```python
import asyncio
import time
from dataclasses import dataclass

@dataclass
class ClientHealth:
    is_connected: bool
    last_successful_call: float
    total_calls: int
    failed_calls: int
    handshake_time: float

class HealthMonitoredClient:
    """Client wrapper with health monitoring."""
    
    def __init__(self, command: list[str]):
        self.client = RPCPluginClient(command=command)
        self.health = ClientHealth(
            is_connected=False,
            last_successful_call=0,
            total_calls=0,
            failed_calls=0,
            handshake_time=0
        )
    
    async def start(self):
        start_time = time.time()
        await self.client.start()
        self.health.handshake_time = time.time() - start_time
        self.health.is_connected = True
    
    async def call_with_monitoring(self, stub_method, request):
        """Wrapper for RPC calls that tracks health metrics."""
        self.health.total_calls += 1
        
        try:
            response = await stub_method(request)
            self.health.last_successful_call = time.time()
            return response
            
        except Exception as e:
            self.health.failed_calls += 1
            logger.error(f"RPC call failed: {e}")
            raise
    
    def get_health_status(self) -> dict:
        """Get current health metrics."""
        now = time.time()
        return {
            "connected": self.health.is_connected,
            "handshake_duration": self.health.handshake_time,
            "total_calls": self.health.total_calls,
            "failed_calls": self.health.failed_calls,
            "success_rate": (
                (self.health.total_calls - self.health.failed_calls) / 
                max(self.health.total_calls, 1)
            ),
            "seconds_since_last_success": (
                now - self.health.last_successful_call
                if self.health.last_successful_call > 0 else -1
            ),
        }
```

## Security Considerations

### Certificate Management

```python
# Production certificate configuration
client = RPCPluginClient(
    command=["./secure-plugin"],
    config={
        "env": {
            # Use manual certificates for production
            "PLUGIN_AUTO_MTLS": "false",
            "PLUGIN_CLIENT_CERT": "file:///etc/ssl/client.crt",
            "PLUGIN_CLIENT_KEY": "file:///etc/ssl/client.key",
            "PLUGIN_CLIENT_ROOT_CERTS": "file:///etc/ssl/ca.crt",
        }
    }
)
```

### Process Isolation

- Run plugin processes with minimal privileges
- Use container isolation when possible
- Implement resource limits (CPU, memory, file descriptors)
- Monitor for suspicious plugin behavior

### Network Security

- Use Unix sockets for local plugins when possible
- Restrict TCP listening to localhost for local plugins
- Implement proper firewall rules for remote plugins
- Use strong TLS configurations with current cipher suites

## Class Reference

The following section provides detailed API reference for the RPCPluginClient class:

::: pyvider.rpcplugin.client.RPCPluginClient

## Related Components

- [Factory Functions](../factories.md) - `plugin_client()` factory function
- [Server API](../server/server.md) - Corresponding server implementation
- [Transport Layer](../transport/) - Transport protocol details
- [Configuration](../config/) - Complete configuration reference
- [Exception Handling](../../guide/error-handling.md) - Error handling patterns
- [Testing Guide](../../guide/testing.md) - Testing client implementations