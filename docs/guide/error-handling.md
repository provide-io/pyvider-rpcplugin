# Error Handling

Robust plugin systems require comprehensive error handling. Pyvider RPC Plugin provides a structured exception hierarchy and patterns for building resilient applications.

## Exception Hierarchy

### Core Exceptions

All plugin-related exceptions inherit from the base `RPCPluginError`:

```python
from pyvider.rpcplugin.exception import (
    RPCPluginError,      # Base exception
    TransportError,      # Network/transport issues  
    HandshakeError,      # Connection establishment failures
    ProtocolError,       # Protocol violations
    SecurityError,       # Authentication/encryption issues
    ConfigError,         # Configuration problems
)
```

### Exception Details

Each exception provides helpful context:

```python
try:
    await client.start()
except RPCPluginError as e:
    print(f"Error: {e.message}")     # Human-readable description
    print(f"Hint: {e.hint}")         # Resolution suggestion
    print(f"Code: {e.code}")         # Optional error code
```

### Specific Exception Types

#### `TransportError`
**When it occurs:** Network connection issues, socket errors, transport setup failures

**Common scenarios:**
- Plugin process fails to start
- Network connectivity problems
- Port conflicts or binding issues
- Unix socket permission problems

```python
try:
    client = plugin_client(command=["python", "my_plugin.py"])
    await client.start()
except TransportError as e:
    logger.error(f"❌ Connection failed: {e.message}")
    if "port" in str(e).lower():
        # Try different port
        configure(tcp_port=0)  # Auto-assign port
    elif "permission" in str(e).lower():
        # Fix socket permissions
        configure(unix_socket_permissions=0o666)
```

#### `HandshakeError`
**When it occurs:** Authentication and protocol negotiation failures

**Common scenarios:**
- Magic cookie mismatch
- Protocol version incompatibility  
- mTLS certificate validation failures
- Handshake timeout

```python
try:
    await client.start()
except HandshakeError as e:
    logger.error(f"🤝 Handshake failed: {e.message}")
    if "magic cookie" in str(e).lower():
        # Check magic cookie configuration
        cookie_key = rpcplugin_config.magic_cookie_key()
        logger.error(f"Expected cookie key: {cookie_key}")
    elif "certificate" in str(e).lower():
        # Check mTLS configuration
        logger.error("Verify certificate paths and validity")
```

#### `SecurityError` / `CertificateError`
**When it occurs:** Security and certificate-related issues

**Common scenarios:**
- Invalid certificate files
- Expired certificates
- Key/certificate mismatches
- CA trust issues

```python
from pyvider.rpcplugin.exception import CertificateError

try:
    configure(
        auto_mtls=True,
        server_cert="file:///path/to/cert.pem",
        server_key="file:///path/to/key.pem"
    )
except CertificateError as e:
    logger.error(f"🔐 Certificate error: {e.message}")
    # Check certificate validity
    # openssl x509 -in cert.pem -text -noout
```

#### `ConfigError`
**When it occurs:** Configuration validation and loading issues

**Common scenarios:**
- Missing required configuration
- Invalid configuration values
- Environment variable parsing errors

```python
try:
    server = plugin_server(protocol=my_protocol, handler=my_handler)
except ConfigError as e:
    logger.error(f"⚙️ Configuration error: {e.message}")
    if e.hint:
        logger.error(f"💡 Hint: {e.hint}")
```

## gRPC Errors

After successful connection, RPC method calls may raise gRPC errors:

```python
import grpc
from my_service_pb2_grpc import MyServiceStub

async def make_rpc_call():
    try:
        stub = MyServiceStub(client.grpc_channel)
        response = await stub.MyMethod(request)
        return response
    except grpc.aio.AioRpcError as e:
        status_code = e.code()
        error_details = e.details()
        
        if status_code == grpc.StatusCode.UNAVAILABLE:
            logger.warning("🔄 Service temporarily unavailable")
            # Implement retry logic
        elif status_code == grpc.StatusCode.UNIMPLEMENTED:
            logger.error(f"❌ Method not implemented: {error_details}")
            # Handle unsupported operation
        elif status_code == grpc.StatusCode.DEADLINE_EXCEEDED:
            logger.error("⏰ Request timeout")
            # Increase timeout or optimize request
        else:
            logger.error(f"🚨 RPC error: {status_code} - {error_details}")
```

## Error Handling Patterns

### 1. Graceful Degradation

Provide fallback functionality when plugins fail:

```python
async def resilient_plugin_call():
    """Call plugin with fallback to local implementation."""
    try:
        # Try plugin first
        result = await plugin_method()
        return result
    except (TransportError, HandshakeError) as e:
        logger.warning(f"Plugin unavailable: {e}, using fallback")
        # Fallback to local implementation
        return local_fallback_method()
    except grpc.aio.AioRpcError as e:
        if e.code() == grpc.StatusCode.UNAVAILABLE:
            logger.warning("Plugin service unavailable, using cache")
            return cached_result()
        raise  # Re-raise unexpected gRPC errors
```

### 2. Retry with Exponential Backoff

Handle transient failures with intelligent retry:

```python
import asyncio
import random
from typing import Callable, Any

async def retry_with_backoff(
    func: Callable,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_factor: float = 2.0,
    jitter: bool = True
) -> Any:
    """Retry function with exponential backoff."""
    
    for attempt in range(max_retries):
        try:
            return await func()
        except (TransportError, grpc.aio.AioRpcError) as e:
            # Check if error is retryable
            if isinstance(e, grpc.aio.AioRpcError):
                if e.code() not in [grpc.StatusCode.UNAVAILABLE, 
                                   grpc.StatusCode.RESOURCE_EXHAUSTED,
                                   grpc.StatusCode.DEADLINE_EXCEEDED]:
                    raise  # Don't retry non-transient errors
            
            if attempt == max_retries - 1:
                logger.error(f"❌ All {max_retries} attempts failed")
                raise
            
            # Calculate delay with exponential backoff
            delay = min(base_delay * (backoff_factor ** attempt), max_delay)
            if jitter:
                delay *= (0.5 + random.random() * 0.5)  # Add jitter
            
            logger.warning(f"🔄 Attempt {attempt + 1} failed: {e}")
            logger.info(f"⏰ Retrying in {delay:.1f}s...")
            await asyncio.sleep(delay)

# Usage
async def make_reliable_call():
    return await retry_with_backoff(
        lambda: stub.MyMethod(request),
        max_retries=3
    )
```

### 3. Circuit Breaker Pattern

Prevent cascading failures with circuit breaker:

```python
import time
from enum import Enum

class CircuitState(Enum):
    CLOSED = "closed"      # Normal operation
    OPEN = "open"         # Failing, reject calls
    HALF_OPEN = "half_open"  # Testing recovery

class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        success_threshold: int = 2
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout  
        self.success_threshold = success_threshold
        
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = 0
        self.state = CircuitState.CLOSED
    
    async def call(self, func: Callable) -> Any:
        """Execute function with circuit breaker protection."""
        
        # Check if we should attempt recovery
        if (self.state == CircuitState.OPEN and 
            time.time() - self.last_failure_time >= self.recovery_timeout):
            self.state = CircuitState.HALF_OPEN
            self.success_count = 0
            logger.info("🔄 Circuit breaker: HALF_OPEN")
        
        # Reject calls if circuit is open
        if self.state == CircuitState.OPEN:
            raise TransportError("Circuit breaker is OPEN")
        
        try:
            result = await func()
            
            # Success handling
            if self.state == CircuitState.HALF_OPEN:
                self.success_count += 1
                if self.success_count >= self.success_threshold:
                    self._reset()
                    logger.info("✅ Circuit breaker: CLOSED")
            
            return result
            
        except Exception as e:
            self._record_failure()
            raise e
    
    def _record_failure(self):
        """Record a failure."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.warning(f"🚫 Circuit breaker: OPEN after {self.failure_count} failures")
    
    def _reset(self):
        """Reset circuit to closed state."""
        self.failure_count = 0
        self.success_count = 0
        self.state = CircuitState.CLOSED

# Usage
circuit_breaker = CircuitBreaker(failure_threshold=3)

async def protected_plugin_call():
    return await circuit_breaker.call(
        lambda: stub.MyMethod(request)
    )
```

### 4. Health Monitoring

Proactively monitor plugin health:

```python
async def monitor_plugin_health(client: RPCPluginClient):
    """Monitor plugin health and restart if needed."""
    
    while True:
        try:
            # Check if client is connected
            if not client.is_started:
                logger.warning("🔄 Plugin disconnected, reconnecting...")
                await client.start()
                continue
            
            # Optional: Make health check RPC
            # health_response = await health_stub.Check(HealthCheckRequest())
            
            # Check gRPC channel state
            channel_state = client.grpc_channel.get_state()
            if channel_state not in [grpc.ChannelConnectivity.READY,
                                   grpc.ChannelConnectivity.IDLE]:
                logger.warning(f"⚠️ Channel state: {channel_state}")
                # Consider reconnection
                
        except Exception as e:
            logger.error(f"❌ Health check failed: {e}")
            
        await asyncio.sleep(30)  # Check every 30 seconds
```

## Error Recovery Strategies

### Automatic Reconnection

```python
class ResilientPluginClient:
    def __init__(self, plugin_command: list[str]):
        self.plugin_command = plugin_command
        self.client = None
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5
    
    async def ensure_connected(self):
        """Ensure plugin is connected, reconnect if needed."""
        if self.client and self.client.is_started:
            return
        
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            raise TransportError("Max reconnection attempts exceeded")
        
        try:
            if self.client:
                await self.client.close()
            
            self.client = plugin_client(command=self.plugin_command)
            await self.client.start()
            self.reconnect_attempts = 0
            logger.info("✅ Plugin reconnected successfully")
            
        except Exception as e:
            self.reconnect_attempts += 1
            logger.error(f"🔄 Reconnection attempt {self.reconnect_attempts} failed: {e}")
            raise
    
    async def call_with_retry(self, func: Callable) -> Any:
        """Make RPC call with automatic reconnection."""
        try:
            await self.ensure_connected()
            return await func(self.client)
        except (TransportError, HandshakeError):
            logger.warning("Connection lost, attempting reconnection...")
            self.client = None  # Force reconnection
            await self.ensure_connected()
            return await func(self.client)
```

### Resource Cleanup

Always ensure proper cleanup:

```python
async def robust_plugin_usage():
    """Example of robust plugin resource management."""
    client = None
    try:
        # Setup
        client = plugin_client(command=["python", "my_plugin.py"])
        await client.start()
        
        # Use plugin
        stub = MyServiceStub(client.grpc_channel)
        result = await stub.MyMethod(request)
        
        return result
        
    except TransportError as e:
        logger.error(f"❌ Transport error: {e}")
        # Maybe try fallback or retry
        raise
    except HandshakeError as e:
        logger.error(f"🤝 Handshake error: {e}")
        # Check configuration
        raise
    except grpc.aio.AioRpcError as e:
        logger.error(f"📡 RPC error: {e.code()} - {e.details()}")
        raise
    except Exception as e:
        logger.error(f"💥 Unexpected error: {e}", exc_info=True)
        raise
    finally:
        # Always cleanup
        if client:
            try:
                await client.close()
                logger.info("🔌 Plugin cleanup completed")
            except Exception as cleanup_error:
                logger.error(f"⚠️ Cleanup error: {cleanup_error}")
```

## Best Practices

### 1. Error Classification

Categorize errors for appropriate handling:

```python
def classify_error(error: Exception) -> str:
    """Classify errors for appropriate handling."""
    if isinstance(error, HandshakeError):
        return "authentication"
    elif isinstance(error, TransportError):
        return "connectivity"
    elif isinstance(error, CertificateError):
        return "security"
    elif isinstance(error, grpc.aio.AioRpcError):
        if error.code() == grpc.StatusCode.UNAVAILABLE:
            return "temporary"
        elif error.code() in [grpc.StatusCode.UNIMPLEMENTED,
                             grpc.StatusCode.NOT_FOUND]:
            return "permanent"
    return "unknown"

async def handle_classified_error(func: Callable):
    try:
        return await func()
    except Exception as e:
        error_type = classify_error(e)
        
        if error_type == "temporary":
            # Retry with backoff
            return await retry_with_backoff(func)
        elif error_type == "connectivity":
            # Try fallback
            return await fallback_method()
        elif error_type == "permanent":
            # Log and fail fast
            logger.error(f"Permanent error: {e}")
            raise
        else:
            # Unknown error, be cautious
            logger.error(f"Unknown error: {e}", exc_info=True)
            raise
```

### 2. Structured Error Logging

Use structured logging for better observability:

```python
from provide.foundation import logger

async def log_plugin_error(error: Exception, context: dict[str, Any]):
    """Log plugin errors with structured context."""
    
    error_data = {
        "error_type": type(error).__name__,
        "error_message": str(error),
        "plugin_command": context.get("command"),
        "transport": context.get("transport"),
        "mtls_enabled": context.get("mtls_enabled"),
    }
    
    if isinstance(error, RPCPluginError):
        error_data.update({
            "error_code": error.code,
            "error_hint": error.hint,
        })
    
    if isinstance(error, grpc.aio.AioRpcError):
        error_data.update({
            "grpc_code": error.code().name,
            "grpc_details": error.details(),
        })
    
    logger.error("❌ Plugin operation failed", **error_data)
```

### 3. User-Friendly Error Messages

Translate technical errors to user-friendly messages:

```python
def get_user_friendly_message(error: Exception) -> str:
    """Convert technical errors to user-friendly messages."""
    
    if isinstance(error, HandshakeError):
        if "magic cookie" in str(error).lower():
            return "Plugin authentication failed. Please check plugin configuration."
        elif "timeout" in str(error).lower():
            return "Plugin took too long to start. Please try again."
    
    elif isinstance(error, TransportError):
        if "connection refused" in str(error).lower():
            return "Could not connect to plugin. The plugin may not be running."
        elif "permission denied" in str(error).lower():
            return "Permission denied. Please check file permissions."
    
    elif isinstance(error, CertificateError):
        return "Security certificate error. Please check SSL/TLS configuration."
    
    elif isinstance(error, grpc.aio.AioRpcError):
        if error.code() == grpc.StatusCode.UNAVAILABLE:
            return "Service is temporarily unavailable. Please try again later."
        elif error.code() == grpc.StatusCode.UNIMPLEMENTED:
            return "The requested operation is not supported."
    
    return "An unexpected error occurred. Please contact support."
```

## What's Next?

Now that you understand error handling:

- **[Testing](testing.md)** - Learn how to test error conditions
- **[Monitoring](../production/monitoring.md)** - Set up error monitoring and alerting  
- **[Performance](performance.md)** - Optimize error handling performance
- **[Production Deployment](../production/)** - Error handling in production