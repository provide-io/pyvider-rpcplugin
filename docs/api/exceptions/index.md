# Exception Handling

The Pyvider RPC Plugin system provides a comprehensive exception hierarchy that enables precise error handling and debugging. All plugin-specific exceptions inherit from `RPCPluginError`, allowing for both broad and specific error handling patterns.

## Overview

The exception system provides:
- **Hierarchical Structure**: Clear inheritance hierarchy for precise error handling
- **Rich Error Information**: Messages, hints, and error codes for debugging
- **Foundation Integration**: Built on provide.foundation error framework
- **Backward Compatibility**: Consistent API across all exception types
- **Context Preservation**: Error context and stack traces maintained

All exceptions follow a consistent pattern with message, optional hint, and optional error code for comprehensive error reporting.

## Exception Hierarchy

```
RPCPluginError (base)
├── ConfigError
├── HandshakeError  
├── ProtocolError
├── TransportError
├── SecurityError
└── CertificateError (from provide.foundation.crypto)
```

## Base Exception: RPCPluginError

All plugin exceptions inherit from `RPCPluginError`, which provides the core error handling interface:

```python
from pyvider.rpcplugin.exception import RPCPluginError

class RPCPluginError(FoundationError):
    def __init__(
        self,
        message: str,
        hint: str | None = None,
        code: int | str | None = None,
        *args,
        **kwargs
    ):
        # Error details stored and accessible
        pass
```

**Attributes**:
- `message`: Human-readable error description
- `hint`: Optional guidance for resolving the error
- `code`: Optional error code for programmatic handling

**Usage**:
```python
try:
    # Plugin operation
    await plugin_operation()
except RPCPluginError as e:
    print(f"Plugin error: {e.message}")
    if e.hint:
        print(f"Resolution hint: {e.hint}")
    if e.code:
        print(f"Error code: {e.code}")
```

## Specific Exception Types

### ConfigError

**Purpose**: Configuration-related errors (validation, missing values, invalid formats)

**Common Scenarios**:
- Invalid configuration values
- Missing required configuration
- Configuration file parsing errors
- Environment variable format issues

```python
from pyvider.rpcplugin.exception import ConfigError

# Example usage in configuration validation
try:
    if not config.plugin_magic_cookie_value:
        raise ConfigError(
            message="Magic cookie value is required",
            hint="Set PLUGIN_MAGIC_COOKIE_VALUE environment variable",
            code="CONFIG_MISSING_COOKIE"
        )
except ConfigError as e:
    print(f"Configuration error: {e}")
```

### HandshakeError

**Purpose**: Errors during the plugin handshake protocol

**Common Scenarios**:
- Plugin process fails to start
- Invalid handshake response format
- Handshake timeout
- Process exits during handshake

```python
from pyvider.rpcplugin.exception import HandshakeError

# Example handshake validation
try:
    handshake_data = await read_handshake()
    if not handshake_data:
        raise HandshakeError(
            message="Empty handshake response from plugin",
            hint="Check plugin stdout output and ensure handshake protocol is implemented",
            code="HANDSHAKE_EMPTY_RESPONSE"
        )
except HandshakeError as e:
    print(f"Handshake failed: {e}")
```

### ProtocolError

**Purpose**: Protocol violations and RPC communication errors

**Common Scenarios**:
- Invalid RPC method calls
- Protocol version mismatches
- Service registration errors
- gRPC channel issues

```python
from pyvider.rpcplugin.exception import ProtocolError

# Example protocol validation
try:
    if protocol_version not in SUPPORTED_VERSIONS:
        raise ProtocolError(
            message=f"Unsupported protocol version: {protocol_version}",
            hint=f"Supported versions: {SUPPORTED_VERSIONS}",
            code="PROTOCOL_VERSION_MISMATCH"
        )
except ProtocolError as e:
    print(f"Protocol error: {e}")
```

### TransportError

**Purpose**: Network transport and communication failures

**Common Scenarios**:
- Connection failures (TCP/Unix socket)
- Port binding errors
- Socket permission issues
- Network timeouts

```python
from pyvider.rpcplugin.exception import TransportError

# Example transport error handling
try:
    await transport.connect(endpoint)
except OSError as e:
    raise TransportError(
        message=f"Failed to connect to {endpoint}",
        hint="Check network connectivity and endpoint availability",
        code="TRANSPORT_CONNECTION_FAILED"
    ) from e
```

### SecurityError

**Purpose**: Security and authentication-related errors

**Common Scenarios**:
- TLS/mTLS configuration errors
- Certificate validation failures
- Authentication failures
- Cryptographic errors

```python
from pyvider.rpcplugin.exception import SecurityError

# Example security validation
try:
    if not validate_certificate(cert):
        raise SecurityError(
            message="Invalid server certificate",
            hint="Check certificate validity and trust chain",
            code="SECURITY_INVALID_CERTIFICATE"
        )
except SecurityError as e:
    print(f"Security error: {e}")
```

### CertificateError

**Purpose**: Certificate-specific errors (imported from provide.foundation.crypto)

**Common Scenarios**:
- Certificate loading failures
- Invalid certificate format
- Certificate expiration
- Key/certificate mismatches

```python
from provide.foundation.crypto import CertificateError

# Example certificate handling
try:
    cert = Certificate(cert_pem=cert_data, key_pem=key_data)
except CertificateError as e:
    print(f"Certificate error: {e}")
```

## Error Handling Patterns

### Basic Exception Handling

```python
from pyvider.rpcplugin.exception import RPCPluginError, TransportError, HandshakeError

async def robust_plugin_client():
    try:
        client = RPCPluginClient(command=["./my-plugin"])
        await client.start()
        return client
        
    except HandshakeError as e:
        print(f"Plugin handshake failed: {e.message}")
        if "process exited" in e.message:
            print("Plugin process crashed during startup")
        raise
        
    except TransportError as e:
        print(f"Transport error: {e.message}")
        if e.hint:
            print(f"Try: {e.hint}")
        raise
        
    except RPCPluginError as e:
        print(f"General plugin error: {e.message}")
        raise
```

### Granular Error Handling

```python
from pyvider.rpcplugin.exception import *

async def detailed_error_handling():
    try:
        await setup_plugin_server()
        
    except ConfigError as e:
        if "magic cookie" in e.message.lower():
            print("Authentication configuration issue")
        elif "transport" in e.message.lower():
            print("Transport configuration issue")
        else:
            print(f"Configuration error: {e.message}")
    
    except SecurityError as e:
        if "certificate" in e.message.lower():
            print("Certificate configuration issue")
        elif "tls" in e.message.lower():
            print("TLS configuration issue")
        else:
            print(f"Security error: {e.message}")
    
    except TransportError as e:
        if "port" in e.message.lower():
            print("Port binding issue")
        elif "permission" in e.message.lower():
            print("Socket permission issue")
        else:
            print(f"Transport error: {e.message}")
```

### Error Recovery Patterns

```python
import asyncio
from pyvider.rpcplugin.exception import TransportError, HandshakeError

async def retry_with_backoff(operation, max_retries=3):
    """Retry operation with exponential backoff."""
    
    for attempt in range(max_retries):
        try:
            return await operation()
            
        except (TransportError, HandshakeError) as e:
            if attempt == max_retries - 1:
                print(f"Operation failed after {max_retries} attempts: {e}")
                raise
            
            wait_time = 2 ** attempt
            print(f"Attempt {attempt + 1} failed: {e.message}")
            print(f"Retrying in {wait_time}s...")
            await asyncio.sleep(wait_time)

# Usage
async def connect_with_retry():
    async def connect_operation():
        client = RPCPluginClient(command=["./plugin"])
        await client.start()
        return client
    
    return await retry_with_backoff(connect_operation)
```

### Logging Integration

```python
import logging
from pyvider.rpcplugin.exception import RPCPluginError

logger = logging.getLogger(__name__)

async def logged_plugin_operation():
    try:
        await plugin_operation()
        
    except RPCPluginError as e:
        # Log with structured information
        logger.error(
            "Plugin operation failed",
            extra={
                "error_type": e.__class__.__name__,
                "error_message": e.message,
                "error_hint": e.hint,
                "error_code": e.code,
                "operation": "plugin_operation"
            }
        )
        
        # Re-raise for caller handling
        raise
```

## Production Error Handling

### Comprehensive Error Handler

```python
from pyvider.rpcplugin.exception import *
import traceback

class PluginErrorHandler:
    """Production-grade error handler for plugin operations."""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.error_counts = {}
    
    async def handle_error(self, error: Exception, operation: str = "unknown"):
        """Handle and categorize plugin errors."""
        
        error_type = error.__class__.__name__
        self.error_counts[error_type] = self.error_counts.get(error_type, 0) + 1
        
        if isinstance(error, ConfigError):
            await self._handle_config_error(error, operation)
        elif isinstance(error, HandshakeError):
            await self._handle_handshake_error(error, operation)
        elif isinstance(error, TransportError):
            await self._handle_transport_error(error, operation)
        elif isinstance(error, SecurityError):
            await self._handle_security_error(error, operation)
        elif isinstance(error, RPCPluginError):
            await self._handle_generic_plugin_error(error, operation)
        else:
            await self._handle_unexpected_error(error, operation)
    
    async def _handle_config_error(self, error: ConfigError, operation: str):
        self.logger.error(f"Configuration error in {operation}: {error.message}")
        if error.hint:
            self.logger.info(f"Resolution hint: {error.hint}")
        
        # Potentially restart with default configuration
        if "magic cookie" in error.message.lower():
            self.logger.warning("Consider regenerating magic cookie value")
    
    async def _handle_handshake_error(self, error: HandshakeError, operation: str):
        self.logger.error(f"Handshake error in {operation}: {error.message}")
        
        if "timeout" in error.message.lower():
            self.logger.warning("Consider increasing PLUGIN_HANDSHAKE_TIMEOUT")
        elif "process exited" in error.message.lower():
            self.logger.critical("Plugin process crashed - check plugin logs")
    
    async def _handle_transport_error(self, error: TransportError, operation: str):
        self.logger.error(f"Transport error in {operation}: {error.message}")
        
        if "port" in error.message.lower():
            self.logger.warning("Port conflict detected - consider using port 0 for auto-assignment")
        elif "permission" in error.message.lower():
            self.logger.warning("Socket permission issue - check file system permissions")
    
    async def _handle_security_error(self, error: SecurityError, operation: str):
        self.logger.error(f"Security error in {operation}: {error.message}")
        self.logger.warning("Check TLS/mTLS configuration and certificate validity")
    
    async def _handle_generic_plugin_error(self, error: RPCPluginError, operation: str):
        self.logger.error(f"Plugin error in {operation}: {error.message}")
        if error.hint:
            self.logger.info(f"Resolution hint: {error.hint}")
    
    async def _handle_unexpected_error(self, error: Exception, operation: str):
        self.logger.error(f"Unexpected error in {operation}: {error}")
        self.logger.debug(f"Stack trace: {traceback.format_exc()}")
    
    def get_error_summary(self):
        """Get summary of error counts for monitoring."""
        return dict(self.error_counts)

# Usage
error_handler = PluginErrorHandler()

async def production_plugin_operation():
    try:
        await plugin_operation()
    except Exception as e:
        await error_handler.handle_error(e, "production_plugin_operation")
        raise
```

### Health Check Integration

```python
from pyvider.rpcplugin.exception import RPCPluginError

class PluginHealthMonitor:
    """Monitor plugin health based on error patterns."""
    
    def __init__(self):
        self.error_history = []
        self.max_history = 100
    
    def record_error(self, error: Exception):
        """Record error for health monitoring."""
        self.error_history.append({
            "timestamp": time.time(),
            "error_type": error.__class__.__name__,
            "message": str(error),
            "is_plugin_error": isinstance(error, RPCPluginError)
        })
        
        # Keep only recent errors
        if len(self.error_history) > self.max_history:
            self.error_history = self.error_history[-self.max_history:]
    
    def get_health_status(self):
        """Assess plugin health based on error patterns."""
        if not self.error_history:
            return {"status": "healthy", "errors": []}
        
        recent_errors = [
            e for e in self.error_history 
            if time.time() - e["timestamp"] < 300  # Last 5 minutes
        ]
        
        if len(recent_errors) > 10:
            return {"status": "unhealthy", "reason": "high error rate"}
        
        critical_errors = [
            e for e in recent_errors 
            if "HandshakeError" in e["error_type"] or "SecurityError" in e["error_type"]
        ]
        
        if critical_errors:
            return {"status": "degraded", "reason": "critical errors detected"}
        
        return {"status": "healthy", "recent_errors": len(recent_errors)}
```

## Testing Exception Handling

### Exception Testing Patterns

```python
import pytest
from pyvider.rpcplugin.exception import *

def test_config_error_creation():
    """Test ConfigError instantiation and attributes."""
    error = ConfigError(
        message="Invalid configuration",
        hint="Check environment variables",
        code="CONFIG_001"
    )
    
    assert error.message == "Invalid configuration"
    assert error.hint == "Check environment variables"
    assert error.code == "CONFIG_001"
    assert "ConfigError" in str(error)
    assert "Hint:" in str(error)

def test_error_hierarchy():
    """Test exception inheritance hierarchy."""
    config_error = ConfigError("test")
    transport_error = TransportError("test")
    
    assert isinstance(config_error, RPCPluginError)
    assert isinstance(transport_error, RPCPluginError)
    assert not isinstance(config_error, TransportError)

@pytest.mark.asyncio
async def test_exception_handling_in_context():
    """Test exception handling in realistic context."""
    with pytest.raises(HandshakeError) as exc_info:
        raise HandshakeError(
            message="Handshake timeout",
            hint="Increase timeout value",
            code="HANDSHAKE_TIMEOUT"
        )
    
    error = exc_info.value
    assert error.message == "Handshake timeout"
    assert error.hint == "Increase timeout value"
```

### Mock Error Scenarios

```python
import asyncio
from unittest.mock import AsyncMock, patch
from pyvider.rpcplugin.exception import *

class MockPluginErrors:
    """Mock various plugin error scenarios for testing."""
    
    @staticmethod
    async def simulate_handshake_timeout():
        """Simulate handshake timeout scenario."""
        await asyncio.sleep(0.1)  # Simulate delay
        raise HandshakeError(
            message="Handshake timed out waiting for response",
            hint="Increase PLUGIN_HANDSHAKE_TIMEOUT or check plugin startup",
            code="HANDSHAKE_TIMEOUT"
        )
    
    @staticmethod
    async def simulate_transport_failure():
        """Simulate transport connection failure."""
        raise TransportError(
            message="Failed to connect to Unix socket",
            hint="Check socket path and permissions",
            code="TRANSPORT_CONNECTION_FAILED"
        )
    
    @staticmethod
    async def simulate_config_error():
        """Simulate configuration validation error."""
        raise ConfigError(
            message="Magic cookie value not set",
            hint="Set PLUGIN_MAGIC_COOKIE_VALUE environment variable",
            code="CONFIG_MISSING_COOKIE"
        )

# Test usage
@pytest.mark.asyncio
async def test_error_recovery():
    """Test error recovery mechanisms."""
    mock_errors = MockPluginErrors()
    
    with pytest.raises(HandshakeError):
        await mock_errors.simulate_handshake_timeout()
    
    with pytest.raises(TransportError):
        await mock_errors.simulate_transport_failure()
```

## Best Practices

### Exception Raising Guidelines

```python
# ✅ Good: Specific error type with helpful information
raise ConfigError(
    message="Invalid protocol version: 8",
    hint="Supported versions are 1-7",
    code="CONFIG_INVALID_PROTOCOL_VERSION"
)

# ✅ Good: Chain exceptions to preserve context
try:
    await network_operation()
except OSError as e:
    raise TransportError(
        message=f"Network operation failed: {e}",
        hint="Check network connectivity and firewall settings"
    ) from e

# ❌ Avoid: Generic errors without context
raise Exception("Something went wrong")

# ❌ Avoid: Losing original exception context
try:
    await operation()
except OSError:
    raise TransportError("Network error")  # Original error lost
```

### Exception Catching Guidelines

```python
# ✅ Good: Specific exception handling
try:
    await plugin_operation()
except HandshakeError as e:
    # Handle handshake-specific issues
    log_handshake_failure(e)
    raise
except TransportError as e:
    # Handle transport-specific issues
    log_transport_failure(e)
    raise

# ✅ Good: Broad exception handling when appropriate
try:
    await plugin_operation()
except RPCPluginError as e:
    # Handle any plugin-specific error
    log_plugin_error(e)
    raise
except Exception as e:
    # Handle unexpected errors
    log_unexpected_error(e)
    raise

# ❌ Avoid: Catching too broadly without re-raising
try:
    await plugin_operation()
except Exception:
    pass  # Silently ignoring errors
```

## Related Documentation

- [Server Error Handling](../server/server.md#error-handling) - Server-specific error patterns
- [Client Error Handling](../client/client.md#error-handling) - Client-specific error patterns
- [Transport Error Handling](../transport/index.md) - Transport-specific error scenarios
- [Configuration Validation](../config/schema.md) - Configuration error handling