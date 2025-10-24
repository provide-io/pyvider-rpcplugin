# Advanced Foundation Integration

This guide demonstrates advanced integration patterns between Pyvider RPC Plugin and Foundation, showcasing how to leverage Foundation's infrastructure for production-ready plugin systems.

## Configuration Inheritance

### Custom Configuration Classes

Extend Foundation's `RuntimeConfig` with plugin-specific configuration:

```python
from dataclasses import dataclass, field
from provide.foundation.config import RuntimeConfig, ConfigError
from provide.foundation import logger
from pyvider.rpcplugin.config import rpcplugin_config
import os

@dataclass
class PluginServiceConfig(RuntimeConfig):
    """Advanced plugin configuration extending Foundation's RuntimeConfig."""
    
    # Service identification
    service_name: str = field(default=os.environ.get("SERVICE_NAME", "unnamed"))
    service_version: str = field(default=os.environ.get("SERVICE_VERSION", "1.0.0"))
    
    # Performance tuning
    max_concurrent_requests: int = field(default=int(os.environ.get("MAX_CONCURRENT_REQUESTS", "100")))
    request_timeout: float = field(default=float(os.environ.get("REQUEST_TIMEOUT", "30.0")))
    
    # Foundation integration settings
    enable_structured_logging: bool = field(default=True)
    enable_rate_limiting: bool = field(default=True)
    rate_limit_rps: float = field(default=100.0)
    
    def validate(self) -> None:
        """Custom validation logic using Foundation patterns."""
        super().validate()
        
        if self.max_concurrent_requests < 1:
            raise ConfigError("max_concurrent_requests must be positive")
        
        if self.request_timeout <= 0:
            raise ConfigError("request_timeout must be positive")
        
        logger.info("Configuration validated", extra={
            "service": self.service_name,
            "version": self.service_version,
            "max_concurrent": self.max_concurrent_requests
        })

# Usage
config = PluginServiceConfig()
config.validate()

# Access both custom and inherited Foundation config
logger.info(f"Service: {config.service_name}")
logger.info(f"RPC timeout: {rpcplugin_config.plugin_handshake_timeout}")
```

## Cryptography & Certificate Management

### Dynamic Certificate Generation

Use Foundation's crypto module for dynamic certificate generation:

```python
import datetime
from pathlib import Path
from provide.foundation.crypto import (
    Certificate,
    PrivateKey,
    generate_self_signed_certificate
)
from provide.foundation import logger
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.transport import TCPSocketTransport

class CertificateManager:
    """Manages certificates using Foundation's crypto utilities."""
    
    def __init__(self, cert_dir: Path):
        self.cert_dir = cert_dir
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Certificate manager initialized: {cert_dir}")
    
    async def ensure_certificates(self) -> tuple[Certificate, PrivateKey]:
        """Ensure valid certificates exist, generating if needed."""
        cert_path = self.cert_dir / "server.crt"
        key_path = self.cert_dir / "server.key"
        
        # Check existing certificates
        if cert_path.exists() and key_path.exists():
            try:
                cert = Certificate.load_from_file(str(cert_path))
                key = PrivateKey.load_from_file(str(key_path))
                
                # Validate certificate expiry
                if cert.not_after > datetime.datetime.now():
                    logger.info("Using existing valid certificates")
                    return cert, key
                else:
                    logger.warning("Certificate expired, regenerating")
            except Exception as e:
                logger.warning(f"Error loading certificates: {e}, regenerating")
        
        # Generate new certificates
        logger.info("Generating new self-signed certificates")
        cert, key = generate_self_signed_certificate(
            common_name="plugin.local",
            organization="Pyvider RPC Plugin",
            validity_days=365,
            key_size=2048
        )
        
        # Save to disk
        cert.save_to_file(str(cert_path))
        key.save_to_file(str(key_path))
        logger.info("New certificates generated and saved")
        
        return cert, key

# Usage in plugin server
async def create_secure_server():
    cert_manager = CertificateManager(Path("/etc/plugin/certs"))
    cert, key = await cert_manager.ensure_certificates()
    
    # Create secure transport with Foundation-managed certificates
    transport = TCPSocketTransport(
        host="0.0.0.0",
        port=8443
    )
    
    return plugin_server(
        protocol=plugin_protocol(),
        handler=SecureHandler(),
        transport=transport
    )
```

### Certificate Rotation

Implement certificate rotation with Foundation:

```python
import asyncio
import signal
from datetime import datetime, timedelta
from provide.foundation.crypto import Certificate, PrivateKey
from provide.foundation import logger

class CertificateRotator:
    """Handles automatic certificate rotation using Foundation."""
    
    def __init__(self, cert_manager: CertificateManager, server):
        self.cert_manager = cert_manager
        self.server = server
        self.rotation_task = None
        
    async def start_rotation(self, check_interval: int = 3600):
        """Start automatic certificate rotation."""
        self.rotation_task = asyncio.create_task(
            self._rotation_loop(check_interval)
        )
        logger.info(f"Certificate rotation started (interval: {check_interval}s)")
    
    async def _rotation_loop(self, interval: int):
        """Check and rotate certificates periodically."""
        while True:
            try:
                await asyncio.sleep(interval)
                
                cert, key = await self.cert_manager.ensure_certificates()
                days_until_expiry = (cert.not_after - datetime.now()).days
                
                if days_until_expiry < 30:
                    logger.warning(f"Certificate expires in {days_until_expiry} days, rotating")
                    await self._rotate_certificates()
                else:
                    logger.debug(f"Certificate valid for {days_until_expiry} more days")
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Certificate rotation error: {e}", exc_info=True)
    
    async def _rotate_certificates(self):
        """Perform certificate rotation with zero downtime."""
        # Generate new certificates
        new_cert, new_key = await self.cert_manager.ensure_certificates()
        
        # Update server with new certificates (implementation depends on transport)
        await self.server.update_certificates(new_cert, new_key)
        
        logger.info("Certificates rotated successfully")
```

## Advanced Rate Limiting

### Per-Client Rate Limiting

Implement sophisticated per-client rate limiting using Foundation:

```python
from collections import defaultdict
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter
from provide.foundation import logger
import time

class PerClientRateLimiter:
    """Per-client rate limiting using Foundation's TokenBucketRateLimiter."""
    
    def __init__(self, default_rps: float = 10.0, default_burst: float = 20.0):
        self.default_rps = default_rps
        self.default_burst = default_burst
        self.limiters: dict[str, TokenBucketRateLimiter] = {}
        self.last_cleanup = time.time()
        logger.info(f"Per-client rate limiter initialized (RPS: {default_rps})")
    
    def get_limiter(self, client_id: str) -> TokenBucketRateLimiter:
        """Get or create rate limiter for client."""
        if client_id not in self.limiters:
            self.limiters[client_id] = TokenBucketRateLimiter(
                capacity=self.default_burst,
                refill_rate=self.default_rps
            )
            logger.debug(f"Created rate limiter for client: {client_id}")
        
        # Periodic cleanup of old limiters
        if time.time() - self.last_cleanup > 300:  # 5 minutes
            self._cleanup_old_limiters()
        
        return self.limiters[client_id]
    
    def _cleanup_old_limiters(self):
        """Remove limiters for inactive clients."""
        current_time = time.time()
        to_remove = []
        
        for client_id, limiter in self.limiters.items():
            if current_time - limiter.last_access > 600:  # 10 minutes inactive
                to_remove.append(client_id)
        
        for client_id in to_remove:
            del self.limiters[client_id]
            logger.debug(f"Removed inactive rate limiter: {client_id}")
        
        self.last_cleanup = current_time
    
    async def check_rate_limit(self, client_id: str, weight: float = 1.0) -> bool:
        """Check if request is allowed for client."""
        limiter = self.get_limiter(client_id)
        
        if await limiter.is_allowed():
            logger.debug(f"Request allowed for client: {client_id}")
            return True
        else:
            tokens = await limiter.get_current_tokens()
            logger.warning(f"Rate limit exceeded for client: {client_id}", extra={
                "available_tokens": tokens,
                "required_tokens": weight
            })
            return False

# Integration with RPC handler
class RateLimitedHandler:
    def __init__(self):
        self.rate_limiter = PerClientRateLimiter(
            default_rps=100.0,
            default_burst=200.0
        )
    
    async def handle_request(self, request, context):
        # Extract client ID from context
        client_id = context.peer() or "unknown"
        
        if not await self.rate_limiter.check_rate_limit(client_id):
            raise Exception("Rate limit exceeded")
        
        return await self.process_request(request)
```

## Structured Logging & Observability

### Context-Aware Logging

Leverage Foundation's structured logging for comprehensive observability:

```python
from contextvars import ContextVar
from provide.foundation import logger
from pyvider.rpcplugin import plugin_server
import uuid
import time

# Context variables for request tracking
request_id_var: ContextVar[str] = ContextVar('request_id', default=None)
client_id_var: ContextVar[str] = ContextVar('client_id', default=None)

class ObservableHandler:
    """Handler with comprehensive observability using Foundation logging."""
    
    def __init__(self):
        self.request_counter = 0
        self.error_counter = 0
        self.latencies = []
    
    async def handle_request(self, request, context):
        """Handle request with full observability."""
        request_id = str(uuid.uuid4())
        client_id = context.peer() or "unknown"
        start_time = time.time()
        
        # Set context variables
        request_id_var.set(request_id)
        client_id_var.set(client_id)
        
        # Log request with context
        logger.info("Request received", extra={
            "request_id": request_id,
            "client_id": client_id,
            "method": context.method,
            "request_size": len(str(request))
        })
        
        try:
            # Process request
            result = await self.process_request(request)
            
            # Calculate metrics
            duration = time.time() - start_time
            self.request_counter += 1
            self.latencies.append(duration)
            
            # Log success with metrics
            logger.info("Request completed", extra={
                "request_id": request_id,
                "client_id": client_id,
                "duration_ms": duration * 1000,
                "response_size": len(str(result)),
                "total_requests": self.request_counter
            })
            
            return result
            
        except Exception as e:
            # Log error with context
            duration = time.time() - start_time
            self.error_counter += 1
            
            logger.error("Request failed", extra={
                "request_id": request_id,
                "client_id": client_id,
                "duration_ms": duration * 1000,
                "error": str(e),
                "error_rate": self.error_counter / max(1, self.request_counter)
            }, exc_info=True)
            
            raise
    
    def get_metrics(self) -> dict:
        """Get handler metrics."""
        if not self.latencies:
            return {"requests": 0}
        
        return {
            "total_requests": self.request_counter,
            "total_errors": self.error_counter,
            "error_rate": self.error_counter / max(1, self.request_counter),
            "avg_latency_ms": sum(self.latencies) / len(self.latencies) * 1000,
            "p95_latency_ms": sorted(self.latencies)[int(len(self.latencies) * 0.95)] * 1000
        }
```

## Error Handling & Recovery

### Circuit Breaker Pattern

Implement circuit breaker using Foundation patterns:

```python
import asyncio
from enum import Enum
from datetime import datetime, timedelta
from provide.foundation import logger

class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

class CircuitBreaker:
    """Circuit breaker implementation using Foundation patterns."""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = Exception
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time = None
        self.state = CircuitState.CLOSED
        
        logger.info("Circuit breaker initialized", extra={
            "threshold": failure_threshold,
            "timeout": recovery_timeout
        })
    
    async def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker entering half-open state")
            else:
                logger.warning("Circuit breaker is open, rejecting call")
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
        except self.expected_exception as e:
            self._on_failure()
            raise
    
    def _should_attempt_reset(self) -> bool:
        """Check if we should try to reset the circuit."""
        if self.last_failure_time is None:
            return False
        
        return datetime.now() >= self.last_failure_time + timedelta(seconds=self.recovery_timeout)
    
    def _on_success(self):
        """Handle successful call."""
        if self.state == CircuitState.HALF_OPEN:
            logger.info("Circuit breaker reset to closed")
            self.state = CircuitState.CLOSED
        
        self.failure_count = 0
        self.last_failure_time = None
    
    def _on_failure(self):
        """Handle failed call."""
        self.failure_count += 1
        self.last_failure_time = datetime.now()
        
        if self.failure_count >= self.failure_threshold:
            self.state = CircuitState.OPEN
            logger.error("Circuit breaker opened", extra={
                "failures": self.failure_count,
                "threshold": self.failure_threshold
            })
        else:
            logger.warning(f"Circuit breaker failure {self.failure_count}/{self.failure_threshold}")

# Usage in plugin handler
class ResilientHandler:
    def __init__(self):
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=3,
            recovery_timeout=30
        )
    
    async def handle_request(self, request, context):
        return await self.circuit_breaker.call(
            self._process_with_retry,
            request
        )
    
    async def _process_with_retry(self, request):
        # Actual processing logic
        return await external_service.process(request)
```

## Performance Optimization

### Connection Pooling with Foundation

Implement efficient connection pooling:

```python
import asyncio
from provide.foundation import logger
from provide.foundation.config import RuntimeConfig

class ConnectionPool:
    """Connection pool using Foundation patterns."""
    
    def __init__(self, min_size: int = 5, max_size: int = 20):
        self.min_size = min_size
        self.max_size = max_size
        self.connections = []
        self.available = asyncio.Queue(maxsize=max_size)
        self.in_use = set()
        
        logger.info(f"Connection pool initialized (min: {min_size}, max: {max_size})")
    
    async def initialize(self):
        """Pre-create minimum connections."""
        for _ in range(self.min_size):
            conn = await self._create_connection()
            await self.available.put(conn)
        
        logger.info(f"Connection pool ready with {self.min_size} connections")
    
    async def acquire(self) -> Any:
        """Acquire connection from pool."""
        try:
            # Try to get available connection
            conn = await asyncio.wait_for(self.available.get(), timeout=0.1)
        except asyncio.TimeoutError:
            # Create new connection if under limit
            if len(self.connections) < self.max_size:
                conn = await self._create_connection()
                logger.debug("Created new connection for pool")
            else:
                # Wait for connection to become available
                logger.warning("Connection pool at maximum, waiting...")
                conn = await self.available.get()
        
        self.in_use.add(conn)
        return conn
    
    async def release(self, conn):
        """Return connection to pool."""
        self.in_use.discard(conn)
        
        if await self._is_connection_healthy(conn):
            await self.available.put(conn)
        else:
            logger.warning("Unhealthy connection discarded")
            self.connections.remove(conn)
            
            # Maintain minimum pool size
            if len(self.connections) < self.min_size:
                new_conn = await self._create_connection()
                await self.available.put(new_conn)
    
    async def _create_connection(self):
        """Create new connection."""
        # Implementation specific to your needs
        conn = await create_plugin_connection()
        self.connections.append(conn)
        return conn
    
    async def _is_connection_healthy(self, conn) -> bool:
        """Check if connection is still healthy."""
        try:
            await conn.ping()
            return True
        except:
            return False
```

## Summary

These advanced integration patterns demonstrate how Pyvider RPC Plugin leverages Foundation's infrastructure for:

1. **Configuration Management** - Type-safe, validated configuration inheritance
2. **Security** - Dynamic certificate generation and rotation
3. **Rate Limiting** - Sophisticated per-client rate limiting
4. **Observability** - Structured logging with request context
5. **Resilience** - Circuit breakers and error recovery
6. **Performance** - Connection pooling and resource management

Foundation provides the infrastructure layer, while Pyvider RPC Plugin extends it with RPC-specific functionality, creating a powerful and production-ready plugin system.