# Foundation Integration

Advanced integration patterns leveraging Foundation's infrastructure for production-ready plugin systems.

## Overview

Foundation provides core infrastructure for configuration, cryptography, rate limiting, logging, and error handling. This guide demonstrates advanced integration patterns that extend pyvider-rpcplugin with Foundation's capabilities.

## Configuration Inheritance

Extend Foundation's `RuntimeConfig` for plugin-specific configuration:

```python
from dataclasses import dataclass, field
from provide.foundation.config import RuntimeConfig, ConfigError
from provide.foundation import logger
from pyvider.rpcplugin.config import rpcplugin_config
import os

@dataclass
class PluginServiceConfig(RuntimeConfig):
    """Plugin configuration extending Foundation's RuntimeConfig."""

    # Service identification
    service_name: str = field(default=os.environ.get("SERVICE_NAME", "unnamed"))
    service_version: str = field(default=os.environ.get("SERVICE_VERSION", "1.0.0"))

    # Performance tuning
    max_concurrent_requests: int = field(default=int(os.environ.get("MAX_CONCURRENT_REQUESTS", "100")))
    request_timeout: float = field(default=float(os.environ.get("REQUEST_TIMEOUT", "30.0")))

    # Foundation integration
    enable_structured_logging: bool = field(default=True)
    enable_rate_limiting: bool = field(default=True)
    rate_limit_rps: float = field(default=100.0)

    def validate(self):
        """Validate configuration using Foundation patterns."""
        super().validate()

        if self.max_concurrent_requests < 1:
            raise ConfigError("max_concurrent_requests must be positive")

        if self.request_timeout <= 0:
            raise ConfigError("request_timeout must be positive")

        logger.info("Configuration validated", extra={
            "service": self.service_name,
            "version": self.service_version
        })

# Usage
config = PluginServiceConfig()
config.validate()
```

## Cryptography & Certificates

### Dynamic Certificate Generation

Use Foundation's crypto module for certificate management:

```python
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger
from pyvider.rpcplugin import plugin_server

class CertificateManager:
    """Manages certificates using Foundation's crypto utilities."""

    def __init__(self, cert_dir: Path):
        self.cert_dir = cert_dir
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Certificate manager initialized: {cert_dir}")

    async def ensure_certificates(self) -> Certificate:
        """Ensure valid certificates exist."""
        cert_path = self.cert_dir / "server.crt"
        key_path = self.cert_dir / "server.key"

        # Check existing certificates
        if cert_path.exists() and key_path.exists():
            try:
                cert_pem_content = cert_path.read_text()
                key_pem_content = key_path.read_text()

                cert = Certificate.from_pem(
                    cert_pem=cert_pem_content,
                    key_pem=key_pem_content
                )

                logger.info("Loaded existing certificates")
                return cert
            except Exception as e:
                logger.warning(f"Error loading certificates: {e}, regenerating")

        # Generate new self-signed certificate
        logger.info("Generating new certificate")
        cert = Certificate.create_self_signed_server_cert(
            common_name="plugin.local",
            organization_name="Pyvider RPC Plugin",
            validity_days=365,
            alt_names=["localhost", "127.0.0.1"]
        )

        # Save to disk
        cert_path.write_text(cert.cert_pem)
        key_path.write_text(cert.key_pem)
        logger.info("Certificate generated and saved")

        return cert

# Usage
async def create_secure_server():
    cert_manager = CertificateManager(Path("/etc/plugin/certs"))
    cert = await cert_manager.ensure_certificates()

    transport = TCPSocketTransport(host="0.0.0.0", port=8443)

    return plugin_server(
        protocol=plugin_protocol(),
        handler=SecureHandler(),
        transport=transport
    )
```

### Certificate Rotation

Implement automatic certificate rotation:

```python
import asyncio
from provide.foundation import logger

class CertificateRotator:
    """Handles automatic certificate rotation."""

    def __init__(self, cert_manager, server):
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
        """Periodically check and rotate certificates."""
        while True:
            try:
                await asyncio.sleep(interval)
                logger.info("Rotating certificates on schedule")
                await self._rotate_certificates()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Certificate rotation error: {e}", exc_info=True)

    async def _rotate_certificates(self):
        """Perform certificate rotation."""
        new_cert = await self.cert_manager.ensure_certificates()
        await self.server.update_certificates(new_cert)
        logger.info("Certificate rotated successfully")
```

## Advanced Rate Limiting

Per-client rate limiting using Foundation:

```python
from collections import defaultdict
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter
from provide.foundation import logger
import time

class PerClientRateLimiter:
    """Per-client rate limiting with Foundation's TokenBucketRateLimiter."""

    def __init__(self, default_rps: float = 10.0, default_burst: float = 20.0):
        self.default_rps = default_rps
        self.default_burst = default_burst
        self.limiters = {}
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

        # Periodic cleanup
        if time.time() - self.last_cleanup > 300:
            self._cleanup_old_limiters()

        return self.limiters[client_id]

    def _cleanup_old_limiters(self):
        """Remove limiters for inactive clients."""
        current_time = time.time()
        to_remove = []

        for client_id, limiter in self.limiters.items():
            if current_time - limiter.last_access > 600:  # 10 minutes
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
        client_id = context.peer() or "unknown"

        if not await self.rate_limiter.check_rate_limit(client_id):
            raise Exception("Rate limit exceeded")

        return await self.process_request(request)
```

## Structured Logging & Observability

Leverage Foundation's structured logging for comprehensive observability:

```python
from contextvars import ContextVar
from provide.foundation import logger
from pyvider.rpcplugin import plugin_server
import uuid
import time

# Context variables for request tracking
request_id_var = ContextVar('request_id', default=None)
client_id_var = ContextVar('client_id', default=None)

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
            result = await self.process_request(request)

            duration = time.time() - start_time
            self.request_counter += 1
            self.latencies.append(duration)

            logger.info("Request completed", extra={
                "request_id": request_id,
                "client_id": client_id,
                "duration_ms": duration * 1000,
                "response_size": len(str(result)),
                "total_requests": self.request_counter
            })

            return result

        except Exception as e:
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

    def get_metrics(self):
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
        return await external_service.process(request)
```

## Best Practices

### Configuration

- Extend `RuntimeConfig` for type-safe configuration
- Validate early in lifecycle
- Use environment variables with sensible defaults

### Security

- Use Foundation's crypto module for certificate management
- Implement certificate rotation for long-running services
- Never hardcode secrets or credentials

### Observability

- Use structured logging with Foundation's logger
- Include request context in all log messages
- Track metrics for error rates and latencies

### Rate Limiting

- Implement per-client rate limiting
- Clean up inactive limiters periodically
- Log rate limit violations for monitoring

### Error Handling

- Use circuit breakers for external dependencies
- Implement retry logic with exponential backoff
- Log errors with full context for debugging

## Related Topics

- [Configuration](../config/configuration-guide.md) - Configuration patterns
- [Observability](observability.md) - Metrics and tracing
- [Lifecycle Management](lifecycle.md) - Plugin lifecycle
- [Middleware](middleware.md) - Cross-cutting concerns
