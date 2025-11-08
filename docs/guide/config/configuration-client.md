# Client Configuration

**Reading Time:** ~5 minutes

Complete reference for client-side configuration options in Pyvider RPC Plugin. These settings control how the client connects to plugins, manages retries, and handles failures.

## Overview

Client configuration controls:

- **Connection behavior** - Retry logic, timeouts, backoff strategies
- **Transport preferences** - Which transports to try and in what order
- **Security** - Client certificates for mTLS
- **Process management** - How the client launches and monitors plugin subprocesses

## Quick Start

```python
from pyvider.rpcplugin import configure

# Configure client with common settings
configure(
    client_max_retries=5,
    client_retry_delay=2.0,
    connection_timeout=60.0,
    client_transports=["unix", "tcp"]
)
```

## Complete Client Settings

### Retry Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_client_max_retries` | `PLUGIN_CLIENT_MAX_RETRIES` | `int` | `3` | Maximum number of connection retry attempts |
| `plugin_client_retry_enabled` | `PLUGIN_CLIENT_RETRY_ENABLED` | `bool` | `True` | Enable automatic retry on connection failure |
| `plugin_client_retry_delay` | `PLUGIN_CLIENT_RETRY_DELAY` | `float` | `1.0` | Initial retry delay (seconds) |
| `plugin_client_backoff_multiplier` | `PLUGIN_CLIENT_BACKOFF_MULTIPLIER` | `float` | `2.0` | Exponential backoff multiplier |
| `plugin_client_max_retry_delay` | `PLUGIN_CLIENT_MAX_RETRY_DELAY` | `float` | `10.0` | Maximum retry delay (seconds) |

### Backoff Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_client_initial_backoff_ms` | `PLUGIN_CLIENT_INITIAL_BACKOFF_MS` | `int` | `100` | Initial backoff in milliseconds |
| `plugin_client_max_backoff_ms` | `PLUGIN_CLIENT_MAX_BACKOFF_MS` | `int` | `5000` | Maximum backoff in milliseconds |
| `plugin_client_retry_jitter_ms` | `PLUGIN_CLIENT_RETRY_JITTER_MS` | `int` | `50` | Retry jitter in milliseconds |
| `plugin_client_retry_total_timeout_s` | `PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S` | `float` | `30.0` | Total timeout for all retries (seconds) |

### Transport Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_client_transports` | `PLUGIN_CLIENT_TRANSPORTS` | `list[str]` | `["unix", "tcp"]` | Ordered list of transports to try |

### Security Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_client_cert` | `PLUGIN_CLIENT_CERT` | `str \| None` | `None` | Client certificate (PEM or file:// URL) |
| `plugin_client_key` | `PLUGIN_CLIENT_KEY` | `str \| None` | `None` | Client private key (PEM or file:// URL) |
| `plugin_client_cert_file` | `PLUGIN_CLIENT_CERT_FILE` | `str` | `""` | Client certificate file path |
| `plugin_client_key_file` | `PLUGIN_CLIENT_KEY_FILE` | `str` | `""` | Client private key file path |
| `plugin_client_root_certs` | `PLUGIN_CLIENT_ROOT_CERTS` | `str` | `""` | Client root CA certificates (PEM format) |

## Usage Examples

### Basic Retry Configuration

```python
from pyvider.rpcplugin import configure

# Aggressive retry for flaky connections
configure(
    client_max_retries=10,
    client_retry_delay=0.5,
    client_backoff_multiplier=1.5,
    client_max_retry_delay=5.0
)
```

### Environment Variable Configuration

```bash
# Set via environment
export PLUGIN_CLIENT_MAX_RETRIES=5
export PLUGIN_CLIENT_RETRY_DELAY=2.0
export PLUGIN_CLIENT_BACKOFF_MULTIPLIER=2.0
export PLUGIN_CONNECTION_TIMEOUT=60.0

python my_client.py
```

### Transport Preferences

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Prefer TCP over Unix sockets (e.g., Windows)
rpcplugin_config.plugin_client_transports = ["tcp"]

# Try Unix first, fallback to TCP
rpcplugin_config.plugin_client_transports = ["unix", "tcp"]
```

### Client mTLS Configuration

```python
import os

# Configure client certificates for mTLS
os.environ.update({
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_CLIENT_CERT": "file:///etc/certs/client.crt",
    "PLUGIN_CLIENT_KEY": "file:///etc/certs/client.key",
    "PLUGIN_CLIENT_ROOT_CERTS": "file:///etc/certs/ca.crt"
})
```

## Retry Behavior

### Exponential Backoff

The client uses exponential backoff with jitter:

```
Attempt 1: wait = initial_delay = 1.0s
Attempt 2: wait = 1.0 * 2.0 = 2.0s (+ jitter)
Attempt 3: wait = 2.0 * 2.0 = 4.0s (+ jitter)
Attempt 4: wait = 4.0 * 2.0 = 8.0s (+ jitter)
Attempt 5: wait = min(16.0, max_delay) = 10.0s (+ jitter)
```

Jitter (random variation) prevents thundering herd when multiple clients retry simultaneously.

### Total Timeout

The `client_retry_total_timeout_s` setting caps the **total** time spent retrying:

```python
# Will stop retrying after 30 seconds total, regardless of max_retries
configure(
    client_max_retries=100,  # Many retries
    client_retry_total_timeout_s=30.0  # But stop after 30s total
)
```

## Best Practices

### 1. Set Appropriate Timeouts

Match timeouts to your environment:

```python
# Development (fast failure)
configure(
    connection_timeout=10.0,
    client_max_retries=2,
    client_retry_total_timeout_s=15.0
)

# Production (resilient to transient failures)
configure(
    connection_timeout=30.0,
    client_max_retries=5,
    client_retry_total_timeout_s=120.0
)
```

### 2. Disable Retries for Testing

For deterministic test behavior:

```python
# Disable retries in tests
configure(client_retry_enabled=False)
```

### 3. Platform-Specific Transport

Choose transports based on platform:

```python
import platform

if platform.system() == "Windows":
    # Windows: TCP only (Unix sockets not available)
    configure(client_transports=["tcp"])
else:
    # Linux/macOS: prefer Unix, fallback to TCP
    configure(client_transports=["unix", "tcp"])
```

### 4. Log Retry Attempts

Monitor retry behavior in production:

```python
from provide.foundation import logger
from pyvider.rpcplugin import plugin_client

async def connect_with_logging():
    client = plugin_client(command=["python", "plugin.py"])
    
    for attempt in range(1, 6):
        try:
            await client.start()
            logger.info(f"Connected on attempt {attempt}")
            return client
        except Exception as e:
            logger.warning(f"Attempt {attempt} failed: {e}")
            if attempt == 5:
                raise
```

## Troubleshooting

### Connection Timeouts

**Problem:** Client fails to connect even though plugin is running

**Solutions:**
```python
# Increase connection timeout
configure(connection_timeout=60.0)

# Increase handshake timeout
configure(handshake_timeout=20.0)

# Check plugin is actually listening
# Enable debug logging to see handshake details
configure(log_level="DEBUG")
```

### Excessive Retries

**Problem:** Client retries too many times, slowing down failures

**Solutions:**
```python
# Reduce max retries
configure(client_max_retries=2)

# Set aggressive total timeout
configure(client_retry_total_timeout_s=10.0)
```

### Transport Negotiation Failures

**Problem:** Client can't find compatible transport

**Solutions:**
```python
# Ensure both client and server support same transports
configure(
    client_transports=["unix", "tcp"],
    server_transports=["unix", "tcp"]  
)

# Check platform compatibility
# Windows requires TCP
```

## Related Topics

- **[Configuration Reference](configuration-reference/)** - All configuration options
- **[Server Configuration](configuration-server/)** - Server-side settings
- **[Security Configuration](configuration-security/)** - mTLS and certificates
- **[Connection Management](../client/connections/)** - Client connection patterns
- **[Error Handling](../client/error-handling/)** - Handling connection failures
- **[Retry Logic](../client/retry-logic/)** - Advanced retry strategies
