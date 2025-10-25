# Advanced Configuration

**Reading Time:** ~8 minutes

Complete reference for advanced configuration options in Pyvider RPC Plugin. These settings control gRPC behavior, timeouts, buffers, and other low-level parameters.

## Overview

Advanced configuration controls:

- **gRPC parameters** - Keepalive, message sizes, grace periods
- **Timeout values** - Connection, handshake, channel timeouts
- **Buffer sizes** - Network buffers, chunk sizes
- **Protocol versions** - Version negotiation
- **Transport settings** - Low-level transport parameters
- **Logging** - Framework logging configuration
- **UI/Display** - Debug output options

## Quick Start

```python
from pyvider.rpcplugin import configure

# Common advanced settings
configure(
    # gRPC tuning
    grpc_max_receive_message_size=16 * 1024 * 1024,  # 16MB
    grpc_keepalive_time_ms=60000,  # 60s
    
    # Timeout tuning
    handshake_timeout=20.0,
    connection_timeout=60.0,
    
    # Buffer tuning
    buffer_size=32768,  # 32KB
    
    # Logging
    log_level="DEBUG"
)
```

## Complete Advanced Settings

### gRPC Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_grpc_grace_period` | `PLUGIN_GRPC_GRACE_PERIOD` | `float` | `0.5` | Grace period for graceful shutdown (seconds) |
| `plugin_grpc_keepalive_time_ms` | `PLUGIN_GRPC_KEEPALIVE_TIME_MS` | `int` | `30000` | Keepalive ping interval (milliseconds) |
| `plugin_grpc_keepalive_timeout_ms` | `PLUGIN_GRPC_KEEPALIVE_TIMEOUT_MS` | `int` | `5000` | Keepalive ping timeout (milliseconds) |
| `plugin_grpc_max_receive_message_size` | `PLUGIN_GRPC_MAX_RECEIVE_MESSAGE_SIZE` | `int` | `4194304` | Max receive message size (4MB default) |
| `plugin_grpc_max_send_message_size` | `PLUGIN_GRPC_MAX_SEND_MESSAGE_SIZE` | `int` | `4194304` | Max send message size (4MB default) |

### Timeout Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_handshake_timeout` | `PLUGIN_HANDSHAKE_TIMEOUT` | `float` | `10.0` | Handshake timeout (seconds) |
| `plugin_connection_timeout` | `PLUGIN_CONNECTION_TIMEOUT` | `float` | `30.0` | Connection timeout (seconds) |
| `plugin_channel_ready_timeout` | `PLUGIN_CHANNEL_READY_TIMEOUT` | `float` | `10.0` | Channel ready timeout (seconds) |
| `plugin_server_ready_timeout` | `PLUGIN_SERVER_READY_TIMEOUT` | `float` | `5.0` | Server ready timeout (seconds) |

### Buffer Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_buffer_size` | `PLUGIN_BUFFER_SIZE` | `int` | `16384` | Buffer size in bytes (16KB) |
| `plugin_transport_buffer_size` | `PLUGIN_TRANSPORT_BUFFER_SIZE` | `int` | `16384` | Transport layer buffer size in bytes (16KB) |
| `plugin_chunk_size` | `PLUGIN_CHUNK_SIZE` | `int` | `8192` | Chunk size in bytes (8KB) |

### Protocol Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_core_version` | `PLUGIN_CORE_VERSION` | `int` | `1` | Core plugin version |
| `plugin_protocol_versions` | `PLUGIN_PROTOCOL_VERSIONS` | `list[int]` | `[1]` | Supported protocol versions |
| `plugin_protocol_version` | `PLUGIN_PROTOCOL_VERSION` | `int` | `1` | Active protocol version |
| `supported_protocol_versions` | `SUPPORTED_PROTOCOL_VERSIONS` | `list[int]` | `[1, 2, 3, 4, 5, 6, 7]` | All supported protocol versions |
| `plugin_handshake_protocol_version` | `PLUGIN_HANDSHAKE_PROTOCOL_VERSION` | `int` | `1` | Handshake protocol version |

### Transport Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_supported_transports` | `PLUGIN_SUPPORTED_TRANSPORTS` | `list[str]` | `["unix", "tcp"]` | All supported transport types |

### Logging Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_log_level` | `PLUGIN_LOG_LEVEL` | `str` | `"INFO"` | Logging level (DEBUG, INFO, WARNING, ERROR) |

### UI and Display Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_ui_enabled` | `PLUGIN_UI_ENABLED` | `bool` | `False` | Enable UI features |
| `plugin_show_emoji_matrix` | `PLUGIN_SHOW_EMOJI_MATRIX` | `bool` | `False` | Show emoji matrix in output |

## gRPC Tuning

### Message Size Limits

```python
from pyvider.rpcplugin import configure

# Increase for large messages
configure(
    grpc_max_receive_message_size=32 * 1024 * 1024,  # 32MB
    grpc_max_send_message_size=32 * 1024 * 1024      # 32MB
)

# Default (4MB) is sufficient for most use cases
```

### Keepalive Settings

```python
# Aggressive keepalive (unstable networks)
configure(
    grpc_keepalive_time_ms=10000,   # 10s ping interval
    grpc_keepalive_timeout_ms=3000  # 3s timeout
)

# Conservative keepalive (stable networks)
configure(
    grpc_keepalive_time_ms=120000,  # 120s ping interval
    grpc_keepalive_timeout_ms=20000 # 20s timeout
)
```

### Graceful Shutdown

```python
# Allow time for in-flight requests
configure(grpc_grace_period=5.0)  # 5 seconds

# Fast shutdown
configure(grpc_grace_period=0.1)  # 100ms
```

## Timeout Tuning

### Handshake Timeout

```python
# Slow networks or busy systems
configure(handshake_timeout=30.0)  # 30 seconds

# Fast local plugins
configure(handshake_timeout=5.0)   # 5 seconds
```

### Connection Timeout

```python
# Long-running initialization
configure(connection_timeout=120.0)  # 2 minutes

# Quick failure detection
configure(connection_timeout=10.0)   # 10 seconds
```

### Channel Ready Timeout

```python
# Wait for gRPC channel to become ready
configure(channel_ready_timeout=20.0)  # 20 seconds
```

## Buffer Tuning

### Network Buffers

```python
# Large buffers for high throughput
configure(
    buffer_size=65536,           # 64KB
    transport_buffer_size=65536  # 64KB
)

# Small buffers for memory-constrained environments
configure(
    buffer_size=4096,           # 4KB
    transport_buffer_size=4096  # 4KB
)
```

### Chunk Size

```python
# Large chunks for bulk data transfer
configure(chunk_size=32768)  # 32KB

# Small chunks for streaming
configure(chunk_size=1024)   # 1KB
```

## Protocol Version Negotiation

### Single Protocol Version

```python
# Only support protocol version 1
configure(plugin_protocol_versions=[1])
```

### Multiple Protocol Versions

```python
# Support versions 1 and 2, prefer 2
configure(
    plugin_protocol_versions=[2, 1],  # Try 2 first, fallback to 1
    plugin_protocol_version=2          # Default to version 2
)
```

### Version Compatibility

```python
# Wide compatibility
configure(
    plugin_protocol_versions=[1, 2, 3, 4, 5],
    supported_protocol_versions=[1, 2, 3, 4, 5, 6, 7]
)
```

## Logging Configuration

### Log Levels

```python
from pyvider.rpcplugin import configure

# Development: verbose logging
configure(log_level="DEBUG")

# Production: essential logging
configure(log_level="INFO")

# Production: errors only
configure(log_level="ERROR")
```

### Environment Variable

```bash
# Set via environment
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_LOG_LEVEL=WARNING
export PLUGIN_LOG_LEVEL=ERROR
```

## Performance Profiles

### High Throughput

```python
# Optimized for bulk data transfer
configure(
    grpc_max_receive_message_size=64 * 1024 * 1024,  # 64MB
    grpc_max_send_message_size=64 * 1024 * 1024,     # 64MB
    buffer_size=65536,                                # 64KB
    chunk_size=32768,                                 # 32KB
    grpc_grace_period=10.0                            # Allow time for large messages
)
```

### Low Latency

```python
# Optimized for fast request-response
configure(
    grpc_keepalive_time_ms=5000,     # 5s keepalive
    handshake_timeout=5.0,            # Fast handshake
    connection_timeout=10.0,          # Fast connection
    grpc_grace_period=0.5             # Quick shutdown
)
```

### Resource Constrained

```python
# Minimized memory usage
configure(
    buffer_size=4096,                 # 4KB buffers
    chunk_size=1024,                  # 1KB chunks
    grpc_max_receive_message_size=1 * 1024 * 1024,  # 1MB
    grpc_max_send_message_size=1 * 1024 * 1024      # 1MB
)
```

### Long-Running Plugins

```python
# Resilient to transient failures
configure(
    grpc_keepalive_time_ms=60000,     # 60s keepalive
    grpc_keepalive_timeout_ms=10000,  # 10s timeout
    handshake_timeout=30.0,           # Generous handshake
    connection_timeout=60.0            # Generous connection
)
```

## Best Practices

### 1. Match Timeouts to Environment

```python
# Local development: fast timeouts
if os.getenv("ENV") == "dev":
    configure(
        handshake_timeout=5.0,
        connection_timeout=10.0
    )
# Production: generous timeouts
else:
    configure(
        handshake_timeout=30.0,
        connection_timeout=60.0
    )
```

### 2. Tune Message Sizes for Your Data

```python
# Calculate based on your largest message
max_message_size = calculate_max_message_size()

configure(
    grpc_max_receive_message_size=max_message_size,
    grpc_max_send_message_size=max_message_size
)
```

### 3. Enable Debug Logging During Development

```python
import os

if os.getenv("DEBUG"):
    configure(log_level="DEBUG")
```

### 4. Adjust Keepalive for Network Conditions

```python
# Mobile/WiFi: frequent keepalive
configure(grpc_keepalive_time_ms=10000)

# Datacenter: infrequent keepalive
configure(grpc_keepalive_time_ms=120000)
```

### 5. Profile Before Tuning Buffers

```python
# Don't guess - measure!
# Use profiling to find bottlenecks before adjusting buffers
```

## Troubleshooting

### Message Too Large Error

**Problem:** `RESOURCE_EXHAUSTED: Received message larger than max`

**Solutions:**
```python
# Increase message size limits
configure(
    grpc_max_receive_message_size=16 * 1024 * 1024,
    grpc_max_send_message_size=16 * 1024 * 1024
)
```

### Keepalive Timeout

**Problem:** Connection dropped due to keepalive failure

**Solutions:**
```python
# Increase keepalive timeout
configure(grpc_keepalive_timeout_ms=10000)

# Or reduce ping interval
configure(grpc_keepalive_time_ms=15000)
```

### Slow Handshake

**Problem:** Handshake timeout during startup

**Solutions:**
```python
# Increase handshake timeout
configure(handshake_timeout=30.0)

# Check server startup time
# Enable debug logging
configure(log_level="DEBUG")
```

### Protocol Version Mismatch

**Problem:** Client and server can't agree on protocol version

**Solutions:**
```python
# Expand supported versions
configure(
    plugin_protocol_versions=[1, 2, 3],
    supported_protocol_versions=[1, 2, 3, 4, 5]
)
```

## Environment-Specific Configurations

### Development

```bash
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_HANDSHAKE_TIMEOUT=5.0
export PLUGIN_CONNECTION_TIMEOUT=10.0
export PLUGIN_GRPC_GRACE_PERIOD=0.5
```

### Testing

```bash
export PLUGIN_LOG_LEVEL=WARNING
export PLUGIN_HANDSHAKE_TIMEOUT=10.0
export PLUGIN_CONNECTION_TIMEOUT=20.0
export PLUGIN_TEST_MODE=true
```

### Production

```bash
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_HANDSHAKE_TIMEOUT=30.0
export PLUGIN_CONNECTION_TIMEOUT=60.0
export PLUGIN_GRPC_KEEPALIVE_TIME_MS=60000
export PLUGIN_GRPC_MAX_RECEIVE_MESSAGE_SIZE=8388608  # 8MB
```

## Related Topics

- **[Configuration Reference](configuration-reference.md)** - All configuration options
- **[Client Configuration](configuration-client.md)** - Client-side settings
- **[Server Configuration](configuration-server.md)** - Server-side settings
- **[Security Configuration](configuration-security.md)** - mTLS and certificates
- **[Performance Tuning](../advanced/performance.md)** - Performance optimization
- **[Protocol Development](../advanced/custom-protocols.md)** - Custom protocol versions
