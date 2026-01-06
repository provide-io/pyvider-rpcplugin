# Advanced Configuration

Complete reference for advanced configuration, production deployment, and rate limiting in Pyvider RPC Plugin.

## Overview

Advanced configuration controls:

- **gRPC parameters**: Keepalive, message sizes, grace periods
- **Timeout values**: Connection, handshake, channel timeouts
- **Buffer sizes**: Network buffers, chunk sizes
- **Protocol versions**: Version negotiation
- **Production patterns**: Security, deployment, monitoring
- **Rate limiting**: Traffic control and protection

## Advanced Settings Reference

=== "gRPC Configuration"

    | Setting | Environment Variable | Type | Default | Description |
    |---------|---------------------|------|---------|-------------|
    | `plugin_grpc_grace_period` | `PLUGIN_GRPC_GRACE_PERIOD` | `float` | `0.5` | Grace period for graceful shutdown (seconds) |
    | `plugin_grpc_keepalive_time_ms` | `PLUGIN_GRPC_KEEPALIVE_TIME_MS` | `int` | `30000` | Keepalive ping interval (milliseconds) |
    | `plugin_grpc_keepalive_timeout_ms` | `PLUGIN_GRPC_KEEPALIVE_TIMEOUT_MS` | `int` | `5000` | Keepalive ping timeout (milliseconds) |
    | `plugin_grpc_max_receive_message_size` | `PLUGIN_GRPC_MAX_RECEIVE_MESSAGE_SIZE` | `int` | `4194304` | Max receive message size (4MB) |
    | `plugin_grpc_max_send_message_size` | `PLUGIN_GRPC_MAX_SEND_MESSAGE_SIZE` | `int` | `4194304` | Max send message size (4MB) |

=== "Timeout Configuration"

    | Setting | Environment Variable | Type | Default | Description |
    |---------|---------------------|------|---------|-------------|
    | `plugin_handshake_timeout` | `PLUGIN_HANDSHAKE_TIMEOUT` | `float` | `10.0` | Handshake timeout (seconds) |
    | `plugin_connection_timeout` | `PLUGIN_CONNECTION_TIMEOUT` | `float` | `30.0` | Connection timeout (seconds) |
    | `plugin_channel_ready_timeout` | `PLUGIN_CHANNEL_READY_TIMEOUT` | `float` | `10.0` | Channel ready timeout (seconds) |
    | `plugin_server_ready_timeout` | `PLUGIN_SERVER_READY_TIMEOUT` | `float` | `5.0` | Server ready timeout (seconds) |

=== "Buffer Configuration"

    | Setting | Environment Variable | Type | Default | Description |
    |---------|---------------------|------|---------|-------------|
    | `plugin_buffer_size` | `PLUGIN_BUFFER_SIZE` | `int` | `16384` | Buffer size (16KB) |
    | `plugin_transport_buffer_size` | `PLUGIN_TRANSPORT_BUFFER_SIZE` | `int` | `16384` | Transport buffer size (16KB) |
    | `plugin_chunk_size` | `PLUGIN_CHUNK_SIZE` | `int` | `8192` | Chunk size (8KB) |

=== "Protocol Configuration"

    | Setting | Environment Variable | Type | Default | Description |
    |---------|---------------------|------|---------|-------------|
    | `plugin_protocol_versions` | `PLUGIN_PROTOCOL_VERSIONS` | `list[int]` | `[1]` | Supported protocol versions |
    | `plugin_protocol_version` | `PLUGIN_PROTOCOL_VERSION` | `int` | `1` | Active protocol version |
    | `supported_protocol_versions` | `SUPPORTED_PROTOCOL_VERSIONS` | `list[int]` | `[1, 2, 3, 4, 5, 6, 7]` | All supported versions |

---

## Performance Profiles

### High Throughput

Optimized for bulk data transfer:

```python
from pyvider.rpcplugin import configure

configure(
    grpc_max_receive_message_size=64 * 1024 * 1024,  # 64MB
    grpc_max_send_message_size=64 * 1024 * 1024,     # 64MB
    buffer_size=65536,                                # 64KB
    chunk_size=32768,                                 # 32KB
    grpc_grace_period=10.0
)
```

### Low Latency

Optimized for fast request-response:

```python
configure(
    grpc_keepalive_time_ms=5000,     # 5s keepalive
    handshake_timeout=5.0,
    connection_timeout=10.0,
    grpc_grace_period=0.5
)
```

### Resource Constrained

Minimized memory usage:

```python
configure(
    buffer_size=4096,                 # 4KB buffers
    chunk_size=1024,                  # 1KB chunks
    grpc_max_receive_message_size=1 * 1024 * 1024,  # 1MB
    grpc_max_send_message_size=1 * 1024 * 1024
)
```

### Long-Running Plugins

Resilient to transient failures:

```python
configure(
    grpc_keepalive_time_ms=60000,     # 60s keepalive
    grpc_keepalive_timeout_ms=10000,  # 10s timeout
    handshake_timeout=30.0,
    connection_timeout=60.0
)
```

---

## Production Deployment

### Security Configuration

Always enable mTLS in production:

```bash
# Enable mTLS with proper certificates
export PLUGIN_AUTO_MTLS=true
export PLUGIN_SERVER_CERT=file:///etc/ssl/certs/plugin-server.pem
export PLUGIN_SERVER_KEY=file:///etc/ssl/private/plugin-server.key
export PLUGIN_CLIENT_ROOT_CERTS=file:///etc/ssl/certs/ca-bundle.pem
```

**Certificate Best Practices:**

1. Use trusted Certificate Authority (avoid self-signed in production)
2. Set proper file permissions (private keys mode 600)
3. Implement automated certificate renewal
4. Use separate certificates per environment

```bash
# Set proper permissions
sudo chown plugin-user:plugin-group /etc/ssl/private/plugin-server.key
sudo chmod 600 /etc/ssl/private/plugin-server.key
sudo chmod 644 /etc/ssl/certs/plugin-server.pem
```

### Magic Cookie Security

Use cryptographically secure random strings:

```bash
# Generate secure magic cookie
export PLUGIN_MAGIC_COOKIE_VALUE=$(openssl rand -hex 32)

# Or use secrets management
export PLUGIN_MAGIC_COOKIE_VALUE=$(aws secretsmanager get-secret-value ...)
```

### Network Security

Configure appropriate transport and firewall rules:

```bash
# TCP for networked deployments
export PLUGIN_SERVER_TRANSPORTS='["tcp"]'
export PLUGIN_SERVER_HOST=0.0.0.0
export PLUGIN_SERVER_PORT=8080

# Unix socket for same-host (higher security)
export PLUGIN_SERVER_TRANSPORTS='["unix"]'
export PLUGIN_SERVER_UNIX_SOCKET_PATH=/var/run/plugin/plugin.sock
```

---

## Systemd Service

Production deployment with systemd:

```ini
# /etc/systemd/system/plugin.service
[Unit]
Description=My Plugin Service
After=network.target
Requires=network.target

[Service]
Type=exec
User=plugin
Group=plugin
ExecStart=/opt/plugin/venv/bin/python -m my_plugin.server
WorkingDirectory=/opt/plugin
Environment=PLUGIN_LOG_LEVEL=INFO
Environment=PLUGIN_AUTO_MTLS=true
Environment=PLUGIN_HEALTH_SERVICE_ENABLED=true
EnvironmentFile=-/etc/plugin/environment

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/plugin /var/run/plugin

# Resource limits
LimitNOFILE=65536
MemoryMax=1G
CPUQuota=200%

# Restart policy
Restart=always
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3

[Install]
WantedBy=multi-user.target
```

---

## Environment-Specific Configuration

=== "Development"

    ```bash
    # .env.development
    PLUGIN_LOG_LEVEL=DEBUG
    PLUGIN_SHOW_EMOJI_MATRIX=true
    PLUGIN_AUTO_MTLS=false
    PLUGIN_SERVER_TRANSPORTS='["unix"]'
    PLUGIN_HANDSHAKE_TIMEOUT=5.0
    PLUGIN_CONNECTION_TIMEOUT=10.0
    ```

=== "Staging"

    ```bash
    # .env.staging
    PLUGIN_LOG_LEVEL=INFO
    PLUGIN_SHOW_EMOJI_MATRIX=false
    PLUGIN_AUTO_MTLS=true
    PLUGIN_SERVER_TRANSPORTS='["tcp"]'
    PLUGIN_SERVER_CERT=file:///etc/ssl/certs/staging-server.pem
    PLUGIN_SERVER_KEY=file:///etc/ssl/private/staging-server.key
    PLUGIN_RATE_LIMIT_ENABLED=true
    PLUGIN_HEALTH_SERVICE_ENABLED=true
    ```

=== "Production"

    ```bash
    # .env.production
    PLUGIN_LOG_LEVEL=WARNING
    PLUGIN_SHOW_EMOJI_MATRIX=false
    PLUGIN_AUTO_MTLS=true
    PLUGIN_SERVER_TRANSPORTS='["tcp"]'
    PLUGIN_SERVER_CERT=file:///etc/ssl/certs/production-server.pem
    PLUGIN_SERVER_KEY=file:///etc/ssl/private/production-server.key
    PLUGIN_CLIENT_ROOT_CERTS=file:///etc/ssl/certs/ca-bundle.pem
    PLUGIN_HANDSHAKE_TIMEOUT=30.0
    PLUGIN_CONNECTION_TIMEOUT=60.0
    PLUGIN_RATE_LIMIT_ENABLED=true
    PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=500.0
    PLUGIN_RATE_LIMIT_BURST_CAPACITY=1000.0
    PLUGIN_HEALTH_SERVICE_ENABLED=true
    ```

---

## Rate Limiting

Server-side rate limiting using Foundation's token bucket algorithm protects against abuse and ensures fair resource usage.

### Configuration

Enable rate limiting with default settings (100 requests/second, 200 burst):

```bash
export PLUGIN_RATE_LIMIT_ENABLED=true
```

Custom configuration:

```bash
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=50.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=100
```

| Parameter | Environment Variable | Type | Default | Description |
|-----------|---------------------|------|---------|-------------|
| **Enabled** | `PLUGIN_RATE_LIMIT_ENABLED` | `bool` | `false` | Enable/disable rate limiting |
| **Rate** | `PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND` | `float` | `100.0` | Average requests per second |
| **Burst** | `PLUGIN_RATE_LIMIT_BURST_CAPACITY` | `int` | `200` | Maximum burst size |

### Token Bucket Algorithm

Rate limiting uses a token bucket:

- **Token generation**: Tokens added at configured rate (requests/second)
- **Request processing**: Each request consumes one token
- **Burst handling**: Bucket holds up to burst capacity
- **Rate limiting**: Empty bucket rejects requests with `RESOURCE_EXHAUSTED` error

### Configuration Patterns

=== "Development"

    ```bash
    # Very permissive for testing
    export PLUGIN_RATE_LIMIT_ENABLED=true
    export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000.0
    export PLUGIN_RATE_LIMIT_BURST_CAPACITY=5000
    ```

=== "Web API"

    ```bash
    # Typical web API
    export PLUGIN_RATE_LIMIT_ENABLED=true
    export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=100.0
    export PLUGIN_RATE_LIMIT_BURST_CAPACITY=300
    ```

=== "High-Throughput"

    ```bash
    # High-throughput microservice
    export PLUGIN_RATE_LIMIT_ENABLED=true
    export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000.0
    export PLUGIN_RATE_LIMIT_BURST_CAPACITY=2000
    ```

=== "Public API"

    ```bash
    # Public-facing with abuse protection
    export PLUGIN_RATE_LIMIT_ENABLED=true
    export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=20.0
    export PLUGIN_RATE_LIMIT_BURST_CAPACITY=100
    ```

### Error Handling

When rate limits are exceeded, server returns `RESOURCE_EXHAUSTED` error:

```python
import grpc
import asyncio
from pyvider.rpcplugin import plugin_client

async def handle_rate_limited_request():
    async with plugin_client() as client:
        for attempt in range(3):
            try:
                response = await client.my_service.process_request(data="example")
                return response
            except grpc.aio.AioRpcError as e:
                if e.code() == grpc.StatusCode.RESOURCE_EXHAUSTED:
                    # Rate limited - exponential backoff
                    backoff_time = min(2 ** attempt, 10)
                    logger.warning(f"Rate limited, retrying in {backoff_time}s")
                    await asyncio.sleep(backoff_time)
                    continue
                raise
```

### Performance Characteristics

The token bucket implementation is highly optimized:

- **O(1) complexity**: Constant time per request
- **Minimal memory**: <1KB per server
- **Low latency**: <0.1μs overhead per request
- **Thread-safe**: Lock-free atomic operations

---

## Graceful Shutdown

Implement proper shutdown handling for zero-downtime deployments:

```python
import asyncio
import signal
from pyvider.rpcplugin import plugin_server

async def main():
    server = plugin_server(protocol=my_protocol, handler=my_handler)

    # Handle shutdown signals
    shutdown_event = asyncio.Event()

    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, initiating graceful shutdown")
        shutdown_event.set()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    # Start server
    server_task = asyncio.create_task(server.serve())

    # Wait for shutdown signal
    await shutdown_event.wait()

    # Graceful shutdown
    logger.info("Stopping server...")
    await server.stop()
    await server_task
    logger.info("Server stopped gracefully")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## Monitoring and Alerting

### Key Metrics to Monitor

1. **Connection Health**:
   - Connection success/failure rates
   - Handshake completion time
   - Active connection count

2. **Request Metrics**:
   - Request rate (RPS)
   - Request latency (p50, p95, p99)
   - Error rates by type

3. **Resource Usage**:
   - Memory consumption
   - CPU utilization
   - File descriptor usage
   - Network I/O

4. **Security Events**:
   - Authentication failures
   - Rate limiting triggers
   - Certificate expiration warnings

### Prometheus Integration

```python
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Define metrics
REQUEST_COUNT = Counter('plugin_requests_total', 'Total requests', ['method', 'status'])
REQUEST_LATENCY = Histogram('plugin_request_duration_seconds', 'Request latency')
ACTIVE_CONNECTIONS = Gauge('plugin_active_connections', 'Active connections')

# In your handler
@REQUEST_LATENCY.time()
async def my_rpc_method(self, request, context):
    try:
        result = await process_request(request)
        REQUEST_COUNT.labels(method='my_method', status='success').inc()
        return result
    except Exception:
        REQUEST_COUNT.labels(method='my_method', status='error').inc()
        raise

# Start metrics server
start_http_server(9090)
```

---

## Troubleshooting

### Message Too Large Error

**Problem**: `RESOURCE_EXHAUSTED: Received message larger than max`

**Solution**:
```python
configure(
    grpc_max_receive_message_size=16 * 1024 * 1024,
    grpc_max_send_message_size=16 * 1024 * 1024
)
```

### Keepalive Timeout

**Problem**: Connection dropped due to keepalive failure

**Solution**:
```python
# Increase timeout or reduce interval
configure(grpc_keepalive_timeout_ms=10000)
configure(grpc_keepalive_time_ms=15000)
```

### Certificate Problems

**Problem**: mTLS handshake failures

**Solution**:
```python
from pyvider.rpcplugin.config import rpcplugin_config

# Verify certificate configuration
config = rpcplugin_config
server_cert = config.server_cert()
if server_cert:
    logger.info("Server certificate configured")
else:
    logger.warning("No server certificate configured")
```

### Rate Limiting Issues

**Problem**: Legitimate requests being rejected

**Solution**:
```bash
# Increase limits
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=200.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=500
```

**Problem**: Rate limiting not working

**Solution**:
```bash
# Ensure enabled explicitly
export PLUGIN_RATE_LIMIT_ENABLED=true
```

---

## Best Practices

### Configuration

1. **Match timeouts to environment** - Fast for dev, generous for production
2. **Tune message sizes for your data** - Calculate based on largest message
3. **Enable debug logging during development** - Disable in production
4. **Adjust keepalive for network conditions** - Frequent for mobile/WiFi, infrequent for datacenter
5. **Profile before tuning buffers** - Measure, don't guess

### Security

1. **Always use mTLS in production** - Non-negotiable
2. **Proper certificate permissions** - Private keys mode 600
3. **Secure magic cookies** - Use cryptographically secure random strings
4. **Network isolation** - Unix sockets for same-host, firewall rules for TCP

### Rate Limiting

1. **Start conservative** - Begin with lower limits, increase based on monitoring
2. **Monitor metrics** - Track rate limiting events and patterns
3. **Client-side handling** - Always implement exponential backoff
4. **Burst capacity** - Set 2-5x higher than sustained rate
5. **Environment specific** - Different limits for dev/staging/production

### Operations

1. **Implement health checks** - Enable `PLUGIN_HEALTH_SERVICE_ENABLED=true`
2. **Structured logging** - Disable emoji for production log aggregation
3. **Graceful shutdown** - Handle SIGTERM/SIGINT properly
4. **Resource limits** - Set appropriate memory/CPU limits
5. **Process management** - Use systemd or equivalent

---

## Related Topics

- **[Configuration Guide](configuration-guide.md)** - Client, server, and security configuration
- **[Logging Configuration](logging.md)** - Structured logging and observability
- **[Environment Variables](environment.md)** - All configuration options reference
- **[Performance Tuning](../advanced/observability.md)** - Performance optimization guide
