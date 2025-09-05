# Production Setup

Deploying Pyvider RPC Plugin applications to production requires careful attention to security, performance, observability, and operational practices. This guide outlines battle-tested patterns and configurations for production environments.

## Security Configuration

### mTLS and Certificate Management

**Always enable mTLS in production** - this is non-negotiable for secure plugin communication:

```bash
# Enable mTLS with proper certificates
export PYVIDER_PLUGIN_AUTO_MTLS="true"
export PYVIDER_PLUGIN_SERVER_CERT="file:///etc/ssl/certs/plugin-server.pem" 
export PYVIDER_PLUGIN_SERVER_KEY="file:///etc/ssl/private/plugin-server.key"
export PYVIDER_PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/ca-bundle.pem"
```

#### Certificate Best Practices

1. **Use trusted Certificate Authority**: Avoid self-signed certificates in production
2. **Proper file permissions**: Private keys should be mode 600, owned by service user
3. **Certificate rotation**: Implement automated certificate renewal (Let's Encrypt, internal CA)
4. **Separate certificates per environment**: Never reuse dev certificates in production

```bash
# Set proper permissions on certificate files
sudo chown plugin-user:plugin-group /etc/ssl/private/plugin-server.key
sudo chmod 600 /etc/ssl/private/plugin-server.key
sudo chmod 644 /etc/ssl/certs/plugin-server.pem
```

### Magic Cookie Security

Use cryptographically secure random strings for magic cookies:

```bash
# Generate secure magic cookie
export PYVIDER_PLUGIN_MAGIC_COOKIE_VALUE="$(openssl rand -hex 32)"

# Or use a secrets management system
export PYVIDER_PLUGIN_MAGIC_COOKIE_VALUE="$(aws secretsmanager get-secret-value --secret-id plugin-auth-token --query SecretString --output text)"
```

### Network Security

Configure appropriate network transport and firewall rules:

```bash
# TCP configuration for networked deployments
export PYVIDER_PLUGIN_SERVER_TRANSPORTS="tcp"
export PYVIDER_PLUGIN_SERVER_ENDPOINT="0.0.0.0:8080"  # Container/K8s
# or
export PYVIDER_PLUGIN_SERVER_ENDPOINT="10.0.1.100:8080"  # Specific interface

# Unix socket for same-host deployments (higher security)
export PYVIDER_PLUGIN_SERVER_TRANSPORTS="unix"
export PYVIDER_PLUGIN_SERVER_ENDPOINT="/var/run/plugin/plugin.sock"
```

## Performance Configuration

### Timeout Tuning

Adjust timeouts based on your network conditions and service requirements:

```bash
# Conservative timeouts for reliable networks
export PYVIDER_PLUGIN_HANDSHAKE_TIMEOUT="30.0"
export PYVIDER_PLUGIN_CONNECTION_TIMEOUT="60.0"

# Aggressive timeouts for fast networks
export PYVIDER_PLUGIN_HANDSHAKE_TIMEOUT="10.0"
export PYVIDER_PLUGIN_CONNECTION_TIMEOUT="30.0"
```

### Rate Limiting

Enable server-side rate limiting to protect against abuse:

```bash
# Enable rate limiting with reasonable defaults
export PYVIDER_PLUGIN_RATE_LIMIT_ENABLED="true"
export PYVIDER_PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND="100.0"
export PYVIDER_PLUGIN_RATE_LIMIT_BURST_CAPACITY="200.0"

# High-throughput configuration
export PYVIDER_PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND="1000.0"
export PYVIDER_PLUGIN_RATE_LIMIT_BURST_CAPACITY="2000.0"

# Restrictive configuration for sensitive operations
export PYVIDER_PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND="10.0"
export PYVIDER_PLUGIN_RATE_LIMIT_BURST_CAPACITY="50.0"
```

### Client Retry Configuration

Configure robust client retry behavior:

```bash
# Production client retry settings
export PYVIDER_PLUGIN_CLIENT_RETRY_ENABLED="true"
export PYVIDER_PLUGIN_CLIENT_MAX_RETRIES="5"
export PYVIDER_PLUGIN_CLIENT_INITIAL_BACKOFF_MS="1000"
export PYVIDER_PLUGIN_CLIENT_MAX_BACKOFF_MS="10000"
export PYVIDER_PLUGIN_CLIENT_RETRY_JITTER_MS="250"
export PYVIDER_PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S="120"
```

## Observability and Monitoring

### Logging Configuration

Configure structured logging for production monitoring:

```bash
# Production logging settings
export PYVIDER_PLUGIN_LOG_LEVEL="INFO"  # Or WARNING to reduce volume
export PYVIDER_PLUGIN_SHOW_EMOJI_MATRIX="false"  # Disable for log aggregation
```

### Health Checks

Enable health services for load balancer and orchestrator integration:

```bash
# Enable health checking service
export PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED="true"
```

#### Kubernetes Health Check Example

```yaml
apiVersion: v1
kind: Service
metadata:
  name: plugin-service
spec:
  selector:
    app: plugin
  ports:
    - name: grpc
      port: 8080
      targetPort: 8080
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: plugin-deployment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: plugin
  template:
    metadata:
      labels:
        app: plugin
    spec:
      containers:
      - name: plugin
        image: my-plugin:latest
        ports:
        - containerPort: 8080
        env:
        - name: PYVIDER_PLUGIN_SERVER_ENDPOINT
          value: "0.0.0.0:8080"
        - name: PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED
          value: "true"
        livenessProbe:
          exec:
            command:
            - grpc-health-probe
            - -addr=localhost:8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          exec:
            command:
            - grpc-health-probe
            - -addr=localhost:8080
          initialDelaySeconds: 5
          periodSeconds: 10
```

## Deployment Patterns

### Container Deployment

Dockerfile example for production:

```dockerfile
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r plugin && useradd -r -g plugin plugin

# Install system dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    grpc-health-probe \
    && rm -rf /var/lib/apt/lists/*

# Copy application
COPY --chown=plugin:plugin . /app
WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create directories with proper permissions
RUN mkdir -p /var/run/plugin /var/log/plugin && \
    chown plugin:plugin /var/run/plugin /var/log/plugin

# Switch to non-root user
USER plugin

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD grpc-health-probe -addr=localhost:8080 || exit 1

EXPOSE 8080

CMD ["python", "-m", "my_plugin.server"]
```

### Docker Compose Production Stack

```yaml
version: '3.8'

services:
  plugin:
    build: .
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - PYVIDER_PLUGIN_LOG_LEVEL=INFO
      - PYVIDER_PLUGIN_SERVER_ENDPOINT=0.0.0.0:8080
      - PYVIDER_PLUGIN_AUTO_MTLS=true
      - PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED=true
      - PYVIDER_PLUGIN_RATE_LIMIT_ENABLED=true
      - PYVIDER_PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=100.0
    volumes:
      - ./certs:/etc/ssl/certs:ro
      - ./private:/etc/ssl/private:ro
      - plugin-logs:/var/log/plugin
    networks:
      - plugin-network
    healthcheck:
      test: ["CMD", "grpc-health-probe", "-addr=localhost:8080"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s

  # Log aggregation
  fluent-bit:
    image: fluent/fluent-bit:latest
    volumes:
      - plugin-logs:/var/log/plugin:ro
      - ./fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf
    depends_on:
      - plugin

volumes:
  plugin-logs:

networks:
  plugin-network:
    driver: bridge
```

### Systemd Service

For traditional server deployments:

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
Environment=PYVIDER_PLUGIN_LOG_LEVEL=INFO
Environment=PYVIDER_PLUGIN_AUTO_MTLS=true
Environment=PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED=true
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

## Environment-Specific Configuration

### Development Environment

```bash
# .env.development
PYVIDER_PLUGIN_LOG_LEVEL=DEBUG
PYVIDER_PLUGIN_SHOW_EMOJI_MATRIX=true
PYVIDER_PLUGIN_AUTO_MTLS=false
PYVIDER_PLUGIN_SERVER_TRANSPORTS=unix
PYVIDER_PLUGIN_HANDSHAKE_TIMEOUT=5.0
PYVIDER_PLUGIN_CONNECTION_TIMEOUT=10.0
```

### Staging Environment

```bash
# .env.staging
PYVIDER_PLUGIN_LOG_LEVEL=INFO
PYVIDER_PLUGIN_SHOW_EMOJI_MATRIX=false
PYVIDER_PLUGIN_AUTO_MTLS=true
PYVIDER_PLUGIN_SERVER_TRANSPORTS=tcp
PYVIDER_PLUGIN_SERVER_CERT=file:///etc/ssl/certs/staging-server.pem
PYVIDER_PLUGIN_SERVER_KEY=file:///etc/ssl/private/staging-server.key
PYVIDER_PLUGIN_RATE_LIMIT_ENABLED=true
PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED=true
```

### Production Environment

```bash
# .env.production
PYVIDER_PLUGIN_LOG_LEVEL=WARNING
PYVIDER_PLUGIN_SHOW_EMOJI_MATRIX=false
PYVIDER_PLUGIN_AUTO_MTLS=true
PYVIDER_PLUGIN_SERVER_TRANSPORTS=tcp
PYVIDER_PLUGIN_SERVER_CERT=file:///etc/ssl/certs/production-server.pem
PYVIDER_PLUGIN_SERVER_KEY=file:///etc/ssl/private/production-server.key
PYVIDER_PLUGIN_CLIENT_ROOT_CERTS=file:///etc/ssl/certs/ca-bundle.pem
PYVIDER_PLUGIN_HANDSHAKE_TIMEOUT=30.0
PYVIDER_PLUGIN_CONNECTION_TIMEOUT=60.0
PYVIDER_PLUGIN_RATE_LIMIT_ENABLED=true
PYVIDER_PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=500.0
PYVIDER_PLUGIN_RATE_LIMIT_BURST_CAPACITY=1000.0
PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED=true
PYVIDER_PLUGIN_CLIENT_MAX_RETRIES=5
PYVIDER_PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S=180
```

## Resource Management

### Memory and CPU Limits

Configure appropriate resource limits for your plugin:

```python
# In your plugin server code
import resource

# Set memory limit (1GB)
resource.setrlimit(resource.RLIMIT_AS, (1024*1024*1024, 1024*1024*1024))

# Set file descriptor limit
resource.setrlimit(resource.RLIMIT_NOFILE, (65536, 65536))
```

### Connection Limits

For high-throughput scenarios:

```python
from pyvider.rpcplugin import RPCPluginServer

server = RPCPluginServer(
    protocol=my_protocol,
    handler=my_handler,
    transport=my_transport,
    # gRPC server options for high concurrency
    max_concurrent_rpcs=1000,
    max_receive_message_length=4 * 1024 * 1024,  # 4MB
    max_send_message_length=4 * 1024 * 1024,     # 4MB
    keepalive_time_ms=30000,
    keepalive_timeout_ms=5000,
    keepalive_permit_without_calls=True,
    max_connection_idle_ms=300000,  # 5 minutes
)
```

## Graceful Shutdown

Implement proper shutdown handling for zero-downtime deployments:

```bash
# Enable file-based shutdown signaling
export PYVIDER_PLUGIN_SHUTDOWN_FILE_PATH="/tmp/shutdown-plugin"
```

```python
# In your application code
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

## Monitoring and Alerting

### Key Metrics to Monitor

1. **Connection Health**:
   - Connection success/failure rates
   - Handshake completion time
   - Active connection count

2. **Request Metrics**:
   - Request rate (RPS)
   - Request latency (p50, p95, p99)
   - Error rates by error type

3. **Resource Usage**:
   - Memory consumption
   - CPU utilization  
   - File descriptor usage
   - Network I/O

4. **Security Events**:
   - Authentication failures
   - Rate limiting triggers
   - Certificate expiration warnings

### Prometheus Integration Example

```python
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Define metrics
REQUEST_COUNT = Counter('plugin_requests_total', 'Total plugin requests', ['method', 'status'])
REQUEST_LATENCY = Histogram('plugin_request_duration_seconds', 'Request latency')
ACTIVE_CONNECTIONS = Gauge('plugin_active_connections', 'Active connections')

# In your handler code
@REQUEST_LATENCY.time()
async def my_rpc_method(self, request, context):
    try:
        result = await process_request(request)
        REQUEST_COUNT.labels(method='my_method', status='success').inc()
        return result
    except Exception as e:
        REQUEST_COUNT.labels(method='my_method', status='error').inc()
        raise

# Start metrics server
start_http_server(9090)
```

## Troubleshooting Common Issues

### Certificate Problems

```python
# Verify certificate configuration
from pyvider.rpcplugin.config import rpcplugin_config

try:
    config = rpcplugin_config
    server_cert = config.server_cert()
    if server_cert:
        logger.info("✅ Server certificate configured")
    else:
        logger.warning("⚠️ No server certificate configured")
except Exception as e:
    logger.error(f"❌ Certificate configuration error: {e}")
```

### Connection Issues

```python
# Debug connection problems
import asyncio
from pyvider.rpcplugin import plugin_client
from pyvider.rpcplugin.exception import TransportError

try:
    async with plugin_client() as client:
        # Connection successful
        logger.info("✅ Client connection established")
except TransportError as e:
    logger.error(f"❌ Transport error: {e}")
    if "Connection refused" in str(e):
        logger.info("💡 Check if server is running and endpoint is correct")
    elif "timeout" in str(e):
        logger.info("💡 Increase timeout values or check network connectivity")
except Exception as e:
    logger.error(f"❌ Unexpected error: {e}")
```

### Performance Issues

1. **High latency**: Check network conditions, increase timeouts
2. **Rate limiting**: Adjust rate limit configuration or client retry behavior  
3. **Memory usage**: Monitor for memory leaks, implement proper cleanup
4. **CPU usage**: Profile your handler code, optimize expensive operations

## Next Steps

- **[Rate Limiting](rate-limiting.md)** - Detailed rate limiting configuration and tuning
- **[Logging Configuration](logging.md)** - Structured logging and observability setup
- **[Environment Variables](environment.md)** - Complete configuration reference
- **[API Configuration](../../api/config/)** - Programmatic configuration options