# Server Configuration

**Reading Time:** ~5 minutes

Complete reference for server-side configuration options in Pyvider RPC Plugin. These settings control server binding, transports, health checks, and rate limiting.

## Overview

Server configuration controls:

- **Network binding** - Host, port, and transport selection
- **Health checks** - gRPC health service configuration
- **Rate limiting** - Request throttling with token bucket
- **Shutdown behavior** - Graceful shutdown and file-based signals
- **Test mode** - Special behavior for testing environments

## Quick Start

```python
from pyvider.rpcplugin import configure

# Configure server with common settings
configure(
    server_port=8080,
    server_host="0.0.0.0",
    health_service_enabled=True,
    rate_limit_enabled=True,
    rate_limit_requests_per_second=100.0
)
```

## Complete Server Settings

### Network Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_server_port` | `PLUGIN_SERVER_PORT` | `int` | `0` | Server port (0 = dynamic allocation) |
| `plugin_server_host` | `PLUGIN_SERVER_HOST` | `str` | `"localhost"` | Server bind address |
| `plugin_server_transports` | `PLUGIN_SERVER_TRANSPORTS` | `list[str]` | `["unix", "tcp"]` | Available transport protocols |
| `plugin_server_unix_socket_path` | `PLUGIN_SERVER_UNIX_SOCKET_PATH` | `str` | `"/tmp/plugin.sock"` | Unix socket path for server |

### Health Check Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_health_service_enabled` | `PLUGIN_HEALTH_SERVICE_ENABLED` | `bool` | `True` | Enable gRPC health check service |

### Rate Limiting Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_rate_limit_enabled` | `PLUGIN_RATE_LIMIT_ENABLED` | `bool` | `False` | Enable rate limiting |
| `plugin_rate_limit_requests_per_second` | `PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND` | `float` | `100.0` | Request rate limit |
| `plugin_rate_limit_burst_capacity` | `PLUGIN_RATE_LIMIT_BURST_CAPACITY` | `int` | `200` | Token bucket burst capacity |

### Lifecycle Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_shutdown_file_path` | `PLUGIN_SHUTDOWN_FILE_PATH` | `str` | `""` | File path for shutdown signal |
| `plugin_test_mode` | `PLUGIN_TEST_MODE` | `bool` | `False` | Enable test mode features |

## Usage Examples

### Basic Server Setup

```python
from pyvider.rpcplugin import plugin_server, plugin_protocol, configure

# Configure server
configure(
    server_port=8080,
    server_host="0.0.0.0",  # Listen on all interfaces
    health_service_enabled=True
)

# Create server
server = plugin_server(
    protocol=plugin_protocol(),
    handler=MyHandler()
)

await server.serve()
```

### Environment Variable Configuration

```bash
# Production server configuration
export PLUGIN_SERVER_HOST=0.0.0.0
export PLUGIN_SERVER_PORT=8080
export PLUGIN_HEALTH_SERVICE_ENABLED=true
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=2000

python my_server.py
```

### Transport Configuration

```python
from pyvider.rpcplugin import configure

# Unix sockets only (Linux/macOS)
configure(server_transports=["unix"])

# TCP only (Windows or network plugins)
configure(server_transports=["tcp"])

# Both transports (negotiate with client)
configure(server_transports=["unix", "tcp"])
```

### Rate Limiting Setup

```python
from pyvider.rpcplugin import configure

# Enable rate limiting with custom limits
configure(
    rate_limit_enabled=True,
    rate_limit_requests_per_second=50.0,  # 50 req/s sustained
    rate_limit_burst_capacity=100         # 100 req burst
)
```

### Custom Unix Socket Path

```python
from pyvider.rpcplugin import configure
import tempfile
from pathlib import Path

# Use custom socket directory
socket_dir = Path(tempfile.gettempdir()) / "my_app"
socket_dir.mkdir(exist_ok=True)

configure(
    server_unix_socket_path=str(socket_dir / "plugin.sock")
)
```

### File-Based Shutdown

```python
from pyvider.rpcplugin import configure
from pathlib import Path

# Server will shutdown when this file is created
shutdown_file = Path("/tmp/shutdown_signal")

configure(
    shutdown_file_path=str(shutdown_file)
)

# To shutdown: touch /tmp/shutdown_signal
```

## Network Binding

### Bind Address Options

| Address | Description | Use Case |
|---------|-------------|----------|
| `"localhost"` | Local connections only (default) | Development, local plugins |
| `"127.0.0.1"` | IPv4 local only | Explicit local binding |
| `"0.0.0.0"` | All IPv4 interfaces | Production, network plugins |
| `"::"` | All IPv6 interfaces | IPv6 networks |

### Port Selection

```python
# Dynamic port (recommended for plugins)
configure(server_port=0)  # OS assigns available port

# Fixed port (for known network services)
configure(server_port=8080)

# High port (no root required)
configure(server_port=50051)  # Common gRPC port
```

## Health Checks

### Basic Health Check

```python
from pyvider.rpcplugin import configure

# Enable default health checks
configure(health_service_enabled=True)
```

The health service implements the [gRPC Health Checking Protocol](https://github.com/grpc/grpc/blob/master/doc/health-checking/), compatible with:

- Kubernetes liveness/readiness probes
- Load balancers
- Monitoring systems

### Query Health Status

```bash
# Using grpc_health_probe
grpc_health_probe -addr=localhost:8080

# Using grpcurl
grpcurl -plaintext localhost:8080 grpc.health.v1.Health/Check
```

## Rate Limiting

### Token Bucket Algorithm

Rate limiting uses a token bucket:

- **Bucket size**: Maximum burst capacity
- **Refill rate**: Tokens added per second
- **Request cost**: Each request consumes 1 token

### Configuration Examples

```python
# Conservative (small services)
configure(
    rate_limit_enabled=True,
    rate_limit_requests_per_second=10.0,
    rate_limit_burst_capacity=20
)

# Moderate (typical services)
configure(
    rate_limit_enabled=True,
    rate_limit_requests_per_second=100.0,
    rate_limit_burst_capacity=200
)

# Aggressive (high-throughput services)
configure(
    rate_limit_enabled=True,
    rate_limit_requests_per_second=1000.0,
    rate_limit_burst_capacity=2000
)
```

### Disable for Development

```python
# Development: no rate limiting
configure(rate_limit_enabled=False)
```

## Best Practices

### 1. Use Dynamic Ports for Plugins

```python
# Let OS assign port (recommended)
configure(server_port=0)
```

Plugins communicate via handshake - the actual port doesn't matter.

### 2. Bind to Localhost for Local Plugins

```python
# Secure default: local only
configure(server_host="localhost")
```

Only use `0.0.0.0` when plugins need network access.

### 3. Enable Health Checks in Production

```python
# Production: always enable health checks
configure(health_service_enabled=True)
```

Essential for Kubernetes, load balancers, and monitoring.

### 4. Set Appropriate Rate Limits

```python
# Match your service capacity
configure(
    rate_limit_enabled=True,
    rate_limit_requests_per_second=your_max_rps * 0.8  # 80% of capacity
)
```

### 5. Use Test Mode for Testing

```python
# Enable test mode features
configure(test_mode=True)
```

Enables special behavior for testing (e.g., faster timeouts, debug output).

## Platform Considerations

### Linux/macOS

```python
# Prefer Unix sockets for performance
configure(
    server_transports=["unix", "tcp"],  # Unix first
    server_unix_socket_path="/tmp/my_plugin.sock"
)
```

### Windows

```python
# TCP only (Unix sockets not available)
configure(
    server_transports=["tcp"],
    server_port=8080
)
```

### Containers/Kubernetes

```python
# Listen on all interfaces for container networking
configure(
    server_host="0.0.0.0",
    server_port=8080,  # Fixed port for service discovery
    health_service_enabled=True,  # For liveness probes
    rate_limit_enabled=True  # Protect from overload
)
```

## Troubleshooting

### Port Already in Use

**Problem:** Server fails to bind to port

**Solutions:**
```python
# Use dynamic port allocation
configure(server_port=0)

# Or choose different port
configure(server_port=8081)
```

### Unix Socket Permission Denied

**Problem:** Can't create Unix socket

**Solutions:**
```bash
# Ensure directory is writable
mkdir -p /tmp/my_app
chmod 755 /tmp/my_app

# Or use different path
export PLUGIN_SERVER_UNIX_SOCKET_PATH=/tmp/plugin.sock
```

### Rate Limit Too Restrictive

**Problem:** Legitimate requests getting throttled

**Solutions:**
```python
# Increase rate limit
configure(
    rate_limit_requests_per_second=200.0,
    rate_limit_burst_capacity=400
)

# Or disable for debugging
configure(rate_limit_enabled=False)
```

### Health Check Not Working

**Problem:** Health probe fails

**Solutions:**
```python
# Ensure health service is enabled
configure(health_service_enabled=True)

# Check server is actually running
# Check port is accessible
```

## Related Topics

- **[Configuration Reference](configuration-reference/)** - All configuration options
- **[Client Configuration](configuration-client/)** - Client-side settings
- **[Security Configuration](configuration-security/)** - mTLS and certificates
- **[Server Development](../server/index/)** - Server implementation patterns
- **[Health Checks](../server/health-checks/)** - Health check implementation
- **[Rate Limiting Guide](../server/rate-limiting/)** - Advanced rate limiting
