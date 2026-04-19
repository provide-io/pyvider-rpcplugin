# Configuration Guide

**Reading Time:** ~10 minutes

Complete guide for configuring Pyvider RPC Plugin. This covers client-side, server-side, and security configuration in one comprehensive reference.

## Overview

Pyvider RPC Plugin configuration controls three main areas:

- **Client Configuration** - Connection behavior, retry logic, transport preferences
- **Server Configuration** - Network binding, health checks, rate limiting
- **Security Configuration** - mTLS, certificates, authentication

### Configuration Methods

Configure via code or environment variables:

=== "Code Configuration"

````
```python
from pyvider.rpcplugin import configure

configure(
    # Client
    client_max_retries=5,
    connection_timeout=60.0,

    # Server
    server_port=8080,
    health_service_enabled=True,

    # Security
    auto_mtls=True
)
```
````

=== "Environment Variables"

````
```bash
# Client
export PLUGIN_CLIENT_MAX_RETRIES=5
export PLUGIN_CONNECTION_TIMEOUT=60.0

# Server
export PLUGIN_SERVER_PORT=8080
export PLUGIN_HEALTH_SERVICE_ENABLED=true

# Security
export PLUGIN_AUTO_MTLS=true
```
````

______________________________________________________________________

## Configuration Reference

=== "Client Configuration"

````
### Overview

Client configuration controls how the client connects to plugins, manages retries, and handles failures.

### Quick Start

```python
from pyvider.rpcplugin import configure

configure(
    client_max_retries=5,
    client_retry_delay=2.0,
    connection_timeout=60.0,
    client_transports=["unix", "tcp"]
)
```

### Settings Tables

#### Retry Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_client_max_retries` | `PLUGIN_CLIENT_MAX_RETRIES` | `int` | `3` | Maximum retry attempts |
| `plugin_client_retry_enabled` | `PLUGIN_CLIENT_RETRY_ENABLED` | `bool` | `True` | Enable automatic retry |
| `plugin_client_retry_delay` | `PLUGIN_CLIENT_RETRY_DELAY` | `float` | `1.0` | Initial retry delay (seconds) |
| `plugin_client_backoff_multiplier` | `PLUGIN_CLIENT_BACKOFF_MULTIPLIER` | `float` | `2.0` | Exponential backoff multiplier |
| `plugin_client_max_retry_delay` | `PLUGIN_CLIENT_MAX_RETRY_DELAY` | `float` | `10.0` | Maximum retry delay (seconds) |

#### Backoff Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_client_initial_backoff_ms` | `PLUGIN_CLIENT_INITIAL_BACKOFF_MS` | `int` | `100` | Initial backoff (milliseconds) |
| `plugin_client_max_backoff_ms` | `PLUGIN_CLIENT_MAX_BACKOFF_MS` | `int` | `5000` | Maximum backoff (milliseconds) |
| `plugin_client_retry_jitter_ms` | `PLUGIN_CLIENT_RETRY_JITTER_MS` | `int` | `50` | Retry jitter (milliseconds) |
| `plugin_client_retry_total_timeout_s` | `PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S` | `float` | `30.0` | Total timeout for retries (seconds) |

#### Transport & Security

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_client_transports` | `PLUGIN_CLIENT_TRANSPORTS` | `list[str]` | `["unix", "tcp"]` | Ordered transports to try |
| `plugin_client_cert` | `PLUGIN_CLIENT_CERT` | `str \| None` | `None` | Client certificate (PEM or file://) |
| `plugin_client_key` | `PLUGIN_CLIENT_KEY` | `str \| None` | `None` | Client private key (PEM or file://) |
| `plugin_client_root_certs` | `PLUGIN_CLIENT_ROOT_CERTS` | `str` | `""` | Root CA certificates (PEM) |

### Key Concepts

#### Exponential Backoff

The client uses exponential backoff with jitter to prevent thundering herd:

```
Attempt 1: 1.0s
Attempt 2: 2.0s + jitter
Attempt 3: 4.0s + jitter
Attempt 4: 8.0s + jitter
Attempt 5: min(16.0, max_delay) = 10.0s + jitter
```

#### Total Timeout

`client_retry_total_timeout_s` caps the **total** time spent retrying:

```python
# Stop after 30 seconds total, regardless of max_retries
configure(
    client_max_retries=100,
    client_retry_total_timeout_s=30.0
)
```

### Platform-Specific Configuration

```python
import platform

if platform.system() == "Windows":
    # Windows: TCP only
    configure(client_transports=["tcp"])
else:
    # Linux/macOS: prefer Unix, fallback to TCP
    configure(client_transports=["unix", "tcp"])
```
````

=== "Server Configuration"

````
### Overview

Server configuration controls network binding, health checks, rate limiting, and lifecycle behavior.

### Quick Start

```python
from pyvider.rpcplugin import configure

configure(
    server_port=8080,
    server_host="0.0.0.0",
    health_service_enabled=True,
    rate_limit_enabled=True,
    rate_limit_requests_per_second=100.0
)
```

### Settings Tables

#### Network Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_server_port` | `PLUGIN_SERVER_PORT` | `int` | `0` | Server port (0 = dynamic) |
| `plugin_server_host` | `PLUGIN_SERVER_HOST` | `str` | `"localhost"` | Server bind address |
| `plugin_server_transports` | `PLUGIN_SERVER_TRANSPORTS` | `list[str]` | `["unix", "tcp"]` | Available transports |
| `plugin_server_unix_socket_path` | `PLUGIN_SERVER_UNIX_SOCKET_PATH` | `str` | `"/tmp/plugin.sock"` | Unix socket path |

#### Health & Rate Limiting

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_health_service_enabled` | `PLUGIN_HEALTH_SERVICE_ENABLED` | `bool` | `True` | Enable gRPC health checks |
| `plugin_rate_limit_enabled` | `PLUGIN_RATE_LIMIT_ENABLED` | `bool` | `False` | Enable rate limiting |
| `plugin_rate_limit_requests_per_second` | `PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND` | `float` | `100.0` | Request rate limit |
| `plugin_rate_limit_burst_capacity` | `PLUGIN_RATE_LIMIT_BURST_CAPACITY` | `int` | `200` | Burst capacity |

#### Lifecycle

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_shutdown_file_path` | `PLUGIN_SHUTDOWN_FILE_PATH` | `str` | `""` | Shutdown signal file path |
| `plugin_test_mode` | `PLUGIN_TEST_MODE` | `bool` | `False` | Enable test mode |

### Key Concepts

#### Bind Address Options

| Address | Description | Use Case |
|---------|-------------|----------|
| `"localhost"` | Local connections only | Development, local plugins |
| `"0.0.0.0"` | All IPv4 interfaces | Production, network plugins |
| `"::"` | All IPv6 interfaces | IPv6 networks |

#### Rate Limiting (Token Bucket)

- **Bucket size**: Maximum burst capacity
- **Refill rate**: Tokens added per second
- **Request cost**: Each request consumes 1 token

```python
# Moderate service (100 req/s sustained, 200 burst)
configure(
    rate_limit_enabled=True,
    rate_limit_requests_per_second=100.0,
    rate_limit_burst_capacity=200
)
```

### Platform-Specific Configuration

=== "Linux/macOS"

    ```python
    # Prefer Unix sockets for performance
    configure(
        server_transports=["unix", "tcp"],
        server_unix_socket_path="/tmp/my_plugin.sock"
    )
    ```

=== "Windows"

    ```python
    # TCP only (Unix sockets unavailable)
    configure(
        server_transports=["tcp"],
        server_port=8080
    )
    ```

=== "Kubernetes"

    ```python
    # Listen on all interfaces
    configure(
        server_host="0.0.0.0",
        server_port=8080,  # Fixed for service discovery
        health_service_enabled=True,  # For liveness probes
        rate_limit_enabled=True
    )
    ```
````

=== "Security Configuration"

````
### Overview

Security configuration controls mTLS, certificates, and authentication.

!!! warning "Security by Default"
    **mTLS is ENABLED by default** (`PLUGIN_AUTO_MTLS=true`). For development/testing, disable with `configure(auto_mtls=False)` or `PLUGIN_INSECURE=true`.

### Quick Start

=== "Development (Insecure)"

    ```python
    from pyvider.rpcplugin import configure

    # Disable mTLS for local testing
    configure(auto_mtls=False)

    # Or disable all security
    configure(insecure=True)
    ```

=== "Production (mTLS)"

    ```python
    import os

    # Server configuration
    os.environ.update({
        "PLUGIN_AUTO_MTLS": "true",
        "PLUGIN_SERVER_CERT": "file:///etc/certs/server.crt",
        "PLUGIN_SERVER_KEY": "file:///etc/certs/server.key",
        "PLUGIN_CA_CERT": "file:///etc/certs/ca.crt"
    })

    # Client configuration
    os.environ.update({
        "PLUGIN_CLIENT_CERT": "file:///etc/certs/client.crt",
        "PLUGIN_CLIENT_KEY": "file:///etc/certs/client.key",
        "PLUGIN_CA_CERT": "file:///etc/certs/ca.crt"
    })
    ```

### Settings Tables

#### mTLS Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_auto_mtls` | `PLUGIN_AUTO_MTLS` | `bool` | `True` | Enable automatic mTLS |
| `plugin_insecure` | `PLUGIN_INSECURE` | `bool` | `False` | Disable all security (dev only) |
| `plugin_mtls_cert_dir` | `PLUGIN_MTLS_CERT_DIR` | `str` | `"/tmp/plugin-certs"` | mTLS cert directory |
| `plugin_cert_validity_days` | `PLUGIN_CERT_VALIDITY_DAYS` | `int` | `365` | Cert validity (days) |

#### Server Certificates

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_server_cert` | `PLUGIN_SERVER_CERT` | `str \| None` | `None` | Server cert (PEM or file://) |
| `plugin_server_key` | `PLUGIN_SERVER_KEY` | `str \| None` | `None` | Server key (PEM or file://) |
| `plugin_server_root_certs` | `PLUGIN_SERVER_ROOT_CERTS` | `str \| None` | `None` | Server root CA (PEM) |

#### Client Certificates

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_client_cert` | `PLUGIN_CLIENT_CERT` | `str \| None` | `None` | Client cert (PEM or file://) |
| `plugin_client_key` | `PLUGIN_CLIENT_KEY` | `str \| None` | `None` | Client key (PEM or file://) |
| `plugin_client_root_certs` | `PLUGIN_CLIENT_ROOT_CERTS` | `str` | `""` | Client root CA (PEM) |

#### Authentication

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_ca_cert` | `PLUGIN_CA_CERT` | `str \| None` | `None` | CA cert for validation |
| `plugin_magic_cookie_key` | `PLUGIN_MAGIC_COOKIE_KEY` | `str` | `"PLUGIN_MAGIC_COOKIE"` | Magic cookie env var name |
| `plugin_magic_cookie_value` | `PLUGIN_MAGIC_COOKIE_VALUE` | `str` | `"test_cookie_value"` | Magic cookie value (testing) |

### mTLS Modes

#### Auto-Generated Certificates (Default)

```python
configure(auto_mtls=True)
```

- Framework generates self-signed certs automatically
- Stored in `plugin_mtls_cert_dir`
- Valid for `plugin_cert_validity_days`
- **Use for:** Development, testing, local plugins

#### Provided Certificates (Production)

```python
# Using file:// URLs (recommended)
os.environ.update({
    "PLUGIN_SERVER_CERT": "file:///etc/certs/server.crt",
    "PLUGIN_SERVER_KEY": "file:///etc/certs/server.key",
    "PLUGIN_CA_CERT": "file:///etc/certs/ca.crt"
})
```

- **Use for:** Production, enterprise deployments

#### Insecure Mode (Development Only)

```python
configure(insecure=True)  # WARNING: No encryption or auth
```

- **Never use in production!**

### Certificate Formats

| Format | Example | Use Case |
|--------|---------|----------|
| File URL | `file:///etc/certs/server.crt` | Recommended |
| Inline PEM | `"-----BEGIN CERTIFICATE-----\n..."` | Secrets management |
| File path | `"/etc/certs/server.crt"` | Legacy |

### Security Profiles

| Profile | mTLS | Certificates | Use Case |
|---------|------|--------------|----------|
| **Development** | Disabled | None | Fast iteration |
| **Testing** | Auto-generated | Self-signed | Integration tests |
| **Production** | Enabled | Provided | Live deployments |
````

______________________________________________________________________

## Common Configuration Patterns

### Development Setup

```python
from pyvider.rpcplugin import configure

# Fast iteration, minimal security
configure(
    insecure=True,
    client_max_retries=2,
    connection_timeout=10.0,
    log_level="DEBUG"
)
```

### Testing Setup

```python
# Auto-generated certs, deterministic behavior
configure(
    auto_mtls=True,
    client_retry_enabled=False,  # Deterministic tests
    test_mode=True,
    log_level="WARNING"
)
```

### Production Setup

```python
import os

# Secure, resilient, monitored
os.environ.update({
    # Security
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_SERVER_CERT": "file:///etc/certs/server.crt",
    "PLUGIN_SERVER_KEY": "file:///etc/certs/server.key",
    "PLUGIN_CA_CERT": "file:///etc/certs/ca.crt",

    # Client resilience
    "PLUGIN_CLIENT_MAX_RETRIES": "5",
    "PLUGIN_CONNECTION_TIMEOUT": "30.0",
    "PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S": "120.0",

    # Server
    "PLUGIN_SERVER_HOST": "0.0.0.0",
    "PLUGIN_HEALTH_SERVICE_ENABLED": "true",
    "PLUGIN_RATE_LIMIT_ENABLED": "true",
    "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": "1000",
})
```

______________________________________________________________________

## Best Practices

### Client Best Practices

1. **Set appropriate timeouts** - Match timeouts to your environment (dev: fast failure, prod: resilient)
1. **Platform-specific transports** - Windows uses TCP only; Linux/macOS prefer Unix sockets
1. **Log retry attempts** - Monitor retry behavior in production for debugging

### Server Best Practices

1. **Use dynamic ports for plugins** - Let OS assign port (recommended: `server_port=0`)
1. **Bind to localhost for local plugins** - Only use `0.0.0.0` for network plugins
1. **Enable health checks in production** - Essential for Kubernetes and load balancers
1. **Set rate limits** - Match your service capacity (use ~80% of max capacity)

### Security Best Practices

1. **Always use mTLS in production** - Never disable security in production
1. **Rotate certificates regularly** - Monitor expiration, automate rotation (recommend 90-day certs)
1. **Secure certificate storage** - Use secrets management, not hardcoded paths
1. **Separate dev/prod configs** - Use environment-based configuration switching
1. **Use strong magic cookies** - Generate cryptographically secure tokens

______________________________________________________________________

## Troubleshooting

### Client Issues

**Connection Timeouts**

```python
# Increase timeouts
configure(
    connection_timeout=60.0,
    handshake_timeout=20.0
)
```

**Excessive Retries**

```python
# Reduce retries or set aggressive timeout
configure(
    client_max_retries=2,
    client_retry_total_timeout_s=10.0
)
```

### Server Issues

**Port Already in Use**

```python
# Use dynamic port allocation
configure(server_port=0)
```

**Rate Limit Too Restrictive**

```python
# Increase limits or disable for debugging
configure(
    rate_limit_requests_per_second=200.0,
    rate_limit_burst_capacity=400
)
```

### Security Issues

**Certificate Verification Failed**

```bash
# Verify certificate chain manually
openssl verify -CAfile ca.crt server.crt

# Disable for debugging (NEVER in production)
configure(insecure=True)
```

**Permission Denied for Cert Files**

```bash
# Fix file permissions
chmod 600 /etc/certs/server.key
chmod 644 /etc/certs/server.crt
```

______________________________________________________________________

## Related Topics

- **[Configuration Reference](configuration-reference.md)** - Complete settings reference
- **[Config vs Factory Parameters](configuration-vs-factory-parameters.md)** - Understanding the difference
- **[Environment Variables](environment.md)** - Environment variable reference
- **[Advanced Configuration](advanced.md)** - Production patterns, rate limiting details
- **[Logging Configuration](logging.md)** - Logging setup and patterns
- **[Server Development](../server/index.md)** - Server implementation
- **[Client Development](../client/index.md)** - Client implementation
- **[Security Guide](../security/index.md)** - Complete security implementation
