# Configuration Reference

**Reading Time:** ~3 minutes

This page provides an overview of the configuration system and links to detailed documentation for each configuration area.

!!! warning "Security-First Design: mTLS Enabled by Default"
    **`PLUGIN_AUTO_MTLS` defaults to `True`** for security-first design. This means mutual TLS (mTLS) is **automatically enabled** for all connections unless explicitly disabled.

    **For local development/testing:**
    ```python
    from pyvider.rpcplugin import configure
    configure(auto_mtls=False)  # Disable mTLS for local testing
    ```

    **For production:** Keep the default `auto_mtls=True` and provide proper certificates via:
    - `PLUGIN_SERVER_CERT` and `PLUGIN_SERVER_KEY` (server-side)
    - `PLUGIN_CLIENT_CERT` and `PLUGIN_CLIENT_KEY` (client-side)

    See [Security Configuration](configuration-security.md) for complete mTLS setup instructions.

!!! info "Source of Truth"
    All default values are defined in `src/pyvider/rpcplugin/defaults.py`. If you notice any discrepancies between this documentation and the actual defaults, the code is authoritative. You can verify defaults programmatically:

    ```python
    from pyvider.rpcplugin import defaults
    print(f"Server host: {defaults.DEFAULT_PLUGIN_SERVER_HOST}")
    print(f"Auto mTLS: {defaults.DEFAULT_PLUGIN_AUTO_MTLS}")  # True (security by default)
    ```

!!! note "Optional Configuration Fields"
    Fields with `None` as the default value are **optional**. When set to `None`, the framework uses sensible fallback behavior:

    - **Certificate fields** (`plugin_client_cert`, `plugin_server_cert`, etc.): Auto-generate self-signed certificates when mTLS is enabled
    - **String fields with empty defaults** (`""`): Feature is disabled or uses system defaults
    - **Numeric fields**: Always have non-None defaults with documented values

    You only need to set these fields when you want to override the default behavior (e.g., providing production certificates).

## Configuration Areas

The configuration documentation is organized into focused areas. Choose the section relevant to your needs:

| Configuration Area | Topics Covered | When to Use |
|-------------------|----------------|-------------|
| **[Client Configuration](configuration-client.md)** | Retry logic, backoff, transport preferences, connection timeouts | Setting up plugin clients, tuning connection reliability |
| **[Server Configuration](configuration-server.md)** | Network binding, health checks, rate limiting, shutdown behavior | Configuring plugin servers, production deployment |
| **[Security Configuration](configuration-security.md)** | mTLS, certificates, authentication, insecure mode | Setting up secure communication, certificate management |
| **[Advanced Configuration](configuration-advanced.md)** | gRPC tuning, timeouts, buffers, protocol versions, logging | Performance optimization, debugging, custom setups |

## Configuration System Overview

The configuration system is based on the `RPCPluginConfig` class which extends Foundation's `RuntimeConfig`. All settings can be configured through:

1. **Environment Variables** - Primary configuration method (recommended)
2. **Programmatic API** - Direct attribute setting or `configure()` function
3. **Configuration Files** - Via Foundation's config file support

## Quick Configuration Examples

### Environment Variables

```bash
# Basic setup
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_SERVER_PORT=8080

# Security
export PLUGIN_AUTO_MTLS=true
export PLUGIN_SERVER_CERT=file:///etc/certs/server.crt
export PLUGIN_SERVER_KEY=file:///etc/certs/server.key

# Performance
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=100

python my_plugin.py
```

### Programmatic Configuration

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Direct attribute setting
rpcplugin_config.plugin_log_level = "DEBUG"
rpcplugin_config.plugin_server_port = 8080
rpcplugin_config.plugin_rate_limit_enabled = True
```

### Using the configure() Function

```python
from pyvider.rpcplugin import configure

# Convenient API (recommended)
configure(
    log_level="DEBUG",
    server_port=8080,
    rate_limit_enabled=True,
    rate_limit_requests_per_second=100.0,
    auto_mtls=True
)
```

## Common Configuration Scenarios

### Development Setup

```python
from pyvider.rpcplugin import configure

# Fast iteration, minimal security
configure(
    log_level="DEBUG",
    insecure=True,           # Disable mTLS
    test_mode=True,
    client_max_retries=2,    # Fail fast
    rate_limit_enabled=False # No throttling
)
```

### Production Setup

```python
import os

# Production: security and resilience
os.environ.update({
    "PLUGIN_LOG_LEVEL": "INFO",
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_SERVER_CERT": "file:///etc/certs/server.crt",
    "PLUGIN_SERVER_KEY": "file:///etc/certs/server.key",
    "PLUGIN_RATE_LIMIT_ENABLED": "true",
    "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": "1000",
    "PLUGIN_HEALTH_SERVICE_ENABLED": "true",
    "PLUGIN_CLIENT_MAX_RETRIES": "5"
})
```

### Testing Setup

```bash
# Testing: predictable behavior
export PLUGIN_TEST_MODE=true
export PLUGIN_LOG_LEVEL=WARNING
export PLUGIN_CLIENT_RETRY_ENABLED=false  # Deterministic tests
export PLUGIN_HANDSHAKE_TIMEOUT=5.0
```

## Configuration Validation

The framework validates configuration values at startup:

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Validation happens automatically
# Invalid values raise ConfigError

# Example: protocol versions must be in supported range
rpcplugin_config.plugin_protocol_version = 999  # Raises ValueError

# Example: transports must be valid
rpcplugin_config.plugin_client_transports = ["invalid"]  # Raises ValueError
```

## Multi-Instance Configuration

For running multiple plugin instances with different configurations:

```python
from pyvider.rpcplugin.config import (
    RPCPluginConfig,
    register_plugin_config,
    get_plugin_config
)

# Create separate configurations
auth_config = RPCPluginConfig()
auth_config.plugin_server_port = 8081
auth_config.plugin_rate_limit_enabled = True

data_config = RPCPluginConfig()
data_config.plugin_server_port = 8082
data_config.plugin_auto_mtls = True

# Register with unique names
register_plugin_config("auth_plugin", auth_config)
register_plugin_config("data_plugin", data_config)

# Retrieve when needed
config = get_plugin_config("auth_plugin")
```

## Detailed Configuration Settings

For complete configuration tables and detailed explanations, see:

- **[Client Configuration](configuration-client.md)** - 11 client settings
- **[Server Configuration](configuration-server.md)** - 8 server settings
- **[Security Configuration](configuration-security.md)** - 12 security settings
- **[Advanced Configuration](configuration-advanced.md)** - 20+ advanced settings

## Best Practices

### 1. Use Environment Variables

Environment variables are the recommended primary configuration method:

**Why:** Portable across platforms, container-friendly, separates configuration from code

```bash
# Good: configuration via environment
export PLUGIN_SERVER_PORT=8080

# Less preferred: hardcoded in application
# configure(server_port=8080)
```

### 2. Validate Configuration at Startup

Catch configuration errors early:

```python
def validate_config():
    """Validate required configuration."""
    from pyvider.rpcplugin.config import rpcplugin_config

    if rpcplugin_config.plugin_auto_mtls:
        if not rpcplugin_config.plugin_server_cert:
            raise ValueError("Server cert required for mTLS")

    if rpcplugin_config.plugin_rate_limit_enabled:
        if rpcplugin_config.plugin_rate_limit_requests_per_second <= 0:
            raise ValueError("Invalid rate limit")

# Call during initialization
validate_config()
```

### 3. Document Required Configuration

Document what your plugin needs:

```python
"""
MyPlugin - Configuration Requirements

Required:
- PLUGIN_MAGIC_COOKIE_VALUE: Authentication cookie
- MY_APP_API_KEY: External API key

Optional:
- PLUGIN_LOG_LEVEL: Logging level (default: INFO)
- PLUGIN_RATE_LIMIT_ENABLED: Enable throttling (default: false)
"""
```

### 4. Use Configuration Profiles

Create profiles for different environments:

```python
import os

ENV = os.getenv("ENVIRONMENT", "development")

PROFILES = {
    "development": {
        "log_level": "DEBUG",
        "insecure": True,
        "test_mode": True
    },
    "testing": {
        "log_level": "WARNING",
        "auto_mtls": True,
        "client_retry_enabled": False
    },
    "production": {
        "log_level": "INFO",
        "auto_mtls": True,
        "rate_limit_enabled": True,
        "health_service_enabled": True
    }
}

# Apply profile
from pyvider.rpcplugin import configure
configure(**PROFILES[ENV])
```

## Troubleshooting Configuration

### Configuration Not Loading

1. **Check environment variable names** (case-sensitive, must start with `PLUGIN_`)
2. **Verify type conversion** (e.g., `"true"` for booleans, not `"True"`)
3. **Check for typos** in variable names
4. **Enable debug logging** to see what configuration is loaded

```python
configure(log_level="DEBUG")
# Check logs for configuration values
```

### Invalid Configuration Values

1. **Review validation rules** in `src/pyvider/rpcplugin/config/validators.py`
2. **Check type requirements** (int, float, str, bool, list)
3. **Verify value ranges** (e.g., ports 0-65535, positive timeouts)

### Multi-Instance Conflicts

1. **Use unique configuration names** when registering
2. **Avoid modifying global `rpcplugin_config`** when using multiple instances
3. **Consider configuration manager** for complex multi-instance setups

## Next Steps

Now that you understand configuration:

1. **Review** your specific configuration area:
   - [Client Configuration](configuration-client.md) for client setup
   - [Server Configuration](configuration-server.md) for server setup
   - [Security Configuration](configuration-security.md) for mTLS
   - [Advanced Configuration](configuration-advanced.md) for tuning

2. **Check** configuration examples in:
   - [Production Guide](production.md) for deployment patterns
   - [Security Guide](../security/index.md) for security setup

3. **Explore** the complete API:
   - [API Reference](../../reference/pyvider/rpcplugin/config/index.md) for configuration classes

## Related Topics

- **[Environment Configuration Guide](environment.md)** - Setting up environment variables
- **[Production Configuration](production.md)** - Production deployment patterns
- **[Configuration API Reference](../../reference/pyvider/rpcplugin/config/index.md)** - Complete API docs

---

**Navigation:** [← Config Index](index.md) | [Client Config →](configuration-client.md)
