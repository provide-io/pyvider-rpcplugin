# Configuration Reference

**Reading Time:** ~3 minutes

This page provides an overview of the configuration system and links to detailed documentation for each configuration area.

!!! warning "Security-First Design: mTLS Enabled by Default" **`PLUGIN_AUTO_MTLS` defaults to `True`** for security-first design. This means mutual TLS (mTLS) is **automatically enabled** for all connections unless explicitly disabled.

````
**For local development/testing:**
```python
from pyvider.rpcplugin import configure
configure(auto_mtls=False)  # Disable mTLS for local testing
```

**For production:** Keep the default `auto_mtls=True` and provide proper certificates via:
- `PLUGIN_SERVER_CERT` and `PLUGIN_SERVER_KEY` (server-side)
- `PLUGIN_CLIENT_CERT` and `PLUGIN_CLIENT_KEY` (client-side)

    See [Security Configuration](configuration-security/) for complete mTLS setup instructions.

!!! info "Source of Truth" All default values are defined in `src/pyvider/rpcplugin/defaults.py`. If you notice any discrepancies between this documentation and the actual defaults, the code is authoritative. You can verify defaults programmatically:

````
```python
from pyvider.rpcplugin import defaults
print(f"Server host: {defaults.DEFAULT_PLUGIN_SERVER_HOST}")
print(f"Auto mTLS: {defaults.DEFAULT_PLUGIN_AUTO_MTLS}")  # True (security by default)
```
````

!!! note "Optional Configuration Fields" Fields with `None` as the default value are **optional**. When set to `None`, the framework uses sensible fallback behavior:

```
- **Certificate fields** (`plugin_client_cert`, `plugin_server_cert`, etc.): Auto-generate self-signed certificates when mTLS is enabled
- **String fields with empty defaults** (`""`): Feature is disabled or uses system defaults
- **Numeric fields**: Always have non-None defaults with documented values

You only need to set these fields when you want to override the default behavior (e.g., providing production certificates).
```

## Configuration Areas

The configuration documentation is organized into focused areas. Choose the section relevant to your needs:

| Configuration Area | Topics Covered | When to Use |
|-------------------|----------------|-------------|
| **[Client Configuration](configuration-client/)** | Retry logic, backoff, transport preferences, connection timeouts | Setting up plugin clients, tuning connection reliability |
| **[Server Configuration](configuration-server/)** | Network binding, health checks, rate limiting, shutdown behavior | Configuring plugin servers, production deployment |
| **[Security Configuration](configuration-security/)** | mTLS, certificates, authentication, insecure mode | Setting up secure communication, certificate management |
| **[Advanced Configuration](configuration-advanced/)** | gRPC tuning, timeouts, buffers, protocol versions, logging | Performance optimization, debugging, custom setups |

## Configuration System Overview

The configuration system is based on the `RPCPluginConfig` class which extends Foundation's `RuntimeConfig`. All settings can be configured through:

1. **Environment Variables** - Primary configuration method (recommended)
1. **Programmatic API** - Direct attribute setting or `configure()` function
1. **Configuration Files** - Via Foundation's config file support

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

!!! info "Understanding configure() Parameters" The `configure()` function has **5 explicit parameters** with type hints and IDE autocomplete:

```
- `magic_cookie: str | None`
- `protocol_version: int | None`
- `transports: list[str] | None`
- `auto_mtls: bool | None`
- `handshake_timeout: float | None`

All other settings can be passed via `**kwargs`, which are automatically prefixed with `plugin_` and set on the config object.
```

```python
from pyvider.rpcplugin import configure

# Using explicit parameters (type-checked, autocomplete-friendly)
configure(
    magic_cookie="my-plugin-secret",
    protocol_version=1,
    transports=["unix", "tcp"],
    auto_mtls=True,
    handshake_timeout=10.0
)

# Using **kwargs for additional settings (automatically prefixed with 'plugin_')
configure(
    magic_cookie="my-plugin-secret",
    auto_mtls=True,
    log_level="DEBUG",                    # Sets plugin_log_level
    server_port=8080,                     # Sets plugin_server_port
    rate_limit_enabled=True,              # Sets plugin_rate_limit_enabled
    rate_limit_requests_per_second=100.0  # Sets plugin_rate_limit_requests_per_second
)

# For better IDE support, you can also set directly on the config object
from pyvider.rpcplugin.config import rpcplugin_config
rpcplugin_config.plugin_log_level = "DEBUG"  # Type-checked by your IDE
rpcplugin_config.plugin_server_port = 8080
```

## Common Configuration Scenarios

### Development Setup

```python
from pyvider.rpcplugin import configure

# Fast iteration, minimal security
# Note: Parameters beyond the 5 explicit ones are passed via **kwargs
configure(
    auto_mtls=False,                 # Explicit param: Disable mTLS for local dev
    handshake_timeout=30.0,          # Explicit param: Longer timeout for debugging
    log_level="DEBUG",               # Via **kwargs: Sets plugin_log_level
    client_max_retries=2,            # Via **kwargs: Fail fast
    rate_limit_enabled=False         # Via **kwargs: No throttling
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

## Configuration Instance Patterns

Understanding when to use different RPCPluginConfig instantiation methods:

### Using the Global Singleton (Recommended)

For most use cases, use the pre-configured global instance:

```python
from pyvider.rpcplugin.config import rpcplugin_config

# ✅ Recommended: Use the global singleton
# Already initialized with environment variables via .from_env()
timeout = rpcplugin_config.plugin_handshake_timeout
port = rpcplugin_config.plugin_server_port
```

**When to use:**

- Single plugin instance per process (most common)
- Configuration from environment variables
- Working with factory functions (`plugin_server()`, `plugin_client()`)

### Creating Custom Instances with Environment

If you need a fresh instance loaded from environment:

```python
from pyvider.rpcplugin.config import RPCPluginConfig

# ✅ Load from environment variables
custom_config = RPCPluginConfig.from_env()

# Configuration is populated from PLUGIN_* environment variables
assert custom_config.plugin_server_port == int(os.getenv("PLUGIN_SERVER_PORT", "8080"))
```

**When to use:**

- Need isolated config that still respects environment
- Testing scenarios requiring clean config state
- Custom plugin initialization flows

### Creating Empty Instances

For programmatic configuration without environment variables:

```python
from pyvider.rpcplugin.config import RPCPluginConfig

# ⚠️  Creates empty config with defaults only
# Does NOT load environment variables
manual_config = RPCPluginConfig()

# You must set all required values manually
manual_config.plugin_server_port = 8080
manual_config.plugin_magic_cookie_value = "my-secret"
manual_config.plugin_auto_mtls = True
```

**When to use:**

- Multi-instance configurations (see below)
- Complete programmatic control needed
- Testing with controlled config state

!!! warning "Empty Instances Don't Load Environment" `RPCPluginConfig()` creates an instance with **default values only**. It does NOT load `PLUGIN_*` environment variables. Use `RPCPluginConfig.from_env()` if you need environment variable support.

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

- **[Client Configuration](configuration-client/)** - 11 client settings
- **[Server Configuration](configuration-server/)** - 8 server settings
- **[Security Configuration](configuration-security/)** - 12 security settings
- **[Advanced Configuration](configuration-advanced/)** - 20+ advanced settings

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
1. **Verify type conversion** (e.g., `"true"` for booleans, not `"True"`)
1. **Check for typos** in variable names
1. **Enable debug logging** to see what configuration is loaded

```python
configure(log_level="DEBUG")
# Check logs for configuration values
```

### Invalid Configuration Values

1. **Review validation rules** in `src/pyvider/rpcplugin/config/validators.py`
1. **Check type requirements** (int, float, str, bool, list)
1. **Verify value ranges** (e.g., ports 0-65535, positive timeouts)

### Multi-Instance Conflicts

1. **Use unique configuration names** when registering
1. **Avoid modifying global `rpcplugin_config`** when using multiple instances
1. **Consider configuration manager** for complex multi-instance setups

## Next Steps

Now that you understand configuration:

1. **Review** your specific configuration area:
   - [Client Configuration](configuration-client/) for client setup
   - [Server Configuration](configuration-server/) for server setup
   - [Security Configuration](configuration-security/) for mTLS
   - [Advanced Configuration](configuration-advanced/) for tuning

2. **Check** configuration examples in:
   - [Production Guide](production/) for deployment patterns
   - [Security Guide](../security/index/) for security setup

3. **Explore** the complete API:
   - [API Reference](../../reference/pyvider/rpcplugin/config/index/) for configuration classes

## Related Topics

- **[Environment Configuration Guide](environment/)** - Setting up environment variables
- **[Production Configuration](production/)** - Production deployment patterns
- **[Configuration API Reference](../../reference/pyvider/rpcplugin/config/index/)** - Complete API docs

______________________________________________________________________

**Navigation:** [← Config Index](index/) | [Client Config →](configuration-client/)
