# Configuration Guide

The Pyvider RPC Plugin provides a comprehensive configuration system designed for both development and production environments. Configuration is environment-driven, type-safe, and follows 12-factor app principles with sensible defaults.

## Quick Start

Most common configuration needs can be addressed with just a few environment variables:

```bash
# Basic server configuration
export PLUGIN_CORE_VERSION=1
export PLUGIN_SERVER_TRANSPORTS='["unix", "tcp"]'
export PLUGIN_AUTO_MTLS=true

# Security and authentication
export PLUGIN_MAGIC_COOKIE_VALUE="<SECURE_VALUE_HERE>"
export PLUGIN_SERVER_CERT="file:///path/to/server.pem"
export PLUGIN_SERVER_KEY="file:///path/to/server.key"

# Development settings
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_SHOW_EMOJI_MATRIX=true
```

The plugin will automatically load and validate all configuration from the environment when it starts.

## Configuration Architecture

### Foundation Integration

The configuration system is built on [Foundation](https://github.com/provide-io/provide-foundation), which provides:

- **Type-safe configuration**: Automatic type conversion and validation
- **Multi-source loading**: Environment variables, files, and programmatic sources
- **Runtime validation**: Comprehensive field validation with detailed error messages
- **Async configuration**: Non-blocking configuration loading and updates

```python
from pyvider.rpcplugin.config import rpcplugin_config
from provide.foundation.config import RuntimeConfig

# The RPCPluginConfig extends Foundation's RuntimeConfig
class RPCPluginConfig(RuntimeConfig):
    plugin_core_version: int = field(default=1, validator=validate_range(1, 7))
    plugin_auto_mtls: bool = field(default=True)
    # ... other RPC-specific fields
```

### Environment Variable Loading

All configuration uses the `PLUGIN_` prefix and follows a consistent naming convention:

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Access any configuration value with automatic type conversion
protocol_version: int = rpcplugin_config.plugin_protocol_version
transports: list[str] = rpcplugin_config.plugin_server_transports
mtls_enabled: bool = rpcplugin_config.plugin_auto_mtls
handshake_timeout: float = rpcplugin_config.plugin_handshake_timeout
```

### Programmatic Configuration

For dynamic or complex configurations, you can configure values programmatically using the `configure()` function:

```python
from pyvider.rpcplugin import configure
from pyvider.rpcplugin.config import rpcplugin_config

# Set configuration values using simplified parameter names
configure(
    magic_cookie="my-secure-cookie",  # Sets plugin_magic_cookie_value
    protocol_version=1,                # Sets plugin_core_version AND plugin_protocol_versions
    transports=["unix"],               # Sets both plugin_server_transports and plugin_client_transports
    auto_mtls=True,                    # Sets plugin_auto_mtls
    handshake_timeout=30.0,            # Sets plugin_handshake_timeout
)

# Additional options via kwargs (automatically prefixed with "plugin_")
configure(
    log_level="INFO",                  # Sets plugin_log_level
    rate_limit_enabled=True,           # Sets plugin_rate_limit_enabled
    rate_limit_requests_per_second=100.0,  # Sets plugin_rate_limit_requests_per_second
)

# Or update the configuration instance directly using full attribute names
config = rpcplugin_config
config.plugin_rate_limit_enabled = True
config.plugin_rate_limit_requests_per_second = 100.0
config.plugin_rate_limit_burst_capacity = 200.0
```

#### Parameter Name Mapping

The `configure()` function uses simplified parameter names that map to the underlying configuration attributes:

| `configure()` Parameter | Maps to Configuration Attribute                         | Environment Variable                                    |
| ----------------------- | ------------------------------------------------------- | ------------------------------------------------------- |
| `magic_cookie`          | `plugin_magic_cookie_value`                             | `PLUGIN_MAGIC_COOKIE_VALUE`                             |
| `protocol_version`      | `plugin_core_version` & `plugin_protocol_versions`      | `PLUGIN_CORE_VERSION` & `PLUGIN_PROTOCOL_VERSIONS`      |
| `transports`            | `plugin_server_transports` & `plugin_client_transports` | `PLUGIN_SERVER_TRANSPORTS` & `PLUGIN_CLIENT_TRANSPORTS` |
| `auto_mtls`             | `plugin_auto_mtls`                                      | `PLUGIN_AUTO_MTLS`                                      |
| `handshake_timeout`     | `plugin_handshake_timeout`                              | `PLUGIN_HANDSHAKE_TIMEOUT`                              |
| `**kwargs`              | `plugin_{key}` (auto-prefixed)                          | `PLUGIN_{KEY}`                                          |

!!! info "Protocol Version Dual Assignment" Setting `protocol_version` via `configure()` updates **two configuration fields**:

````
- `plugin_core_version` - The plugin's primary protocol version
- `plugin_protocol_versions` - List of supported versions (set to `[protocol_version]`)

This ensures backward compatibility while establishing a primary version. For example:

```python
configure(protocol_version=3)
# Results in:
# rpcplugin_config.plugin_core_version = 3
# rpcplugin_config.plugin_protocol_versions = [3]
```

To support multiple protocol versions, set `plugin_protocol_versions` directly:

```python
rpcplugin_config.plugin_protocol_versions = [1, 2, 3]  # Support versions 1-3
rpcplugin_config.plugin_core_version = 3  # Primary version is 3
```
````

### Configuration Validation

All configuration values are validated when loaded:

```python
# Type validation happens automatically
try:
    config = rpcplugin_config
    timeout = config.plugin_handshake_timeout  # Ensures this is a float
except ConfigError as e:
    logger.error(f"Invalid configuration: {e.validation_errors}")
    # Handle configuration errors appropriately
```

## Configuration Reference

For a complete list of all configuration options with defaults, types, and descriptions, see the **[Configuration Reference](configuration-reference.md)**.

### Most Commonly Used Settings

Here are the most frequently configured options:

**Core Settings:**

- `PLUGIN_CORE_VERSION` - Protocol version (default: `1`)
- `PLUGIN_SERVER_TRANSPORTS` - Server transport types (default: `["unix", "tcp"]`)
- `PLUGIN_MAGIC_COOKIE_VALUE` - Authentication secret (default: `"test_cookie_value"`)

**Timeouts:**

- `PLUGIN_HANDSHAKE_TIMEOUT` - Handshake timeout in seconds (default: `10.0`)
- `PLUGIN_CONNECTION_TIMEOUT` - Connection timeout in seconds (default: `30.0`)

**Security:**

- `PLUGIN_AUTO_MTLS` - Enable automatic mTLS (default: `true`)
- `PLUGIN_SERVER_CERT` - Server TLS certificate path
- `PLUGIN_SERVER_KEY` - Server TLS private key path

**Performance:**

- `PLUGIN_RATE_LIMIT_ENABLED` - Enable rate limiting (default: `false`)
- `PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND` - Request rate limit (default: `100.0`)
- `PLUGIN_HEALTH_SERVICE_ENABLED` - Enable health checks (default: `true`)

See **[Configuration Reference](configuration-reference.md)** for all 60+ configuration options

## Configuration Examples

### Development Environment

```bash
# Development configuration for local testing
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_SHOW_EMOJI_MATRIX=true
export PLUGIN_AUTO_MTLS=false  # Disable TLS for local dev
export PLUGIN_SERVER_TRANSPORTS='["unix"]'  # Unix sockets only
export PLUGIN_HANDSHAKE_TIMEOUT=5.0
export PLUGIN_CONNECTION_TIMEOUT=10.0
```

### Production Environment

```bash
# Production configuration with full security
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_SHOW_EMOJI_MATRIX=false
export PLUGIN_AUTO_MTLS=true
export PLUGIN_SERVER_TRANSPORTS='["tcp"]'
export PLUGIN_SERVER_CERT="file:///etc/ssl/certs/plugin-server.pem"
export PLUGIN_SERVER_KEY="file:///etc/ssl/private/plugin-server.key"
export PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/ca-bundle.pem"
export PLUGIN_HANDSHAKE_TIMEOUT=30.0
export PLUGIN_CONNECTION_TIMEOUT=60.0
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=100.0
export PLUGIN_HEALTH_SERVICE_ENABLED=true
```

### Container Environment

```bash
# Docker/Kubernetes configuration
export PLUGIN_SERVER_HOST="0.0.0.0"  # Listen on all interfaces
export PLUGIN_SERVER_PORT=8080
export PLUGIN_AUTO_MTLS=true
export PLUGIN_SERVER_CERT="$SERVER_CERT_PEM"  # Direct PEM content
export PLUGIN_SERVER_KEY="$SERVER_KEY_PEM"    # From secrets
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_HEALTH_SERVICE_ENABLED=true   # For health checks
export PLUGIN_SHUTDOWN_FILE_PATH="/tmp/shutdown"  # Graceful shutdown
```

## Configuration Best Practices

### Security First

1. **Always enable mTLS in production**: Set `PLUGIN_AUTO_MTLS=true`
1. **Use strong magic cookies**: Generate cryptographically secure random strings
1. **Secure certificate management**: Use proper file permissions (600) for private keys
1. **Rotate secrets regularly**: Update magic cookies and certificates on a schedule

### Performance Optimization

1. **Choose appropriate transports**: Unix sockets for local, TCP for network
1. **Tune timeouts**: Balance responsiveness vs. reliability based on your environment
1. **Enable rate limiting**: Protect against abuse with `PLUGIN_RATE_LIMIT_ENABLED=true`
1. **Monitor health checks**: Use `PLUGIN_HEALTH_SERVICE_ENABLED=true` for observability

### Development Workflow

1. **Use different configs per environment**: Separate dev, staging, production settings
1. **Enable debug logging**: Set `PLUGIN_LOG_LEVEL=DEBUG` during development
1. **Use environment files**: Store configuration in `.env` files (excluded from git)
1. **Validate early**: Test configuration changes in isolated environments first

## Advanced Configuration

### Environment File Loading

Use `.env` files for development convenience:

```bash
# .env.development
PLUGIN_LOG_LEVEL=DEBUG
PLUGIN_AUTO_MTLS=false
PLUGIN_SHOW_EMOJI_MATRIX=true

# .env.production  
PLUGIN_LOG_LEVEL=INFO
PLUGIN_AUTO_MTLS=true
PLUGIN_RATE_LIMIT_ENABLED=true
```

Load with:

```python
from dotenv import load_dotenv
import os

# Load appropriate environment file
env = os.getenv('ENVIRONMENT', 'development')
load_dotenv(f'.env.{env}')

# Configuration loads automatically from environment
from pyvider.rpcplugin import plugin_server
server = plugin_server(protocol=my_protocol, handler=my_handler)
```

### Configuration Inheritance

Combine multiple configuration sources:

```python
import os
from pyvider.rpcplugin import configure

# Base configuration
configure(
    protocol_version=1,
    auto_mtls=True,
    log_level="INFO"
)

# Environment-specific overrides
if os.getenv('ENVIRONMENT') == 'development':
    configure(
        log_level="DEBUG",
        auto_mtls=False,
        show_emoji_matrix=True
    )
elif os.getenv('ENVIRONMENT') == 'production':
    configure(
        rate_limit_enabled=True,
        health_service_enabled=True
    )
```

## Related Documentation

### Complete Configuration Details
- **[Configuration Reference](configuration-reference.md)** - Complete list of all 60+ configuration options with defaults and types

### Security Configuration
- **[Security Implementation Guide](../security/index.md)** - Security-focused configuration patterns including mTLS, certificates, and magic cookies
- **[Security Concepts](../concepts/security.md)** - Understanding the security model and how configuration enables different security layers

### Transport Configuration
- **[Transport Concepts](../concepts/transports.md)** - Understanding transport types and selection criteria
- **[Server Transport Configuration](../server/transports.md)** - Advanced transport configuration for production servers

## Next Steps

- **[Environment Variables](environment.md)** - Complete reference of all configuration options
- **[Production Setup](advanced.md)** - Production deployment patterns and security
- **[Rate Limiting](../server/rate-limiting.md)** - Request rate limiting and throttling configuration  
- **[Logging Configuration](logging.md)** - Logging setup and structured output patterns
