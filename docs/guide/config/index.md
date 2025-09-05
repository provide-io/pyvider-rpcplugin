# Configuration Guide

The Pyvider RPC Plugin provides a comprehensive configuration system designed for both development and production environments. Configuration is environment-driven, type-safe, and follows 12-factor app principles with sensible defaults.

## Quick Start

Most common configuration needs can be addressed with just a few environment variables:

```bash
# Basic server configuration
export PYVIDER_PLUGIN_PROTOCOL_VERSION="1"
export PYVIDER_PLUGIN_SERVER_TRANSPORTS="unix,tcp" 
export PYVIDER_PLUGIN_AUTO_MTLS="true"

# Security and authentication
export PYVIDER_PLUGIN_MAGIC_COOKIE_VALUE="your-secure-cookie-here"
export PYVIDER_PLUGIN_SERVER_CERT="file:///path/to/server.pem"
export PYVIDER_PLUGIN_SERVER_KEY="file:///path/to/server.key"

# Development settings
export PYVIDER_PLUGIN_LOG_LEVEL="DEBUG"
export PYVIDER_PLUGIN_SHOW_EMOJI_MATRIX="true"
```

The plugin will automatically load and validate all configuration from the environment when it starts.

## Configuration Architecture

### Environment Variable Loading

All configuration uses the `PYVIDER_PLUGIN_` prefix and follows a consistent naming convention:

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Access any configuration value with automatic type conversion
protocol_version: int = rpcplugin_config.protocol_version()
transports: list[str] = rpcplugin_config.server_transports()
mtls_enabled: bool = rpcplugin_config.auto_mtls_enabled()
handshake_timeout: float = rpcplugin_config.handshake_timeout()
```

### Programmatic Configuration

For dynamic or complex configurations, you can configure values programmatically:

```python
from pyvider.rpcplugin import configure
from pyvider.rpcplugin.config import rpcplugin_config

# Set configuration values programmatically
configure(
    protocol_version=1,
    server_transports=["unix"],
    auto_mtls=True,
    handshake_timeout=30.0,
    log_level="INFO"
)

# Or update the configuration instance directly
config = rpcplugin_config
config.update({
    'rate_limit_enabled': True,
    'rate_limit_requests_per_second': 100.0,
    'rate_limit_burst_capacity': 200.0
})
```

### Configuration Validation

All configuration values are validated when loaded:

```python
# Type validation happens automatically
try:
    config = rpcplugin_config
    timeout = config.handshake_timeout()  # Ensures this is a float
except ConfigError as e:
    logger.error(f"Invalid configuration: {e.validation_errors}")
    # Handle configuration errors appropriately
```

## Configuration Categories

### Core Communication Settings

Essential settings for plugin protocol and communication:

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| Protocol Version | `PYVIDER_PLUGIN_PROTOCOL_VERSION` | `int` | `1` | Plugin protocol version for negotiation |
| Server Transports | `PYVIDER_PLUGIN_SERVER_TRANSPORTS` | `list[str]` | `["unix","tcp"]` | Transport types server supports |
| Client Transports | `PYVIDER_PLUGIN_CLIENT_TRANSPORTS` | `list[str]` | `["unix","tcp"]` | Transport types client prefers |
| Magic Cookie | `PYVIDER_PLUGIN_MAGIC_COOKIE_VALUE` | `str` | `"test_cookie_value"` | Authentication secret between client and server |

### Connection and Timeout Settings

Network and timing configurations:

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| Handshake Timeout | `PYVIDER_PLUGIN_HANDSHAKE_TIMEOUT` | `float` | `10.0` | Seconds to wait for handshake completion |
| Connection Timeout | `PYVIDER_PLUGIN_CONNECTION_TIMEOUT` | `float` | `30.0` | Seconds to wait for connection establishment |
| Server Endpoint | `PYVIDER_PLUGIN_SERVER_ENDPOINT` | `str` | `None` | Force specific server endpoint (e.g., "localhost:8080") |
| Client Endpoint | `PYVIDER_PLUGIN_CLIENT_ENDPOINT` | `str` | `None` | Force specific client connection endpoint |

### Security Configuration

TLS, mTLS, and authentication settings:

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| Auto mTLS | `PYVIDER_PLUGIN_AUTO_MTLS` | `bool` | `true` | Enable automatic mutual TLS |
| Server Certificate | `PYVIDER_PLUGIN_SERVER_CERT` | `str` | `None` | Server TLS certificate (PEM or file path) |
| Server Private Key | `PYVIDER_PLUGIN_SERVER_KEY` | `str` | `None` | Server TLS private key (PEM or file path) |
| Client Certificate | `PYVIDER_PLUGIN_CLIENT_CERT` | `str` | `None` | Client TLS certificate for mTLS |
| Client Private Key | `PYVIDER_PLUGIN_CLIENT_KEY` | `str` | `None` | Client TLS private key for mTLS |

## Configuration Examples

### Development Environment

```bash
# Development configuration for local testing
export PYVIDER_PLUGIN_LOG_LEVEL="DEBUG"
export PYVIDER_PLUGIN_SHOW_EMOJI_MATRIX="true"
export PYVIDER_PLUGIN_AUTO_MTLS="false"  # Disable TLS for local dev
export PYVIDER_PLUGIN_SERVER_TRANSPORTS="unix"  # Unix sockets only
export PYVIDER_PLUGIN_HANDSHAKE_TIMEOUT="5.0"
export PYVIDER_PLUGIN_CONNECTION_TIMEOUT="10.0"
```

### Production Environment

```bash
# Production configuration with full security
export PYVIDER_PLUGIN_LOG_LEVEL="INFO"
export PYVIDER_PLUGIN_SHOW_EMOJI_MATRIX="false"
export PYVIDER_PLUGIN_AUTO_MTLS="true"
export PYVIDER_PLUGIN_SERVER_TRANSPORTS="tcp"
export PYVIDER_PLUGIN_SERVER_CERT="file:///etc/ssl/certs/plugin-server.pem"
export PYVIDER_PLUGIN_SERVER_KEY="file:///etc/ssl/private/plugin-server.key"
export PYVIDER_PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/ca-bundle.pem"
export PYVIDER_PLUGIN_HANDSHAKE_TIMEOUT="30.0"
export PYVIDER_PLUGIN_CONNECTION_TIMEOUT="60.0"
export PYVIDER_PLUGIN_RATE_LIMIT_ENABLED="true"
export PYVIDER_PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND="100.0"
export PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED="true"
```

### Container Environment

```bash
# Docker/Kubernetes configuration
export PYVIDER_PLUGIN_SERVER_ENDPOINT="0.0.0.0:8080"  # Listen on all interfaces
export PYVIDER_PLUGIN_AUTO_MTLS="true"
export PYVIDER_PLUGIN_SERVER_CERT="$SERVER_CERT_PEM"  # Direct PEM content
export PYVIDER_PLUGIN_SERVER_KEY="$SERVER_KEY_PEM"    # From secrets
export PYVIDER_PLUGIN_LOG_LEVEL="INFO"
export PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED="true"   # For health checks
export PYVIDER_PLUGIN_SHUTDOWN_FILE_PATH="/tmp/shutdown"  # Graceful shutdown
```

## Configuration Best Practices

### Security First

1. **Always enable mTLS in production**: Set `PYVIDER_PLUGIN_AUTO_MTLS="true"`
2. **Use strong magic cookies**: Generate cryptographically secure random strings
3. **Secure certificate management**: Use proper file permissions (600) for private keys
4. **Rotate secrets regularly**: Update magic cookies and certificates on a schedule

### Performance Optimization

1. **Choose appropriate transports**: Unix sockets for local, TCP for network
2. **Tune timeouts**: Balance responsiveness vs. reliability based on your environment
3. **Enable rate limiting**: Protect against abuse with `PYVIDER_PLUGIN_RATE_LIMIT_ENABLED`
4. **Monitor health checks**: Use `PYVIDER_PLUGIN_HEALTH_SERVICE_ENABLED` for observability

### Development Workflow

1. **Use different configs per environment**: Separate dev, staging, production settings
2. **Enable debug logging**: Set `PYVIDER_PLUGIN_LOG_LEVEL="DEBUG"` during development
3. **Use environment files**: Store configuration in `.env` files (excluded from git)
4. **Validate early**: Test configuration changes in isolated environments first

## Advanced Configuration

### Environment File Loading

Use `.env` files for development convenience:

```bash
# .env.development
PYVIDER_PLUGIN_LOG_LEVEL=DEBUG
PYVIDER_PLUGIN_AUTO_MTLS=false
PYVIDER_PLUGIN_SHOW_EMOJI_MATRIX=true

# .env.production  
PYVIDER_PLUGIN_LOG_LEVEL=INFO
PYVIDER_PLUGIN_AUTO_MTLS=true
PYVIDER_PLUGIN_RATE_LIMIT_ENABLED=true
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
server = await plugin_server(protocol=my_protocol, handler=my_handler)
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

## Next Steps

- **[Environment Variables](environment.md)** - Complete reference of all configuration options
- **[Production Setup](production.md)** - Production deployment patterns and security
- **[Rate Limiting](rate-limiting.md)** - Request rate limiting and throttling configuration  
- **[Logging Configuration](logging.md)** - Logging setup and structured output patterns

For API-level configuration details, see the [Configuration API Reference](../../api/config/).