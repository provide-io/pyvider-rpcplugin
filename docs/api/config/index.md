# Configuration System

The Pyvider RPC Plugin system uses a comprehensive configuration framework based on Foundation that supports environment variables, configuration files, validation, and runtime configuration management.

## Overview

The configuration system provides:
- **Environment Variable Support**: Automatically reads from environment variables
- **Type Validation**: Strong typing with runtime validation
- **Default Values**: Sensible defaults for all configuration options
- **Runtime Access**: Global configuration singleton for easy access
- **Multi-Source Loading**: Support for multiple configuration sources
- **Sensitive Data Protection**: Special handling for secrets and credentials

All configuration is managed through the `RPCPluginConfig` class, which extends Foundation's `RuntimeConfig`, and accessed via the global `rpcplugin_config` instance.

## Quick Start

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Read configuration values
magic_cookie = rpcplugin_config.plugin_magic_cookie_value
protocol_versions = rpcplugin_config.plugin_protocol_versions
auto_mtls = rpcplugin_config.plugin_auto_mtls

# Use helper methods
transports = rpcplugin_config.server_transports()
timeout = rpcplugin_config.handshake_timeout()
```

## Configuration Categories

### Core Configuration

**Protocol and Version Settings**:
- `plugin_core_version`: Core protocol version (default: 1)
- `plugin_protocol_versions`: Supported protocol versions (default: [1])
- `plugin_log_level`: Logging level (default: "INFO")

### Magic Cookie Authentication

**Security Authentication**:
- `plugin_magic_cookie_key`: Environment variable name for cookie (default: "PLUGIN_MAGIC_COOKIE")
- `plugin_magic_cookie_value`: Cookie value for authentication (default: "test_cookie_value")

### Transport Configuration

**Server Transport Settings**:
- `plugin_server_transports`: Supported transports (default: ["unix", "tcp"])
- `plugin_server_endpoint`: Server endpoint address (optional)

**Client Transport Settings**:
- `plugin_client_transports`: Client-supported transports (default: ["unix", "tcp"])
- `plugin_client_endpoint`: Client endpoint address (optional)

### Security and mTLS

**Server TLS Configuration**:
- `plugin_auto_mtls`: Enable automatic mutual TLS (default: True)
- `plugin_server_cert`: Server certificate PEM or file path
- `plugin_server_key`: Server private key PEM or file path
- `plugin_server_root_certs`: Server root certificates PEM or file path

**Client TLS Configuration**:
- `plugin_client_cert`: Client certificate PEM or file path
- `plugin_client_key`: Client private key PEM or file path
- `plugin_client_root_certs`: Client root certificates PEM or file path

### Timeouts and Connection Management

**Connection Timeouts**:
- `plugin_handshake_timeout`: Handshake timeout in seconds (default: 10.0)
- `plugin_connection_timeout`: Connection timeout in seconds (default: 30.0)

### Client Retry Configuration

**Retry Behavior**:
- `plugin_client_retry_enabled`: Enable client retries (default: True)
- `plugin_client_max_retries`: Maximum retry attempts (default: 3)
- `plugin_client_initial_backoff_ms`: Initial backoff time in ms (default: 500)
- `plugin_client_max_backoff_ms`: Maximum backoff time in ms (default: 5000)
- `plugin_client_retry_jitter_ms`: Retry jitter in ms (default: 100)
- `plugin_client_retry_total_timeout_s`: Total retry timeout in seconds (default: 60)

### Rate Limiting

**Request Rate Control**:
- `plugin_rate_limit_enabled`: Enable rate limiting (default: False)
- `plugin_rate_limit_requests_per_second`: Rate limit in requests/sec (default: 100.0)
- `plugin_rate_limit_burst_capacity`: Burst capacity (default: 200.0)

### Health and Monitoring

**Service Health**:
- `plugin_health_service_enabled`: Enable health service (default: True)
- `plugin_show_emoji_matrix`: Show emoji matrix in logs (default: True)

### Shutdown Control

**Process Management**:
- `plugin_shutdown_file_path`: Path to shutdown signal file (optional)

## Environment Variable Usage

### Setting Configuration via Environment

All configuration options can be set via environment variables:

```bash
# Core settings
export PLUGIN_CORE_VERSION=1
export PLUGIN_LOG_LEVEL=DEBUG

# Authentication
export PLUGIN_MAGIC_COOKIE_KEY="MY_PLUGIN_COOKIE"
export PLUGIN_MAGIC_COOKIE_VALUE="super-secret-value-123"

# Transport
export PLUGIN_SERVER_TRANSPORTS='["unix", "tcp"]'
export PLUGIN_SERVER_ENDPOINT="/tmp/my-plugin.sock"

# Security
export PLUGIN_AUTO_MTLS=true
export PLUGIN_SERVER_CERT="file:///path/to/server.crt"
export PLUGIN_SERVER_KEY="file:///path/to/server.key"

# Timeouts
export PLUGIN_HANDSHAKE_TIMEOUT=15.0
export PLUGIN_CONNECTION_TIMEOUT=45.0

# Rate limiting
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000.0
```

### JSON Configuration for Lists

Complex values like lists use JSON format:

```bash
# Protocol versions
export PLUGIN_PROTOCOL_VERSIONS='[1, 2, 3]'

# Transport lists
export PLUGIN_SERVER_TRANSPORTS='["unix"]'
export PLUGIN_CLIENT_TRANSPORTS='["tcp", "unix"]'
```

## Configuration Access Patterns

### Direct Attribute Access

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Direct access to configuration values
if rpcplugin_config.plugin_auto_mtls:
    print("mTLS is enabled")

timeout = rpcplugin_config.plugin_connection_timeout
print(f"Connection timeout: {timeout}s")
```

### Helper Methods

```python
# Use convenience methods for common patterns
magic_key = rpcplugin_config.magic_cookie_key()
magic_value = rpcplugin_config.magic_cookie_value()

server_transports = rpcplugin_config.server_transports()
client_transports = rpcplugin_config.client_transports()

handshake_timeout = rpcplugin_config.handshake_timeout()
connection_timeout = rpcplugin_config.connection_timeout()
```

### Runtime Configuration Override

For testing or dynamic configuration:

```python
# Server and client can override config at runtime
from pyvider.rpcplugin.server import RPCPluginServer

server = RPCPluginServer(
    protocol=my_protocol,
    handler=my_handler,
    config={
        "PLUGIN_RATE_LIMIT_ENABLED": True,
        "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 500.0,
        "PLUGIN_AUTO_MTLS": False,
    }
)
```

## Validation and Error Handling

### Built-in Validation

The configuration system includes comprehensive validation:

```python
# Invalid values raise ValidationError
import os
os.environ["PLUGIN_CORE_VERSION"] = "invalid"  # Must be 1-7
# Will raise ValidationError when accessed

os.environ["PLUGIN_PROTOCOL_VERSIONS"] = '[0, 8]'  # Must be 1-7
# Will raise ValidationError when accessed

os.environ["PLUGIN_SERVER_TRANSPORTS"] = '["invalid"]'  # Must be unix/tcp
# Will raise ValidationError when accessed
```

### Error Handling

```python
from provide.foundation.errors.config import ValidationError
from pyvider.rpcplugin.exception import ConfigError

try:
    config_value = rpcplugin_config.plugin_core_version
except ValidationError as e:
    print(f"Configuration validation error: {e}")
except ConfigError as e:
    print(f"Configuration error: {e.message}")
    if e.hint:
        print(f"Hint: {e.hint}")
```

## Development vs Production Configuration

### Development Configuration

```bash
# Development settings - permissive and verbose
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_AUTO_MTLS=true
export PLUGIN_SERVER_TRANSPORTS='["unix"]'
export PLUGIN_HANDSHAKE_TIMEOUT=30.0
export PLUGIN_CLIENT_RETRY_ENABLED=true
export PLUGIN_CLIENT_MAX_RETRIES=5
export PLUGIN_SHOW_EMOJI_MATRIX=true
```

### Production Configuration

```bash
# Production settings - secure and optimized
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_AUTO_MTLS=false
export PLUGIN_SERVER_CERT="file:///etc/ssl/certs/server.crt"
export PLUGIN_SERVER_KEY="file:///etc/ssl/private/server.key"
export PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/ca.crt"
export PLUGIN_SERVER_TRANSPORTS='["tcp"]'
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000.0
export PLUGIN_HEALTH_SERVICE_ENABLED=true
export PLUGIN_CLIENT_RETRY_ENABLED=true
export PLUGIN_CLIENT_MAX_RETRIES=3
export PLUGIN_SHOW_EMOJI_MATRIX=false
```

### Docker Configuration

```dockerfile
# Dockerfile configuration example
FROM python:3.11

# Set plugin configuration
ENV PLUGIN_LOG_LEVEL=INFO
ENV PLUGIN_AUTO_MTLS=true
ENV PLUGIN_SERVER_TRANSPORTS='["tcp"]'
ENV PLUGIN_HANDSHAKE_TIMEOUT=10.0
ENV PLUGIN_CONNECTION_TIMEOUT=30.0
ENV PLUGIN_RATE_LIMIT_ENABLED=true
ENV PLUGIN_HEALTH_SERVICE_ENABLED=true

# Application code
COPY . /app
WORKDIR /app
RUN pip install -e .

EXPOSE 8080
CMD ["python", "-m", "my_plugin_server"]
```

## Configuration File Support

While primarily environment-based, you can use configuration files:

```python
# config.yaml
plugin:
  core_version: 1
  log_level: INFO
  magic_cookie_key: MY_PLUGIN_COOKIE
  magic_cookie_value: production-cookie-value
  auto_mtls: false
  server_cert: file:///etc/ssl/server.crt
  server_key: file:///etc/ssl/server.key
  server_transports: ["tcp"]
  rate_limit_enabled: true
  rate_limit_requests_per_second: 1000.0
```

```python
# Load from file (requires custom loader)
import yaml
import os

def load_config_from_file(config_path: str):
    """Load configuration from YAML file to environment."""
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    plugin_config = config.get('plugin', {})
    for key, value in plugin_config.items():
        env_key = f"PLUGIN_{key.upper()}"
        if isinstance(value, (list, dict)):
            os.environ[env_key] = json.dumps(value)
        else:
            os.environ[env_key] = str(value)

# Usage
load_config_from_file("config.yaml")
from pyvider.rpcplugin.config import rpcplugin_config
# Config is now available
```

## Security Considerations

### Sensitive Configuration

Mark sensitive configuration appropriately:

```bash
# Use secure methods for sensitive values
export PLUGIN_MAGIC_COOKIE_VALUE="$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)"

# Use file references for certificates
export PLUGIN_SERVER_CERT="file:///etc/ssl/certs/server.crt"
export PLUGIN_SERVER_KEY="file:///etc/ssl/private/server.key"

# Avoid inline certificate content in environment variables
# BAD: export PLUGIN_SERVER_CERT="-----BEGIN CERTIFICATE-----..."
```

### Configuration Validation

```python
def validate_production_config():
    """Validate configuration for production deployment."""
    from pyvider.rpcplugin.config import rpcplugin_config
    
    issues = []
    
    # Check security settings
    if rpcplugin_config.plugin_magic_cookie_value == "test_cookie_value":
        issues.append("Using default magic cookie - security risk!")
    
    if rpcplugin_config.plugin_auto_mtls and not rpcplugin_config.plugin_client_root_certs:
        issues.append("Auto-mTLS enabled but no client root certs configured")
    
    # Check performance settings
    if not rpcplugin_config.plugin_rate_limit_enabled:
        issues.append("Rate limiting disabled - may impact performance")
    
    # Check logging
    if rpcplugin_config.plugin_log_level == "DEBUG":
        issues.append("Debug logging enabled - may impact performance")
    
    return issues

# Usage
issues = validate_production_config()
if issues:
    print("Configuration issues found:")
    for issue in issues:
        print(f"  - {issue}")
```

## Configuration Testing

### Test Configuration Setup

```python
import os
import contextlib

@contextlib.contextmanager
def test_config(**config_overrides):
    """Temporarily override configuration for testing."""
    original_values = {}
    
    try:
        # Set test values
        for key, value in config_overrides.items():
            env_key = f"PLUGIN_{key.upper()}"
            original_values[env_key] = os.environ.get(env_key)
            
            if isinstance(value, (list, dict)):
                os.environ[env_key] = json.dumps(value)
            else:
                os.environ[env_key] = str(value)
        
        # Force config reload (implementation-specific)
        # rpcplugin_config.reload()  # If available
        
        yield
        
    finally:
        # Restore original values
        for env_key, original_value in original_values.items():
            if original_value is None:
                os.environ.pop(env_key, None)
            else:
                os.environ[env_key] = original_value

# Usage in tests
def test_with_custom_config():
    with test_config(
        log_level="DEBUG",
        auto_mtls=False,
        server_transports=["unix"]
    ):
        from pyvider.rpcplugin.config import rpcplugin_config
        assert rpcplugin_config.plugin_log_level == "DEBUG"
        assert not rpcplugin_config.plugin_auto_mtls
```

## Related Documentation

- [Configuration Schema Reference](schema.md) - Complete configuration option reference
- [Environment Variables Guide](environment.md) - Environment variable setup patterns
- [Server Configuration](../server/server.md) - Using configuration in servers
- [Client Configuration](../client/client.md) - Using configuration in clients
- [Security Configuration](../../guide/security/index.md) - Security-focused configuration patterns