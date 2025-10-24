# Configuration Reference

This page provides a comprehensive reference for all configuration options available in `pyvider.rpcplugin`. The framework uses Foundation's configuration system with support for environment variables, type conversion, and validation.

!!! info "Source of Truth"
    All default values are defined in `src/pyvider/rpcplugin/defaults.py`. If you notice any discrepancies between this documentation and the actual defaults, the code is authoritative. You can verify defaults programmatically:

    ```python
    from pyvider.rpcplugin import defaults
    print(f"Server host: {defaults.DEFAULT_PLUGIN_SERVER_HOST}")
    print(f"Auto mTLS: {defaults.DEFAULT_PLUGIN_AUTO_MTLS}")
    ```

## Configuration System Overview

The configuration system is based on the `RPCPluginConfig` class which extends Foundation's `RuntimeConfig`. All settings can be configured through:

1. **Environment Variables** - Primary configuration method
2. **Programmatic API** - Direct attribute setting
3. **Configuration Files** - Via Foundation's config file support

## Complete Configuration Reference

### Client Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_client_max_retries` | `PLUGIN_CLIENT_MAX_RETRIES` | `int` | `3` | Maximum number of connection retry attempts |
| `plugin_client_retry_enabled` | `PLUGIN_CLIENT_RETRY_ENABLED` | `bool` | `True` | Enable automatic retry on connection failure |
| `plugin_client_retry_delay` | `PLUGIN_CLIENT_RETRY_DELAY` | `float` | `1.0` | Initial retry delay (seconds) |
| `plugin_client_backoff_multiplier` | `PLUGIN_CLIENT_BACKOFF_MULTIPLIER` | `float` | `2.0` | Exponential backoff multiplier |
| `plugin_client_max_retry_delay` | `PLUGIN_CLIENT_MAX_RETRY_DELAY` | `float` | `10.0` | Maximum retry delay (seconds) |
| `plugin_client_initial_backoff_ms` | `PLUGIN_CLIENT_INITIAL_BACKOFF_MS` | `int` | `100` | Initial backoff in milliseconds |
| `plugin_client_max_backoff_ms` | `PLUGIN_CLIENT_MAX_BACKOFF_MS` | `int` | `5000` | Maximum backoff in milliseconds |
| `plugin_client_retry_jitter_ms` | `PLUGIN_CLIENT_RETRY_JITTER_MS` | `int` | `50` | Retry jitter in milliseconds |
| `plugin_client_retry_total_timeout_s` | `PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S` | `float` | `30.0` | Total timeout for all retries (seconds) |
| `plugin_client_transports` | `PLUGIN_CLIENT_TRANSPORTS` | `list[str]` | `["unix", "tcp"]` | Ordered list of transports to try |
| `plugin_client_subprocess_timeout` | `PLUGIN_CLIENT_SUBPROCESS_TIMEOUT` | `float` | `30.0` | Timeout for subprocess startup (seconds) |
| `plugin_client_reattach` | `PLUGIN_CLIENT_REATTACH` | `bool` | `False` | Allow reattaching to existing plugin process |
| `plugin_client_cmd` | `PLUGIN_CLIENT_CMD` | `str` | `""` | Command to launch plugin (space-separated) |
| `plugin_min_port` | `PLUGIN_MIN_PORT` | `int` | `10000` | Minimum port for dynamic allocation |
| `plugin_max_port` | `PLUGIN_MAX_PORT` | `int` | `25000` | Maximum port for dynamic allocation |

### Server Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_server_port` | `PLUGIN_SERVER_PORT` | `int` | `0` | Server port (0 = dynamic allocation) |
| `plugin_server_host` | `PLUGIN_SERVER_HOST` | `str` | `"localhost"` | Server bind address |
| `plugin_server_transports` | `PLUGIN_SERVER_TRANSPORTS` | `list[str]` | `["unix", "tcp"]` | Available transport protocols |
| `plugin_server_unix_socket_path` | `PLUGIN_SERVER_UNIX_SOCKET_PATH` | `str` | `"/tmp/plugin.sock"` | Unix socket path for server |
| `plugin_shutdown_file_path` | `PLUGIN_SHUTDOWN_FILE_PATH` | `str` | `""` | File path for shutdown signal |
| `plugin_test_mode` | `PLUGIN_TEST_MODE` | `bool` | `False` | Enable test mode features |

### Core Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_core_version` | `PLUGIN_CORE_VERSION` | `int` | `1` | Core plugin version |
| `plugin_protocol_versions` | `PLUGIN_PROTOCOL_VERSIONS` | `list[int]` | `[1]` | Supported protocol versions |
| `plugin_protocol_version` | `PLUGIN_PROTOCOL_VERSION` | `int` | `1` | Active protocol version |
| `supported_protocol_versions` | `SUPPORTED_PROTOCOL_VERSIONS` | `list[int]` | `[1, 2, 3, 4, 5, 6, 7]` | All supported protocol versions |

### Security Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_auto_mtls` | `PLUGIN_AUTO_MTLS` | `bool` | `True` | Enable automatic mTLS setup |
| `plugin_insecure` | `PLUGIN_INSECURE` | `bool` | `False` | Disable all security features (development only) |
| `plugin_mtls_cert_dir` | `PLUGIN_MTLS_CERT_DIR` | `str` | `"/tmp/plugin-certs"` | Directory for mTLS certificates |
| `plugin_cert_validity_days` | `PLUGIN_CERT_VALIDITY_DAYS` | `int` | `365` | Certificate validity period in days |
| `plugin_client_cert` | `PLUGIN_CLIENT_CERT` | `str` | `None` | Client certificate (PEM or file:// URL) |
| `plugin_client_key` | `PLUGIN_CLIENT_KEY` | `str` | `None` | Client private key (PEM or file:// URL) |
| `plugin_client_cert_file` | `PLUGIN_CLIENT_CERT_FILE` | `str` | `""` | Client certificate file path |
| `plugin_client_key_file` | `PLUGIN_CLIENT_KEY_FILE` | `str` | `""` | Client private key file path |
| `plugin_client_root_certs` | `PLUGIN_CLIENT_ROOT_CERTS` | `str` | `""` | Client root certificates |
| `plugin_server_cert` | `PLUGIN_SERVER_CERT` | `str` | `None` | Server certificate (PEM or file:// URL) |
| `plugin_server_key` | `PLUGIN_SERVER_KEY` | `str` | `None` | Server private key (PEM or file:// URL) |
| `plugin_server_root_certs` | `PLUGIN_SERVER_ROOT_CERTS` | `str` | `None` | Server root certificates |
| `plugin_root_certs_pem` | `PLUGIN_ROOT_CERTS_PEM` | `str` | `""` | Root CA certificates (PEM format) |
| `plugin_ca_cert` | `PLUGIN_CA_CERT` | `str` | `None` | CA certificate for validation |
| `plugin_skip_verify` | `PLUGIN_SKIP_VERIFY` | `bool` | `False` | Skip certificate verification (insecure) |

### gRPC Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_grpc_grace_period` | `PLUGIN_GRPC_GRACE_PERIOD` | `float` | `0.5` | Grace period for graceful shutdown (seconds) |
| `plugin_grpc_keepalive_time` | `PLUGIN_GRPC_KEEPALIVE_TIME` | `int` | `30000` | Keepalive ping interval (milliseconds) |
| `plugin_grpc_keepalive_timeout` | `PLUGIN_GRPC_KEEPALIVE_TIMEOUT` | `int` | `5000` | Keepalive ping timeout (milliseconds) |
| `plugin_grpc_max_connection_idle` | `PLUGIN_GRPC_MAX_CONNECTION_IDLE` | `int` | `900000` | Max connection idle time (milliseconds) |
| `plugin_grpc_max_connection_age` | `PLUGIN_GRPC_MAX_CONNECTION_AGE` | `int` | `0` | Max connection age (0 = unlimited) |
| `plugin_grpc_max_connection_age_grace` | `PLUGIN_GRPC_MAX_CONNECTION_AGE_GRACE` | `int` | `0` | Grace period after max age |
| `plugin_grpc_permit_without_stream` | `PLUGIN_GRPC_PERMIT_WITHOUT_STREAM` | `bool` | `False` | Allow keepalive pings without active streams |
| `plugin_grpc_max_concurrent_streams` | `PLUGIN_GRPC_MAX_CONCURRENT_STREAMS` | `int` | `100` | Maximum concurrent streams per connection |
| `plugin_grpc_max_receive_message_length` | `PLUGIN_GRPC_MAX_RECEIVE_MESSAGE_LENGTH` | `int` | `4194304` | Max receive message size (4MB default) |
| `plugin_grpc_max_send_message_length` | `PLUGIN_GRPC_MAX_SEND_MESSAGE_LENGTH` | `int` | `4194304` | Max send message size (4MB default) |

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

### UI and Display Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_ui_enabled` | `PLUGIN_UI_ENABLED` | `bool` | `False` | Enable UI features |
| `plugin_show_emoji_matrix` | `PLUGIN_SHOW_EMOJI_MATRIX` | `bool` | `False` | Show emoji matrix in output |

### Timeout Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_handshake_timeout` | `PLUGIN_HANDSHAKE_TIMEOUT` | `float` | `10.0` | Handshake timeout (seconds) |
| `plugin_connection_timeout` | `PLUGIN_CONNECTION_TIMEOUT` | `float` | `30.0` | Connection timeout (seconds) |
| `plugin_channel_ready_timeout` | `PLUGIN_CHANNEL_READY_TIMEOUT` | `float` | `10.0` | Channel ready timeout (seconds) |
| `plugin_server_ready_timeout` | `PLUGIN_SERVER_READY_TIMEOUT` | `float` | `5.0` | Server ready timeout (seconds) |

### Handshake Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_handshake_protocol_version` | `PLUGIN_HANDSHAKE_PROTOCOL_VERSION` | `int` | `1` | Handshake protocol version |
| `plugin_magic_cookie_key` | `PLUGIN_MAGIC_COOKIE_KEY` | `str` | `"PLUGIN_MAGIC_COOKIE"` | Magic cookie environment variable name |
| `plugin_magic_cookie_value` | `PLUGIN_MAGIC_COOKIE_VALUE` | `str` | `"test_cookie_value"` | Magic cookie value for authentication (testing only) |

### Buffer Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_buffer_size` | `PLUGIN_BUFFER_SIZE` | `int` | `16384` | Buffer size in bytes (16KB) |
| `plugin_chunk_size` | `PLUGIN_CHUNK_SIZE` | `int` | `8192` | Chunk size in bytes (8KB) |

### Transport Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_supported_transports` | `PLUGIN_SUPPORTED_TRANSPORTS` | `list[str]` | `["unix", "tcp"]` | All supported transport types |

### Logging Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_log_level` | `PLUGIN_LOG_LEVEL` | `str` | `"INFO"` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `plugin_log_format` | `PLUGIN_LOG_FORMAT` | `str` | `"json"` | Log format (json, text) |
| `plugin_log_grpc` | `PLUGIN_LOG_GRPC` | `bool` | `False` | Enable gRPC internal logging |

## Usage Examples

### Environment Variables

Set configuration via environment:

```bash
# Basic configuration
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_SERVER_PORT=8080
export PLUGIN_RATE_LIMIT_ENABLED=true

# Security configuration
export PLUGIN_AUTO_MTLS=true
export PLUGIN_SERVER_CERT="file:///etc/certs/server.crt"
export PLUGIN_SERVER_KEY="file:///etc/certs/server.key"

# Run your plugin
python my_plugin.py
```

### Programmatic Configuration

Configure in Python code:

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Basic settings
rpcplugin_config.plugin_log_level = "DEBUG"
rpcplugin_config.plugin_server_port = 8080

# Rate limiting
rpcplugin_config.plugin_rate_limit_enabled = True
rpcplugin_config.plugin_rate_limit_requests_per_second = 50.0
rpcplugin_config.plugin_rate_limit_burst_capacity = 100

# Security
rpcplugin_config.plugin_auto_mtls = True
rpcplugin_config.plugin_server_cert = "file:///etc/certs/server.crt"
```

### Using the Configure Function

The `configure()` function provides a convenient API:

```python
from pyvider.rpcplugin import configure

configure(
    log_level="DEBUG",
    server_port=8080,
    rate_limit_enabled=True,
    rate_limit_requests_per_second=50.0,
    auto_mtls=True
)
```

## Configuration Validation

The framework validates configuration values:

### Protocol Version Validation

```python
from pyvider.rpcplugin.config.validators import validate_protocol_version

# Valid versions
validate_protocol_version(1)  # OK
validate_protocol_version([1, 2])  # OK

# Invalid versions
validate_protocol_version(0)  # Raises ValueError
validate_protocol_version("1")  # Raises TypeError
```

### Transport List Validation

```python
from pyvider.rpcplugin.config.validators import validate_transport_list

# Valid transports
validate_transport_list(["unix", "tcp"])  # OK
validate_transport_list(["tcp"])  # OK

# Invalid transports
validate_transport_list([])  # Raises ValueError
validate_transport_list(["invalid"])  # Raises ValueError
```

## Multi-Instance Configuration

For multiple plugin instances with different configurations:

```python
from pyvider.rpcplugin.config import (
    RPCPluginConfig,
    register_plugin_config,
    get_plugin_config
)

# Create configurations for different plugins
auth_config = RPCPluginConfig()
auth_config.plugin_server_port = 8081
auth_config.plugin_rate_limit_enabled = True

data_config = RPCPluginConfig()
data_config.plugin_server_port = 8082
data_config.plugin_auto_mtls = True

# Register configurations
register_plugin_config("auth_plugin", auth_config)
register_plugin_config("data_plugin", data_config)

# Retrieve configuration by name
config = get_plugin_config("auth_plugin")
```

## Configuration Profiles

### Development Profile

```bash
# Development settings
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_INSECURE=true
export PLUGIN_TEST_MODE=true
export PLUGIN_RATE_LIMIT_ENABLED=false
```

### Production Profile

```bash
# Production settings
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_AUTO_MTLS=true
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000
export PLUGIN_GRPC_MAX_CONCURRENT_STREAMS=500
export PLUGIN_HEALTH_SERVICE_ENABLED=true
```

### Testing Profile

```bash
# Testing settings
export PLUGIN_TEST_MODE=true
export PLUGIN_LOG_LEVEL=WARNING
export PLUGIN_CLIENT_SUBPROCESS_TIMEOUT=5.0
export PLUGIN_HANDSHAKE_TIMEOUT=5.0
```

## Best Practices

### 1. Use Environment Variables

Environment variables are the recommended configuration method:

```python
# Good: Configuration via environment
os.environ["PLUGIN_SERVER_PORT"] = "8080"

# Less preferred: Direct attribute setting
rpcplugin_config.plugin_server_port = 8080
```

### 2. Validate Early

Validate configuration at startup:

```python
from pyvider.rpcplugin.config import rpcplugin_config

def validate_config():
    """Validate configuration at startup."""
    if rpcplugin_config.plugin_auto_mtls:
        if not rpcplugin_config.plugin_server_cert:
            raise ValueError("Server certificate required for mTLS")

    if rpcplugin_config.plugin_rate_limit_enabled:
        if rpcplugin_config.plugin_rate_limit_requests_per_second <= 0:
            raise ValueError("Invalid rate limit configuration")

# Call during initialization
validate_config()
```

### 3. Document Configuration

Document required configuration for your plugin:

```python
"""
MyPlugin - Configuration Requirements

Required Environment Variables:
- PLUGIN_MAGIC_COOKIE_VALUE: Authentication cookie
- MY_PLUGIN_API_KEY: API key for external service

Optional Environment Variables:
- PLUGIN_LOG_LEVEL: Logging level (default: INFO)
- PLUGIN_RATE_LIMIT_ENABLED: Enable rate limiting (default: false)
"""
```

### 4. Provide Defaults

Set sensible defaults for optional configuration:

```python
from pyvider.rpcplugin.config import rpcplugin_config

# Set defaults if not configured
if not rpcplugin_config.plugin_grpc_max_concurrent_streams:
    rpcplugin_config.plugin_grpc_max_concurrent_streams = 100

if not rpcplugin_config.plugin_handshake_timeout:
    rpcplugin_config.plugin_handshake_timeout = 30.0
```

## Troubleshooting

### Configuration Not Loading

1. Check environment variable names (case-sensitive)
2. Verify type conversion (e.g., "true" vs True for booleans)
3. Check for typos in variable names

### Invalid Configuration Values

1. Review validation rules
2. Check type requirements
3. Verify value ranges

### Multi-Instance Conflicts

1. Use unique configuration names
2. Avoid modifying global config when using multiple instances
3. Consider using configuration manager

## Related Topics

- [Environment Variables](environment.md) - Detailed environment variable guide
- [Production Setup](production.md) - Production configuration guide
- [Rate Limiting](rate-limiting.md) - Rate limiting configuration
- [Logging Configuration](logging.md) - Logging setup and configuration