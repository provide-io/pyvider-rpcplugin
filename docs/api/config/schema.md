# Configuration Schema Reference

This document provides a complete reference for all configuration options available in the Pyvider RPC Plugin system, including their types, default values, validation rules, and usage examples.

## Configuration Class

The configuration is defined in the `RPCPluginConfig` class, which extends `provide.foundation.config.RuntimeConfig` to provide comprehensive configuration management.

```python
from pyvider.rpcplugin.config import rpcplugin_config
# Global configuration instance - automatically loaded from environment
```

## Core Configuration

### `plugin_core_version`

**Type**: `int`  
**Default**: `1`  
**Environment Variable**: `PLUGIN_CORE_VERSION`  
**Validation**: Range 1-7  
**Description**: Core protocol version to use

```bash
export PLUGIN_CORE_VERSION=1
```

```python
version = rpcplugin_config.plugin_core_version  # 1
```

### `plugin_log_level`

**Type**: `str`  
**Default**: `"INFO"`  
**Environment Variable**: `PLUGIN_LOG_LEVEL`  
**Validation**: Must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL  
**Description**: Logging level for the plugin

```bash
export PLUGIN_LOG_LEVEL=DEBUG
```

```python
log_level = rpcplugin_config.plugin_log_level  # "DEBUG"
```

### `supported_protocol_versions`

**Type**: `list[int]`  
**Default**: `[1, 2, 3, 4, 5, 6, 7]`  
**Environment Variable**: `SUPPORTED_PROTOCOL_VERSIONS`  
**Description**: Reference list of all supported protocol versions

```bash
export SUPPORTED_PROTOCOL_VERSIONS='[1, 2, 3, 4, 5]'
```

## Magic Cookie Authentication

### `plugin_magic_cookie_key`

**Type**: `str`  
**Default**: `"PLUGIN_MAGIC_COOKIE"`  
**Environment Variable**: `PLUGIN_MAGIC_COOKIE_KEY`  
**Description**: Environment variable name for the magic cookie value

```bash
export PLUGIN_MAGIC_COOKIE_KEY="MY_PLUGIN_SECRET"
```

```python
cookie_key = rpcplugin_config.plugin_magic_cookie_key  # "MY_PLUGIN_SECRET"
```

### `plugin_magic_cookie_value`

**Type**: `str`  
**Default**: `"test_cookie_value"`  
**Environment Variable**: `PLUGIN_MAGIC_COOKIE_VALUE`  
**Sensitive**: Yes  
**Description**: Magic cookie value for plugin authentication

```bash
export PLUGIN_MAGIC_COOKIE_VALUE="production-secret-cookie-2024"
```

```python
cookie_value = rpcplugin_config.plugin_magic_cookie_value  # "production-secret-cookie-2024"
```

## Protocol Configuration

### `plugin_protocol_versions`

**Type**: `list[int]`  
**Default**: `[1]`  
**Environment Variable**: `PLUGIN_PROTOCOL_VERSIONS`  
**Validation**: Each version must be 1-7  
**Description**: List of protocol versions supported by this plugin

```bash
export PLUGIN_PROTOCOL_VERSIONS='[1, 2]'
```

```python
versions = rpcplugin_config.plugin_protocol_versions  # [1, 2]
```

## Server Transport Configuration

### `plugin_server_transports`

**Type**: `list[str]`  
**Default**: `["unix", "tcp"]`  
**Environment Variable**: `PLUGIN_SERVER_TRANSPORTS`  
**Validation**: Must be valid combination of "unix" and "tcp"  
**Description**: List of transports supported by the server

Valid combinations:
- `["unix"]` - Unix sockets only
- `["tcp"]` - TCP sockets only  
- `["unix", "tcp"]` - Unix preferred, TCP fallback
- `["tcp", "unix"]` - TCP preferred, Unix fallback

```bash
export PLUGIN_SERVER_TRANSPORTS='["unix"]'
```

```python
transports = rpcplugin_config.plugin_server_transports  # ["unix"]
```

### `plugin_server_endpoint`

**Type**: `str | None`  
**Default**: `None`  
**Environment Variable**: `PLUGIN_SERVER_ENDPOINT`  
**Description**: Server endpoint for connection (optional override)

```bash
export PLUGIN_SERVER_ENDPOINT="/tmp/my-plugin.sock"
# or
export PLUGIN_SERVER_ENDPOINT="127.0.0.1:8080"
```

```python
endpoint = rpcplugin_config.plugin_server_endpoint  # "/tmp/my-plugin.sock" or None
```

## mTLS Server Configuration

### `plugin_auto_mtls`

**Type**: `bool`  
**Default**: `True`  
**Environment Variable**: `PLUGIN_AUTO_MTLS`  
**Description**: Enable automatic mutual TLS

```bash
export PLUGIN_AUTO_MTLS=false
```

```python
auto_mtls = rpcplugin_config.plugin_auto_mtls  # False
```

### `plugin_server_cert`

**Type**: `str | None`  
**Default**: `None`  
**Environment Variable**: `PLUGIN_SERVER_CERT`  
**Sensitive**: Yes  
**Description**: Server certificate (PEM format or file:// path)

```bash
export PLUGIN_SERVER_CERT="file:///etc/ssl/certs/server.crt"
# or inline PEM (not recommended)
export PLUGIN_SERVER_CERT="-----BEGIN CERTIFICATE-----..."
```

```python
server_cert = rpcplugin_config.plugin_server_cert  # "file:///etc/ssl/certs/server.crt"
```

### `plugin_server_key`

**Type**: `str | None`  
**Default**: `None`  
**Environment Variable**: `PLUGIN_SERVER_KEY`  
**Sensitive**: Yes  
**Description**: Server private key (PEM format or file:// path)

```bash
export PLUGIN_SERVER_KEY="file:///etc/ssl/private/server.key"
```

### `plugin_server_root_certs`

**Type**: `str | None`  
**Default**: `None`  
**Environment Variable**: `PLUGIN_SERVER_ROOT_CERTS`  
**Sensitive**: Yes  
**Description**: Server root certificates (PEM format or file:// path)

```bash
export PLUGIN_SERVER_ROOT_CERTS="file:///etc/ssl/certs/ca.crt"
```

## Client Transport Configuration

### `plugin_client_transports`

**Type**: `list[str]`  
**Default**: `["unix", "tcp"]`  
**Environment Variable**: `PLUGIN_CLIENT_TRANSPORTS`  
**Validation**: Same as server transports  
**Description**: List of transports supported by the client

```bash
export PLUGIN_CLIENT_TRANSPORTS='["tcp", "unix"]'
```

### `plugin_client_endpoint`

**Type**: `str | None`  
**Default**: `None`  
**Environment Variable**: `PLUGIN_CLIENT_ENDPOINT`  
**Description**: Client endpoint for connection (optional override)

```bash
export PLUGIN_CLIENT_ENDPOINT="127.0.0.1:8080"
```

## mTLS Client Configuration

### `plugin_client_cert`

**Type**: `str | None`  
**Default**: `None`  
**Environment Variable**: `PLUGIN_CLIENT_CERT`  
**Sensitive**: Yes  
**Description**: Client certificate (PEM format or file:// path)

```bash
export PLUGIN_CLIENT_CERT="file:///etc/ssl/certs/client.crt"
```

### `plugin_client_key`

**Type**: `str | None`  
**Default**: `None`  
**Environment Variable**: `PLUGIN_CLIENT_KEY`  
**Sensitive**: Yes  
**Description**: Client private key (PEM format or file:// path)

```bash
export PLUGIN_CLIENT_KEY="file:///etc/ssl/private/client.key"
```

### `plugin_client_root_certs`

**Type**: `str | None`  
**Default**: `None`  
**Environment Variable**: `PLUGIN_CLIENT_ROOT_CERTS`  
**Sensitive**: Yes  
**Description**: Client root certificates (PEM format or file:// path)

```bash
export PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/ca.crt"
```

## Timeout Configuration

### `plugin_handshake_timeout`

**Type**: `float`  
**Default**: `10.0`  
**Environment Variable**: `PLUGIN_HANDSHAKE_TIMEOUT`  
**Validation**: Range 0.1-300.0  
**Description**: Timeout for plugin handshake in seconds

```bash
export PLUGIN_HANDSHAKE_TIMEOUT=15.0
```

```python
timeout = rpcplugin_config.plugin_handshake_timeout  # 15.0
```

### `plugin_connection_timeout`

**Type**: `float`  
**Default**: `30.0`  
**Environment Variable**: `PLUGIN_CONNECTION_TIMEOUT`  
**Validation**: Range 0.1-3600.0  
**Description**: Timeout for connection establishment in seconds

```bash
export PLUGIN_CONNECTION_TIMEOUT=45.0
```

## UI Configuration

### `plugin_show_emoji_matrix`

**Type**: `bool`  
**Default**: `True`  
**Environment Variable**: `PLUGIN_SHOW_EMOJI_MATRIX`  
**Description**: Show emoji matrix in logs

```bash
export PLUGIN_SHOW_EMOJI_MATRIX=false
```

```python
show_emojis = rpcplugin_config.plugin_show_emoji_matrix  # False
```

## Client Retry Configuration

### `plugin_client_retry_enabled`

**Type**: `bool`  
**Default**: `True`  
**Environment Variable**: `PLUGIN_CLIENT_RETRY_ENABLED`  
**Description**: Enable client retry mechanism

```bash
export PLUGIN_CLIENT_RETRY_ENABLED=false
```

### `plugin_client_max_retries`

**Type**: `int`  
**Default**: `3`  
**Environment Variable**: `PLUGIN_CLIENT_MAX_RETRIES`  
**Validation**: Non-negative  
**Description**: Maximum number of retry attempts

```bash
export PLUGIN_CLIENT_MAX_RETRIES=5
```

### `plugin_client_initial_backoff_ms`

**Type**: `int`  
**Default**: `500`  
**Environment Variable**: `PLUGIN_CLIENT_INITIAL_BACKOFF_MS`  
**Validation**: Positive  
**Description**: Initial backoff time in milliseconds

```bash
export PLUGIN_CLIENT_INITIAL_BACKOFF_MS=1000
```

### `plugin_client_max_backoff_ms`

**Type**: `int`  
**Default**: `5000`  
**Environment Variable**: `PLUGIN_CLIENT_MAX_BACKOFF_MS`  
**Validation**: Positive  
**Description**: Maximum backoff time in milliseconds

```bash
export PLUGIN_CLIENT_MAX_BACKOFF_MS=10000
```

### `plugin_client_retry_jitter_ms`

**Type**: `int`  
**Default**: `100`  
**Environment Variable**: `PLUGIN_CLIENT_RETRY_JITTER_MS`  
**Validation**: Non-negative  
**Description**: Retry jitter in milliseconds

```bash
export PLUGIN_CLIENT_RETRY_JITTER_MS=200
```

### `plugin_client_retry_total_timeout_s`

**Type**: `int`  
**Default**: `60`  
**Environment Variable**: `PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S`  
**Validation**: Positive  
**Description**: Total retry timeout in seconds

```bash
export PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S=120
```

## Shutdown Configuration

### `plugin_shutdown_file_path`

**Type**: `str | None`  
**Default**: `None`  
**Environment Variable**: `PLUGIN_SHUTDOWN_FILE_PATH`  
**Description**: Path to shutdown signal file

```bash
export PLUGIN_SHUTDOWN_FILE_PATH="/tmp/shutdown-plugin"
```

```python
shutdown_path = rpcplugin_config.plugin_shutdown_file_path  # "/tmp/shutdown-plugin"
```

## Rate Limiting Configuration

### `plugin_rate_limit_enabled`

**Type**: `bool`  
**Default**: `False`  
**Environment Variable**: `PLUGIN_RATE_LIMIT_ENABLED`  
**Description**: Enable rate limiting

```bash
export PLUGIN_RATE_LIMIT_ENABLED=true
```

### `plugin_rate_limit_requests_per_second`

**Type**: `float`  
**Default**: `100.0`  
**Environment Variable**: `PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND`  
**Validation**: Positive  
**Description**: Rate limit in requests per second

```bash
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000.0
```

### `plugin_rate_limit_burst_capacity`

**Type**: `float`  
**Default**: `200.0`  
**Environment Variable**: `PLUGIN_RATE_LIMIT_BURST_CAPACITY`  
**Validation**: Positive  
**Description**: Rate limit burst capacity

```bash
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=500.0
```

## Health Service Configuration

### `plugin_health_service_enabled`

**Type**: `bool`  
**Default**: `True`  
**Environment Variable**: `PLUGIN_HEALTH_SERVICE_ENABLED`  
**Description**: Enable health service

```bash
export PLUGIN_HEALTH_SERVICE_ENABLED=false
```

```python
health_enabled = rpcplugin_config.plugin_health_service_enabled  # False
```

## Helper Methods

The configuration class provides convenient helper methods:

### `magic_cookie_key() -> str`

Returns the magic cookie environment variable name.

```python
key = rpcplugin_config.magic_cookie_key()  # "PLUGIN_MAGIC_COOKIE"
```

### `magic_cookie_value() -> str`

Returns the magic cookie value.

```python
value = rpcplugin_config.magic_cookie_value()  # Current cookie value
```

### `server_transports() -> list[str]`

Returns the list of server-supported transports.

```python
transports = rpcplugin_config.server_transports()  # ["unix", "tcp"]
```

### `client_transports() -> list[str]`

Returns the list of client-supported transports.

```python
transports = rpcplugin_config.client_transports()  # ["unix", "tcp"]
```

### `handshake_timeout() -> float`

Returns the handshake timeout in seconds.

```python
timeout = rpcplugin_config.handshake_timeout()  # 10.0
```

### `connection_timeout() -> float`

Returns the connection timeout in seconds.

```python
timeout = rpcplugin_config.connection_timeout()  # 30.0
```

### `auto_mtls_enabled() -> bool`

Returns whether auto-mTLS is enabled.

```python
auto_mtls = rpcplugin_config.auto_mtls_enabled()  # True/False
```

## Configuration Validation

The configuration system includes comprehensive validation:

### Transport Validation

```python
# Valid transport combinations
["unix"]               # ✅ Unix only
["tcp"]                # ✅ TCP only
["unix", "tcp"]        # ✅ Unix preferred, TCP fallback
["tcp", "unix"]        # ✅ TCP preferred, Unix fallback

# Invalid combinations
["invalid"]            # ❌ ValidationError
["unix", "tcp", "ws"]  # ❌ ValidationError
[]                     # ❌ ValidationError
```

### Protocol Version Validation

```python
# Valid protocol versions
[1]                    # ✅ Single version
[1, 2, 3]             # ✅ Multiple versions
[7]                    # ✅ Latest version

# Invalid protocol versions
[0]                    # ❌ ValidationError (below range)
[8]                    # ❌ ValidationError (above range)
["1"]                  # ❌ ValidationError (wrong type)
```

### Numeric Range Validation

```python
# Valid numeric values
PLUGIN_HANDSHAKE_TIMEOUT=0.1      # ✅ Minimum
PLUGIN_HANDSHAKE_TIMEOUT=300.0    # ✅ Maximum
PLUGIN_CONNECTION_TIMEOUT=30.0    # ✅ Default

# Invalid numeric values
PLUGIN_HANDSHAKE_TIMEOUT=0.0      # ❌ ValidationError (below minimum)
PLUGIN_HANDSHAKE_TIMEOUT=301.0    # ❌ ValidationError (above maximum)
PLUGIN_HANDSHAKE_TIMEOUT=-1.0     # ❌ ValidationError (negative)
```

### Choice Validation

```python
# Valid log levels
PLUGIN_LOG_LEVEL=DEBUG      # ✅
PLUGIN_LOG_LEVEL=INFO       # ✅
PLUGIN_LOG_LEVEL=WARNING    # ✅
PLUGIN_LOG_LEVEL=ERROR      # ✅
PLUGIN_LOG_LEVEL=CRITICAL   # ✅

# Invalid log level
PLUGIN_LOG_LEVEL=TRACE      # ❌ ValidationError (not in choices)
```

## Environment Variable Examples

### Complete Development Configuration

```bash
#!/bin/bash
# development.env

# Core settings
export PLUGIN_CORE_VERSION=1
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_SHOW_EMOJI_MATRIX=true

# Authentication
export PLUGIN_MAGIC_COOKIE_KEY="DEV_PLUGIN_COOKIE"
export PLUGIN_MAGIC_COOKIE_VALUE="dev-cookie-123"

# Transport
export PLUGIN_SERVER_TRANSPORTS='["unix"]'
export PLUGIN_SERVER_ENDPOINT="/tmp/dev-plugin.sock"

# Security (auto-mTLS for development)
export PLUGIN_AUTO_MTLS=true

# Timeouts (generous for debugging)
export PLUGIN_HANDSHAKE_TIMEOUT=30.0
export PLUGIN_CONNECTION_TIMEOUT=60.0

# Retry configuration (aggressive for development)
export PLUGIN_CLIENT_RETRY_ENABLED=true
export PLUGIN_CLIENT_MAX_RETRIES=5
export PLUGIN_CLIENT_INITIAL_BACKOFF_MS=1000

# Health service
export PLUGIN_HEALTH_SERVICE_ENABLED=true

# Rate limiting (disabled for development)
export PLUGIN_RATE_LIMIT_ENABLED=false
```

### Complete Production Configuration

```bash
#!/bin/bash
# production.env

# Core settings
export PLUGIN_CORE_VERSION=1
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_SHOW_EMOJI_MATRIX=false

# Authentication (use strong cookie)
export PLUGIN_MAGIC_COOKIE_KEY="PRODUCTION_PLUGIN_COOKIE"
export PLUGIN_MAGIC_COOKIE_VALUE="$(openssl rand -base64 32)"

# Transport
export PLUGIN_SERVER_TRANSPORTS='["tcp"]'
export PLUGIN_SERVER_ENDPOINT="0.0.0.0:8080"

# Security (manual certificates)
export PLUGIN_AUTO_MTLS=false
export PLUGIN_SERVER_CERT="file:///etc/ssl/certs/plugin-server.crt"
export PLUGIN_SERVER_KEY="file:///etc/ssl/private/plugin-server.key"
export PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/plugin-ca.crt"

# Timeouts (optimized for production)
export PLUGIN_HANDSHAKE_TIMEOUT=10.0
export PLUGIN_CONNECTION_TIMEOUT=30.0

# Retry configuration (conservative)
export PLUGIN_CLIENT_RETRY_ENABLED=true
export PLUGIN_CLIENT_MAX_RETRIES=3
export PLUGIN_CLIENT_INITIAL_BACKOFF_MS=500
export PLUGIN_CLIENT_MAX_BACKOFF_MS=5000
export PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S=60

# Health service
export PLUGIN_HEALTH_SERVICE_ENABLED=true

# Rate limiting (enabled for protection)
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=2000.0

# Shutdown control
export PLUGIN_SHUTDOWN_FILE_PATH="/var/run/plugin-shutdown"
```

## Related Documentation

- [Configuration System Overview](index.md) - Configuration system introduction
- [Environment Variables Guide](environment.md) - Environment variable setup patterns
- [Server Configuration](../server/server.md) - Using configuration in servers
- [Client Configuration](../client/client.md) - Using configuration in clients