# Environment Variables

Complete reference for all environment variables supported by Pyvider RPC Plugin. All variables use the `PLUGIN_` prefix and support automatic type conversion from string values.

## Core Protocol Settings

### PLUGIN_CORE_VERSION
- **Type**: `int`
- **Default**: `1`
- **Description**: Plugin protocol version for client-server negotiation
- **Valid Values**: `1-7`
- **Example**: `export PLUGIN_CORE_VERSION=1`

### PLUGIN_PROTOCOL_VERSIONS
- **Type**: `list[int]`
- **Default**: `[1]`
- **Description**: List of protocol versions supported by this plugin
- **Valid Values**: JSON array of integers 1-7
- **Example**: `export PLUGIN_PROTOCOL_VERSIONS='[1, 2, 3]'`

## Transport Configuration

### PLUGIN_SERVER_TRANSPORTS
- **Type**: `list[str]`
- **Default**: `["unix", "tcp"]`
- **Description**: Transport types the server supports and announces
- **Valid Values**: JSON array of "unix" and/or "tcp"
- **Example**: `export PLUGIN_SERVER_TRANSPORTS='["unix", "tcp"]'`

### PLUGIN_CLIENT_TRANSPORTS
- **Type**: `list[str]`
- **Default**: `["unix", "tcp"]`
- **Description**: Transport types the client prefers (in priority order)
- **Valid Values**: JSON array of "unix" and/or "tcp"
- **Example**: `export PLUGIN_CLIENT_TRANSPORTS='["unix", "tcp"]'`

## Security and Authentication

### PLUGIN_AUTO_MTLS
- **Type**: `bool`
- **Default**: `true`
- **Description**: Whether a server answers a host's automatic-mTLS request. A
  plugin server serves TLS when the host sends `PLUGIN_CLIENT_CERT`, or when
  `PLUGIN_SERVER_CERT`/`PLUGIN_SERVER_KEY` are configured by hand -- never
  otherwise, since a host that did not ask for TLS cannot parse a certificate
  in the handshake. With a host certificate in hand and this setting on, the
  server generates its own certificate, requires the host's, and verifies it
  against that certificate alone. Setting it `false` declines automatic mTLS:
  the server serves plaintext even when the host offers a certificate.
- **Valid Values**: `"true"`, `"false"`, `"yes"`, `"no"`, `"1"`, `"0"`
- **Example**: `export PLUGIN_AUTO_MTLS=true`

### PLUGIN_IGNORE_SIGINT
- **Type**: `bool`
- **Default**: `true`
- **Description**: Whether a plugin server ignores SIGINT. A plugin is not put
  in its own process group, so a terminal Ctrl-C reaches the plugin as well as
  its host; the host is the one that must sequence the shutdown. Set it
  `false` for interactive or in-process servers that should stop on Ctrl-C.
  SIGTERM shuts the server down either way.
- **Valid Values**: `"true"`, `"false"`, `"yes"`, `"no"`, `"1"`, `"0"`
- **Example**: `export PLUGIN_IGNORE_SIGINT=false`

### PLUGIN_MAGIC_COOKIE_KEY
- **Type**: `str`
- **Default**: `"PLUGIN_MAGIC_COOKIE"`
- **Description**: Environment variable name containing the magic cookie
- **Usage**: Server reads magic cookie from this environment variable
- **Example**: `export PLUGIN_MAGIC_COOKIE_KEY=MY_PLUGIN_SECRET`

### PLUGIN_MAGIC_COOKIE_VALUE
- **Type**: `str`
- **Default**: `"test_cookie_value"`
- **Description**: The actual magic cookie secret for authentication
- **Security**: Use cryptographically secure random strings in production
- **Example**: `export PLUGIN_MAGIC_COOKIE_VALUE=$(openssl rand -hex 32)`

## TLS Certificate Configuration

### PLUGIN_SERVER_CERT
- **Type**: `str`
- **Default**: `None` (auto-generated for development)
- **Description**: Server TLS certificate (PEM format or file path)
- **Format**: Direct PEM string or `file:///path/to/cert.pem`
- **Example**:
  ```bash
  export PLUGIN_SERVER_CERT=file:///etc/ssl/certs/server.pem
  # or direct PEM:
  export PLUGIN_SERVER_CERT="-----BEGIN CERTIFICATE-----..."
  ```

### PLUGIN_SERVER_KEY
- **Type**: `str`
- **Default**: `None` (auto-generated for development)
- **Description**: Server TLS private key (PEM format or file path)
- **Format**: Direct PEM string or `file:///path/to/key.pem`
- **Security**: Ensure private key files have 600 permissions
- **Example**: `export PLUGIN_SERVER_KEY=file:///etc/ssl/private/server.key`

### PLUGIN_CLIENT_CERT
- **Type**: `str`
- **Default**: `None` (auto-generated for development)
- **Description**: Client TLS certificate for mutual TLS
- **Format**: Same as server certificate
- **Example**: `export PLUGIN_CLIENT_CERT=file:///etc/ssl/certs/client.pem`

### PLUGIN_CLIENT_KEY
- **Type**: `str`
- **Default**: `None` (auto-generated for development)  
- **Description**: Client TLS private key for mutual TLS
- **Format**: Same as server key
- **Example**: `export PLUGIN_CLIENT_KEY=file:///etc/ssl/private/client.key`

### PLUGIN_SERVER_ROOT_CERTS
- **Type**: `str`
- **Default**: `None` (use system CA bundle)
- **Description**: CA certificates for client to verify server certificate
- **Format**: PEM bundle or `file:///path/to/ca-bundle.pem`
- **Example**: `export PLUGIN_SERVER_ROOT_CERTS=file:///etc/ssl/certs/ca-bundle.pem`

### PLUGIN_CLIENT_ROOT_CERTS
- **Type**: `str`
- **Default**: `None` (use system CA bundle)
- **Description**: CA certificates for server to verify client certificate
- **Format**: Same as server root certs
- **Example**: `export PLUGIN_CLIENT_ROOT_CERTS=file:///etc/ssl/certs/ca-bundle.pem`

## Timeout and Connection Settings

### PLUGIN_HANDSHAKE_TIMEOUT
- **Type**: `float`
- **Default**: `10.0`
- **Description**: Timeout in seconds for handshake completion
- **Range**: `0.1` to `300.0` (practical limits)
- **Example**: `export PLUGIN_HANDSHAKE_TIMEOUT=30.0`

### PLUGIN_CONNECTION_TIMEOUT
- **Type**: `float`
- **Default**: `30.0`
- **Description**: Timeout in seconds for connection establishment
- **Range**: `1.0` to `600.0` (practical limits)
- **Example**: `export PLUGIN_CONNECTION_TIMEOUT=60.0`

## Client Retry Configuration

### PLUGIN_CLIENT_RETRY_ENABLED
- **Type**: `bool`
- **Default**: `true`
- **Description**: Enable automatic client retry on connection failures
- **Example**: `export PLUGIN_CLIENT_RETRY_ENABLED=true`

### PLUGIN_CLIENT_MAX_RETRIES
- **Type**: `int`
- **Default**: `3`
- **Description**: Maximum number of retry attempts
- **Range**: `0` to `10` (practical limits)
- **Example**: `export PLUGIN_CLIENT_MAX_RETRIES=5`

### PLUGIN_CLIENT_INITIAL_BACKOFF_MS
- **Type**: `int`
- **Default**: `500`
- **Description**: Initial delay in milliseconds before first retry
- **Range**: `100` to `10000`
- **Example**: `export PLUGIN_CLIENT_INITIAL_BACKOFF_MS=1000`

### PLUGIN_CLIENT_MAX_BACKOFF_MS
- **Type**: `int`
- **Default**: `5000`
- **Description**: Maximum delay in milliseconds between retries
- **Range**: `1000` to `60000`
- **Example**: `export PLUGIN_CLIENT_MAX_BACKOFF_MS=10000`

### PLUGIN_CLIENT_RETRY_JITTER_MS
- **Type**: `int`
- **Default**: `100`
- **Description**: Maximum random jitter in milliseconds to add to backoff
- **Range**: `0` to `1000`
- **Purpose**: Prevents thundering herd scenarios
- **Example**: `export PLUGIN_CLIENT_RETRY_JITTER_MS=250`

### PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S
- **Type**: `int`
- **Default**: `60`
- **Description**: Total time in seconds to spend retrying before giving up
- **Range**: `10` to `600`
- **Example**: `export PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S=120`

## Server Features

### PLUGIN_HEALTH_SERVICE_ENABLED
- **Type**: `bool`
- **Default**: `true`
- **Description**: Enable standard gRPC health checking service
- **Usage**: Required for Kubernetes health checks and load balancers
- **Example**: `export PLUGIN_HEALTH_SERVICE_ENABLED=true`

### PLUGIN_RATE_LIMIT_ENABLED
- **Type**: `bool`
- **Default**: `false`
- **Description**: Enable server-side request rate limiting
- **Algorithm**: Token bucket with configurable rate and burst
- **Example**: `export PLUGIN_RATE_LIMIT_ENABLED=true`

### PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND
- **Type**: `float`
- **Default**: `100.0`
- **Description**: Average requests per second allowed by rate limiter
- **Range**: `0.1` to `10000.0`
- **Example**: `export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=50.0`

### PLUGIN_RATE_LIMIT_BURST_CAPACITY
- **Type**: `float`
- **Default**: `200.0`
- **Description**: Maximum requests allowed in short burst (token bucket size)
- **Range**: `1.0` to `50000.0`
- **Rule**: Should be >= requests per second for smooth operation
- **Example**: `export PLUGIN_RATE_LIMIT_BURST_CAPACITY=100.0`

### PLUGIN_SHUTDOWN_FILE_PATH
- **Type**: `str`
- **Default**: `None` (disabled)
- **Description**: File path to monitor for graceful shutdown trigger
- **Usage**: Server shuts down when this file is created
- **Example**: `export PLUGIN_SHUTDOWN_FILE_PATH=/tmp/shutdown-plugin`

## Logging and Development

### PLUGIN_LOG_LEVEL
- **Type**: `str`
- **Default**: `"INFO"`
- **Description**: Logging level for structured output
- **Valid Values**: `"DEBUG"`, `"INFO"`, `"WARNING"`, `"ERROR"`, `"CRITICAL"`
- **Example**: `export PLUGIN_LOG_LEVEL=DEBUG`

### PLUGIN_SHOW_EMOJI_MATRIX
- **Type**: `bool`
- **Default**: `true`
- **Description**: Enable emoji enhancements in log messages
- **Usage**: Improves visual tracking during development
- **Example**: `export PLUGIN_SHOW_EMOJI_MATRIX=false`

## Environment Loading Examples

### Development Environment File

```bash
# .env.development
PLUGIN_LOG_LEVEL=DEBUG
PLUGIN_SHOW_EMOJI_MATRIX=true
PLUGIN_AUTO_MTLS=false
PLUGIN_SERVER_TRANSPORTS=["unix"]
PLUGIN_HANDSHAKE_TIMEOUT=5.0
PLUGIN_CONNECTION_TIMEOUT=10.0
PLUGIN_CLIENT_MAX_RETRIES=2
PLUGIN_MAGIC_COOKIE_VALUE=dev-cookie-123
```

### Production Environment File

```bash
# .env.production
PLUGIN_LOG_LEVEL=INFO
PLUGIN_SHOW_EMOJI_MATRIX=false
PLUGIN_AUTO_MTLS=true
PLUGIN_SERVER_TRANSPORTS=["tcp"]
PLUGIN_SERVER_CERT=file:///etc/ssl/certs/plugin-server.pem
PLUGIN_SERVER_KEY=file:///etc/ssl/private/plugin-server.key
PLUGIN_CLIENT_ROOT_CERTS=file:///etc/ssl/certs/ca-bundle.pem
PLUGIN_HANDSHAKE_TIMEOUT=30.0
PLUGIN_CONNECTION_TIMEOUT=60.0
PLUGIN_RATE_LIMIT_ENABLED=true
PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=100.0
PLUGIN_RATE_LIMIT_BURST_CAPACITY=200.0
PLUGIN_HEALTH_SERVICE_ENABLED=true
PLUGIN_CLIENT_MAX_RETRIES=5
PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S=120
```

### Container/Kubernetes Environment

```bash
# Container environment with secrets integration
PLUGIN_LOG_LEVEL=INFO
PLUGIN_SERVER_HOST=0.0.0.0
PLUGIN_SERVER_PORT=8080
PLUGIN_AUTO_MTLS=true
PLUGIN_SERVER_CERT=${SERVER_CERT_PEM}  # From Kubernetes secret
PLUGIN_SERVER_KEY=${SERVER_KEY_PEM}    # From Kubernetes secret
PLUGIN_MAGIC_COOKIE_VALUE=${PLUGIN_SECRET}  # From secret manager
PLUGIN_HEALTH_SERVICE_ENABLED=true
PLUGIN_SHUTDOWN_FILE_PATH=/tmp/shutdown
```

## Type Conversion Rules

### Boolean Values
The following string values are converted to `True` (case-insensitive):
- `"true"`, `"yes"`, `"on"`, `"1"`, `"enabled"`

All other values are converted to `False`.

### List Values
Comma-separated strings are split into lists:
- `"unix,tcp"` → `["unix", "tcp"]`
- `"1,2,3"` → `[1, 2, 3]` (for integer lists)
- Whitespace around commas is automatically stripped

### Numeric Values
- **Integers**: Standard Python `int()` conversion
- **Floats**: Standard Python `float()` conversion
- Invalid numeric strings raise `ConfigError`

### File Path Values
Values starting with `file://` are treated as file paths and the content is loaded:
- `"file:///path/to/cert.pem"` loads the file content
- Direct PEM strings are used as-is
- Missing files raise `ConfigError`

## Validation and Error Handling

All environment variables are validated when the configuration is first accessed:

```python
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.exception import ConfigError

try:
    config = rpcplugin_config
    # All environment variables are validated here
    protocol_version = config.protocol_version()
except ConfigError as e:
    logger.error(f"Configuration validation failed: {e.validation_errors}")
    # Handle configuration errors (fix values, provide defaults, etc.)
```

Common validation errors:
- Invalid boolean values: `"maybe"` → `ConfigError`
- Invalid numeric values: `"not-a-number"` → `ConfigError`  
- Missing certificate files: `"file:///missing/cert.pem"` → `ConfigError`
- Invalid transport types: `"invalid-transport"` → `ConfigError`

## Next Steps

- **[Production Setup](advanced.md)** - Production deployment configuration patterns
- **[Rate Limiting](../server/rate-limiting.md)** - Detailed rate limiting configuration
- **[Logging Configuration](logging.md)** - Structured logging setup
- **[Configuration Reference](configuration-reference.md)** - Complete configuration reference
