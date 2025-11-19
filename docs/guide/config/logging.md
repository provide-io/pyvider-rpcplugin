# Logging Configuration

Pyvider RPC Plugin provides comprehensive structured logging built on the provide.foundation framework, offering rich context, emoji enhancements, and seamless integration with log aggregation systems.

## Overview

The logging system provides:

- **Structured logging**: JSON-formatted logs with consistent field names
- **Emoji enhancement**: Visual indicators for different components and actions
- **Context preservation**: Automatic inclusion of request IDs, client info, and timing
- **Multiple output formats**: Console-friendly and machine-readable formats
- **Integration ready**: Works with ELK, Splunk, Datadog, and other log systems
- **Performance optimized**: Low-overhead logging with configurable levels

## Basic Configuration

### Log Level

Control logging verbosity:

```bash
# Development
export PLUGIN_LOG_LEVEL=DEBUG

# Production
export PLUGIN_LOG_LEVEL=INFO

# High-traffic production
export PLUGIN_LOG_LEVEL=WARNING
```

### Emoji Enhancement

```bash
# Enable for development (human-readable)
export PLUGIN_SHOW_EMOJI_MATRIX=true

# Disable for production (machine-readable)
export PLUGIN_SHOW_EMOJI_MATRIX=false
```

---

## Log Levels

### Quick Reference

| Level | Use Case | Overhead | Example |
|-------|----------|----------|---------|
| **DEBUG** | Local development, troubleshooting | ~50μs/req | `🔌 Creating Unix socket transport path="/tmp/plugin.sock"` |
| **INFO** | Production monitoring | ~20μs/req | `🚀 Plugin server started endpoint="unix:/tmp/plugin.sock"` |
| **WARNING** | Important events | ~10μs/req | `⚠️ Self-signed certificate detected - not for production` |
| **ERROR** | Service operation errors | ~5μs/req | `❌ Connection failed endpoint="tcp:server:8080"` |
| **CRITICAL** | System-threatening | Minimal | `💥 Server shutdown due to critical error` |

### Detailed Usage

=== "DEBUG"

    Most verbose logging including internal operations.

    ```python
    2024-01-15 10:30:45.123 DEBUG [pyvider.rpcplugin.server] 🏗️ Server initialization transport=unix
    2024-01-15 10:30:45.125 DEBUG [pyvider.rpcplugin.handshake] 🤝 Handshake initiated protocol_version=1
    ```

    **Use for:** Local development, connection debugging, TLS troubleshooting

=== "INFO"

    Standard operational logging.

    ```python
    2024-01-15 10:30:45.200 INFO [pyvider.rpcplugin.server] 🚀 Plugin server started endpoint="unix:/tmp/plugin.sock"
    2024-01-15 10:30:45.205 INFO [pyvider.rpcplugin.client] 🔗 Client connected handshake_time=0.005s
    ```

    **Use for:** Production monitoring, service health tracking, performance metrics

=== "WARNING/ERROR"

    Important events and errors.

    ```python
    2024-01-15 10:30:45.300 WARNING [pyvider.rpcplugin.ratelimit] 🚦 Rate limit threshold reached
    2024-01-15 10:30:45.400 ERROR [pyvider.rpcplugin.transport] ❌ Connection failed error="Connection refused"
    ```

    **Use for:** Production with established monitoring, alert-driven systems

---

## Structured Logging Format

### JSON Output (Production)

When emoji enhancement is disabled:

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "logger": "pyvider.rpcplugin.server",
  "message": "Plugin server started",
  "context": {
    "endpoint": "unix:/tmp/plugin.sock",
    "protocol_version": 1,
    "server_id": "srv_abc123"
  },
  "correlation_id": "req_xyz789",
  "duration_ms": 5.2
}
```

### Console Output (Development)

With emoji enhancement enabled:

```
2024-01-15 10:30:45.123 INFO [pyvider.rpcplugin.server] 🚀 Plugin server started
  └─ endpoint: unix:/tmp/plugin.sock
  └─ protocol_version: 1
  └─ duration: 5.2ms
```

---

## Context and Correlation

### Automatic Context

The logging system automatically includes contextual information:

```python
# Server context
{
  "server_id": "srv_abc123",
  "transport_type": "unix",
  "endpoint": "/tmp/plugin.sock"
}

# Client context
{
  "client_id": "cli_def456",
  "connection_id": "conn_ghi789",
  "request_id": "req_jkl012"
}

# Request context
{
  "method": "MyService.ProcessData",
  "duration_ms": 15.7,
  "status": "OK"
}
```

### Custom Context

Add custom context using the `extra` parameter:

```python
from provide.foundation.logger import get_logger

logger = get_logger(__name__)

logger.info("Processing user request", extra={
    "user_id": "user_12345",
    "operation": "data_processing",
    "priority": "high"
})
```

---

## Log Aggregation Integration

Configure for log aggregation systems by disabling emoji and using JSON format:

```bash
# Common configuration for all log aggregation systems
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_SHOW_EMOJI_MATRIX=false
```

### Platform-Specific Configuration

=== "ELK Stack"

    **Logstash configuration:**

    ```ruby
    input {
      file {
        path => "/var/log/plugin/*.log"
        codec => "json"
      }
    }

    filter {
      if [logger] =~ /pyvider\.rpcplugin/ {
        mutate { add_tag => ["pyvider-plugin"] }
      }
    }

    output {
      elasticsearch {
        hosts => ["localhost:9200"]
        index => "pyvider-plugin-%{+YYYY.MM.dd}"
      }
    }
    ```

=== "Splunk"

    **props.conf:**

    ```ini
    [pyvider_plugin]
    KV_MODE = json
    DATETIME_CONFIG = CURRENT
    SHOULD_LINEMERGE = false
    ```

=== "Datadog"

    **Agent configuration:**

    ```yaml
    logs:
      - type: file
        path: /var/log/plugin/*.log
        service: pyvider-plugin
        source: python
        tags:
          - env:production
          - component:rpc-plugin
    ```

=== "Fluentd"

    **Configuration:**

    ```ruby
    <source>
      @type tail
      format json
      path /var/log/plugin/*.log
      tag pyvider.plugin
    </source>

    <match pyvider.plugin>
      @type forward
      <server>
        host aggregator.example.com
        port 24224
      </server>
    </match>
    ```

**Common patterns:** All platforms support JSON format logs. Use structured logging (emoji disabled) for best compatibility.

---

## Performance and Security Logging

### Performance Metrics

Key performance metrics are automatically logged:

```python
# Request performance
{
  "method": "MyService.ProcessData",
  "request_size": 1024,
  "response_size": 2048,
  "duration_ms": 15.7,
  "concurrent_requests": 23
}

# Connection performance
{
  "transport": "tcp",
  "handshake_duration_ms": 5.2,
  "tls_negotiation_ms": 8.1
}
```

### Security Events

Security events are logged with appropriate context:

```python
# Authentication
{
  "message": "Client authentication successful",
  "certificate_subject": "CN=client.example.com",
  "auth_method": "mtls"
}

# Security violations
{
  "message": "Rate limit exceeded",
  "level": "WARNING",
  "rate_limit": 100.0,
  "current_rate": 125.3
}
```

---

## Development and Debugging

### Development Configuration

```bash
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_SHOW_EMOJI_MATRIX=true
```

### Component-Specific Debugging

Add context to target specific components:

```python
from provide.foundation.logger import get_logger

logger = get_logger(__name__)

# Transport debugging
logger.debug("Transport debug enabled", extra={
    "component": "transport",
    "socket_path": "/tmp/plugin.sock"
})

# Security debugging
logger.debug("Security debug enabled", extra={
    "component": "security"
})
```

### Request Tracing

Use correlation IDs for request tracing:

```python
import uuid

trace_id = str(uuid.uuid4())

logger.info("Request started", extra={"trace_id": trace_id})
# ... process request ...
logger.info("Request completed", extra={"trace_id": trace_id})
```

---

## Log Rotation and Management

### System-Level Rotation

Pyvider RPC Plugin logs to stderr by default. Use system-level log rotation:

```bash
# /etc/logrotate.d/pyvider-plugin
/var/log/plugin/*.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
}
```

For file-based logging, redirect stderr or use Python's logging handlers.

---

## Monitoring and Alerting

### Key Log Patterns

Monitor these patterns for issues:

1. **Connection Failures**: `level="ERROR" AND message CONTAINS "Connection failed"`
2. **Rate Limiting**: `level="WARNING" AND message CONTAINS "Rate limit"`
3. **Security Events**: `logger="pyvider.rpcplugin.security" AND level IN ["WARNING", "ERROR"]`
4. **Performance Degradation**: `duration_ms > 1000`

### Alert Example (Prometheus)

```yaml
- alert: PluginHighErrorRate
  expr: rate(pyvider_plugin_errors_total[5m]) > 0.1
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "High error rate in Pyvider Plugin"
```

---

## Best Practices

### Production

1. **Use INFO level** - DEBUG only for troubleshooting
2. **Disable emoji enhancement** - Set `PLUGIN_SHOW_EMOJI_MATRIX="false"`
3. **Use JSON format** - For log aggregation systems
4. **Implement log rotation** - Prevent disk space issues
5. **Never log sensitive data** - No passwords, tokens, or PII

### Development

1. **Enable emoji enhancement** - Set `PLUGIN_SHOW_EMOJI_MATRIX="true"`
2. **Use DEBUG level** - Set `PLUGIN_LOG_LEVEL="DEBUG"`
3. **Console output** - Human-readable format
4. **Request tracing** - Enable correlation IDs

### Security

1. **Log access control** - Restrict log file access
2. **Data sanitization** - Ensure no sensitive data in logs
3. **Audit trails** - Maintain security event logs
4. **Retention policies** - Define appropriate retention periods

---

## Troubleshooting

### No Log Output

```bash
# Check log level
export PLUGIN_LOG_LEVEL=DEBUG

# Verify Foundation logger
python -c "from provide.foundation.logger import get_logger

logger = get_logger(__name__); logger.info('Test')"

# Logs go to stderr - ensure stderr is not suppressed
```

### Log Format Issues

```bash
# For machine processing
export PLUGIN_SHOW_EMOJI_MATRIX=false

# For human reading
export PLUGIN_SHOW_EMOJI_MATRIX=true
```

### Missing Context

```python
# Preserve context in async operations
async def my_handler(request, context):
    with logger.context(request_id=generate_request_id()):
        logger.info("Processing request")
        result = await process_request(request)
        return result
```

---

## Related Topics

- **[Production Setup](production.md)** - Complete production deployment configuration
- **[Environment Variables](environment.md)** - All configuration options reference
- **[Configuration Reference](configuration-reference.md)** - Complete configuration options
- **[Configuration Guide](configuration-guide.md)** - Client, server, and security configuration
