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

### Log Level Configuration

Control logging verbosity with the log level setting:

```bash
# Development: Verbose logging
export PLUGIN_LOG_LEVEL=DEBUG

# Production: Standard logging
export PLUGIN_LOG_LEVEL=INFO

# High-traffic production: Minimal logging
export PLUGIN_LOG_LEVEL=WARNING
```

### Emoji Enhancement

Enable or disable emoji indicators in log messages:

```bash
# Enable emoji enhancement (development)
export PLUGIN_SHOW_EMOJI_MATRIX=true

# Disable emoji enhancement (production log aggregation)
export PLUGIN_SHOW_EMOJI_MATRIX=false
```

## Log Levels and Content

### DEBUG Level

Most verbose logging including internal operations:

```python
# Example DEBUG log messages
2024-01-15 10:30:45.123 DEBUG [pyvider.rpcplugin.transport.unix] 🔌 Creating Unix socket transport path="/tmp/plugin.sock"
2024-01-15 10:30:45.124 DEBUG [pyvider.rpcplugin.server] 🏗️ Server initialization transport=unix endpoint="/tmp/plugin.sock"
2024-01-15 10:30:45.125 DEBUG [pyvider.rpcplugin.handshake] 🤝 Handshake initiated protocol_version=1 magic_cookie_length=32
2024-01-15 10:30:45.126 DEBUG [pyvider.rpcplugin.security] 🔐 mTLS configuration loaded server_cert_path="/etc/ssl/server.pem"
```

**Use DEBUG for:**
- Local development
- Troubleshooting connection issues  
- Understanding handshake flow
- Certificate and TLS debugging

### INFO Level

Standard operational logging:

```python
# Example INFO log messages  
2024-01-15 10:30:45.200 INFO [pyvider.rpcplugin.server] 🚀 Plugin server started endpoint="unix:/tmp/plugin.sock" protocol_version=1
2024-01-15 10:30:45.205 INFO [pyvider.rpcplugin.client] 🔗 Client connected to server endpoint="unix:/tmp/plugin.sock" handshake_time=0.005s
2024-01-15 10:30:45.210 INFO [pyvider.rpcplugin.health] ❤️ Health service registered endpoints=["/grpc.health.v1.Health/Check"]
2024-01-15 10:30:45.215 INFO [pyvider.rpcplugin.ratelimit] 🚦 Rate limiting enabled rate=100.0/s burst=200
```

**Use INFO for:**
- Production monitoring
- Service health tracking
- Connection lifecycle events
- Performance metrics

### WARNING Level

Important events that may require attention:

```python
# Example WARNING log messages
2024-01-15 10:30:45.300 WARNING [pyvider.rpcplugin.security] ⚠️ Self-signed certificate detected - not recommended for production
2024-01-15 10:30:45.305 WARNING [pyvider.rpcplugin.ratelimit] 🚦 Rate limit threshold reached client="192.168.1.100" requests=95/100
2024-01-15 10:30:45.310 WARNING [pyvider.rpcplugin.transport] 🔌 Connection retry attempt=3/5 backoff=2.0s endpoint="tcp:server:8080"
```

**Use WARNING for:**
- Production environments with moderate traffic
- Security-focused deployments
- Systems with established monitoring

### ERROR Level

Error conditions that affect service operation:

```python
# Example ERROR log messages
2024-01-15 10:30:45.400 ERROR [pyvider.rpcplugin.transport] ❌ Connection failed endpoint="tcp:server:8080" error="Connection refused"
2024-01-15 10:30:45.405 ERROR [pyvider.rpcplugin.security] 🔐 Certificate validation failed cert_path="/etc/ssl/bad.pem" error="Invalid certificate format"
2024-01-15 10:30:45.410 ERROR [pyvider.rpcplugin.handshake] 🤝 Handshake timeout exceeded client="192.168.1.100" timeout=30.0s
```

**Use ERROR for:**
- Critical production systems
- Alert-driven monitoring
- Minimal log volume requirements

### CRITICAL Level

System-threatening conditions requiring immediate attention:

```python
# Example CRITICAL log messages
2024-01-15 10:30:45.500 CRITICAL [pyvider.rpcplugin.server] 💥 Server shutdown due to critical error error="Out of memory"
2024-01-15 10:30:45.505 CRITICAL [pyvider.rpcplugin.security] 🚨 Security breach detected unauthorized_access=true client="unknown"
```

**Use CRITICAL for:**
- High-security environments
- Systems where any error is critical
- Alert-only logging configurations

## Structured Logging Format

### JSON Output Format

When emoji enhancement is disabled, logs use structured JSON format:

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "logger": "pyvider.rpcplugin.server",
  "message": "Plugin server started",
  "context": {
    "endpoint": "unix:/tmp/plugin.sock",
    "protocol_version": 1,
    "transport_type": "unix",
    "server_id": "srv_abc123",
    "pid": 12345
  },
  "correlation_id": "req_xyz789",
  "duration_ms": 5.2
}
```

### Console Output Format

With emoji enhancement enabled for development:

```
2024-01-15 10:30:45.123 INFO [pyvider.rpcplugin.server] 🚀 Plugin server started
  └─ endpoint: unix:/tmp/plugin.sock
  └─ protocol_version: 1
  └─ transport_type: unix
  └─ server_id: srv_abc123
  └─ duration: 5.2ms
```

## Context and Correlation

### Automatic Context

The logging system automatically includes contextual information:

```python
# Server context
{
  "server_id": "srv_abc123",
  "transport_type": "unix",
  "endpoint": "/tmp/plugin.sock",
  "pid": 12345,
  "thread_id": "MainThread"
}

# Client context  
{
  "client_id": "cli_def456", 
  "connection_id": "conn_ghi789",
  "peer_address": "unix:/tmp/plugin.sock",
  "request_id": "req_jkl012"
}

# Request context
{
  "method": "MyService.ProcessData",
  "request_size": 1024,
  "response_size": 2048,
  "duration_ms": 15.7,
  "status": "OK"
}
```

### Custom Context

Add custom context to log messages:

```python
from provide.foundation import logger

# Add context to specific log message
logger.info("Processing user request", extra={
    "user_id": "user_12345",
    "operation": "data_processing", 
    "batch_size": 100,
    "priority": "high"
})

# Use context manager for multiple log messages
with logger.context(user_id="user_12345", session_id="sess_67890"):
    logger.info("Starting user session")
    logger.debug("Loading user preferences")
    logger.info("Session initialized successfully")
```

## Integration Examples

### ELK Stack (Elasticsearch, Logstash, Kibana)

Configure for ELK ingestion:

```bash
# Production ELK configuration
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_SHOW_EMOJI_MATRIX=false
```

Logstash configuration:
```ruby
input {
  file {
    path => "/var/log/plugin/*.log"
    codec => "json"
  }
}

filter {
  if [logger] =~ /pyvider\.rpcplugin/ {
    mutate {
      add_tag => ["pyvider-plugin"]
    }
  }
  
  # Extract performance metrics
  if [duration_ms] {
    mutate {
      convert => { "duration_ms" => "float" }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "pyvider-plugin-%{+YYYY.MM.dd}"
  }
}
```

### Splunk

Configure for Splunk ingestion:

```bash
# Splunk configuration
export PLUGIN_LOG_LEVEL=INFO 
export PLUGIN_SHOW_EMOJI_MATRIX=false
```

Splunk props.conf:
```ini
[pyvider_plugin]
KV_MODE = json
DATETIME_CONFIG = CURRENT
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
```

### Datadog

Configure for Datadog log management:

```bash
# Datadog configuration  
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_SHOW_EMOJI_MATRIX=false
```

Datadog agent configuration:
```yaml
logs:
  - type: file
    path: /var/log/plugin/*.log
    service: pyvider-plugin
    source: python
    sourcecategory: pyvider
    tags:
      - env:production
      - component:rpc-plugin
```

### Fluentd

Configure for Fluentd collection:

```ruby
<source>
  @type tail
  format json
  path /var/log/plugin/*.log
  pos_file /var/log/fluentd/plugin.log.pos
  tag pyvider.plugin
</source>

<filter pyvider.plugin>
  @type parser
  key_name message
  reserve_data true
  <parse>
    @type json
  </parse>
</filter>

<match pyvider.plugin>
  @type forward
  <server>
    host aggregator.example.com
    port 24224
  </server>
</match>
```

## Performance and Security Logging

### Performance Monitoring

Key performance metrics are automatically logged:

```python
# Request performance logging
{
  "message": "Request completed",
  "context": {
    "method": "MyService.ProcessData",
    "request_size": 1024,
    "response_size": 2048, 
    "duration_ms": 15.7,
    "status": "OK",
    "concurrent_requests": 23
  }
}

# Transport performance logging
{
  "message": "Connection established", 
  "context": {
    "transport": "tcp",
    "endpoint": "server:8080",
    "handshake_duration_ms": 5.2,
    "tls_negotiation_ms": 8.1,
    "total_connection_time_ms": 13.3
  }
}
```

### Security Event Logging

Security-related events are logged with appropriate context:

```python
# Authentication events
{
  "message": "Client authentication successful",
  "context": {
    "client_id": "cli_abc123",
    "peer_address": "192.168.1.100:12345",
    "certificate_subject": "CN=client.example.com",
    "auth_method": "mtls"
  }
}

# Security violations
{
  "message": "Rate limit exceeded", 
  "level": "WARNING",
  "context": {
    "client_id": "cli_def456",
    "peer_address": "192.168.1.100:23456", 
    "rate_limit": 100.0,
    "current_rate": 125.3,
    "action": "request_rejected"
  }
}
```

## Development and Debugging

### Development Configuration

Optimal settings for development:

```bash
# Development logging configuration
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_SHOW_EMOJI_MATRIX=true
```

### Debugging Specific Components

Enable targeted debugging:

```python
import logging
from provide.foundation import logger

# Enable debug logging for specific components
logging.getLogger("pyvider.rpcplugin.transport").setLevel(logging.DEBUG)
logging.getLogger("pyvider.rpcplugin.security").setLevel(logging.DEBUG)
logging.getLogger("pyvider.rpcplugin.handshake").setLevel(logging.INFO)  # Less verbose

# Temporarily increase log level
with logger.level("DEBUG"):
    # All logging in this block will be at DEBUG level
    await client.connect("unix:/tmp/plugin.sock")
```

### Request Tracing

Enable request tracing for debugging:

```python
from provide.foundation import logger
import uuid

class TracingMiddleware:
    async def intercept_request(self, request, context, handler):
        # Generate trace ID
        trace_id = str(uuid.uuid4())
        
        # Add to context
        with logger.context(trace_id=trace_id):
            logger.debug("Request started", extra={
                "method": context.method,
                "peer": context.peer(),
                "headers": dict(context.invocation_metadata())
            })
            
            try:
                response = await handler(request, context)
                logger.debug("Request completed successfully")
                return response
            except Exception as e:
                logger.error("Request failed", extra={"error": str(e)})
                raise
```

## Log Rotation and Management

### File-Based Logging

Configure log rotation for file output:

```python
import logging.handlers
from provide.foundation import logger

# Configure rotating file handler
file_handler = logging.handlers.RotatingFileHandler(
    "/var/log/plugin/plugin.log",
    maxBytes=100 * 1024 * 1024,  # 100MB
    backupCount=10,
    encoding="utf-8"
)

# Set JSON formatter for file output
file_handler.setFormatter(logging.Formatter(
    '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}'
))

# Add to logger
logger.addHandler(file_handler)
```

### Logrotate Configuration

System-level log rotation:

```bash
# /etc/logrotate.d/pyvider-plugin
/var/log/plugin/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 plugin plugin
    postrotate
        /usr/bin/systemctl reload plugin.service > /dev/null 2>&1 || true
    endrotate
}
```

## Monitoring and Alerting

### Key Log Patterns to Monitor

1. **Connection Failures**:
   ```
   level="ERROR" AND message CONTAINS "Connection failed"
   ```

2. **Rate Limiting Events**:
   ```
   level="WARNING" AND message CONTAINS "Rate limit"
   ```

3. **Security Events**:
   ```
   logger="pyvider.rpcplugin.security" AND level IN ["WARNING", "ERROR", "CRITICAL"]
   ```

4. **Performance Degradation**:
   ```
   duration_ms > 1000 OR handshake_duration_ms > 500
   ```

### Alert Configuration Examples

#### Elasticsearch Watcher Alert

```json
{
  "trigger": {
    "schedule": {
      "interval": "1m"
    }
  },
  "input": {
    "search": {
      "request": {
        "search_type": "query_then_fetch",
        "indices": ["pyvider-plugin-*"],
        "body": {
          "query": {
            "bool": {
              "filter": [
                {"term": {"level": "ERROR"}},
                {"range": {"timestamp": {"gte": "now-1m"}}}
              ]
            }
          }
        }
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "gt": 5
      }
    }
  },
  "actions": {
    "send_email": {
      "email": {
        "to": ["ops-team@example.com"],
        "subject": "Pyvider Plugin Error Alert",
        "body": "More than 5 errors in the last minute"
      }
    }
  }
}
```

#### Prometheus/Grafana Alerts

```yaml
groups:
  - name: pyvider-plugin
    rules:
      - alert: PluginHighErrorRate
        expr: rate(pyvider_plugin_errors_total[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High error rate in Pyvider Plugin"
          description: "Error rate is {{ $value }} errors per second"

      - alert: PluginConnectionFailures  
        expr: rate(pyvider_plugin_connection_failures_total[5m]) > 0.05
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Connection failures in Pyvider Plugin"
          description: "Connection failure rate is {{ $value }} per second"
```

## Best Practices

### Production Logging

1. **Use appropriate log levels**: INFO for production, DEBUG only for troubleshooting
2. **Disable emoji enhancement**: Set `PLUGIN_SHOW_EMOJI_MATRIX="false"`
3. **Structured output**: Use JSON format for log aggregation systems
4. **Log rotation**: Implement proper log rotation to prevent disk space issues
5. **Sensitive data**: Never log passwords, tokens, or personal information

### Development Logging

1. **Enable emoji enhancement**: Set `PLUGIN_SHOW_EMOJI_MATRIX="true"`
2. **Use DEBUG level**: Set `PLUGIN_LOG_LEVEL="DEBUG"`
3. **Console output**: Human-readable format for development
4. **Request tracing**: Enable correlation IDs for request flow tracking

### Security Considerations

1. **Log access control**: Restrict access to log files and systems
2. **Data sanitization**: Ensure no sensitive data in log messages
3. **Audit trails**: Maintain security event logs for compliance
4. **Retention policies**: Define appropriate log retention periods

## Troubleshooting

### Common Logging Issues

#### No Log Output
```bash
# Check log level configuration
export PLUGIN_LOG_LEVEL=DEBUG

# Verify logger configuration
python -c "from provide.foundation import logger; logger.info('Test message')"
```

#### Log Format Issues
```bash
# For machine processing, disable emoji
export PLUGIN_SHOW_EMOJI_MATRIX=false

# For human reading, enable emoji
export PLUGIN_SHOW_EMOJI_MATRIX=true
```

#### Missing Context Information
```python
# Ensure context is preserved in async operations
async def my_handler(request, context):
    with logger.context(request_id=generate_request_id()):
        logger.info("Processing request")
        result = await process_request(request)
        logger.info("Request completed", extra={"result_size": len(result)})
        return result
```

### Performance Impact

Logging performance characteristics:

| Log Level | Overhead per Request | Disk I/O Impact |
|-----------|---------------------|-----------------|
| DEBUG | ~50μs | High |
| INFO | ~20μs | Medium |
| WARNING | ~10μs | Low |
| ERROR | ~5μs | Minimal |

## Next Steps

- **[Production Setup](production.md)** - Complete production deployment configuration
- **[Environment Variables](environment.md)** - All configuration options reference
- **[Rate Limiting](rate-limiting.md)** - Request rate limiting configuration
- **[Configuration API](../../api/config/)** - Programmatic configuration reference