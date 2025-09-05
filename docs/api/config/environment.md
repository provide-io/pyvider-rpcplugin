# Environment Variables Guide

This guide provides comprehensive information on setting up and managing environment variables for the Pyvider RPC Plugin system, including best practices, common patterns, and deployment scenarios.

## Overview

The Pyvider RPC Plugin system is configured entirely through environment variables, providing:
- **12-Factor App Compliance**: Configuration separated from code
- **Container Friendly**: Easy integration with Docker, Kubernetes, etc.
- **Development Flexibility**: Easy switching between configurations
- **Security**: Sensitive values kept out of source code
- **Deployment Agnostic**: Works across all deployment environments

All configuration variables follow the `PLUGIN_*` naming convention for easy identification and management.

## Environment Variable Categories

### Authentication Variables

```bash
# Magic cookie authentication
PLUGIN_MAGIC_COOKIE_KEY="MY_PLUGIN_COOKIE"
PLUGIN_MAGIC_COOKIE_VALUE="super-secret-cookie-value-123"
```

### Transport and Networking

```bash
# Server transport configuration
PLUGIN_SERVER_TRANSPORTS='["unix", "tcp"]'
PLUGIN_SERVER_ENDPOINT="/tmp/my-plugin.sock"

# Client transport configuration
PLUGIN_CLIENT_TRANSPORTS='["tcp", "unix"]'
PLUGIN_CLIENT_ENDPOINT="127.0.0.1:8080"
```

### Security and TLS

```bash
# Automatic mTLS
PLUGIN_AUTO_MTLS=true

# Manual certificate configuration
PLUGIN_SERVER_CERT="file:///etc/ssl/certs/server.crt"
PLUGIN_SERVER_KEY="file:///etc/ssl/private/server.key"
PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/ca.crt"
```

### Performance and Reliability

```bash
# Timeout configuration
PLUGIN_HANDSHAKE_TIMEOUT=10.0
PLUGIN_CONNECTION_TIMEOUT=30.0

# Retry configuration
PLUGIN_CLIENT_RETRY_ENABLED=true
PLUGIN_CLIENT_MAX_RETRIES=3
PLUGIN_CLIENT_INITIAL_BACKOFF_MS=500

# Rate limiting
PLUGIN_RATE_LIMIT_ENABLED=true
PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000.0
```

## Data Types and Formats

### Boolean Values

Boolean configuration accepts various formats:

```bash
# True values (case insensitive)
PLUGIN_AUTO_MTLS=true
PLUGIN_AUTO_MTLS=True
PLUGIN_AUTO_MTLS=TRUE
PLUGIN_AUTO_MTLS=yes
PLUGIN_AUTO_MTLS=1

# False values (case insensitive)
PLUGIN_AUTO_MTLS=false
PLUGIN_AUTO_MTLS=False
PLUGIN_AUTO_MTLS=FALSE
PLUGIN_AUTO_MTLS=no
PLUGIN_AUTO_MTLS=0
```

### Numeric Values

Numeric values are parsed according to their expected type:

```bash
# Integer values
PLUGIN_CORE_VERSION=1
PLUGIN_CLIENT_MAX_RETRIES=5
PLUGIN_CLIENT_INITIAL_BACKOFF_MS=1000

# Float values
PLUGIN_HANDSHAKE_TIMEOUT=10.5
PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000.0
PLUGIN_RATE_LIMIT_BURST_CAPACITY=2000.5
```

### List Values (JSON Format)

List values must be provided in JSON format:

```bash
# String lists
PLUGIN_SERVER_TRANSPORTS='["unix", "tcp"]'
PLUGIN_CLIENT_TRANSPORTS='["tcp"]'

# Integer lists
PLUGIN_PROTOCOL_VERSIONS='[1, 2, 3]'
SUPPORTED_PROTOCOL_VERSIONS='[1, 2, 3, 4, 5, 6, 7]'

# Single-item lists
PLUGIN_SERVER_TRANSPORTS='["unix"]'
```

### String Values

String values are used as-is:

```bash
# Simple strings
PLUGIN_LOG_LEVEL=INFO
PLUGIN_MAGIC_COOKIE_KEY="MY_PLUGIN_COOKIE"

# File paths
PLUGIN_SERVER_CERT="file:///etc/ssl/certs/server.crt"
PLUGIN_SHUTDOWN_FILE_PATH="/tmp/shutdown-signal"

# Network addresses
PLUGIN_SERVER_ENDPOINT="127.0.0.1:8080"
PLUGIN_CLIENT_ENDPOINT="/tmp/plugin.sock"
```

## Setting Environment Variables

### Command Line (Temporary)

For testing and development:

```bash
# Set for current session
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_AUTO_MTLS=true

# Run command with specific environment
PLUGIN_LOG_LEVEL=DEBUG PLUGIN_AUTO_MTLS=true python -m my_plugin
```

### Shell Configuration Files

Add to `~/.bashrc`, `~/.zshrc`, or equivalent:

```bash
# ~/.bashrc
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_MAGIC_COOKIE_VALUE="dev-cookie-123"
export PLUGIN_SERVER_TRANSPORTS='["unix"]'
```

### Environment Files

Create dedicated environment files:

```bash
# development.env
PLUGIN_LOG_LEVEL=DEBUG
PLUGIN_AUTO_MTLS=true
PLUGIN_SERVER_TRANSPORTS=["unix"]
PLUGIN_HANDSHAKE_TIMEOUT=30.0

# production.env  
PLUGIN_LOG_LEVEL=INFO
PLUGIN_AUTO_MTLS=false
PLUGIN_SERVER_CERT=file:///etc/ssl/certs/server.crt
PLUGIN_SERVER_KEY=file:///etc/ssl/private/server.key
```

Load environment files:

```bash
# Using source
source development.env

# Using export with env file
export $(grep -v '^#' production.env | xargs)

# Using dotenv tools
pip install python-dotenv
python -c "from dotenv import load_dotenv; load_dotenv('production.env')"
```

## Deployment-Specific Patterns

### Docker Containers

#### Dockerfile Environment

```dockerfile
FROM python:3.11

# Set default environment variables
ENV PLUGIN_LOG_LEVEL=INFO
ENV PLUGIN_AUTO_MTLS=true
ENV PLUGIN_SERVER_TRANSPORTS='["tcp"]'
ENV PLUGIN_HANDSHAKE_TIMEOUT=10.0
ENV PLUGIN_CONNECTION_TIMEOUT=30.0
ENV PLUGIN_HEALTH_SERVICE_ENABLED=true

COPY . /app
WORKDIR /app
RUN pip install -e .

EXPOSE 8080
CMD ["python", "-m", "my_plugin_server"]
```

#### Docker Run with Environment

```bash
# Using -e flags
docker run -e PLUGIN_LOG_LEVEL=DEBUG \
           -e PLUGIN_AUTO_MTLS=true \
           -e PLUGIN_SERVER_TRANSPORTS='["tcp"]' \
           my-plugin-image

# Using --env-file
docker run --env-file production.env my-plugin-image

# Using environment file
cat > plugin.env << EOF
PLUGIN_LOG_LEVEL=INFO
PLUGIN_AUTO_MTLS=false
PLUGIN_SERVER_CERT=file:///etc/ssl/certs/server.crt
PLUGIN_RATE_LIMIT_ENABLED=true
EOF

docker run --env-file plugin.env my-plugin-image
```

#### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  plugin-server:
    build: .
    environment:
      - PLUGIN_LOG_LEVEL=INFO
      - PLUGIN_AUTO_MTLS=true
      - PLUGIN_SERVER_TRANSPORTS=["tcp"]
      - PLUGIN_HANDSHAKE_TIMEOUT=10.0
      - PLUGIN_RATE_LIMIT_ENABLED=true
      - PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=1000.0
    ports:
      - "8080:8080"
    volumes:
      - /etc/ssl:/etc/ssl:ro

  plugin-server-with-file:
    build: .
    env_file:
      - production.env
    ports:
      - "8081:8080"
```

### Kubernetes

#### ConfigMap for Non-Sensitive Values

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: plugin-config
data:
  PLUGIN_LOG_LEVEL: "INFO"
  PLUGIN_AUTO_MTLS: "false"
  PLUGIN_SERVER_TRANSPORTS: '["tcp"]'
  PLUGIN_HANDSHAKE_TIMEOUT: "10.0"
  PLUGIN_CONNECTION_TIMEOUT: "30.0"
  PLUGIN_RATE_LIMIT_ENABLED: "true"
  PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND: "1000.0"
  PLUGIN_HEALTH_SERVICE_ENABLED: "true"
```

#### Secret for Sensitive Values

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: plugin-secrets
type: Opaque
data:
  PLUGIN_MAGIC_COOKIE_VALUE: <base64-encoded-cookie-value>
  PLUGIN_SERVER_CERT: <base64-encoded-certificate>
  PLUGIN_SERVER_KEY: <base64-encoded-private-key>
```

#### Deployment with Environment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: plugin-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: plugin-server
  template:
    metadata:
      labels:
        app: plugin-server
    spec:
      containers:
      - name: plugin-server
        image: my-plugin-server:latest
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: plugin-config
        - secretRef:
            name: plugin-secrets
        env:
        - name: PLUGIN_SERVER_ENDPOINT
          value: "0.0.0.0:8080"
```

### Systemd Services

```ini
# /etc/systemd/system/plugin-server.service
[Unit]
Description=Plugin Server
After=network.target

[Service]
Type=simple
User=plugin
Group=plugin
WorkingDirectory=/opt/plugin-server
ExecStart=/opt/plugin-server/venv/bin/python -m plugin_server
Restart=always
RestartSec=5

# Environment configuration
Environment="PLUGIN_LOG_LEVEL=INFO"
Environment="PLUGIN_AUTO_MTLS=false"
Environment="PLUGIN_SERVER_CERT=file:///etc/ssl/certs/plugin-server.crt"
Environment="PLUGIN_SERVER_KEY=file:///etc/ssl/private/plugin-server.key"
Environment="PLUGIN_SERVER_TRANSPORTS=[\"tcp\"]"
Environment="PLUGIN_HANDSHAKE_TIMEOUT=10.0"
Environment="PLUGIN_RATE_LIMIT_ENABLED=true"
Environment="PLUGIN_HEALTH_SERVICE_ENABLED=true"

# Or use EnvironmentFile
EnvironmentFile=/etc/plugin-server/environment

[Install]
WantedBy=multi-user.target
```

### AWS/Cloud Environments

#### AWS ECS Task Definition

```json
{
  "family": "plugin-server",
  "containerDefinitions": [
    {
      "name": "plugin-server",
      "image": "my-plugin-server:latest",
      "memory": 512,
      "cpu": 256,
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "PLUGIN_LOG_LEVEL",
          "value": "INFO"
        },
        {
          "name": "PLUGIN_AUTO_MTLS",
          "value": "false"
        },
        {
          "name": "PLUGIN_SERVER_TRANSPORTS",
          "value": "[\"tcp\"]"
        },
        {
          "name": "PLUGIN_RATE_LIMIT_ENABLED",
          "value": "true"
        }
      ],
      "secrets": [
        {
          "name": "PLUGIN_MAGIC_COOKIE_VALUE",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:plugin-cookie-value"
        },
        {
          "name": "PLUGIN_SERVER_CERT",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:plugin-server-cert"
        }
      ]
    }
  ]
}
```

#### AWS Lambda Environment

```python
# serverless.yml or CloudFormation template
Environment:
  Variables:
    PLUGIN_LOG_LEVEL: INFO
    PLUGIN_AUTO_MTLS: 'true'
    PLUGIN_SERVER_TRANSPORTS: '["tcp"]'
    PLUGIN_HANDSHAKE_TIMEOUT: '5.0'  # Shorter for Lambda
    PLUGIN_CONNECTION_TIMEOUT: '15.0'
```

## Security Best Practices

### Sensitive Value Management

**Never store sensitive values in code or version control:**

```bash
# ❌ BAD - Don't do this
export PLUGIN_MAGIC_COOKIE_VALUE="hardcoded-secret"
export PLUGIN_SERVER_KEY="-----BEGIN PRIVATE KEY-----..."

# ✅ GOOD - Use file references or secret management
export PLUGIN_MAGIC_COOKIE_VALUE="$(cat /run/secrets/plugin-cookie)"
export PLUGIN_SERVER_CERT="file:///etc/ssl/certs/server.crt"
export PLUGIN_SERVER_KEY="file:///etc/ssl/private/server.key"
```

### Secret Generation

Generate strong secrets for production:

```bash
# Generate magic cookie value
PLUGIN_MAGIC_COOKIE_VALUE="$(openssl rand -base64 32)"

# Generate random passwords
PLUGIN_DB_PASSWORD="$(openssl rand -base64 24)"

# Use UUID for unique identifiers
PLUGIN_INSTANCE_ID="$(uuidgen)"
```

### File-Based Certificate References

Use file references instead of inline certificates:

```bash
# ✅ Recommended - File references
export PLUGIN_SERVER_CERT="file:///etc/ssl/certs/server.crt"
export PLUGIN_SERVER_KEY="file:///etc/ssl/private/server.key"
export PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/ca.crt"

# ❌ Avoid - Inline certificates (harder to manage, version control risk)
export PLUGIN_SERVER_CERT="-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
...
-----END CERTIFICATE-----"
```

### Environment Variable Validation

Create validation scripts for critical deployments:

```bash
#!/bin/bash
# validate-plugin-env.sh

# Check required variables
required_vars=(
    "PLUGIN_MAGIC_COOKIE_VALUE"
    "PLUGIN_SERVER_TRANSPORTS"
    "PLUGIN_HANDSHAKE_TIMEOUT"
    "PLUGIN_CONNECTION_TIMEOUT"
)

for var in "${required_vars[@]}"; do
    if [[ -z "${!var}" ]]; then
        echo "❌ Required environment variable $var is not set"
        exit 1
    fi
done

# Check sensitive values are not defaults
if [[ "$PLUGIN_MAGIC_COOKIE_VALUE" == "test_cookie_value" ]]; then
    echo "❌ Using default magic cookie value in production!"
    exit 1
fi

# Validate certificate files exist
if [[ "$PLUGIN_AUTO_MTLS" == "false" ]]; then
    cert_file="${PLUGIN_SERVER_CERT#file://}"
    key_file="${PLUGIN_SERVER_KEY#file://}"
    
    if [[ ! -f "$cert_file" ]]; then
        echo "❌ Server certificate file not found: $cert_file"
        exit 1
    fi
    
    if [[ ! -f "$key_file" ]]; then
        echo "❌ Server key file not found: $key_file"
        exit 1
    fi
fi

echo "✅ Environment validation passed"
```

## Environment-Specific Configurations

### Development Environment

```bash
#!/bin/bash
# dev-env.sh
export PLUGIN_LOG_LEVEL=DEBUG
export PLUGIN_SHOW_EMOJI_MATRIX=true
export PLUGIN_AUTO_MTLS=true
export PLUGIN_SERVER_TRANSPORTS='["unix"]'
export PLUGIN_SERVER_ENDPOINT="/tmp/dev-plugin.sock"
export PLUGIN_HANDSHAKE_TIMEOUT=30.0
export PLUGIN_CONNECTION_TIMEOUT=60.0
export PLUGIN_CLIENT_RETRY_ENABLED=true
export PLUGIN_CLIENT_MAX_RETRIES=5
export PLUGIN_RATE_LIMIT_ENABLED=false
export PLUGIN_HEALTH_SERVICE_ENABLED=true

# Development cookie (not for production)
export PLUGIN_MAGIC_COOKIE_VALUE="dev-cookie-$(date +%s)"
```

### Testing Environment

```bash
#!/bin/bash
# test-env.sh
export PLUGIN_LOG_LEVEL=WARNING  # Reduce noise in tests
export PLUGIN_SHOW_EMOJI_MATRIX=false
export PLUGIN_AUTO_MTLS=true     # Use auto-generated certs
export PLUGIN_SERVER_TRANSPORTS='["unix"]'  # Faster than TCP
export PLUGIN_HANDSHAKE_TIMEOUT=5.0   # Quick timeout for tests
export PLUGIN_CONNECTION_TIMEOUT=10.0
export PLUGIN_CLIENT_RETRY_ENABLED=false  # Predictable behavior
export PLUGIN_RATE_LIMIT_ENABLED=false    # No limits in tests
export PLUGIN_HEALTH_SERVICE_ENABLED=false # Skip health checks

# Test-specific cookie
export PLUGIN_MAGIC_COOKIE_VALUE="test-cookie-123"
```

### Staging Environment

```bash
#!/bin/bash
# staging-env.sh
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_SHOW_EMOJI_MATRIX=false
export PLUGIN_AUTO_MTLS=false
export PLUGIN_SERVER_CERT="file:///etc/ssl/certs/staging-server.crt"
export PLUGIN_SERVER_KEY="file:///etc/ssl/private/staging-server.key"
export PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/staging-ca.crt"
export PLUGIN_SERVER_TRANSPORTS='["tcp"]'
export PLUGIN_HANDSHAKE_TIMEOUT=10.0
export PLUGIN_CONNECTION_TIMEOUT=30.0
export PLUGIN_CLIENT_RETRY_ENABLED=true
export PLUGIN_CLIENT_MAX_RETRIES=3
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=500.0
export PLUGIN_HEALTH_SERVICE_ENABLED=true

# Staging cookie (from secure storage)
export PLUGIN_MAGIC_COOKIE_VALUE="$(cat /run/secrets/staging-cookie)"
```

### Production Environment

```bash
#!/bin/bash
# production-env.sh
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_SHOW_EMOJI_MATRIX=false
export PLUGIN_AUTO_MTLS=false
export PLUGIN_SERVER_CERT="file:///etc/ssl/certs/production-server.crt"
export PLUGIN_SERVER_KEY="file:///etc/ssl/private/production-server.key"
export PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/production-ca.crt"
export PLUGIN_SERVER_TRANSPORTS='["tcp"]'
export PLUGIN_SERVER_ENDPOINT="0.0.0.0:8080"
export PLUGIN_HANDSHAKE_TIMEOUT=10.0
export PLUGIN_CONNECTION_TIMEOUT=30.0
export PLUGIN_CLIENT_RETRY_ENABLED=true
export PLUGIN_CLIENT_MAX_RETRIES=3
export PLUGIN_CLIENT_INITIAL_BACKOFF_MS=500
export PLUGIN_CLIENT_MAX_BACKOFF_MS=5000
export PLUGIN_CLIENT_RETRY_TOTAL_TIMEOUT_S=60
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=2000.0
export PLUGIN_RATE_LIMIT_BURST_CAPACITY=4000.0
export PLUGIN_HEALTH_SERVICE_ENABLED=true
export PLUGIN_SHUTDOWN_FILE_PATH="/var/run/plugin-shutdown"

# Production cookie (from secret management system)
export PLUGIN_MAGIC_COOKIE_VALUE="$(aws secretsmanager get-secret-value --secret-id plugin-cookie --query SecretString --output text)"
```

## Troubleshooting Environment Issues

### Environment Variable Debugging

```bash
#!/bin/bash
# debug-env.sh

echo "=== Plugin Environment Variables ==="
env | grep ^PLUGIN_ | sort

echo ""
echo "=== Critical Variables Check ==="
critical_vars=(
    "PLUGIN_MAGIC_COOKIE_VALUE"
    "PLUGIN_AUTO_MTLS"
    "PLUGIN_SERVER_TRANSPORTS"
    "PLUGIN_LOG_LEVEL"
)

for var in "${critical_vars[@]}"; do
    if [[ -n "${!var}" ]]; then
        if [[ "$var" == *"COOKIE"* ]]; then
            echo "✅ $var: [REDACTED]"
        else
            echo "✅ $var: ${!var}"
        fi
    else
        echo "❌ $var: NOT SET"
    fi
done
```

### Configuration Validation

```python
#!/usr/bin/env python3
# validate-config.py
import os
import sys

def validate_plugin_environment():
    """Validate plugin environment configuration."""
    errors = []
    warnings = []
    
    # Check required variables
    required_vars = [
        'PLUGIN_MAGIC_COOKIE_VALUE',
        'PLUGIN_SERVER_TRANSPORTS',
    ]
    
    for var in required_vars:
        if not os.getenv(var):
            errors.append(f"Required variable {var} not set")
    
    # Check security concerns
    if os.getenv('PLUGIN_MAGIC_COOKIE_VALUE') == 'test_cookie_value':
        warnings.append("Using default magic cookie value")
    
    if os.getenv('PLUGIN_LOG_LEVEL') == 'DEBUG':
        warnings.append("Debug logging enabled")
    
    # Check file references
    auto_mtls = os.getenv('PLUGIN_AUTO_MTLS', 'true').lower()
    if auto_mtls == 'false':
        cert_path = os.getenv('PLUGIN_SERVER_CERT', '')
        if cert_path.startswith('file://'):
            cert_file = cert_path[7:]
            if not os.path.exists(cert_file):
                errors.append(f"Certificate file not found: {cert_file}")
    
    return errors, warnings

if __name__ == '__main__':
    errors, warnings = validate_plugin_environment()
    
    if warnings:
        print("⚠️  WARNINGS:")
        for warning in warnings:
            print(f"   - {warning}")
        print()
    
    if errors:
        print("❌ ERRORS:")
        for error in errors:
            print(f"   - {error}")
        sys.exit(1)
    else:
        print("✅ Environment validation passed")
```

## Related Documentation

- [Configuration Schema Reference](schema.md) - Complete variable reference
- [Configuration System Overview](index.md) - Configuration system introduction
- [Server Configuration](../server/server.md) - Server-specific configuration
- [Client Configuration](../client/client.md) - Client-specific configuration