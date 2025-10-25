# Security Configuration

**Reading Time:** ~7 minutes

Complete reference for security configuration in Pyvider RPC Plugin. These settings control mTLS, certificates, and authentication.

!!! warning "Security by Default"
    **mTLS is ENABLED by default** (`PLUGIN_AUTO_MTLS=true`). For local development/testing, you can disable it with `configure(auto_mtls=False)` or `PLUGIN_INSECURE=true`.

## Overview

Security configuration controls:

- **mTLS (mutual TLS)** - Automatic mutual authentication
- **Certificates** - X.509 certificate management
- **Insecure mode** - Disable security for development
- **Magic cookies** - Plugin authentication tokens

## Quick Start

### Development (Insecure)

```python
from pyvider.rpcplugin import configure

# Disable mTLS for local testing
configure(auto_mtls=False)

# Or use insecure mode (disables all security)
configure(insecure=True)
```

### Production (mTLS with Certificates)

```python
import os

# Server-side configuration
os.environ.update({
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_SERVER_CERT": "file:///etc/certs/server.crt",
    "PLUGIN_SERVER_KEY": "file:///etc/certs/server.key",
    "PLUGIN_CA_CERT": "file:///etc/certs/ca.crt"
})

# Client-side configuration
os.environ.update({
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_CLIENT_CERT": "file:///etc/certs/client.crt",
    "PLUGIN_CLIENT_KEY": "file:///etc/certs/client.key",
    "PLUGIN_CA_CERT": "file:///etc/certs/ca.crt"
})
```

## Complete Security Settings

### mTLS Configuration

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_auto_mtls` | `PLUGIN_AUTO_MTLS` | `bool` | `True` | Enable automatic mTLS setup |
| `plugin_insecure` | `PLUGIN_INSECURE` | `bool` | `False` | Disable all security features (development only) |
| `plugin_mtls_cert_dir` | `PLUGIN_MTLS_CERT_DIR` | `str` | `"/tmp/plugin-certs"` | Directory for mTLS certificates |
| `plugin_cert_validity_days` | `PLUGIN_CERT_VALIDITY_DAYS` | `int` | `365` | Certificate validity period in days |

### Server Certificates

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_server_cert` | `PLUGIN_SERVER_CERT` | `str \| None` | `None` | Server certificate (PEM or file:// URL) |
| `plugin_server_key` | `PLUGIN_SERVER_KEY` | `str \| None` | `None` | Server private key (PEM or file:// URL) |
| `plugin_server_root_certs` | `PLUGIN_SERVER_ROOT_CERTS` | `str \| None` | `None` | Server root CA certificates (PEM format) |

### Client Certificates

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_client_cert` | `PLUGIN_CLIENT_CERT` | `str \| None` | `None` | Client certificate (PEM or file:// URL) |
| `plugin_client_key` | `PLUGIN_CLIENT_KEY` | `str \| None` | `None` | Client private key (PEM or file:// URL) |
| `plugin_client_cert_file` | `PLUGIN_CLIENT_CERT_FILE` | `str` | `""` | Client certificate file path |
| `plugin_client_key_file` | `PLUGIN_CLIENT_KEY_FILE` | `str` | `""` | Client private key file path |
| `plugin_client_root_certs` | `PLUGIN_CLIENT_ROOT_CERTS` | `str` | `""` | Client root CA certificates (PEM format) |

### Certificate Authority

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_ca_cert` | `PLUGIN_CA_CERT` | `str \| None` | `None` | CA certificate for validation |

### Authentication

| Setting | Environment Variable | Type | Default | Description |
|---------|---------------------|------|---------|-------------|
| `plugin_magic_cookie_key` | `PLUGIN_MAGIC_COOKIE_KEY` | `str` | `"PLUGIN_MAGIC_COOKIE"` | Magic cookie environment variable name |
| `plugin_magic_cookie_value` | `PLUGIN_MAGIC_COOKIE_VALUE` | `str` | `"test_cookie_value"` | Magic cookie value for authentication (testing only) |

## mTLS Modes

### Auto-Generated Certificates (Default)

When `auto_mtls=True` and no certificates are provided:

```python
from pyvider.rpcplugin import configure

# mTLS enabled with auto-generated self-signed certs
configure(auto_mtls=True)
```

- Framework generates self-signed certificates automatically
- Certificates stored in `plugin_mtls_cert_dir` (`/tmp/plugin-certs`)
- Valid for `plugin_cert_validity_days` (365 days default)
- **Suitable for**: Development, testing, local plugins

### Provided Certificates (Production)

Provide your own certificates:

```python
import os

# Using file:// URLs (recommended)
os.environ.update({
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_SERVER_CERT": "file:///etc/certs/server.crt",
    "PLUGIN_SERVER_KEY": "file:///etc/certs/server.key",
    "PLUGIN_CA_CERT": "file:///etc/certs/ca.crt"
})

# Or inline PEM (for secrets management)
os.environ["PLUGIN_SERVER_CERT"] = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKN...
-----END CERTIFICATE-----"""
```

**Suitable for**: Production, enterprise deployments

### Insecure Mode (Development Only)

Disable all security:

```python
from pyvider.rpcplugin import configure

# WARNING: No encryption, no authentication
configure(insecure=True)
```

**Never use in production!**

## Certificate Formats

### File URLs

```python
# Recommended: file:// URLs
os.environ.update({
    "PLUGIN_SERVER_CERT": "file:///etc/certs/server.crt",
    "PLUGIN_SERVER_KEY": "file:///etc/certs/server.key"
})
```

### Inline PEM

```python
# Inline PEM strings
cert_pem = """-----BEGIN CERTIFICATE-----
MIID...
-----END CERTIFICATE-----"""

key_pem = """-----BEGIN PRIVATE KEY-----
MIIE...
-----END PRIVATE KEY-----"""

os.environ.update({
    "PLUGIN_SERVER_CERT": cert_pem,
    "PLUGIN_SERVER_KEY": key_pem
})
```

### File Paths (Legacy)

```python
# Direct file paths (alternative)
os.environ.update({
    "PLUGIN_CLIENT_CERT_FILE": "/etc/certs/client.crt",
    "PLUGIN_CLIENT_KEY_FILE": "/etc/certs/client.key"
})
```

## Certificate Generation

### Using Foundation

```python
from provide.foundation.crypto import Certificate

# Generate self-signed certificate
cert = Certificate.create_self_signed_server_cert(
    common_name="myservice.example.com",
    organization_name="My Organization",
    validity_days=365
)

# Save to files
cert.save_to_files(
    cert_path="/etc/certs/server.crt",
    key_path="/etc/certs/server.key"
)
```

### Using OpenSSL

```bash
# Generate CA
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt

# Generate server cert
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt

# Generate client cert
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr
openssl x509 -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt
```

## Magic Cookie Authentication

Magic cookies prevent accidental plugin execution:

```python
import os

# Server sets magic cookie
os.environ["PLUGIN_MAGIC_COOKIE"] = "my_secret_token_123"

# Client must provide matching cookie
# (automatically handled when launching subprocess)
```

### Custom Magic Cookie

```python
from pyvider.rpcplugin import configure

# Use custom cookie key/value
configure(
    magic_cookie_key="MY_APP_TOKEN",
    magic_cookie_value="custom_secret_xyz"
)
```

## Security Profiles

### Development Profile

```bash
# Insecure for fast iteration
export PLUGIN_INSECURE=true
export PLUGIN_LOG_LEVEL=DEBUG
```

### Testing Profile

```bash
# Auto-generated certs
export PLUGIN_AUTO_MTLS=true
export PLUGIN_MTLS_CERT_DIR=/tmp/test-certs
export PLUGIN_LOG_LEVEL=WARNING
```

### Production Profile

```bash
# Provided certificates
export PLUGIN_AUTO_MTLS=true
export PLUGIN_SERVER_CERT=file:///etc/certs/server.crt
export PLUGIN_SERVER_KEY=file:///etc/certs/server.key
export PLUGIN_CLIENT_CERT=file:///etc/certs/client.crt
export PLUGIN_CLIENT_KEY=file:///etc/certs/client.key
export PLUGIN_CA_CERT=file:///etc/certs/ca.crt
export PLUGIN_CERT_VALIDITY_DAYS=365
```

## Best Practices

### 1. Always Use mTLS in Production

```python
# Production: mTLS required
configure(
    auto_mtls=True,
    insecure=False  # Explicit
)
```

### 2. Rotate Certificates Regularly

```bash
# Monitor certificate expiration
openssl x509 -in server.crt -noout -enddate

# Automate rotation before expiry
export PLUGIN_CERT_VALIDITY_DAYS=90  # 90-day rotation
```

### 3. Secure Certificate Storage

```python
# Use secrets management
from some_secrets_manager import get_secret

os.environ.update({
    "PLUGIN_SERVER_CERT": get_secret("plugin/server/cert"),
    "PLUGIN_SERVER_KEY": get_secret("plugin/server/key")
})
```

### 4. Separate Dev/Prod Configurations

```python
import os

if os.getenv("ENVIRONMENT") == "production":
    configure(auto_mtls=True)  # mTLS required
else:
    configure(insecure=True)   # Dev convenience
```

### 5. Use Strong Magic Cookies

```python
import secrets

# Generate cryptographically secure cookie
magic_cookie = secrets.token_hex(32)

configure(magic_cookie_value=magic_cookie)
```

## Troubleshooting

### Certificate Verification Failed

**Problem:** mTLS handshake fails with verification error

**Solutions:**
```python
# Check certificate chain
# Ensure CA cert matches server/client certs

# Disable for debugging (never in production!)
configure(insecure=True)

# Verify certificates manually
openssl verify -CAfile ca.crt server.crt
```

### Permission Denied for Certificate Files

**Problem:** Can't read certificate files

**Solutions:**
```bash
# Check file permissions
chmod 600 /etc/certs/server.key
chmod 644 /etc/certs/server.crt

# Check file ownership
chown myuser:mygroup /etc/certs/*
```

### Auto-Generated Certs Not Working

**Problem:** Auto mTLS fails

**Solutions:**
```python
# Check cert directory is writable
import os
os.makedirs("/tmp/plugin-certs", exist_ok=True)

# Use custom directory
configure(mtls_cert_dir="/home/user/.plugin-certs")
```

### Magic Cookie Mismatch

**Problem:** Plugin rejected due to cookie mismatch

**Solutions:**
```python
# Ensure same cookie on client and server
cookie_value = "shared_secret_123"
configure(magic_cookie_value=cookie_value)

# Check environment variable propagation
import os
print(os.environ.get("PLUGIN_MAGIC_COOKIE"))
```

## Related Topics

- **[Configuration Reference](configuration-reference.md)** - All configuration options
- **[Client Configuration](configuration-client.md)** - Client-side settings
- **[Server Configuration](configuration-server.md)** - Server-side settings
- **[Security Guide](../security/index.md)** - Complete security implementation
- **[mTLS Setup](../security/mtls.md)** - Step-by-step mTLS guide
- **[Certificate Management](../security/certificates.md)** - Advanced certificate topics
