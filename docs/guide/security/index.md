# Security

Security is a fundamental aspect of the Pyvider RPC Plugin system. This section covers all security features, best practices, and implementation patterns to ensure your plugin communications are secure, authenticated, and protected against common threats.

## Overview

The Pyvider RPC Plugin security model provides multiple layers of protection:

- **mTLS Encryption** - Mutual TLS for encrypted communication
- **Certificate Management** - Automatic certificate generation and validation
- **Magic Cookie Authentication** - Shared secret validation between client and server
- **Process Isolation** - Subprocess isolation and resource limits
- **Transport Security** - Secure transport layer configuration

```python
import os
from pyvider.rpcplugin import plugin_server

# Enable comprehensive security
os.environ.update({
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_SERVER_CERT": "file:///etc/ssl/server.pem",
    "PLUGIN_SERVER_KEY": "file:///etc/ssl/server.key",
    "PLUGIN_CLIENT_ROOT_CERTS": "file:///etc/ssl/ca-bundle.pem",
    "PLUGIN_MAGIC_COOKIE_VALUE": "$(openssl rand -hex 32)"
})

server = plugin_server(protocol=my_protocol, handler=my_handler)
```

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────────┐
│ Host Application Security Boundary                              │
│                                                                 │
│  ┌─────────────────┐   Magic Cookie   ┌─────────────────────┐   │
│  │ Host Application│←─────────────────→│ Plugin Process      │   │
│  │                 │   Authentication  │                     │   │
│  └─────────────────┘                   └─────────┬───────────┘   │
│           │                                       │               │
│           │ Process                               │               │
│           │ Isolation                            │               │
│           │                                       │               │
│  ┌────────▼─────────┐                   ┌────────▼─────────────┐ │
│  │ Client Process   │◄──── mTLS ────────► Server Process       │ │
│  │                  │   Encryption      │                      │ │
│  │ ┌──────────────┐ │                   │ ┌──────────────────┐ │ │
│  │ │ Certificate  │ │                   │ │ Certificate      │ │ │
│  │ │ Validation   │ │                   │ │ Management       │ │ │
│  │ └──────────────┘ │                   │ └──────────────────┘ │ │
│  └──────────────────┘                   └──────────────────────┘ │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Security Components

1. **Transport Layer Security (TLS)**

   - Encrypts all communication between client and server
   - Mutual authentication via certificates
   - Protection against eavesdropping and tampering

1. **Magic Cookie Authentication**

   - Shared secret validation during handshake
   - Prevents unauthorized plugin connections
   - Environment variable-based secret management

1. **Process Isolation**

   - Plugin runs in separate subprocess
   - Resource limits and sandboxing
   - Controlled communication channel

1. **Certificate Management**

   - Automatic certificate generation for development
   - Production certificate integration
   - Certificate rotation and validation

## Security Sections

### 🔐 [mTLS Configuration](mtls.md)
Configure mutual TLS for encrypted communication:

- Certificate setup and management
- Automatic vs manual mTLS configuration
- TLS cipher suite configuration
- Certificate validation and rotation

### 🏆 [Certificate Management](certificates.md)
Manage X.509 certificates for production security:

- Certificate generation and signing
- Root CA configuration and trust chains
- Certificate storage and file permissions
- Automated certificate renewal

### 🍪 [Magic Cookies](magic-cookies.md)
Implement shared secret authentication:

- Magic cookie generation and management
- Environment variable configuration
- Security considerations and best practices
- Integration with secret management systems

### 🏰 [Process Isolation](process-isolation.md)
Secure plugin process execution:

- Subprocess sandboxing and limits
- Resource constraints and monitoring
- Security contexts and permissions
- Container integration patterns

## Quick Security Setup

### Development Security

```python
#!/usr/bin/env python3
import os
import tempfile
from pyvider.rpcplugin import plugin_server
from provide.foundation.crypto import Certificate

async def development_secure_server():
    """Secure server setup for development."""

    # Generate temporary certificates for development
    server_cert = Certificate(
        common_name="localhost",
        generate_keypair=True,
        key_type="ecdsa"
    )

    client_cert = Certificate(
        common_name="client",
        generate_keypair=True,
        key_type="ecdsa"
    )

    # Configure mTLS with generated certificates
    os.environ.update({
        "PLUGIN_AUTO_MTLS": "true",
        "PLUGIN_SERVER_CERT": server_cert.cert,
        "PLUGIN_SERVER_KEY": server_cert.key,
        "PLUGIN_CLIENT_CERT": client_cert.cert,
        "PLUGIN_CLIENT_KEY": client_cert.key,
        "PLUGIN_MAGIC_COOKIE_VALUE": "dev-secure-cookie-123"
    })

    server = plugin_server(protocol=my_protocol, handler=my_handler)
    logger.info("🔒 Development server configured with mTLS")

    await server.serve()

if __name__ == "__main__":
    import asyncio
    asyncio.run(development_secure_server())
```

### Production Security

```python
#!/usr/bin/env python3
import os
import secrets
from pyvider.rpcplugin import plugin_server

def configure_production_security():
    """Configure production-grade security."""

    # Use proper certificate files
    os.environ.update({
        "PLUGIN_AUTO_MTLS": "true",
        "PLUGIN_SERVER_CERT": "file:///etc/ssl/certs/plugin-server.pem",
        "PLUGIN_SERVER_KEY": "file:///etc/ssl/private/plugin-server.key",
        "PLUGIN_CLIENT_ROOT_CERTS": "file:///etc/ssl/certs/ca-bundle.pem",
        "PLUGIN_SERVER_ROOT_CERTS": "file:///etc/ssl/certs/ca-bundle.pem"
    })

    # Generate cryptographically secure magic cookie
    magic_cookie = secrets.token_hex(32)  # 256-bit security
    os.environ["PLUGIN_MAGIC_COOKIE_VALUE"] = magic_cookie

    # Additional security settings
    os.environ.update({
        "PLUGIN_RATE_LIMIT_ENABLED": "true",
        "PLUGIN_HEALTH_SERVICE_ENABLED": "true",
        "PLUGIN_LOG_LEVEL": "INFO"  # Avoid debug logs in production
    })

async def main():
    configure_production_security()

    server = plugin_server(protocol=my_protocol, handler=my_handler)
    logger.info("🏭 Production server configured with enterprise security")

    await server.serve()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

## Security Best Practices

### Certificate Security

```python
import os
import stat
from pathlib import Path

def secure_certificate_setup():
    """Ensure proper certificate file permissions."""

    # Certificate file paths
    cert_file = Path("/etc/ssl/certs/plugin-server.pem")
    key_file = Path("/etc/ssl/private/plugin-server.key")
    ca_file = Path("/etc/ssl/certs/ca-bundle.pem")

    # Set proper permissions
    if cert_file.exists():
        cert_file.chmod(0o644)  # Read for owner, group, others
        logger.info(f"✅ Certificate permissions set: {cert_file}")

    if key_file.exists():
        key_file.chmod(0o600)  # Read/write for owner only
        os.chown(key_file, os.getuid(), os.getgid())
        logger.info(f"🔒 Private key secured: {key_file}")

    if ca_file.exists():
        ca_file.chmod(0o644)  # Read for owner, group, others
        logger.info(f"🏆 CA bundle configured: {ca_file}")

    return {
        "server_cert": f"file://{cert_file}",
        "server_key": f"file://{key_file}",
        "ca_bundle": f"file://{ca_file}"
    }

# Apply secure certificate setup
cert_config = secure_certificate_setup()
os.environ.update({
    "PLUGIN_SERVER_CERT": cert_config["server_cert"],
    "PLUGIN_SERVER_KEY": cert_config["server_key"],
    "PLUGIN_CLIENT_ROOT_CERTS": cert_config["ca_bundle"]
})
```

### Magic Cookie Security

```python
import os
import secrets
import hashlib

def generate_secure_magic_cookie():
    """Generate cryptographically secure magic cookie."""

    # Generate 256-bit random value
    random_bytes = secrets.token_bytes(32)

    # Create hex representation
    magic_cookie = random_bytes.hex()

    # Optional: Add additional entropy
    additional_entropy = f"{os.getpid()}-{secrets.randbits(64)}"
    combined = f"{magic_cookie}-{additional_entropy}"

    # Hash for consistent length and additional security
    final_cookie = hashlib.sha256(combined.encode()).hexdigest()

    logger.info(f"🍪 Generated secure magic cookie (length: {len(final_cookie)})")
    return final_cookie

def configure_magic_cookie_security():
    """Configure magic cookie with security best practices."""

    # Check if cookie is already set (e.g., from secrets manager)
    cookie_key = "PLUGIN_MAGIC_COOKIE_VALUE"
    existing_cookie = os.environ.get(cookie_key)

    if existing_cookie:
        logger.info("🍪 Using existing magic cookie from environment")
        # Validate cookie strength
        if len(existing_cookie) < 32:
            logger.warning("⚠️ Magic cookie may be too short for production")
    else:
        # Generate new secure cookie
        magic_cookie = generate_secure_magic_cookie()
        os.environ[cookie_key] = magic_cookie
        logger.info("🍪 Generated new secure magic cookie")

    # Ensure cookie key is set
    cookie_key_var = "PLUGIN_MAGIC_COOKIE_KEY"
    if not os.environ.get(cookie_key_var):
        os.environ[cookie_key_var] = "PLUGIN_MAGIC_COOKIE"

# Apply magic cookie security
configure_magic_cookie_security()
```

### Process Security

```python
import resource
import os
import pwd
import grp

def configure_process_security():
    """Configure process-level security measures."""

    # Set resource limits
    try:
        # Limit memory usage (1GB)
        resource.setrlimit(
            resource.RLIMIT_AS,
            (1024 * 1024 * 1024, 1024 * 1024 * 1024)
        )

        # Limit file descriptors (prevent descriptor exhaustion)
        resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))

        # Limit CPU time (prevent runaway processes)
        resource.setrlimit(resource.RLIMIT_CPU, (300, 300))  # 5 minutes

        logger.info("🛡️ Process resource limits configured")

    except Exception as e:
        logger.warning(f"⚠️ Could not set resource limits: {e}")

    # Drop privileges if running as root (Linux/Unix)
    if os.name == 'posix' and os.getuid() == 0:
        try:
            # Create or use existing unprivileged user
            nobody_user = pwd.getpwnam('nobody')
            nobody_group = grp.getgrnam('nobody')

            # Switch to unprivileged user
            os.setgid(nobody_group.gr_gid)
            os.setuid(nobody_user.pw_uid)

            logger.info("👤 Dropped root privileges to 'nobody' user")

        except Exception as e:
            logger.error(f"❌ Could not drop privileges: {e}")
            raise

# Apply process security (call early in application startup)
configure_process_security()
```

## Security Monitoring

### Security Event Logging

```python
from provide.foundation import logger

def log_security_event(event_type, details, severity="INFO"):
    """Log security-related events for monitoring."""

    security_context = {
        "event_type": event_type,
        "timestamp": time.time(),
        "process_id": os.getpid(),
        "user_id": os.getuid() if hasattr(os, 'getuid') else None,
        **details
    }

    if severity == "CRITICAL":
        logger.critical(f"🚨 SECURITY: {event_type}", extra=security_context)
    elif severity == "WARNING":
        logger.warning(f"⚠️ SECURITY: {event_type}", extra=security_context)
    else:
        logger.info(f"🔒 SECURITY: {event_type}", extra=security_context)

# Usage examples
log_security_event("certificate_loaded", {
    "cert_path": "/etc/ssl/certs/server.pem",
    "cert_subject": "CN=example.com",
    "cert_expires": "2024-12-31"
})

log_security_event("authentication_success", {
    "client_ip": "192.168.1.100",
    "magic_cookie_verified": True
})

log_security_event("security_violation", {
    "violation_type": "invalid_certificate",
    "client_ip": "192.168.1.200",
    "details": "Certificate validation failed"
}, severity="WARNING")
```

### Security Health Checks

```python
import ssl
from pathlib import Path
from datetime import datetime, timedelta

async def security_health_check():
    """Perform comprehensive security health check."""

    health_status = {
        "mtls_enabled": False,
        "certificates_valid": False,
        "magic_cookie_configured": False,
        "process_secured": False,
        "issues": []
    }

    # Check mTLS configuration
    mtls_enabled = os.getenv("PLUGIN_AUTO_MTLS", "").lower() == "true"
    health_status["mtls_enabled"] = mtls_enabled

    if not mtls_enabled:
        health_status["issues"].append("mTLS is not enabled")

    # Check certificate validity
    cert_path = os.getenv("PLUGIN_SERVER_CERT")
    if cert_path and cert_path.startswith("file://"):
        cert_file = Path(cert_path[7:])
        if cert_file.exists():
            try:
                # Load and validate certificate
                with open(cert_file, 'rb') as f:
                    cert_data = f.read()

                # Parse certificate (simplified check)
                if b"-----BEGIN CERTIFICATE-----" in cert_data:
                    health_status["certificates_valid"] = True
                else:
                    health_status["issues"].append("Invalid certificate format")

            except Exception as e:
                health_status["issues"].append(f"Certificate validation error: {e}")
        else:
            health_status["issues"].append("Certificate file not found")

    # Check magic cookie
    cookie_value = os.getenv("PLUGIN_MAGIC_COOKIE_VALUE")
    if cookie_value and len(cookie_value) >= 32:
        health_status["magic_cookie_configured"] = True
    else:
        health_status["issues"].append("Magic cookie not configured or too weak")

    # Check process security
    try:
        current_limits = resource.getrlimit(resource.RLIMIT_AS)
        if current_limits[0] > 0:  # Memory limit set
            health_status["process_secured"] = True
        else:
            health_status["issues"].append("No memory limits configured")
    except:
        health_status["issues"].append("Could not check process limits")

    # Log security health status
    if health_status["issues"]:
        log_security_event("security_health_check", {
            "status": "WARNING",
            "issues": health_status["issues"]
        }, severity="WARNING")
    else:
        log_security_event("security_health_check", {
            "status": "HEALTHY",
            "all_checks_passed": True
        })

    return health_status

# Run security health check
health = await security_health_check()
```

## Configuration Integration

### Security Configuration Resources
- **[Security Configuration Guide](../config/index.md)** - Environment-driven security configuration with comprehensive examples
- **[Production Configuration](../config/production/)** - Production-grade security configuration patterns
- **[Configuration Reference](../config/configuration-reference.md)** - Complete security configuration options

### Conceptual Foundation
- **[Security Model Concepts](../concepts/security.md)** - Understand the security architecture and how different layers work together
- **[Transport Security](../concepts/transports.md)** - How transport selection impacts security

## Examples and Learning Path

### Hands-On Examples
- **[Echo Service Examples](../../examples/echo-basic/)** - Security implementation in working service examples
- **[Basic Server Example](../../examples/short/basic-server/)** - Simple server setup with security considerations

### Working Examples

- **`security_mtls_example.py`** - Complete mTLS implementation (see `examples/` directory)
- **Production configuration examples** in each security section
- **Certificate generation and management** demonstrated in mTLS examples

## Next Steps

1. **[Configure mTLS](mtls.md)** - Set up mutual TLS encryption
2. **[Manage Certificates](certificates.md)** - Handle X.509 certificates
3. **[Implement Magic Cookies](magic-cookies.md)** - Add authentication layer
4. **[Secure Processes](process-isolation.md)** - Isolate and secure plugin execution
5. **Monitor Security** - Implement security event logging and health checks