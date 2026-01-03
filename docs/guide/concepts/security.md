# Security Model

Security is paramount in plugin architectures. Pyvider RPC Plugin provides multiple layers of security to protect against unauthorized access, ensure data integrity, and maintain process isolation.

## Security Layers

### 🛡️ Process Isolation

The foundation of plugin security is **process-based isolation**:

- **Memory Isolation** - Plugin crashes don't affect the host application
- **Resource Limits** - OS-level resource management and controls
- **Privilege Separation** - Plugins can run with reduced permissions
- **Crash Resilience** - Plugin failures are contained and recoverable

```python
# Plugins run in separate processes
client = plugin_client(command=["python", "my_plugin.py"])
await client.start()  # Spawns isolated subprocess
```

### 🍪 Magic Cookie Authentication

A simple but effective first line of defense:

- **Shared Secret** - Environment variable contains authentication token
- **Launch Verification** - Ensures only trusted executables can connect
- **No Network Exposure** - Secret passed via environment, not network
- **Automatic Generation** - Framework handles cookie management

```python
# Magic cookie is automatically configured
from pyvider.rpcplugin.config import rpcplugin_config

cookie_key = rpcplugin_config.plugin_magic_cookie_key      # "PLUGIN_MAGIC_COOKIE"
cookie_value = rpcplugin_config.plugin_magic_cookie_value  # "secure-random-value"
```

### 🔐 Mutual TLS (mTLS)

For production deployments, **Mutual TLS** provides strong authentication and encryption:

- **Certificate-Based Authentication** - Both client and server verify identity
- **Encrypted Communication** - All RPC traffic is encrypted
- **Certificate Management** - Built-in utilities for certificate lifecycle
- **Trust Establishment** - CA-based trust relationships

## Enabling mTLS

### Quick Setup

Enable mTLS with minimal configuration:

```python
from pyvider.rpcplugin import configure

# Enable auto-mTLS with self-signed certificates
configure(auto_mtls=True)
```

### Production Setup

For production environments, use proper certificates:

```python
configure(
    auto_mtls=True,
    server_cert="file:///path/to/server.crt",
    server_key="file:///path/to/server.key",
    client_cert="file:///path/to/client.crt",
    client_key="file:///path/to/client.key",
    server_root_certs="file:///path/to/ca.crt",
    client_root_certs="file:///path/to/ca.crt"
)
```

### Environment Variables

```bash
# Enable mTLS
export PLUGIN_AUTO_MTLS=true

# Server certificates (for plugin process)
export PLUGIN_SERVER_CERT="file:///etc/ssl/server.crt"
export PLUGIN_SERVER_KEY="file:///etc/ssl/server.key"
export PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/ca.crt"

# Client certificates (for host application)
export PLUGIN_CLIENT_CERT="file:///etc/ssl/client.crt"
export PLUGIN_CLIENT_KEY="file:///etc/ssl/client.key"
export PLUGIN_SERVER_ROOT_CERTS="file:///etc/ssl/ca.crt"
```

## Certificate Management

### Certificate Requirements

For mTLS authentication, you need the following certificate components:

- **Certificate Authority (CA)** - Root certificate that signs both server and client certificates
- **Server Certificate** - Used by the plugin process to authenticate itself
- **Client Certificate** - Used by the host application to authenticate to the plugin
- **Private Keys** - Corresponding private keys for server and client certificates

### Certificate Generation

Certificates can be generated using standard tools like OpenSSL:

```bash
# 1. Create Certificate Authority
openssl req -new -x509 -days 365 -keyout ca.key -out ca.crt \
    -subj "/CN=My Plugin CA/O=My Company"

# 2. Generate Server Certificate
openssl req -new -keyout server.key -out server.csr \
    -subj "/CN=plugin-server.example.com"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt -days 90

# 3. Generate Client Certificate
openssl req -new -keyout client.key -out client.csr \
    -subj "/CN=plugin-client.example.com"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt -days 90
```

### Using External Certificates

Once certificates are generated, they can be used with the plugin system:

```python
# Load certificates from files
configure(
    auto_mtls=True,
    server_cert="file:///path/to/server.crt",
    server_key="file:///path/to/server.key",
    client_cert="file:///path/to/client.crt",
    client_key="file:///path/to/client.key",
    server_root_certs="file:///path/to/ca.crt",
    client_root_certs="file:///path/to/ca.crt"
)
```

## Complete mTLS Example

Here's an example demonstrating mTLS setup with pre-generated certificates:

```python
#!/usr/bin/env python3
import asyncio
import os
from pathlib import Path
from pyvider.rpcplugin import plugin_client, configure
from provide.foundation import logger

async def secure_plugin_example():
    """Complete mTLS plugin example using external certificates."""
    logger.info("🔒 Setting up secure plugin with mTLS...")

    # Assume certificates were generated externally (e.g., using OpenSSL)
    cert_dir = Path("/etc/ssl/plugin-certs")

    # Certificate file paths
    ca_cert_file = cert_dir / "ca.crt"
    server_cert_file = cert_dir / "server.crt"
    server_key_file = cert_dir / "server.key"
    client_cert_file = cert_dir / "client.crt"
    client_key_file = cert_dir / "client.key"

    # Verify certificates exist
    required_files = [ca_cert_file, server_cert_file, server_key_file,
                     client_cert_file, client_key_file]

    for cert_file in required_files:
        if not cert_file.exists():
            logger.error(f"❌ Certificate file missing: {cert_file}")
            return

    try:
        # 1. Configure host application (client) mTLS
        configure(
            auto_mtls=True,
            client_cert=f"file://{client_cert_file}",
            client_key=f"file://{client_key_file}",
            server_root_certs=f"file://{ca_cert_file}",
            magic_cookie_key="SECURE_PLUGIN_COOKIE",
            magic_cookie="ultra-secure-token-456"
        )

        # 2. Prepare plugin environment
        plugin_env = {
            "PLUGIN_AUTO_MTLS": "true",
            "PLUGIN_SERVER_CERT": f"file://{server_cert_file}",
            "PLUGIN_SERVER_KEY": f"file://{server_key_file}",
            "PLUGIN_CLIENT_ROOT_CERTS": f"file://{ca_cert_file}",
            "SECURE_PLUGIN_COOKIE": "ultra-secure-token-456",
            "PLUGIN_MAGIC_COOKIE_KEY": "SECURE_PLUGIN_COOKIE",
            "PLUGIN_MAGIC_COOKIE_VALUE": "ultra-secure-token-456"
        }

        # 3. Launch secure plugin
        client = None
        try:
            logger.info("🚀 Launching secure plugin...")

            client = plugin_client(
                command=["python", "my_plugin.py"],
                config={"env": plugin_env}
            )

            await client.start()  # mTLS handshake happens here
            logger.info("✅ Secure connection established!")

            # Plugin is now ready for encrypted RPC calls
            await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"❌ Security setup failed: {e}")
        finally:
            if client:
                await client.close()
                logger.info("🔒 Secure plugin shutdown complete")

    except Exception as e:
        logger.error(f"❌ mTLS configuration failed: {e}")

if __name__ == "__main__":
    asyncio.run(secure_plugin_example())
```

## Security Best Practices

### Certificate Management

**Certificate Storage:**
```python
# Secure certificate storage
import os
from pathlib import Path

# Use secure temporary directories
cert_dir = Path("/etc/ssl/private/plugin-certs")
cert_dir.mkdir(mode=0o700, exist_ok=True)

# Set restrictive permissions
cert_file.chmod(0o600)  # Owner read/write only
```

**Certificate Rotation:**
Implement certificate renewal workflow before expiration (typically 30-90 days). This involves:
1. Generating new certificates using external tools (OpenSSL, cert-manager, etc.)
2. Updating certificate files on disk
3. Restarting plugin services to pick up new certificates

### Runtime Security

**Principle of Least Privilege:**
```python
import subprocess

# Run plugin with reduced privileges
plugin_process = subprocess.Popen(
    ["python", "my_plugin.py"],
    user="plugin-user",        # Non-privileged user
    group="plugin-group",      # Specific group
    cwd="/var/lib/plugins",    # Restricted directory
    env=minimal_env            # Minimal environment
)
```

**Resource Limits:**
```python
import resource

# Set resource limits for plugin processes
def limit_plugin_resources():
    # Limit memory usage (100MB)
    resource.setrlimit(resource.RLIMIT_AS, (100 * 1024 * 1024, -1))

    # Limit CPU time (30 seconds)
    resource.setrlimit(resource.RLIMIT_CPU, (30, -1))

    # Limit file descriptors
    resource.setrlimit(resource.RLIMIT_NOFILE, (100, -1))
```

### Network Security

**Transport Security:**
```python
# Always use encrypted transports in production
configure(
    transports=["unix"],  # Unix sockets for local security
    auto_mtls=True,       # Encryption for all communication
    tcp_host="127.0.0.1"  # Localhost only for TCP
)
```

**Firewall Configuration:**
```bash
# Block plugin ports from external access
sudo ufw deny 8000:9000/tcp
sudo ufw allow from 127.0.0.1 to any port 8000:9000
```

## Security Monitoring

### Logging Security Events

```python
from provide.foundation import logger

# Log security events
logger.info("🔐 mTLS handshake successful",
           client_cert=client_common_name,
           server_cert=server_common_name)

logger.warning("⚠️ Authentication attempt with invalid certificate",
              client_ip=client_address,
              cert_fingerprint=cert_hash)

logger.error("🚨 Security violation detected",
            violation_type="unauthorized_access",
            plugin_command=command)
```

### Health Checks

```python
async def security_health_check(client):
    """Monitor plugin security status."""
    checks = []

    # Check connection security
    if client.grpc_channel._channel.get_state() != grpc.ChannelConnectivity.READY:
        checks.append("❌ Plugin connection not secure")

    # Check transport security
    transport_secure = getattr(client, '_transport_secure', False)
    if not transport_secure:
        checks.append("⚠️ Transport not using mTLS")

    return checks
```

## Common Security Issues

### Certificate Problems

**Invalid Certificate:**
```bash
# Check certificate validity
openssl x509 -in server.crt -text -noout

# Verify certificate chain
openssl verify -CAfile ca.crt server.crt
```

**Permission Issues:**
```bash
# Fix certificate permissions
chmod 600 *.key  # Private keys
chmod 644 *.crt  # Certificates
chown plugin-user:plugin-group cert-dir/
```

### mTLS Handshake Failures

**Common causes:**
- Certificate expiration
- Mismatched CA certificates
- Incorrect Subject Alternative Names
- Clock synchronization issues

**Debugging:**
```python
# Enable debug logging
configure(log_level="DEBUG")

# Check certificate details using external tools
# For example, using OpenSSL command line:
# openssl x509 -in server.crt -text -noout
#
# Or using Python cryptography library:
# from cryptography import x509
# from cryptography.hazmat.backends import default_backend
#
# with open("server.crt", "rb") as f:
#     cert = x509.load_pem_x509_certificate(f.read(), default_backend())
#     logger.info(f"Certificate expires: {cert.not_valid_after}")
#     logger.info(f"Subject: {cert.subject}")

logger.info("Certificate debugging would use external tools or libraries")
```

## Implementation Resources

### Complete Security Implementation
- **[Security Implementation Guide](../security/index/)** - Step-by-step security setup with practical examples, certificate management, and production patterns
- **[mTLS Configuration Guide](../security/mtls/)** - Detailed mutual TLS setup and certificate management
- **[Certificate Management Guide](../security/certificates/)** - Complete certificate lifecycle management

### Configuration Integration
- **[Configuration Guide](../config/index/)** - Environment-driven security configuration with validation patterns
- **[Production Configuration](../config/production/)** - Production-focused security configuration examples

### Configuration Documentation
- **[Configuration Reference](../config/configuration-reference/)** - Complete security configuration options

## Related Concepts

- **[Transport Security](transports/)** - How transports integrate with the security model
- **[Handshake Process](architecture-and-handshake/)** - Connection establishment with authentication
- **[Server Security Patterns](../security/index/)** - Server-specific security implementation patterns
