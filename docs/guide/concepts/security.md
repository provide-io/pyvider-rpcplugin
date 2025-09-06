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

cookie_key = rpcplugin_config.magic_cookie_key()      # "PLUGIN_MAGIC_COOKIE"
cookie_value = rpcplugin_config.magic_cookie_value()  # "secure-random-value"
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

### Generating Certificates

Use the built-in certificate utilities:

```python
from pyvider.rpcplugin.crypto import Certificate

# 1. Create Certificate Authority
ca_cert = Certificate.create_ca(
    common_name="My Plugin CA",
    organization_name="My Company",
    validity_days=365
)

# 2. Create Server Certificate
server_cert = Certificate.create_signed_certificate(
    ca_certificate=ca_cert,
    common_name="plugin-server.example.com",
    alt_names=["localhost", "127.0.0.1"],
    is_client_cert=False,
    validity_days=90
)

# 3. Create Client Certificate
client_cert = Certificate.create_signed_certificate(
    ca_certificate=ca_cert,
    common_name="plugin-client.example.com",
    is_client_cert=True,
    validity_days=90
)
```

### Using Certificates

```python
# Save certificates to files
with open("ca.crt", "w") as f:
    f.write(ca_cert.cert)

with open("server.crt", "w") as f:
    f.write(server_cert.cert)
    
with open("server.key", "w") as f:
    f.write(server_cert.key)

# Or use directly as PEM strings
configure(
    auto_mtls=True,
    server_cert=server_cert.cert,  # PEM string
    server_key=server_cert.key,    # PEM string
    client_cert=client_cert.cert,  # PEM string
    client_key=client_cert.key,    # PEM string
    server_root_certs=ca_cert.cert # PEM string
)
```

## Complete mTLS Example

Here's a working example demonstrating end-to-end mTLS setup:

```python
#!/usr/bin/env python3
import asyncio
import tempfile
from pathlib import Path
from pyvider.rpcplugin import plugin_client, configure
from pyvider.rpcplugin.crypto import Certificate
from provide.foundation import logger

async def secure_plugin_example():
    """Complete mTLS plugin example."""
    logger.info("🔒 Setting up secure plugin with mTLS...")
    
    # Create temporary directory for certificates
    with tempfile.TemporaryDirectory(prefix="secure_plugin_") as temp_dir:
        temp_path = Path(temp_dir)
        
        # 1. Generate certificates
        logger.info("🔑 Generating certificates...")
        
        # CA certificate
        ca_cert = Certificate.create_ca(
            common_name="Secure Plugin CA",
            organization_name="My Company",
            validity_days=1
        )
        
        # Server certificate (for plugin)
        server_cert = Certificate.create_signed_certificate(
            ca_certificate=ca_cert,
            common_name="secure-plugin.local",
            alt_names=["localhost", "127.0.0.1"],
            is_client_cert=False,
            validity_days=1
        )
        
        # Client certificate (for host)
        client_cert = Certificate.create_signed_certificate(
            ca_certificate=ca_cert,
            common_name="secure-host.local",
            is_client_cert=True,
            validity_days=1
        )
        
        # 2. Save server certificates to files (for plugin subprocess)
        server_cert_file = temp_path / "server.crt"
        server_key_file = temp_path / "server.key"
        ca_cert_file = temp_path / "ca.crt"
        
        server_cert_file.write_text(server_cert.cert)
        server_key_file.write_text(server_cert.key)
        ca_cert_file.write_text(ca_cert.cert)
        
        # 3. Configure host application (client) mTLS
        configure(
            auto_mtls=True,
            client_cert=client_cert.cert,      # PEM string
            client_key=client_cert.key,        # PEM string  
            server_root_certs=ca_cert.cert,    # Trust server certs from this CA
            magic_cookie_key="SECURE_PLUGIN_COOKIE",
            magic_cookie="ultra-secure-token-456"
        )
        
        # 4. Prepare plugin environment
        plugin_env = {
            "PLUGIN_AUTO_MTLS": "true",
            "PLUGIN_SERVER_CERT": f"file://{server_cert_file}",
            "PLUGIN_SERVER_KEY": f"file://{server_key_file}",
            "PLUGIN_CLIENT_ROOT_CERTS": f"file://{ca_cert_file}",
            "SECURE_PLUGIN_COOKIE": "ultra-secure-token-456",
            "PLUGIN_MAGIC_COOKIE_KEY": "SECURE_PLUGIN_COOKIE",
            "PLUGIN_MAGIC_COOKIE_VALUE": "ultra-secure-token-456"
        }
        
        # 5. Launch secure plugin
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

if __name__ == "__main__":
    asyncio.run(secure_plugin_example())
```

## Security Best Practices

### Certificate Management

**Certificate Rotation:**
```python
# Implement automatic certificate renewal
async def rotate_certificates():
    # Generate new certificates before expiration
    new_server_cert = Certificate.create_signed_certificate(
        ca_certificate=ca_cert,
        common_name="plugin-server.example.com",
        validity_days=90
    )
    
    # Update running services
    await update_server_certificates(new_server_cert)
```

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
async def security_health_check():
    """Monitor plugin security status."""
    checks = []
    
    # Check certificate expiration
    cert_expires = server_cert.not_valid_after
    days_until_expiry = (cert_expires - datetime.now()).days
    
    if days_until_expiry < 30:
        checks.append(f"⚠️ Certificate expires in {days_until_expiry} days")
    
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

# Check certificate details
cert_info = Certificate.from_file("server.crt")
logger.info(f"Certificate expires: {cert_info.not_valid_after}")
logger.info(f"Subject: {cert_info.subject}")
logger.info(f"SANs: {cert_info.subject_alt_names}")
```

## What's Next?

Now that you understand the security model:

- **[Configuration](configuration.md)** - Explore all security configuration options
- **[Production Deployment](../production/)** - Security considerations for production
- **[Monitoring](../monitoring/)** - Security monitoring and alerting
- **[Certificate Lifecycle](../advanced/certificates/)** - Advanced certificate management