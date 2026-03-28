# Certificate Management

X.509 certificate lifecycle management for secure plugin communication using Foundation's comprehensive cryptography utilities.

## Overview

Certificate management provides PKI-based authentication and encryption for plugin communication. Foundation handles certificate generation, validation, rotation, and monitoring with production-focused utilities.

### Key Benefits

- **Strong Authentication**: Cryptographic identity verification
- **Data Encryption**: TLS/mTLS encrypted communication channels
- **Non-Repudiation**: Cryptographic proof of message origin
- **Certificate Authority**: Full CA capabilities for certificate signing
- **Automatic Rotation**: Scheduled certificate renewal and replacement

### Quick Start

```python
from pathlib import Path
from provide.foundation.crypto import Certificate
import asyncio

async def certificate_basics():
    """Basic certificate operations."""

    # Create Certificate Authority
    ca_cert = Certificate.create_ca(
        common_name="Plugin CA",
        organization_name="My Company",
        validity_days=3650
    )

    # Generate server certificate
    server_cert = Certificate.create_self_signed_server_cert(
        common_name="plugin-server.local",
        organization_name="My Company",
        alt_names=["DNS:localhost", "IP:127.0.0.1"],
        validity_days=365
    )

    # Save certificates (write PEM strings to files)
    Path("ca.pem").write_text(ca_cert.cert_pem)
    Path("server.pem").write_text(server_cert.cert_pem)
    Path("server.key").write_text(server_cert.key_pem)

    print(f"✅ CA valid: {ca_cert.is_valid}, CN: {ca_cert.common_name}")
    print(f"✅ Server valid: {server_cert.is_valid}, CN: {server_cert.common_name}")
```

## Core Components

### 1. **Certificate Generation**

Foundation provides utilities for creating CA certificates, server certificates, and client certificates with proper extensions and constraints.

```python
from provide.foundation.crypto import Certificate

# Self-signed server certificate
cert = Certificate.create_self_signed_server_cert(
    common_name="my-plugin",
    organization_name="My Organization",
    key_type="ecdsa",
    ecdsa_curve="secp384r1",
    validity_days=365
)

# Certificate Authority
ca_cert = Certificate.create_ca(
    common_name="My Plugin CA",
    organization_name="My Organization",
    validity_days=3650
)

# Note: Foundation Certificate class includes both cert and private key
# Access via: cert.cert_pem and cert.key_pem
```

### 2. **Certificate Validation**

Comprehensive validation including expiration and signature verification.

```python
from provide.foundation.crypto import Certificate
from pathlib import Path

# Load certificate from file - read PEM content first
cert_pem_content = Path("server.pem").read_text()
key_pem_content = Path("server.key").read_text()
cert = Certificate.from_pem(
    cert_pem=cert_pem_content,
    key_pem=key_pem_content
)

# Basic validation - checks certificate validity
if cert.is_valid:
    print("✅ Certificate is valid")
    print(f"   Common Name: {cert.common_name}")
    print(f"   Organization: {cert.organization_name}")
else:
    print("❌ Certificate validation failed")

# Verify trust chain with CA certificate
ca_cert_content = Path("ca.pem").read_text()
ca_cert = Certificate.from_pem(cert_pem=ca_cert_content)
try:
    if cert.verify_trust(ca_cert):
        print("✅ Certificate trust chain validated")
    else:
        print("❌ Trust verification failed")
except Exception as e:
    print(f"❌ Error verifying trust: {e}")
```

### 3. **Certificate Rotation**

Automated certificate renewal with configurable rotation policies and zero-downtime updates.

```python
import asyncio
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger

async def rotate_certificate_if_needed(
    cert_path: str,
    key_path: str,
    ca_cert: Certificate,
    validity_days: int = 90
) -> Certificate:
    """Check and rotate certificate if needed."""
    from pathlib import Path

    # Load current certificate - read PEM content from files
    cert_pem_content = Path(cert_path).read_text()
    key_pem_content = Path(key_path).read_text()
    cert = Certificate.from_pem(
        cert_pem=cert_pem_content,
        key_pem=key_pem_content
    )

    # Check if rotation needed
    if not cert.is_valid:
        logger.warning("Certificate invalid, rotating now")

        # Generate new certificate
        new_cert = Certificate.create_self_signed_server_cert(
            common_name=cert.common_name,
            organization_name=cert.organization_name,
            validity_days=validity_days
        )

        # Save new certificate
        Path(cert_path).write_text(new_cert.cert_pem)
        Path(key_path).write_text(new_cert.key_pem)

        logger.info(f"🔄 Certificate rotated for {new_cert.common_name}")
        return new_cert

    logger.info("Certificate still valid, no rotation needed")
    return cert

# Usage
new_cert = await rotate_certificate_if_needed(
    "server.pem",
    "server.key",
    ca_cert,
    validity_days=90
)
```

## Certificate Types

### Development Certificates

```python
from provide.foundation.crypto import Certificate

# Simple self-signed for development
dev_cert = Certificate.create_self_signed_server_cert(
    common_name="dev-plugin.local",
    organization_name="Development",
    alt_names=["DNS:localhost", "IP:127.0.0.1"],
    validity_days=90
)
```

### Production CA Setup

```python
from provide.foundation.crypto import Certificate

# Root CA with strong security
root_ca = Certificate.create_ca(
    common_name="Production Plugin Root CA",
    organization_name="My Company",
    key_type="ecdsa",
    ecdsa_curve="secp384r1",
    validity_days=3650  # 10 years
)

# Note: Foundation's Certificate class doesn't support intermediate CAs directly.
# For production multi-tier CA hierarchies, consider using external PKI tools
# or manage CA signing manually with the Certificate.from_pem() API.
```

### Server Certificates

```python
from provide.foundation.crypto import Certificate

# Server certificate for production
server_cert = Certificate.create_self_signed_server_cert(
    common_name="plugin-api.company.com",
    organization_name="My Company",
    alt_names=[
        "DNS:plugin-api.company.com",
        "DNS:plugin-api.internal",
        "IP:10.0.1.100"
    ],
    validity_days=90,
    key_type="ecdsa",
    ecdsa_curve="secp384r1"
)
```

### Client Certificates

```python
from provide.foundation.crypto import Certificate

# Client certificate for mutual authentication
client_cert = Certificate.create_self_signed_client_cert(
    common_name="plugin-client-001",
    organization_name="My Company",
    validity_days=30,
    key_type="ecdsa",
    ecdsa_curve="secp384r1"
)
```

## Integration with RPC

### Server Configuration

```python
from pathlib import Path
from pyvider.rpcplugin import plugin_server
from provide.foundation.crypto import Certificate

# Load server certificate - read PEM content from files
cert_pem_content = Path("server.pem").read_text()
key_pem_content = Path("server.key").read_text()
cert = Certificate.from_pem(
    cert_pem=cert_pem_content,
    key_pem=key_pem_content
)

ca_cert_content = Path("ca.pem").read_text()
ca_cert = Certificate.from_pem(cert_pem=ca_cert_content)

server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    tls_certificate=cert,
    tls_ca_certificate=ca_cert,
    require_client_certificate=True  # Enable mTLS
)
```

### Client Configuration

```python
from pathlib import Path
from pyvider.rpcplugin import plugin_client
from provide.foundation.crypto import Certificate

# Load client certificate - read PEM content from files
client_cert_content = Path("client.pem").read_text()
client_key_content = Path("client.key").read_text()
client_cert = Certificate.from_pem(
    cert_pem=client_cert_content,
    key_pem=client_key_content
)

ca_cert_content = Path("ca.pem").read_text()
ca_cert = Certificate.from_pem(cert_pem=ca_cert_content)

async with plugin_client(
    command=["python", "secure-plugin.py"],
    tls_client_certificate=client_cert,
    tls_ca_certificate=ca_cert,
    verify_server_certificate=True
) as client:
    result = await client.service.secure_method()
```

## Configuration Management

### Environment Variables

```bash
# Certificate paths
export PLUGIN_TLS_CERT_PATH="/etc/ssl/plugin/server.pem"
export PLUGIN_TLS_KEY_PATH="/etc/ssl/plugin/server.key"  
export PLUGIN_TLS_CA_PATH="/etc/ssl/plugin/ca.pem"

# Certificate settings
export PLUGIN_TLS_VERIFY_CLIENT="true"
export PLUGIN_CERT_ROTATION_DAYS="30"
```

### Foundation Configuration

```python
from pathlib import Path
from provide.foundation.config import RuntimeConfig
from provide.foundation.crypto import Certificate
from pyvider.rpcplugin.config import rpcplugin_config

# Load certificate from environment-configured paths
cert_path = rpcplugin_config.plugin_server_cert  # Gets path from PLUGIN_SERVER_CERT
key_path = rpcplugin_config.plugin_server_key    # Gets path from PLUGIN_SERVER_KEY

# Load certificate - read PEM content from files
if cert_path and key_path:
    cert_pem_content = Path(cert_path).read_text()
    key_pem_content = Path(key_path).read_text()
    cert = Certificate.from_pem(
        cert_pem=cert_pem_content,
        key_pem=key_pem_content
    )
else:
    # Auto-generate if not configured
    cert = Certificate.create_self_signed_server_cert(
        common_name="plugin.local",
        organization_name="Auto-Generated",
        validity_days=90
    )
```

## Monitoring and Health

### Certificate Health Checks

```python
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger

async def check_certificate_health(cert_paths: list[str]) -> dict[str, bool]:
    """Check health of multiple certificates."""
    results = {}

    for cert_path in cert_paths:
        try:
            # Read PEM content from file
            cert_content = Path(cert_path).read_text()
            cert = Certificate.from_pem(cert_pem=cert_content)

            if cert.is_valid:
                logger.info(f"✅ {cert_path}: Valid (CN: {cert.common_name})")
                results[cert_path] = True
            else:
                logger.error(f"❌ {cert_path}: Invalid certificate")
                results[cert_path] = False

        except Exception as e:
            logger.error(f"❌ {cert_path}: Error loading - {e}")
            results[cert_path] = False

    return results

# Usage
health_status = await check_certificate_health([
    "server.pem",
    "client.pem",
    "ca.pem"
])
```

### Expiration Monitoring

```python
import asyncio
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger

# Monitor expiration and alert
async def monitor_certificate_expiry():
    while True:
        try:
            # Read PEM content from file
            cert_content = Path("server.pem").read_text()
            cert = Certificate.from_pem(cert_pem=cert_content)

            # Check if certificate is still valid
            if not cert.is_valid:
                logger.error("Certificate is invalid - immediate rotation needed!")
                # Trigger alert/rotation
            else:
                logger.info(f"Certificate is valid (CN: {cert.common_name})")

        except Exception as e:
            logger.error(f"Error checking certificate: {e}")

        await asyncio.sleep(3600)  # Check hourly
```

## Security Best Practices

1. **Use Strong Algorithms**: ECDSA P-384 or RSA 4096+ for production
1. **Short Validity Periods**: 90 days maximum for server certificates
1. **Proper Key Usage**: Set appropriate key usage extensions
1. **Certificate Pinning**: Pin CA certificates in production
1. **Regular Rotation**: Automate certificate renewal processes
1. **Secure Storage**: Protect private keys with proper file permissions
1. **Revocation Support**: Implement CRL or OCSP checking
1. **Monitor Expiration**: Alert on upcoming certificate expiry

## Common Patterns

### Development Setup

```python
from provide.foundation.crypto import Certificate

# Simple setup for development - create CA and server cert
ca_cert = Certificate.create_ca(
    common_name="Dev Plugin CA",
    organization_name="Development",
    validity_days=365
)

dev_server_cert = Certificate.create_self_signed_server_cert(
    common_name="localhost",
    organization_name="Development",
    alt_names=["DNS:localhost", "IP:127.0.0.1"],
    validity_days=90
)
```

### Production Deployment

```python
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger

# Production certificate management with validation
def load_production_certificates(cert_dir: str) -> tuple[Certificate, Certificate]:
    """Load and validate production certificates."""

    cert_path = Path(cert_dir) / "server.pem"
    key_path = Path(cert_dir) / "server.key"
    ca_path = Path(cert_dir) / "ca.pem"

    # Load certificates - read PEM content from files
    cert_pem_content = cert_path.read_text()
    key_pem_content = key_path.read_text()
    server_cert = Certificate.from_pem(
        cert_pem=cert_pem_content,
        key_pem=key_pem_content
    )

    ca_cert_content = ca_path.read_text()
    ca_cert = Certificate.from_pem(cert_pem=ca_cert_content)

    # Validate
    if not server_cert.is_valid:
        logger.error("Server certificate is invalid!")
        raise ValueError("Invalid server certificate")

    if not ca_cert.is_valid:
        logger.error("CA certificate is invalid!")
        raise ValueError("Invalid CA certificate")

    logger.info("Production certificates loaded and validated")
    return server_cert, ca_cert

# Usage
server_cert, ca_cert = load_production_certificates("/etc/ssl/plugin")
```

### Disaster Recovery

```python
from pathlib import Path
from provide.foundation.crypto import Certificate
import shutil
from datetime import datetime

# Certificate backup and recovery
def backup_certificates(cert_dir: str, backup_dir: str):
    """Backup certificates with timestamp."""

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = Path(backup_dir) / f"cert_backup_{timestamp}"
    backup_path.mkdir(parents=True, exist_ok=True)

    # Backup certificate files
    for cert_file in ["ca.pem", "server.pem", "server.key", "client.pem", "client.key"]:
        src = Path(cert_dir) / cert_file
        if src.exists():
            shutil.copy2(src, backup_path / cert_file)

    logger.info(f"Certificates backed up to {backup_path}")
    return backup_path

def restore_certificates(backup_path: str, cert_dir: str):
    """Restore certificates from backup."""

    backup_p = Path(backup_path)
    cert_p = Path(cert_dir)

    if not backup_p.exists():
        raise FileNotFoundError(f"Backup not found: {backup_path}")

    # Restore all certificate files
    for cert_file in backup_p.glob("*.pem"):
        shutil.copy2(cert_file, cert_p / cert_file.name)

    logger.info(f"Certificates restored from {backup_path}")

# Usage
backup_path = backup_certificates("/etc/ssl/plugin", "/backups/certs")
# restore_certificates(str(backup_path), "/etc/ssl/plugin")
```

## Troubleshooting

### Common Issues

#### Certificate Validation Errors

```python
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger

# Debug certificate issues
try:
    # Read PEM content from files
    cert_pem_content = Path("server.pem").read_text()
    key_pem_content = Path("server.key").read_text()
    cert = Certificate.from_pem(
        cert_pem=cert_pem_content,
        key_pem=key_pem_content
    )

    if not cert.is_valid:
        logger.error("Certificate validation failed")
        logger.error(f"Common Name: {cert.common_name}")
        logger.error(f"Organization: {cert.organization_name}")
        logger.error(f"Key Type: {cert.key_type}")
    else:
        logger.info("Certificate is valid")

except Exception as e:
    logger.error(f"Error loading certificate: {e}")
```

#### Expiration Problems

```bash
# Check certificate expiration
openssl x509 -in server.pem -noout -dates

# Verify certificate chain
openssl verify -CAfile ca.pem server.pem
```

## Next Steps

- **[Certificate API Reference](certificate-reference.md)** - Quick reference for Certificate.from_pem() usage patterns
- **[mTLS Configuration](mtls.md)** - Complete mutual TLS setup guide
- **[Process Isolation](process-isolation.md)** - Secure plugin sandboxing
- **[Magic Cookies](magic-cookies.md)** - Lightweight authentication alternative
- **[Security Overview](index.md)** - Complete security architecture
