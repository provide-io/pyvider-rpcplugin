# Certificate Management

X.509 certificate lifecycle management for secure plugin communication using Foundation's comprehensive cryptography utilities.

!!! warning "Documentation Under Review - Use These Sections"
    This page is being updated to reflect the correct Foundation Certificate API. **Safe sections to use:**

    ✅ **[Quick Start](#quick-start)** - Correct API for certificate generation and management
    ✅ **[Core Components](#core-components)** - Correct patterns for generation and validation
    ✅ **[Foundation Integration Guide](../advanced/foundation-integration.md)** - Comprehensive, production-ready examples

    ⚠️ **Sections with outdated API examples** (being updated):
    - Certificate Validation (line ~95+) - Uses non-existent `.validate_full()`
    - Certificate Rotation (line ~109+) - Uses non-existent `CertificateRotator` class
    - Loading Certificates (lines ~193, 210, 280) - Uses non-existent `.load_from_file()`
    - Monitoring (line ~258+) - Uses non-existent `CertificateHealthChecker`
    - Troubleshooting (line ~353+) - Uses non-existent `.subject`, `.not_after`

    **Correct API Reference:**
    ```python
    # ✅ CORRECT - Load certificates
    from provide.foundation.crypto import Certificate
    cert = Certificate.from_pem(cert_pem="file://path.pem", key_pem="file://key.pem")

    # ✅ CORRECT - Validate
    if cert.is_valid:  # Property, not method
        print("Valid")

    # ✅ CORRECT - Save to file
    from pathlib import Path
    Path("cert.pem").write_text(cert.cert_pem)
    Path("key.pem").write_text(cert.key_pem)
    ```

## Overview

Certificate management provides PKI-based authentication and encryption for plugin communication. Foundation handles certificate generation, validation, rotation, and monitoring with production-ready utilities.

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

# Load certificate from file (using file:// URI)
cert = Certificate.from_pem(
    cert_pem="file://server.pem",
    key_pem="file://server.key"
)

# Basic validation - checks certificate validity
if cert.is_valid:
    print("✅ Certificate is valid")
    print(f"   Common Name: {cert.common_name}")
    print(f"   Organization: {cert.organization_name}")
else:
    print("❌ Certificate validation failed")

# Verify trust chain with CA certificate
ca_cert = Certificate.from_pem(cert_pem="file://ca.pem")
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

    # Load current certificate
    cert = Certificate.from_pem(
        cert_pem=f"file://{cert_path}",
        key_pem=f"file://{key_path}"
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
# Simple self-signed for development
dev_cert = Certificate.generate_self_signed(
    common_name="dev-plugin.local",
    validity_days=90,
    subject_alternative_names=["DNS:localhost", "IP:127.0.0.1"]
)
```

### Production CA Setup
```python
# Root CA with strong security
root_ca = Certificate.generate_ca(
    common_name="Production Plugin Root CA",
    organization="My Company", 
    country="US",
    key_type=KeyType.ECDSA,
    curve=CurveType.SECP384R1,
    validity_days=3650,  # 10 years
    path_length_constraint=2  # Allow intermediate CAs
)

# Intermediate CA 
intermediate_ca = root_ca.generate_intermediate_ca(
    common_name="Plugin Intermediate CA",
    validity_days=1095,  # 3 years
    path_length_constraint=0  # No further CAs
)
```

### Server Certificates
```python
# Server certificate with proper extensions
server_cert = intermediate_ca.generate_server_certificate(
    common_name="plugin-api.company.com",
    subject_alternative_names=[
        "DNS:plugin-api.company.com",
        "DNS:plugin-api.internal",
        "IP:10.0.1.100"
    ],
    validity_days=90,
    extended_key_usage=["server_auth"],
    key_usage=["digital_signature", "key_encipherment"]
)
```

### Client Certificates  
```python
# Client certificate for mutual authentication
client_cert = intermediate_ca.generate_client_certificate(
    common_name="plugin-client-001",
    email_address="client@company.com",
    validity_days=30,
    extended_key_usage=["client_auth"],
    key_usage=["digital_signature"]
)
```

## Integration with RPC

### Server Configuration
```python
from pyvider.rpcplugin import plugin_server
from provide.foundation.crypto import Certificate

# Load server certificate
cert = Certificate.load_from_file("server.pem", "server.key")
ca_cert = Certificate.load_from_file("ca.pem")

server = plugin_server(
    services=[MyService()],
    tls_certificate=cert,
    tls_ca_certificate=ca_cert,
    require_client_certificate=True,  # mTLS
    certificate_validation=True
)
```

### Client Configuration
```python
from pyvider.rpcplugin import plugin_client

# Load client certificate  
client_cert = Certificate.load_from_file("client.pem", "client.key")
ca_cert = Certificate.load_from_file("ca.pem")

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
from provide.foundation import config
from provide.foundation.crypto import Certificate

# Load from configuration
app_config = config.get_config()
cert = Certificate.load_from_config(
    app_config.tls_certificate_path,
    app_config.tls_private_key_path
)

# Automatic rotation setup
if app_config.enable_cert_rotation:
    rotator = CertificateRotator.from_config(app_config)
    await rotator.start_rotation_service()
```

## Monitoring and Health

### Certificate Health Checks
```python
from provide.foundation.crypto import CertificateHealthChecker

health_checker = CertificateHealthChecker([
    "server.pem",
    "client.pem", 
    "ca.pem"
])

# Check certificate health
health_status = await health_checker.check_all()
for cert_path, status in health_status.items():
    if status.is_healthy:
        print(f"✅ {cert_path}: {status.days_until_expiry} days remaining")
    else:
        print(f"❌ {cert_path}: {status.error}")
```

### Expiration Monitoring
```python
# Monitor expiration and alert
async def monitor_certificate_expiry():
    while True:
        cert = Certificate.load_from_file("server.pem")
        days_remaining = cert.days_until_expiry()
        
        if days_remaining <= 30:
            logger.warning(f"Certificate expires in {days_remaining} days")
            # Trigger alert/rotation
            
        await asyncio.sleep(3600)  # Check hourly
```

## Security Best Practices

1. **Use Strong Algorithms**: ECDSA P-384 or RSA 4096+ for production
2. **Short Validity Periods**: 90 days maximum for server certificates  
3. **Proper Key Usage**: Set appropriate key usage extensions
4. **Certificate Pinning**: Pin CA certificates in production
5. **Regular Rotation**: Automate certificate renewal processes
6. **Secure Storage**: Protect private keys with proper file permissions
7. **Revocation Support**: Implement CRL or OCSP checking
8. **Monitor Expiration**: Alert on upcoming certificate expiry

## Common Patterns

### Development Setup
```python
# Simple setup for development
dev_certs = Certificate.generate_dev_certificates(
    ca_common_name="Dev Plugin CA",
    server_common_name="localhost",
    validity_days=90
)
```

### Production Deployment
```python
# Production certificate management
prod_manager = CertificateManager(
    ca_certificate_path="/etc/ssl/ca/root-ca.pem",
    certificate_store="/etc/ssl/plugin/",
    rotation_policy=RotationPolicy(
        renewal_threshold_days=30,
        backup_old_certificates=True,
        notify_on_rotation=True
    )
)
```

### Disaster Recovery
```python
# Certificate backup and recovery
backup_manager = CertificateBackupManager(
    backup_location="s3://cert-backups/",
    encryption_key="backup-encryption-key",
    retention_days=365
)

# Backup certificates
await backup_manager.backup_certificates([
    "ca.pem", "server.pem", "client.pem"
])

# Restore from backup
await backup_manager.restore_certificate("server.pem", "2024-01-01")
```

## Troubleshooting

### Common Issues

#### Certificate Validation Errors
```python
# Debug certificate issues
try:
    cert.validate_full()
except CertificateValidationError as e:
    logger.error(f"Validation failed: {e.reason}")
    logger.error(f"Certificate details: {cert.subject}")
    logger.error(f"Expires: {cert.not_after}")
```

#### Expiration Problems
```bash
# Check certificate expiration
openssl x509 -in server.pem -noout -dates

# Verify certificate chain
openssl verify -CAfile ca.pem server.pem
```

## Next Steps

- **[mTLS Configuration](mtls.md)** - Complete mutual TLS setup guide
- **[Process Isolation](process-isolation.md)** - Secure plugin sandboxing  
- **[Magic Cookies](magic-cookies.md)** - Lightweight authentication alternative
- **[Security Overview](index.md)** - Complete security architecture