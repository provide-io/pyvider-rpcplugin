# Certificate Management

X.509 certificate lifecycle management for secure plugin communication using Foundation's comprehensive cryptography utilities.

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
from provide.foundation.crypto import Certificate, create_self_signed, create_ca
import asyncio

async def certificate_basics():
    """Basic certificate operations."""
    
    # Create Certificate Authority
    ca_cert = create_ca(
        common_name="Plugin CA",
        organization="My Company", 
        validity_days=3650
    )
    
    # Generate server certificate
    server_cert = create_self_signed(
        common_name="plugin-server.local",
        organization="My Company",
        subject_alternative_names=["DNS:localhost", "IP:127.0.0.1"],
        validity_days=365
    )
    
    # Save certificates
    ca_cert.save_certificate("ca.pem")
    server_cert.save_certificate("server.pem")
    server_cert.save_private_key("server.key")
    
    print(f"✅ CA expires: {ca_cert.not_after}")
    print(f"✅ Server expires: {server_cert.not_after}")
```

## Core Components

### 1. **Certificate Generation**
Foundation provides utilities for creating CA certificates, server certificates, and client certificates with proper extensions and constraints.

```python
from provide.foundation.crypto import Certificate, KeyType, CurveType

# Self-signed certificate
cert = Certificate.generate_self_signed(
    common_name="my-plugin",
    key_type=KeyType.ECDSA,
    curve=CurveType.SECP384R1,
    validity_days=365
)

# CA-signed certificate  
ca_cert = Certificate.load_from_file("ca.pem", "ca.key")
signed_cert = ca_cert.sign_certificate(
    cert_request,
    validity_days=90,
    extended_key_usage=["server_auth", "client_auth"]
)
```

### 2. **Certificate Validation**
Comprehensive validation including expiration, signature verification, chain validation, and revocation checking.

```python
from provide.foundation.crypto import Certificate

cert = Certificate.load_from_file("server.pem")

# Basic validation
if cert.is_valid():
    print("✅ Certificate is valid")
else:
    print("❌ Certificate validation failed")

# Detailed validation
validation_result = cert.validate_full(
    ca_certificates=["ca.pem"],
    check_revocation=True,
    require_key_usage=["digital_signature", "key_encipherment"]
)
```

### 3. **Certificate Rotation**
Automated certificate renewal with configurable rotation policies and zero-downtime updates.

```python
from provide.foundation.crypto import CertificateRotator

rotator = CertificateRotator(
    certificate_path="server.pem",
    private_key_path="server.key",
    ca_certificate="ca.pem",
    renewal_threshold_days=30  # Renew 30 days before expiry
)

# Check if rotation needed
if await rotator.needs_rotation():
    new_cert = await rotator.rotate_certificate()
    print(f"🔄 Certificate rotated, expires: {new_cert.not_after}")
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