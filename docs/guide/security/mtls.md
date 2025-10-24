# mTLS Configuration

Configure mutual TLS (mTLS) authentication for secure plugin communication using Foundation's certificate management capabilities.

## Overview

mTLS (mutual TLS) ensures both client and server authenticate each other using X.509 certificates. Foundation handles certificate management, validation, and rotation.

**Benefits:**
- **Mutual Authentication** - Both sides verify each other's identity
- **Encrypted Communication** - All data encrypted in transit using TLS
- **Certificate-Based Identity** - Cryptographic identity verification
- **Foundation Integration** - Automatic certificate management and rotation

## Quick Setup

### Automatic mTLS (Recommended)

Let Foundation handle certificate generation and management:

```python
from pyvider.rpcplugin import plugin_server, plugin_client
from provide.foundation import logger

# Server with automatic mTLS
server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    auto_mtls=True  # Foundation generates certificates automatically
)

# Client connects with automatic certificate discovery
async with plugin_client(auto_mtls=True) as client:
    response = await client.my_service.secure_method(data="sensitive")
    logger.info("🔒 Secure communication established")
```

### Manual Certificate Configuration

For production environments with existing PKI:

```python
from provide.foundation.crypto import Certificate

# Load certificates via Foundation using file:// URIs or PEM strings
server_cert = Certificate.from_pem(
    cert_pem="file://server.pem",
    key_pem="file://server.key"
)
ca_cert = Certificate.from_pem(cert_pem="file://ca.pem")

# Server with manual certificates
server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    tls_certificate=server_cert,
    tls_ca_certificate=ca_cert,
    require_client_certificate=True
)

# Client with certificates
client_cert = Certificate.from_pem(
    cert_pem="file://client.pem",
    key_pem="file://client.key"
)

async with plugin_client(
    tls_client_certificate=client_cert,
    tls_ca_certificate=ca_cert,
    verify_server_certificate=True
) as client:
    result = await client.my_service.process(data="example")
```

## Certificate Management

### Environment Configuration

Configure mTLS via environment variables:

```bash
# Enable mTLS
export PLUGIN_AUTO_MTLS=true

# Manual certificate paths
export PLUGIN_SERVER_CERT=file:///etc/ssl/certs/server.pem
export PLUGIN_SERVER_KEY=file:///etc/ssl/private/server.key
export PLUGIN_SERVER_ROOT_CERTS=file:///etc/ssl/certs/ca.pem

# Client certificates
export PLUGIN_CLIENT_CERT=file:///etc/ssl/certs/client.pem
export PLUGIN_CLIENT_KEY=file:///etc/ssl/private/client.key
export PLUGIN_CLIENT_ROOT_CERTS=file:///etc/ssl/certs/ca.pem
```

### Foundation Certificate Generation

Use Foundation to generate development certificates:

```python
from provide.foundation.crypto import create_self_signed, create_ca

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

logger.info(f"✅ CA expires: {ca_cert.not_after}")
logger.info(f"✅ Server expires: {server_cert.not_after}")
```

## Production Deployment

### Certificate Authority Setup

```python
from provide.foundation.crypto import Certificate

# Production CA hierarchy
root_ca = Certificate.generate_ca(
    common_name="Production Plugin Root CA",
    organization="My Company",
    country="US",
    validity_days=3650,
    key_strength=4096
)

# Intermediate CA for plugin certificates
intermediate_ca = root_ca.generate_intermediate_ca(
    common_name="Plugin Intermediate CA",
    validity_days=1095,
    path_length_constraint=0
)
```

### Server Certificates

```python
# Production server certificate
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

# Client certificate for service authentication
client_cert = intermediate_ca.generate_client_certificate(
    common_name="plugin-client-001",
    email_address="service@company.com",
    validity_days=30,
    extended_key_usage=["client_auth"],
    key_usage=["digital_signature"]
)
```

### Docker Deployment

```dockerfile
# Dockerfile with mTLS certificates
FROM python:3.11

# Copy certificates
COPY certs/ca.pem /etc/ssl/certs/
COPY certs/server.pem /etc/ssl/certs/
COPY certs/server.key /etc/ssl/private/

# Set certificate permissions
RUN chmod 644 /etc/ssl/certs/*.pem && \
    chmod 600 /etc/ssl/private/*.key

# Configure mTLS
ENV PLUGIN_AUTO_MTLS=false
ENV PLUGIN_SERVER_CERT=file:///etc/ssl/certs/server.pem
ENV PLUGIN_SERVER_KEY=file:///etc/ssl/private/server.key
ENV PLUGIN_SERVER_ROOT_CERTS=file:///etc/ssl/certs/ca.pem

EXPOSE 8443
CMD ["python", "my_plugin_server.py"]
```

## Certificate Rotation

### Automatic Rotation

Foundation provides automatic certificate rotation:

```python
from provide.foundation.crypto import CertificateRotator

# Configure automatic rotation
rotator = CertificateRotator(
    certificate_path="server.pem",
    private_key_path="server.key",
    ca_certificate="ca.pem",
    renewal_threshold_days=30  # Rotate 30 days before expiry
)

# Check if rotation needed
if await rotator.needs_rotation():
    new_cert = await rotator.rotate_certificate()
    logger.info(f"🔄 Certificate rotated, expires: {new_cert.not_after}")

# Start rotation service
await rotator.start_rotation_service()
```

### Manual Rotation

```python
# Check certificate expiration
cert = Certificate.load_from_file("server.pem")
days_remaining = cert.days_until_expiry()

if days_remaining <= 30:
    logger.warning(f"Certificate expires in {days_remaining} days")
    
    # Generate new certificate
    new_cert = ca_cert.renew_certificate(cert, validity_days=90)
    
    # Hot-swap certificate in running server
    await server.update_certificate(new_cert)
    logger.info("✅ Certificate rotated without downtime")
```

## Validation and Debugging

### Certificate Validation

```python
from provide.foundation.crypto import Certificate

cert = Certificate.load_from_file("server.pem")

# Basic validation
if cert.is_valid():
    logger.info("✅ Certificate is valid")
else:
    logger.error("❌ Certificate validation failed")

# Detailed validation
validation_result = cert.validate_full(
    ca_certificates=["ca.pem"],
    check_revocation=True,
    require_key_usage=["digital_signature", "key_encipherment"]
)

if validation_result.is_valid:
    logger.info("✅ Full certificate validation passed")
else:
    for error in validation_result.errors:
        logger.error(f"❌ Validation error: {error}")
```

### Connection Debugging

```python
# Enable TLS debugging
import os
os.environ["PLUGIN_LOG_LEVEL"] = "DEBUG"
os.environ["GRPC_VERBOSITY"] = "DEBUG"
os.environ["GRPC_TRACE"] = "tls,secure_endpoint"

# Test mTLS connection
try:
    async with plugin_client(
        auto_mtls=True,
        verify_server_certificate=True
    ) as client:
        await client.health.check()
        logger.info("✅ mTLS connection successful")
        
except Exception as e:
    logger.error(f"❌ mTLS connection failed: {e}")
    # Check certificate paths, permissions, validity
```

## Security Best Practices

### Certificate Security

1. **Strong Key Lengths**: Use RSA 4096+ or ECDSA P-384
2. **Short Validity Periods**: 90 days maximum for server certificates
3. **Proper Key Usage**: Set appropriate key usage extensions
4. **Secure Storage**: Protect private keys with 600 permissions
5. **Regular Rotation**: Automate certificate renewal

### Network Security

```python
# Production server configuration
server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    
    # Strong TLS configuration
    tls_certificate=server_cert,
    tls_ca_certificate=ca_cert,
    require_client_certificate=True,
    
    # Additional security
    allowed_client_cns=["plugin-client-*"],  # Restrict client CNs
    cipher_suites=["ECDHE-RSA-AES256-GCM-SHA384"],  # Strong ciphers
    min_tls_version="1.3"  # Require TLS 1.3
)
```

### Monitoring

```python
from provide.foundation.crypto import CertificateHealthChecker

# Monitor certificate health
health_checker = CertificateHealthChecker([
    "server.pem",
    "client.pem",
    "ca.pem"
])

health_status = await health_checker.check_all()
for cert_path, status in health_status.items():
    if status.is_healthy:
        logger.info(f"✅ {cert_path}: {status.days_until_expiry} days remaining")
    else:
        logger.error(f"❌ {cert_path}: {status.error}")
```

## Common Patterns

### Development Environment

```python
# Development with self-signed certificates
from provide.foundation.crypto import Certificate

dev_certs = Certificate.generate_dev_certificates(
    ca_common_name="Dev Plugin CA",
    server_common_name="localhost",
    validity_days=90
)

server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    tls_certificate=dev_certs.server_cert,
    tls_ca_certificate=dev_certs.ca_cert
)
```

### Staging Environment

```python
# Staging with intermediate CA
staging_ca = Certificate.load_from_file("staging-ca.pem", "staging-ca.key")

server_cert = staging_ca.generate_server_certificate(
    common_name="staging-plugin.company.internal",
    validity_days=30
)

server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    tls_certificate=server_cert,
    tls_ca_certificate=staging_ca
)
```

### Load Balancer Integration

```python
# Behind load balancer with SSL termination
server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    
    # Internal mTLS for backend security
    auto_mtls=True,
    bind_address="0.0.0.0:8080",  # Internal port
    
    # Trust load balancer headers
    trust_forwarded_headers=True,
    allowed_forwarded_ips=["10.0.0.0/8"]
)
```

## Troubleshooting

### Common Issues

**Certificate Not Found:**
```bash
# Check certificate paths and permissions
ls -la /etc/ssl/certs/server.pem
openssl x509 -in /etc/ssl/certs/server.pem -text -noout
```

**Certificate Expired:**
```bash
# Check expiration
openssl x509 -in server.pem -noout -dates

# Verify certificate chain
openssl verify -CAfile ca.pem server.pem
```

**Connection Refused:**
```python
# Enable detailed TLS logging
import logging
logging.getLogger('grpc').setLevel(logging.DEBUG)

# Check certificate validation
cert = Certificate.load_from_file("server.pem")
logger.info(f"Certificate valid until: {cert.not_after}")
logger.info(f"Subject: {cert.subject}")
logger.info(f"Issuer: {cert.issuer}")
```

## Next Steps

- **[Certificate Management](certificates.md)** - Detailed certificate operations
- **[Process Isolation](process-isolation.md)** - Additional security layers
- **[Production Security](../../examples/production.md)** - Complete security setup

For enterprise certificate management and PKI integration, consult Foundation's security documentation and consider professional PKI services.