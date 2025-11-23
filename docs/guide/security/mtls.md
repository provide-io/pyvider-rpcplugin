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

# Load certificates via Foundation
# Note: from_pem() expects PEM content strings, not file paths
from pathlib import Path

server_cert_content = Path("server.pem").read_text()
server_key_content = Path("server.key").read_text()
server_cert = Certificate.from_pem(
    cert_pem=server_cert_content,
    key_pem=server_key_content
)

ca_cert_content = Path("ca.pem").read_text()
ca_cert = Certificate.from_pem(cert_pem=ca_cert_content)

# Server with manual certificates
server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    tls_certificate=server_cert,
    tls_ca_certificate=ca_cert,
    require_client_certificate=True
)

# Client with certificates
client_cert_content = Path("client.pem").read_text()
client_key_content = Path("client.key").read_text()
client_cert = Certificate.from_pem(
    cert_pem=client_cert_content,
    key_pem=client_key_content
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
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger

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

logger.info(f"✅ CA certificate generated: {ca_cert.common_name}")
logger.info(f"✅ Server certificate generated: {server_cert.common_name}")
logger.info(f"✅ Certificates are valid: CA={ca_cert.is_valid}, Server={server_cert.is_valid}")
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

## Certificate Rotation

### Automatic Rotation

Implement automatic certificate rotation with Foundation:

```python
import asyncio
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger

async def check_and_rotate_certificates(
    cert_path: str,
    key_path: str,
    ca_cert: Certificate,
    check_interval: int = 3600
):
    """Periodically check and rotate certificates."""
    while True:
        await asyncio.sleep(check_interval)

        # Load current certificate
        cert = Certificate.from_pem(
            cert_pem=f"file://{cert_path}",
            key_pem=f"file://{key_path}"
        )

        # Check if rotation needed (based on validity)
        if not cert.is_valid:
            logger.warning("Certificate is invalid, rotating now")

            # Generate new certificate
            new_cert = Certificate.create_self_signed_server_cert(
                common_name=cert.common_name,
                organization_name=cert.organization_name,
                validity_days=90
            )

            # Save new certificate
            Path(cert_path).write_text(new_cert.cert_pem)
            Path(key_path).write_text(new_cert.key_pem)

            logger.info(f"✅ Certificate rotated for {new_cert.common_name}")

# Start rotation service
asyncio.create_task(check_and_rotate_certificates(
    "server.pem",
    "server.key",
    ca_cert
))
```

### Manual Rotation

```python
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger

# Load current certificate
cert = Certificate.from_pem(
    cert_pem="file://server.pem",
    key_pem="file://server.key"
)

# Check validity and rotate if needed
if not cert.is_valid:
    logger.warning("Certificate is invalid, rotating")

    # Generate new certificate
    new_cert = Certificate.create_self_signed_server_cert(
        common_name=cert.common_name,
        organization_name=cert.organization_name,
        validity_days=90
    )

    # Save new certificate
    Path("server.pem").write_text(new_cert.cert_pem)
    Path("server.key").write_text(new_cert.key_pem)

    # Note: Hot-swapping requires server restart or custom reload mechanism
    logger.info("✅ Certificate rotated - restart server to apply")
```

## Validation and Debugging

### Certificate Validation

```python
from provide.foundation.crypto import Certificate
from provide.foundation import logger
from pathlib import Path

# Load certificate - read PEM content from files
cert_pem_content = Path("server.pem").read_text()
key_pem_content = Path("server.key").read_text()
cert = Certificate.from_pem(
    cert_pem=cert_pem_content,
    key_pem=key_pem_content
)

# Basic validation
if cert.is_valid:
    logger.info("✅ Certificate is valid")
    logger.info(f"   Common Name: {cert.common_name}")
    logger.info(f"   Organization: {cert.organization_name}")
else:
    logger.error("❌ Certificate validation failed")

# Check certificate against CA (using verify_trust method)
ca_cert_content = Path("ca.pem").read_text()
ca_cert = Certificate.from_pem(cert_pem=ca_cert_content)

try:
    # verify_trust checks if cert is signed by CA
    if cert.verify_trust(ca_cert):
        logger.info("✅ Certificate trust chain validated")
    else:
        logger.error("❌ Certificate trust verification failed")
except Exception as e:
    logger.error(f"❌ Trust verification error: {e}")
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
1. **Short Validity Periods**: 90 days maximum for server certificates
1. **Proper Key Usage**: Set appropriate key usage extensions
1. **Secure Storage**: Protect private keys with 600 permissions
1. **Regular Rotation**: Automate certificate renewal

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
from provide.foundation.crypto import Certificate
from provide.foundation import logger
from pathlib import Path

# Monitor certificate health
cert_paths = ["server.pem", "client.pem", "ca.pem"]

for cert_path in cert_paths:
    try:
        # Read PEM content from file
        cert_content = Path(cert_path).read_text()
        cert = Certificate.from_pem(cert_pem=cert_content)

        if cert.is_valid:
            logger.info(f"✅ {cert_path}: Valid")
            logger.info(f"   CN: {cert.common_name}")
        else:
            logger.error(f"❌ {cert_path}: Invalid certificate")
    except Exception as e:
        logger.error(f"❌ {cert_path}: Error loading - {e}")
```

## Common Patterns

### Development Environment

```python
# Development with self-signed certificates
from provide.foundation.crypto import Certificate
from pyvider.rpcplugin import plugin_server

# Create CA and server certificate for development
ca_cert = Certificate.create_ca(
    common_name="Dev Plugin CA",
    organization_name="Development",
    validity_days=90
)

server_cert = Certificate.create_self_signed_server_cert(
    common_name="localhost",
    organization_name="Development",
    alt_names=["DNS:localhost", "IP:127.0.0.1"],
    validity_days=90
)

server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    tls_certificate=server_cert,
    tls_ca_certificate=ca_cert
)
```

### Staging Environment

```python
# Staging with intermediate CA
from provide.foundation.crypto import Certificate
from pyvider.rpcplugin import plugin_server

# Load staging CA
staging_ca = Certificate.from_pem(
    cert_pem="file://staging-ca.pem",
    key_pem="file://staging-ca.key"
)

# Create server certificate for staging
server_cert = Certificate.create_self_signed_server_cert(
    common_name="staging-plugin.company.internal",
    organization_name=staging_ca.organization_name,
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
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger

logging.getLogger('grpc').setLevel(logging.DEBUG)

# Check certificate validation - read PEM content from file
cert_content = Path("server.pem").read_text()
cert = Certificate.from_pem(cert_pem=cert_content)
logger.info(f"Certificate valid: {cert.is_valid}")
logger.info(f"Common Name: {cert.common_name}")
logger.info(f"Organization: {cert.organization_name}")
logger.info(f"Certificate type: {cert.key_type}")
```

## Next Steps

- **[Certificate API Reference](certificate-reference/)** - Quick reference for Certificate.from_pem() usage
- **[Certificate Management](certificates/)** - Detailed certificate operations
- **[Process Isolation](process-isolation/)** - Additional security layers
- **[Production Configuration](../config/production/)** - Production deployment and security setup

For enterprise certificate management and PKI integration, consult Foundation's security documentation and consider professional PKI services.
