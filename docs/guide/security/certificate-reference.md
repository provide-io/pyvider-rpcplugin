# Certificate API Reference

A quick reference guide for working with Foundation's `Certificate` class in Pyvider RPC Plugin.

## Quick Reference

### ✅ Correct Usage

```python
from pathlib import Path
from provide.foundation.crypto import Certificate

# Load from PEM files - CORRECT
cert_pem_content = Path("server.pem").read_text()
key_pem_content = Path("server.key").read_text()
cert = Certificate.from_pem(
    cert_pem=cert_pem_content,
    key_pem=key_pem_content
)

# Load CA certificate - CORRECT
ca_cert_content = Path("ca.pem").read_text()
ca_cert = Certificate.from_pem(cert_pem=ca_cert_content)
```

### ❌ Common Mistakes

```python
from provide.foundation.crypto import Certificate

# ❌ WRONG - from_pem() does NOT accept file:// URIs
cert = Certificate.from_pem(
    cert_pem="file://server.pem",
    key_pem="file://server.key"
)

# ❌ WRONG - from_pem() does NOT accept file paths
cert = Certificate.from_pem(
    cert_pem="server.pem",
    key_pem="server.key"
)

# ❌ WRONG - f-string with file:// prefix
cert = Certificate.from_pem(cert_pem=f"file://{cert_path}")
```

## Common Patterns

### Pattern 1: Load Server Certificate

```python
from pathlib import Path
from provide.foundation.crypto import Certificate

# Read PEM content from files
cert_path = Path("/etc/ssl/server.pem")
key_path = Path("/etc/ssl/server.key")

cert_pem_content = cert_path.read_text()
key_pem_content = key_path.read_text()

# Create Certificate object
server_cert = Certificate.from_pem(
    cert_pem=cert_pem_content,
    key_pem=key_pem_content
)

# Validate
if server_cert.is_valid:
    print(f"✅ Valid certificate for {server_cert.common_name}")
else:
    print("❌ Invalid certificate")
```

### Pattern 2: Load CA Certificate

```python
from pathlib import Path
from provide.foundation.crypto import Certificate

# Read CA certificate PEM content
ca_path = Path("/etc/ssl/ca.pem")
ca_cert_content = ca_path.read_text()

# Create Certificate object (no key needed for CA)
ca_cert = Certificate.from_pem(cert_pem=ca_cert_content)
```

### Pattern 3: Load Multiple Certificates

```python
from pathlib import Path
from provide.foundation.crypto import Certificate

def load_certificates(cert_dir: str) -> dict[str, Certificate]:
    """Load all certificates from a directory."""
    certs = {}
    cert_path = Path(cert_dir)

    for pem_file in cert_path.glob("*.pem"):
        try:
            pem_content = pem_file.read_text()
            cert = Certificate.from_pem(cert_pem=pem_content)
            certs[pem_file.stem] = cert
        except Exception as e:
            print(f"Failed to load {pem_file}: {e}")

    return certs
```

### Pattern 4: Dynamic Path Loading

```python
from pathlib import Path
from provide.foundation.crypto import Certificate
from pyvider.rpcplugin.config import rpcplugin_config

# Load from environment-configured paths
cert_path_str = rpcplugin_config.plugin_server_cert
key_path_str = rpcplugin_config.plugin_server_key

if cert_path_str and key_path_str:
    # Read PEM content from configured paths
    cert_pem_content = Path(cert_path_str).read_text()
    key_pem_content = Path(key_path_str).read_text()

    cert = Certificate.from_pem(
        cert_pem=cert_pem_content,
        key_pem=key_pem_content
    )
else:
    # Auto-generate if not configured
    cert = Certificate.create_self_signed_server_cert(
        common_name="plugin.local",
        validity_days=90
    )
```

### Pattern 5: Certificate with Validation

```python
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger

def load_and_validate_certificate(
    cert_path: str,
    key_path: str,
    ca_cert: Certificate | None = None
) -> Certificate:
    """Load certificate with comprehensive validation."""

    # Read PEM content
    cert_pem_content = Path(cert_path).read_text()
    key_pem_content = Path(key_path).read_text()

    # Create certificate
    cert = Certificate.from_pem(
        cert_pem=cert_pem_content,
        key_pem=key_pem_content
    )

    # Validate
    if not cert.is_valid:
        raise ValueError(f"Certificate at {cert_path} is invalid")

    # Verify trust chain if CA provided
    if ca_cert and not cert.verify_trust(ca_cert):
        raise ValueError(f"Certificate trust verification failed")

    logger.info(f"Loaded valid certificate: {cert.common_name}")
    return cert
```

## Creating Self-Signed Certificates

### Server Certificate

```python
from provide.foundation.crypto import Certificate

# Create self-signed server certificate
server_cert = Certificate.create_self_signed_server_cert(
    common_name="myservice.example.com",
    organization_name="My Organization",
    validity_days=365
)

# Save to files (PEM content is in cert_pem and key_pem attributes)
from pathlib import Path

Path("server.pem").write_text(server_cert.cert_pem)
Path("server.key").write_text(server_cert.key_pem)
```

### Client Certificate

```python
from provide.foundation.crypto import Certificate

# Create self-signed client certificate
client_cert = Certificate.create_self_signed_client_cert(
    common_name="client.example.com",
    organization_name="My Organization",
    validity_days=365
)
```

### CA Certificate

```python
from provide.foundation.crypto import Certificate

# Create CA certificate for signing
ca_cert = Certificate.create_self_signed_ca_cert(
    common_name="My CA",
    organization_name="My Organization",
    validity_days=3650  # 10 years
)
```

## Certificate Properties

### Accessing Certificate Information

```python
from pathlib import Path
from provide.foundation.crypto import Certificate

# Load certificate
cert_content = Path("server.pem").read_text()
cert = Certificate.from_pem(cert_pem=cert_content)

# Access properties
print(f"Common Name: {cert.common_name}")
print(f"Organization: {cert.organization_name}")
print(f"Key Type: {cert.key_type}")
print(f"Valid: {cert.is_valid}")

# PEM content (useful for storage or transmission)
pem_string = cert.cert_pem
key_string = cert.key_pem
```

## Integration with Pyvider RPC

### Server Setup

```python
from pathlib import Path
from pyvider.rpcplugin import plugin_server
from provide.foundation.crypto import Certificate

# Load certificates
server_cert_content = Path("server.pem").read_text()
server_key_content = Path("server.key").read_text()
server_cert = Certificate.from_pem(
    cert_pem=server_cert_content,
    key_pem=server_key_content
)

ca_cert_content = Path("ca.pem").read_text()
ca_cert = Certificate.from_pem(cert_pem=ca_cert_content)

# Create server with mTLS
server = plugin_server(
    protocol=my_protocol,
    handler=my_handler,
    tls_certificate=server_cert,
    tls_ca_certificate=ca_cert,
    require_client_certificate=True
)
```

### Client Setup

```python
from pathlib import Path
from pyvider.rpcplugin import plugin_client
from provide.foundation.crypto import Certificate

# Load client certificates
client_cert_content = Path("client.pem").read_text()
client_key_content = Path("client.key").read_text()
client_cert = Certificate.from_pem(
    cert_pem=client_cert_content,
    key_pem=client_key_content
)

ca_cert_content = Path("ca.pem").read_text()
ca_cert = Certificate.from_pem(cert_pem=ca_cert_content)

# Create client with mTLS
async with plugin_client(
    command=["python", "plugin.py"],
    tls_client_certificate=client_cert,
    tls_ca_certificate=ca_cert
) as client:
    await client.start()
    # Make RPC calls
```

## Environment Variables

### Loading from Environment Paths

```python
import os
from pathlib import Path
from provide.foundation.crypto import Certificate

# Get paths from environment
cert_path = os.getenv("PLUGIN_SERVER_CERT", "server.pem")
key_path = os.getenv("PLUGIN_SERVER_KEY", "server.key")

# Read PEM content from configured paths
cert_pem_content = Path(cert_path).read_text()
key_pem_content = Path(key_path).read_text()

cert = Certificate.from_pem(
    cert_pem=cert_pem_content,
    key_pem=key_pem_content
)
```

### Storing PEM Content in Environment

```python
import os
from provide.foundation.crypto import Certificate

# Option 1: Read from environment variable containing PEM content directly
cert_pem_content = os.getenv("SERVER_CERT_PEM")
key_pem_content = os.getenv("SERVER_KEY_PEM")

if cert_pem_content and key_pem_content:
    cert = Certificate.from_pem(
        cert_pem=cert_pem_content,
        key_pem=key_pem_content
    )

# Option 2: Generate and store in environment
server_cert = Certificate.create_self_signed_server_cert(
    common_name="myservice.local",
    validity_days=90
)

os.environ["PLUGIN_SERVER_CERT"] = server_cert.cert_pem
os.environ["PLUGIN_SERVER_KEY"] = server_cert.key_pem
```

## Error Handling

### Robust Certificate Loading

```python
from pathlib import Path
from provide.foundation.crypto import Certificate
from provide.foundation import logger

def load_certificate_safely(
    cert_path: str,
    key_path: str | None = None
) -> Certificate | None:
    """Load certificate with comprehensive error handling."""
    try:
        # Check file exists
        cert_file = Path(cert_path)
        if not cert_file.exists():
            logger.error(f"Certificate file not found: {cert_path}")
            return None

        # Read cert PEM content
        cert_pem_content = cert_file.read_text()

        # Load with or without key
        if key_path:
            key_file = Path(key_path)
            if not key_file.exists():
                logger.error(f"Key file not found: {key_path}")
                return None

            key_pem_content = key_file.read_text()
            cert = Certificate.from_pem(
                cert_pem=cert_pem_content,
                key_pem=key_pem_content
            )
        else:
            cert = Certificate.from_pem(cert_pem=cert_pem_content)

        # Validate
        if not cert.is_valid:
            logger.warning(f"Certificate is invalid: {cert_path}")
            return None

        logger.info(f"Successfully loaded certificate: {cert.common_name}")
        return cert

    except Exception as e:
        logger.error(f"Failed to load certificate: {e}", exc_info=True)
        return None
```

## Summary

### Key Points

1. **`Certificate.from_pem()` expects PEM content strings**, not file paths or URIs
2. **Always read file content first** using `Path().read_text()`
3. **Use `cert_pem` and `key_pem` parameters** for the PEM content strings
4. **Validate certificates** after loading with `is_valid` property
5. **Use Foundation's logger** for certificate operations

### Related Documentation

- **[mTLS Configuration](mtls/)** - Complete mTLS setup guide
- **[Certificate Management](certificates/)** - Detailed certificate operations
- **[Security Best Practices](../security/index/)** - Production security patterns
