# Security Guide - pyvider-rpcplugin

This document provides comprehensive security guidance for deploying and operating `pyvider-rpcplugin` in production environments.

## Table of Contents

- [Security Overview](#security-overview)
- [mTLS Configuration](#mtls-configuration)
- [Certificate Management](#certificate-management)
- [Transport Security](#transport-security)
- [Authentication & Authorization](#authentication--authorization)
- [Network Security](#network-security)
- [Operational Security](#operational-security)
- [Security Monitoring](#security-monitoring)
- [Threat Model](#threat-model)
- [Security Checklist](#security-checklist)

## Security Overview

`pyvider-rpcplugin` implements defense-in-depth security with multiple layers of protection:

1. **Transport Layer Security** - mTLS encryption for all network communication
2. **Authentication** - Certificate-based mutual authentication
3. **Authorization** - Service-level access controls
4. **Network Security** - Transport isolation and access controls
5. **Operational Security** - Secure deployment and monitoring practices

### Security Principles

- **Zero Trust** - Never trust, always verify
- **Least Privilege** - Minimal required permissions
- **Defense in Depth** - Multiple security layers
- **Security by Default** - Secure configurations out of the box
- **Fail Secure** - Secure failure modes

## mTLS Configuration

Mutual TLS (mTLS) provides the foundation for secure RPC communication.

### Quick mTLS Setup

```python
from pyvider.rpcplugin import configure, plugin_server, plugin_client

# Enable mTLS with auto-configuration
configure(
    PLUGIN_AUTO_MTLS=True,  # Enables mTLS if other certs are correctly set

    # Server-side configuration for its own identity
    PLUGIN_SERVER_CERT="file:///path/to/your/ca_signed_server.crt",
    PLUGIN_SERVER_KEY="file:///path/to/your/server.key",

    # Server-side configuration for validating clients
    # This tells the server which CA to trust for client certificates.
    PLUGIN_CLIENT_ROOT_CERTS="file:///path/to/your/ca.crt",

    # Client-side configuration for its own identity (if the client is also a pyvider-rpcplugin based executable)
    PLUGIN_CLIENT_CERT="file:///path/to/your/ca_signed_client.crt",
    PLUGIN_CLIENT_KEY="file:///path/to/your/client.key",

    # Client-side configuration for validating the server
    # This tells the client which CA to trust for the server's certificate.
    PLUGIN_SERVER_ROOT_CERTS="file:///path/to/your/ca.crt"
)

# Server automatically uses mTLS
# When PLUGIN_AUTO_MTLS=True, the server will require client certificates
# if PLUGIN_CLIENT_ROOT_CERTS is also configured. The server uses PLUGIN_SERVER_CERT
# and PLUGIN_SERVER_KEY for its identity.
# server = plugin_server(protocol=my_protocol, handler=my_handler)

# Client automatically uses mTLS (if it's an executable plugin)
# client = plugin_client(server_path="/path/to/executable_plugin")
# await client.start()
print("Note: server/client examples are conceptual in this section.")
```

### Manual mTLS Configuration

For advanced scenarios, configure mTLS manually:

```python
import grpc

# Assume certificate and key PEM strings are read from files:
# Example:
# with open("/path/to/ca.crt", "rb") as f: ca_pem_bytes = f.read()
# with open("/path/to/server.crt", "rb") as f: server_cert_pem_bytes = f.read()
# with open("/path/to/server.key", "rb") as f: server_key_pem_bytes = f.read()
# with open("/path/to/client.crt", "rb") as f: client_cert_pem_bytes = f.read()
# with open("/path/to/client.key", "rb") as f: client_key_pem_bytes = f.read()

# For demonstration, using placeholder PEM byte strings:
ca_pem_bytes = b"-----BEGIN CERTIFICATE-----\n..." # Content of your CA certificate
server_cert_pem_bytes = b"-----BEGIN CERTIFICATE-----\n..." # Content of your server certificate (signed by CA)
server_key_pem_bytes = b"-----BEGIN PRIVATE KEY-----\n..." # Content of your server private key
client_cert_pem_bytes = b"-----BEGIN CERTIFICATE-----\n..." # Content of your client certificate (signed by CA)
client_key_pem_bytes = b"-----BEGIN PRIVATE KEY-----\n..." # Content of your client private key

# Create server credentials
server_credentials = grpc.ssl_server_credentials(
    private_key_certificate_chain_pairs=[(server_key_pem_bytes, server_cert_pem_bytes)],
    root_certificates=ca_pem_bytes,  # Server uses CA cert to verify client certs
    require_client_auth=True         # Enforce client authentication
)

# Create client credentials
client_credentials = grpc.ssl_channel_credentials(
    root_certificates=ca_pem_bytes,     # Client uses CA cert to verify server's cert
    private_key=client_key_pem_bytes,   # Client's own private key
    certificate_chain=client_cert_pem_bytes # Client's own certificate
)
```

### Environment-based mTLS

Configure mTLS via environment variables for containerized deployments:

```bash
# --- Server-Side Configuration ---
# Server's own certificate and key (signed by your CA)
export PLUGIN_SERVER_CERT="file:///etc/ssl/certs/server.crt"
export PLUGIN_SERVER_KEY="file:///etc/ssl/private/server.key"
# CA certificate(s) the server uses to verify client certificates
export PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/ca.crt"

# --- Client-Side Configuration (for a client executable plugin) ---
# Client's own certificate and key (signed by your CA)
export PLUGIN_CLIENT_CERT="file:///etc/ssl/certs/client.crt"
export PLUGIN_CLIENT_KEY="file:///etc/ssl/private/client.key"
# CA certificate(s) the client uses to verify the server's certificate
export PLUGIN_SERVER_ROOT_CERTS="file:///etc/ssl/certs/ca.crt"

# Enable mTLS (applies to both client and server if they use this config)
export PLUGIN_AUTO_MTLS="true"
# If PLUGIN_AUTO_MTLS="true", the server will require client certificates if
# PLUGIN_CLIENT_ROOT_CERTS is set. The client will send its certificate if
# PLUGIN_CLIENT_CERT and PLUGIN_CLIENT_KEY are set, and validate the server
# using PLUGIN_SERVER_ROOT_CERTS.
```

## Certificate Management

### Certificate Generation

Generate a complete certificate chain using a central Certificate Authority (CA). This involves creating a CA, and then using the CA to sign server and client certificates.

```python
from pyvider.rpcplugin.crypto.certificate import Certificate
from pathlib import Path # Recommended for path management

# Define a directory to store certificates (ensure this directory exists and is secure)
# For example purposes, we use a relative path. In production, use absolute, secure paths.
cert_dir = Path("./example_certs_output")
cert_dir.mkdir(exist_ok=True)

# Step 1: Create a Root CA
# This CA certificate is self-signed and will be used to sign other certificates.
# Its private key should be very securely stored.
ca_cert_obj = Certificate.create_ca(
    common_name="My Example Corp CA",
    organization_name="My Example Corp", # organization_name is required
    validity_days=1095,  # e.g., 3 years for a root CA
    key_type="ecdsa", # Default, but explicit
    ecdsa_curve="secp384r1" # Default, but explicit
)

# Save the CA certificate and its private key
ca_cert_path = cert_dir / "ca.crt"
ca_key_path = cert_dir / "ca.key"
with open(ca_cert_path, "w", encoding="utf-8") as f:
    f.write(ca_cert_obj.cert)
if ca_cert_obj.key: # Key will be present for generated CA
    with open(ca_key_path, "w", encoding="utf-8") as f:
        f.write(ca_cert_obj.key)
print(f"CA certificate saved to: {ca_cert_path}")
print(f"CA private key saved to: {ca_key_path} (KEEP THIS KEY VERY SECURE!)")


# Step 2: Create a Server Certificate signed by the CA
# The server certificate is used by the RPC server to identify itself to clients.
server_cert_obj = Certificate.create_signed_certificate(
    ca_certificate=ca_cert_obj,
    common_name="rpc-server.example.com",
    organization_name="My Example Corp Servers", # organization_name is required
    validity_days=90,
    alt_names=["rpc-server.internal.example.com", "localhost", "127.0.0.1"],
    is_client_cert=False # This is a server certificate
)

# Save the server certificate and its private key
server_cert_path = cert_dir / "server.crt"
server_key_path = cert_dir / "server.key"
with open(server_cert_path, "w", encoding="utf-8") as f:
    f.write(server_cert_obj.cert)
if server_cert_obj.key: # Key will be present
    with open(server_key_path, "w", encoding="utf-8") as f:
        f.write(server_cert_obj.key)
print(f"Server certificate saved to: {server_cert_path}")
print(f"Server private key saved to: {server_key_path}")


# Step 3: Create a Client Certificate signed by the CA
# The client certificate is used by RPC clients to identify themselves to the server.
client_cert_obj = Certificate.create_signed_certificate(
    ca_certificate=ca_cert_obj,
    common_name="client-id-007",
    organization_name="My Example Corp Clients", # organization_name is required
    validity_days=30,
    is_client_cert=True # This is a client certificate
)

# Save the client certificate and its private key
client_cert_path = cert_dir / "client.crt"
client_key_path = cert_dir / "client.key"
with open(client_cert_path, "w", encoding="utf-8") as f:
    f.write(client_cert_obj.cert)
if client_cert_obj.key: # Key will be present
    with open(client_key_path, "w", encoding="utf-8") as f:
        f.write(client_cert_obj.key)
print(f"Client certificate saved to: {client_cert_path}")
print(f"Client private key saved to: {client_key_path}")

# Now you have a set of certificates for mTLS:
# - ca.crt: The CA certificate, used by both client and server to verify each other.
# - server.crt, server.key: The server's certificate and private key.
# - client.crt, client.key: The client's certificate and private key.
```

### Certificate Validation

Implement certificate validation. The `Certificate` class itself handles parsing and basic structural validation on load. For chain validation, you can use OpenSSL or other tools. `pyvider.rpcplugin` relies on `grpcio`'s underlying TLS implementation for chain validation during the handshake when CAs are configured.

```python
from pyvider.rpcplugin.crypto.certificate import Certificate # Already imported
from datetime import UTC, datetime # Ensure imports for date logic

# Example: Checking if a certificate is expired
def check_certificate_expiry(cert_pem_or_uri: str, days_warning: int = 30) -> bool:
    """Check if certificate at given path or PEM string expires soon."""
    try:
        cert = Certificate(cert_pem_or_uri=cert_pem_or_uri)
        if not cert.is_valid: # is_valid checks not_valid_before and not_valid_after
            # Calculate days until expiry for logging, even if already expired
            # Note: Certificate._base.not_valid_after is already timezone-aware (UTC)
            days_left = (cert._base.not_valid_after - datetime.now(UTC)).days
            if days_left < 0:
                logger.error(f"Certificate '{cert.subject}' HAS EXPIRED {abs(days_left)} days ago.")
            else: # Should not happen if cert.is_valid is False and it's due to future validity
                 logger.warning(f"Certificate '{cert.subject}' is not currently valid (e.g. not_valid_before is in future).")
            return True # Indicates an issue (expired or not yet valid)

        days_left = (cert._base.not_valid_after - datetime.now(UTC)).days
        if days_left <= days_warning:
            logger.warning(
                f"Certificate '{cert.subject}' is expiring in {days_left} days (warning threshold: {days_warning} days)."
            )
            return True # Indicates it's expiring soon or has an issue
        logger.info(f"Certificate '{cert.subject}' is valid and not expiring within {days_warning} days.")
        return False # No immediate expiry issue
    except Exception as e:
        logger.error(f"Error checking certificate expiry for '{cert_pem_or_uri}': {e}")
        return True # Treat errors as a potential issue

# To validate a chain (e.g., server_cert against ca_cert):
# This is typically handled by the TLS library (grpcio) during connection.
# For manual/programmatic validation, you might use cryptography library directly
# or shell out to OpenSSL:
# `openssl verify -CAfile /path/to/ca.crt /path/to/server.crt`
```

### Certificate Rotation

Implement automated certificate rotation. The example below is conceptual for rotation logic.
Actual rotation involves securely distributing new certs/keys and gracefully restarting/reloading services.

```python
import asyncio
# from datetime import datetime, timedelta # Already imported if needed from above
import os # For os.rename

class CertificateRotator:
    def __init__(self, ca_cert_obj: Certificate): # Takes a Certificate object for the CA
        self.ca_cert_obj = ca_cert_obj
        self.rotation_threshold_days = 7 # Rotate if cert expires within 7 days

    async def rotate_certificate_if_needed(
        self,
        cert_pem_uri: str, # e.g., "file:///path/to/current.crt"
        key_pem_uri: str,  # e.g., "file:///path/to/current.key"
        common_name: str,
        organization_name: str, # Added, as it's required by create_signed_certificate
        alt_names: list[str] | None = None, # Added for completeness
        is_client_cert: bool = False,
        validity_days: int = 90 # Validity for the new certificate
    ) -> bool:
        """Rotate certificate if expiring soon."""
        try:
            current_cert = Certificate(cert_pem_or_uri=cert_pem_uri, key_pem_or_uri=key_pem_uri)

            # Check expiry
            now = datetime.now(UTC)
            if not hasattr(current_cert, '_base'): # Should not happen if loaded correctly
                 logger.error(f"Cannot rotate {common_name}: current certificate not loaded properly.")
                 return False

            if (current_cert._base.not_valid_after - now).days > self.rotation_threshold_days:
                logger.info(f"Certificate for {common_name} does not need rotation yet.")
                return False

            logger.info(f"Rotating certificate for {common_name} (expiring soon or expired).")

            new_cert = Certificate.create_signed_certificate(
                ca_certificate=self.ca_cert_obj,
                common_name=common_name,
                organization_name=organization_name, # Pass through
                validity_days=validity_days, # Use specified validity for new cert
                alt_names=alt_names,
                is_client_cert=is_client_cert
            )

            # Securely write new cert and key then replace old ones (atomic rename)
            # This example assumes cert_pem_uri and key_pem_uri are file URIs
            cert_path_str = cert_pem_uri.replace("file://", "")
            key_path_str = key_pem_uri.replace("file://", "")

            temp_cert_path = f"{cert_path_str}.new"
            temp_key_path = f"{key_path_str}.new"

            with open(temp_cert_path, "w", encoding="utf-8") as f:
                f.write(new_cert.cert)
            if new_cert.key:
                with open(temp_key_path, "w", encoding="utf-8") as f:
                    f.write(new_cert.key)

            # Atomic move (on POSIX, os.rename is atomic if src/dest are on same filesystem)
            os.rename(temp_cert_path, cert_path_str)
            if new_cert.key:
                os.rename(temp_key_path, key_path_str)

            logger.info(f"Certificate rotation completed for {common_name}.")
            # IMPORTANT: The application using this certificate must be signaled to reload it.
            # This logic is outside the scope of this example.
            return True
        except Exception as e:
            logger.error(f"Error during certificate rotation for {common_name}: {e}", exc_info=True)
            return False

# Conceptual: Setup automatic rotation (requires a running CA cert object `ca_cert`)
# async def certificate_rotation_service(ca_cert_for_signing: Certificate):
#     """Background service for certificate rotation."""
#     rotator = CertificateRotator(ca_cert=ca_cert_for_signing)
#     server_cert_details = {
#         "cert_pem_uri": "file:///etc/ssl/certs/server.crt",
#         "key_pem_uri": "file:///etc/ssl/private/server.key",
#         "common_name": "rpc-server.yourdomain.com",
#         "organization_name": "My Server Org",
#         "alt_names": ["rpc-server.yourdomain.com", "localhost"],
#         "is_client_cert": False,
#         "validity_days": 90
#     }
#     # Add client cert details similarly
#
#     while True:
#         try:
#             await rotator.rotate_certificate_if_needed(**server_cert_details)
#             # await rotator.rotate_certificate_if_needed(**client_cert_details)
#         except Exception as e:
#             logger.error(f"Certificate rotation service error: {e}")
#         await asyncio.sleep(24 * 60 * 60) # Check daily
```

## Transport Security

### Unix Socket Security

Unix sockets provide security through filesystem permissions:

```python
import os
import stat

def secure_unix_socket(socket_path: str) -> None:
    """Apply secure permissions to Unix socket."""

    # Set restrictive permissions (owner read/write only)
    os.chmod(socket_path, stat.S_IRUSR | stat.S_IWUSR)

    # Verify ownership
    socket_stat = os.stat(socket_path)
    if socket_stat.st_uid != os.getuid():
        raise SecurityError(f"Socket owned by wrong user: {socket_path}")

# Create secure Unix socket server
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="unix",
    transport_path="/secure/path/rpc.sock"
)

# Apply security after creation
secure_unix_socket("/secure/path/rpc.sock")
```

### TCP Security

TCP transport requires additional network security measures:

```python
# Bind to specific interface (not all interfaces)
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="tcp",
    host="10.0.1.100",  # Specific internal IP
    port=50051
)

# Alternative: localhost only
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="tcp",
    host="127.0.0.1",  # Localhost only
    port=50051
)
```

### Network Access Controls

Implement IP-based access controls:

```python
class IPAccessControl:
    def __init__(self, allowed_networks: List[str]):
        self.allowed_networks = [
            ipaddress.ip_network(net, strict=False)
            for net in allowed_networks
        ]

    def is_allowed(self, client_ip: str) -> bool:
        """Check if client IP is allowed."""
        client_addr = ipaddress.ip_address(client_ip)

        for network in self.allowed_networks:
            if client_addr in network:
                return True

        return False

# Configure access control
access_control = IPAccessControl([
    "10.0.0.0/8",      # Internal network
    "192.168.0.0/16",  # Private network
    "127.0.0.1/32"     # Localhost
])

# Use in server interceptor
class AccessControlInterceptor(grpc.aio.ServerInterceptor):
    async def intercept_service(self, continuation, handler_call_details):
        # Extract client IP from metadata
        client_ip = self._extract_client_ip(handler_call_details.invocation_metadata)

        if not access_control.is_allowed(client_ip):
            logger.warning("Access denied", client_ip=client_ip)
            raise grpc.RpcError(grpc.StatusCode.PERMISSION_DENIED)

        return await continuation(handler_call_details)
```

## Authentication & Authorization

### Magic Cookie Authentication

Implement shared secret authentication:

```python
def validate_magic_cookie(provided_cookie: str, expected_cookie: str) -> bool:
    """Securely compare magic cookies."""

    # Use constant-time comparison to prevent timing attacks
    import secrets
    return secrets.compare_digest(provided_cookie, expected_cookie)

# Server-side configuration for expected magic cookie:
# This is typically set via environment variables or pyvider.rpcplugin.configure()
# at server startup.
# Example:
# from pyvider.rpcplugin import configure
# configure(
#    PLUGIN_MAGIC_COOKIE_KEY="MY_APP_PLUGIN_SECRET_TOKEN", # Name of env var client sets
#    PLUGIN_MAGIC_COOKIE_VALUE="actual-secret-value-for-server-to-expect"
# )
# The server will then use these values to validate the cookie provided by the client
# (which the client sends in the environment variable named by PLUGIN_MAGIC_COOKIE_KEY).
# See docs/configuration.md for the full magic cookie flow.

# Client-side (if using plugin_client to launch an executable):
# The plugin_client factory will automatically read its own configured
# PLUGIN_MAGIC_COOKIE_KEY and PLUGIN_MAGIC_COOKIE_VALUE, and set the
# corresponding environment variable for the launched plugin process.
# Example:
# client_config = {
#     "PLUGIN_MAGIC_COOKIE_KEY": "MY_APP_PLUGIN_SECRET_TOKEN",
#     "PLUGIN_MAGIC_COOKIE_VALUE": "actual-secret-value-for-server-to-expect"
# }
# client = plugin_client(command=["./my_plugin"], config=client_config)
# await client.start()
# This ensures the launched "./my_plugin" has MY_APP_PLUGIN_SECRET_TOKEN set.

# Magic cookie validation happens automatically during the handshake process.
```

### Role-Based Access Control (RBAC)

Implement service-level authorization:

```python
from enum import Enum
from typing import Set

class Role(Enum):
    ADMIN = "admin"
    USER = "user"
    READONLY = "readonly"

class Permission(Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"

ROLE_PERMISSIONS = {
    Role.ADMIN: {Permission.READ, Permission.WRITE, Permission.ADMIN},
    Role.USER: {Permission.READ, Permission.WRITE},
    Role.READONLY: {Permission.READ}
}

class AuthorizedHandler:
    def __init__(self, base_handler):
        self.base_handler = base_handler

    def _get_client_role(self, context) -> Role:
        """Extract client role from certificate or metadata."""

        # Extract from client certificate CN
        peer_identity = context.peer_identity()
        if "admin" in peer_identity:
            return Role.ADMIN
        elif "readonly" in peer_identity:
            return Role.READONLY
        else:
            return Role.USER

    def _check_permission(self, role: Role, required_permission: Permission) -> bool:
        """Check if role has required permission."""
        return required_permission in ROLE_PERMISSIONS.get(role, set())

    async def ReadData(self, request, context):
        """Read operation requiring READ permission."""
        client_role = self._get_client_role(context)

        if not self._check_permission(client_role, Permission.READ):
            logger.warning("Access denied", role=client_role.value, operation="read")
            raise grpc.RpcError(grpc.StatusCode.PERMISSION_DENIED)

        return await self.base_handler.ReadData(request, context)

    async def WriteData(self, request, context):
        """Write operation requiring WRITE permission."""
        client_role = self._get_client_role(context)

        if not self._check_permission(client_role, Permission.WRITE):
            logger.warning("Access denied", role=client_role.value, operation="write")
            raise grpc.RpcError(grpc.StatusCode.PERMISSION_DENIED)

        return await self.base_handler.WriteData(request, context)
```

## Network Security

### Firewall Configuration

Configure firewall rules for RPC services:

```bash
# Ubuntu/Debian iptables rules
# Allow RPC traffic from specific networks only
iptables -A INPUT -p tcp --dport 50051 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 50051 -s 192.168.0.0/16 -j ACCEPT
iptables -A INPUT -p tcp --dport 50051 -j DROP

# CentOS/RHEL firewalld rules
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port protocol="tcp" port="50051" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.0.0/16" port protocol="tcp" port="50051" accept'
firewall-cmd --reload
```

### VPN and Private Networks

Deploy RPC services in isolated networks:

```yaml
# Docker Compose with isolated network
version: '3.8'
services:
  rpc-server:
    image: your-rpc-server:latest
    networks:
      - rpc-internal
    ports:
      - "127.0.0.1:50051:50051"  # Bind to localhost only

  rpc-client:
    image: your-rpc-client:latest
    networks:
      - rpc-internal
    depends_on:
      - rpc-server

networks:
  rpc-internal:
    driver: bridge
    internal: true  # No external access
```

### Load Balancer Security

Configure secure load balancing:

```nginx
# Nginx configuration for RPC load balancing
upstream rpc_backend {
    server 10.0.1.10:50051;
    server 10.0.1.11:50051;
    server 10.0.1.12:50051;
}

server {
    listen 50051 ssl http2;

    # SSL certificate configuration
    ssl_certificate /etc/ssl/certs/rpc-lb.crt;
    ssl_certificate_key /etc/ssl/private/rpc-lb.key;
    ssl_client_certificate /etc/ssl/certs/ca.crt;
    ssl_verify_client on;

    # Security headers
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512;
    ssl_prefer_server_ciphers off;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=rpc:10m rate=100r/s;
    limit_req zone=rpc burst=200 nodelay;

    location / {
        grpc_pass grpc://rpc_backend;

        # Client IP forwarding
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## Operational Security

### Secure Deployment

Deploy with security hardening:

```dockerfile
# Multi-stage secure Dockerfile
FROM python:3.13-slim as builder

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.13-slim

# Create non-root user
RUN groupadd -r rpcuser && useradd -r -g rpcuser rpcuser

# Copy application
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --chown=rpcuser:rpcuser src/ /app/src/

# Create secure directories
RUN mkdir -p /app/certs /app/logs && \
    chown -R rpcuser:rpcuser /app

# Switch to non-root user
USER rpcuser

# Security settings
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app
EXPOSE 50051

CMD ["python", "-m", "your_rpc_service"]
```

### Container Security

Secure container configuration:

```yaml
# Kubernetes deployment with security
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rpc-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rpc-service
  template:
    metadata:
      labels:
        app: rpc-service
    spec:
      serviceAccountName: rpc-service-account

      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000

      containers:
      - name: rpc-service
        image: your-rpc-service:latest

        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL

        ports:
        - containerPort: 50051
          name: grpc

        volumeMounts:
        - name: certs
          mountPath: /app/certs
          readOnly: true
        - name: tmp
          mountPath: /tmp

        env:
        - name: PLUGIN_SERVER_CERT
          value: "file:///app/certs/server.crt"
        - name: PLUGIN_SERVER_KEY
          value: "file:///app/certs/server.key"

        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "250m"

      volumes:
      - name: certs
        secret:
          secretName: rpc-tls-certs
      - name: tmp
        emptyDir: {}
```

### Secret Management

Use proper secret management:

```python
# HashiCorp Vault integration
import hvac

class VaultSecretManager:
    def __init__(self, vault_url: str, vault_token: str):
        self.client = hvac.Client(url=vault_url, token=vault_token)

    def get_certificate(self, path: str) -> str:
        """Retrieve certificate from Vault."""
        response = self.client.secrets.kv.v2.read_secret_version(path=path)
        return response['data']['data']['certificate']

    def get_private_key(self, path: str) -> str:
        """Retrieve private key from Vault."""
        response = self.client.secrets.kv.v2.read_secret_version(path=path)
        return response['data']['data']['private_key']

# Configure with Vault
vault = VaultSecretManager("https://vault.company.com", vault_token)

configure(
    PLUGIN_SERVER_CERT=vault.get_certificate("secret/rpc/server-cert"),
    PLUGIN_SERVER_KEY=vault.get_private_key("secret/rpc/server-key"),
    PLUGIN_CLIENT_CERT=vault.get_certificate("secret/rpc/client-cert"),
    PLUGIN_CLIENT_KEY=vault.get_private_key("secret/rpc/client-key")
    # Potentially PLUGIN_CLIENT_ROOT_CERTS or PLUGIN_SERVER_ROOT_CERTS for CAs
)
```

## Security Monitoring

### Audit Logging

Implement comprehensive audit logging:

```python
class SecurityAuditLogger:
    def __init__(self):
        self.audit_logger = logger.bind(audit=True)

    def log_authentication(
        self,
        client_id: str,
        success: bool,
        reason: str = None
    ) -> None:
        """Log authentication attempts."""
        self.audit_logger.info(
            "Authentication attempt",
            domain="security",
            action="authenticate",
            status="success" if success else "failure",
            client_id=client_id,
            reason=reason,
            timestamp=datetime.utcnow().isoformat()
        )

    def log_authorization(
        self,
        client_id: str,
        operation: str,
        success: bool,
        reason: str = None
    ) -> None:
        """Log authorization attempts."""
        self.audit_logger.info(
            "Authorization check",
            domain="security",
            action="authorize",
            status="success" if success else "failure",
            client_id=client_id,
            operation=operation,
            reason=reason,
            timestamp=datetime.utcnow().isoformat()
        )

# Usage in handlers
audit = SecurityAuditLogger()

class AuditedHandler:
    async def ProcessRequest(self, request, context):
        client_id = self._extract_client_id(context)

        try:
            # Log successful authentication
            audit.log_authentication(client_id, True)

            # Process request
            result = await self._process_request(request, context)

            # Log successful operation
            audit.log_authorization(client_id, "process_request", True)

            return result

        except Exception as e:
            # Log security failures
            audit.log_authorization(client_id, "process_request", False, str(e))
            raise
```

### Intrusion Detection

Monitor for suspicious activity:

```python
from collections import defaultdict, deque
from time import time

class IntrusionDetector:
    def __init__(self):
        self.failed_attempts = defaultdict(deque)
        self.rate_limits = defaultdict(deque)

        # Thresholds
        self.max_failed_attempts = 5
        self.failed_attempt_window = 300  # 5 minutes
        self.max_requests_per_minute = 100

    def check_failed_attempts(self, client_id: str) -> bool:
        """Check if client has too many failed attempts."""
        now = time()
        attempts = self.failed_attempts[client_id]

        # Remove old attempts
        while attempts and attempts[0] < now - self.failed_attempt_window:
            attempts.popleft()

        return len(attempts) >= self.max_failed_attempts

    def record_failed_attempt(self, client_id: str) -> None:
        """Record a failed authentication attempt."""
        self.failed_attempts[client_id].append(time())

        if self.check_failed_attempts(client_id):
            logger.warning(
                "Multiple failed attempts detected",
                domain="security",
                action="intrusion_detection",
                status="alert",
                client_id=client_id,
                failed_attempts=len(self.failed_attempts[client_id])
            )

    def check_rate_limit(self, client_id: str) -> bool:
        """Check if client is making too many requests."""
        now = time()
        requests = self.rate_limits[client_id]

        # Remove old requests
        while requests and requests[0] < now - 60:  # 1 minute window
            requests.popleft()

        requests.append(now)

        if len(requests) > self.max_requests_per_minute:
            logger.warning(
                "Rate limit exceeded",
                domain="security",
                action="rate_limit",
                status="alert",
                client_id=client_id,
                requests_per_minute=len(requests)
            )
            return False

        return True

# Integrate with handler
detector = IntrusionDetector()

class SecureHandler:
    async def ProcessRequest(self, request, context):
        client_id = self._extract_client_id(context)

        # Check for blocked clients
        if detector.check_failed_attempts(client_id):
            raise grpc.RpcError(grpc.StatusCode.PERMISSION_DENIED, "Too many failed attempts")

        # Check rate limiting
        if not detector.check_rate_limit(client_id):
            raise grpc.RpcError(grpc.StatusCode.RESOURCE_EXHAUSTED, "Rate limit exceeded")

        try:
            return await self._process_request(request, context)
        except Exception as e:
            # Record authentication failures
            if isinstance(e, grpc.RpcError) and e.code() == grpc.StatusCode.UNAUTHENTICATED:
                detector.record_failed_attempt(client_id)
            raise
```

## Threat Model

### Identified Threats

1. **Network Eavesdropping**
   - **Mitigation**: mTLS encryption for all communication
   - **Detection**: Monitor for unencrypted connections

2. **Man-in-the-Middle Attacks**
   - **Mitigation**: Certificate pinning and validation
   - **Detection**: Certificate change monitoring

3. **Certificate Compromise**
   - **Mitigation**: Short-lived certificates and rotation
   - **Detection**: Certificate usage monitoring

4. **Unauthorized Access**
   - **Mitigation**: Strong authentication and authorization
   - **Detection**: Access pattern analysis

5. **Denial of Service**
   - **Mitigation**: Rate limiting and resource controls
   - **Detection**: Traffic anomaly detection

6. **Data Exfiltration**
   - **Mitigation**: Access controls and audit logging
   - **Detection**: Data access monitoring

### Security Controls Matrix

| Threat | Prevention | Detection | Response |
|--------|------------|-----------|----------|
| Network Eavesdropping | mTLS Encryption | Unencrypted connection alerts | Block unencrypted |
| MITM Attacks | Certificate Validation | Cert change detection | Revoke compromised certs |
| Cert Compromise | Short-lived certs | Usage monitoring | Emergency rotation |
| Unauthorized Access | RBAC + mTLS | Failed auth monitoring | IP blocking |
| DoS Attacks | Rate limiting | Traffic analysis | Traffic shaping |
| Data Exfiltration | Least privilege | Access auditing | Access revocation |

## Security Checklist

### Pre-Deployment

- [ ] **Certificate Management**
  - [ ] CA certificate generated and secured
  - [ ] Server certificates generated with proper SANs
  - [ ] Client certificates generated for each service
  - [ ] Certificate validation implemented
  - [ ] Certificate rotation process automated

- [ ] **Configuration Security**
  - [ ] mTLS enabled and enforced
  - [ ] Strong magic cookie configured
  - [ ] Transport encryption verified
  - [ ] Secure default configuration applied
  - [ ] Environment variables secured

- [ ] **Network Security**
  - [ ] Firewall rules configured
  - [ ] Network segmentation implemented
  - [ ] Load balancer security configured
  - [ ] VPN/private network setup

### Deployment

- [ ] **Container Security**
  - [ ] Non-root user configured
  - [ ] Read-only filesystem
  - [ ] Minimal capabilities
  - [ ] Resource limits set
  - [ ] Security contexts applied

- [ ] **Secret Management**
  - [ ] Secrets stored in secure vault
  - [ ] No secrets in environment variables
  - [ ] Secure secret rotation process
  - [ ] Access controls on secrets

### Post-Deployment

- [ ] **Monitoring**
  - [ ] Security audit logging enabled
  - [ ] Intrusion detection configured
  - [ ] Rate limiting monitored
  - [ ] Certificate expiry monitoring
  - [ ] Anomaly detection alerts

- [ ] **Operational Security**
  - [ ] Regular security updates
  - [ ] Certificate rotation testing
  - [ ] Incident response procedures
  - [ ] Security training completed
  - [ ] Penetration testing scheduled

### Ongoing Maintenance

- [ ] **Regular Reviews**
  - [ ] Monthly security reviews
  - [ ] Quarterly penetration testing
  - [ ] Annual security audits
  - [ ] Continuous compliance monitoring
  - [ ] Security metrics tracking

This comprehensive security guide ensures `pyvider-rpcplugin` deployments maintain the highest security standards while providing practical implementation guidance for development and operations teams.

### Auto-mTLS with Self-Signed Certificates (No Explicit Configuration)

When `PLUGIN_AUTO_MTLS` is set to `true` (either explicitly or by default) and no specific certificate paths (`PLUGIN_SERVER_CERT`, `PLUGIN_SERVER_KEY`, `PLUGIN_CLIENT_CERT`, `PLUGIN_CLIENT_KEY`, `PLUGIN_CLIENT_ROOT_CERTS`, `PLUGIN_SERVER_ROOT_CERTS`) are provided in the configuration:

1.  **Server-Side Auto-Generation:**
    *   The `RPCPluginServer` will automatically generate an ephemeral, self-signed server certificate and private key.
    *   Importantly, this auto-generated server certificate is created with `BasicConstraints(is_ca=True)`, allowing it to also function as a Certificate Authority (CA).

2.  **Client-Side Auto-Generation:**
    *   If the `RPCPluginClient` is also configured for `PLUGIN_AUTO_MTLS=True` and does not have explicit client certificates (`PLUGIN_CLIENT_CERT`, `PLUGIN_CLIENT_KEY`) or server root CAs (`PLUGIN_SERVER_ROOT_CERTS`) configured, it will also auto-generate an ephemeral, self-signed client certificate and private key.

3.  **Trust Establishment (Server Authentication Only):**
    *   During the handshake, the client receives the server's auto-generated, self-signed certificate.
    *   The client, upon receiving the server's auto-generated certificate in the handshake, will use this certificate as its ad-hoc root CA to validate the server. This establishes server authentication.
    *   **Client Authentication (Behavior):**
        *   If the client also auto-generates its certificate (because `PLUGIN_AUTO_MTLS=True` and no `PLUGIN_CLIENT_CERT`/`PLUGIN_CLIENT_KEY` are provided for it), it *will* use this auto-generated certificate during the TLS handshake.
        *   The server, having auto-generated its own cert (which acts as its own CA) and not having `PLUGIN_CLIENT_ROOT_CERTS` configured to specify external CAs for client verification, will typically *not* be configured to require and validate client certificates against a specific CA set.
        *   However, gRPC server-side TLS can be configured to `request` client certificates without `requiring` them and validating against a specific CA. If a client presents a certificate (even self-signed and auto-generated), it might be available to the server application layer for inspection (e.g., via `context.peer_identity_key()`).
    *   **Effective Security Level**: This setup primarily ensures **server authentication** (client validates the server using the server's self-signed cert) and **encryption**. True mutual authentication (where the server cryptographically verifies the client against a trusted CA) is not achieved unless the server is configured with `PLUGIN_CLIENT_ROOT_CERTS` and the client presents a certificate signed by a CA listed in those roots. If `PLUGIN_CLIENT_ROOT_CERTS` is *not* set on the server, it usually won't strictly require valid client certs.

This auto-mTLS behavior with self-signed certificates provides encrypted communication and server identity verification (based on the ephemeral, self-signed server cert) without manual certificate setup. It's suitable for development or scenarios where client and server are launched in a trusted, controlled environment.

**For production environments requiring strong, verifiable mutual authentication:**
- Generate a proper CA.
- Issue server and client certificates signed by this CA.
- Configure `PLUGIN_SERVER_CERT`, `PLUGIN_SERVER_KEY` on the server.
- Configure `PLUGIN_CLIENT_ROOT_CERTS` on the server (with your CA's cert) to enable client certificate validation.
- Configure `PLUGIN_CLIENT_CERT`, `PLUGIN_CLIENT_KEY` on the client.
- Configure `PLUGIN_SERVER_ROOT_CERTS` on the client (with your CA's cert) to validate the server.
This ensures both parties cryptographically verify each other against a common trusted authority.
