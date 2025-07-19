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
    organization_name="My Example Corp",
    validity_days=1095  # e.g., 3 years for a root CA
)

# Save the CA certificate and its private key
ca_cert_path = cert_dir / "ca.crt"
ca_key_path = cert_dir / "ca.key"
with open(ca_cert_path, "w", encoding="utf-8") as f:
    f.write(ca_cert_obj.cert)
with open(ca_key_path, "w", encoding="utf-8") as f:
    if ca_cert_obj.key: # Key will be present for generated CA
        f.write(ca_cert_obj.key)
print(f"CA certificate saved to: {ca_cert_path}")
print(f"CA private key saved to: {ca_key_path} (KEEP THIS KEY VERY SECURE!)")


# Step 2: Create a Server Certificate signed by the CA
# The server certificate is used by the RPC server to identify itself to clients.
server_cert_obj = Certificate.create_signed_certificate(
    ca_certificate=ca_cert_obj,  # The CA object created above
    common_name="rpc-server.example.com",  # Primary domain name of the server
    organization_name="My Example Corp Servers",
    validity_days=90,  # Shorter validity for end-entity certificates
    alt_names=["rpc-server.internal.example.com", "localhost", "127.0.0.1"], # Subject Alternative Names
    is_client_cert=False  # This is a server certificate
)

# Save the server certificate and its private key
server_cert_path = cert_dir / "server.crt"
server_key_path = cert_dir / "server.key"
with open(server_cert_path, "w", encoding="utf-8") as f:
    f.write(server_cert_obj.cert)
with open(server_key_path, "w", encoding="utf-8") as f:
    if server_cert_obj.key:
        f.write(server_cert_obj.key)
print(f"Server certificate saved to: {server_cert_path}")
print(f"Server private key saved to: {server_key_path}")


# Step 3: Create a Client Certificate signed by the CA
# The client certificate is used by RPC clients to identify themselves to the server.
client_cert_obj = Certificate.create_signed_certificate(
    ca_certificate=ca_cert_obj,  # The CA object created above
    common_name="client-id-007",  # Unique identifier for the client
    organization_name="My Example Corp Clients",
    validity_days=30,  # Can be shorter for clients, or match operational needs
    is_client_cert=True  # This is a client certificate
    # alt_names can be added if the client might also act as a server or needs SANs
)

# Save the client certificate and its private key
client_cert_path = cert_dir / "client.crt"
client_key_path = cert_dir / "client.key"
with open(client_cert_path, "w", encoding="utf-8") as f:
    f.write(client_cert_obj.cert)
with open(client_key_path, "w", encoding="utf-8") as f:
    if client_cert_obj.key:
        f.write(client_cert_obj.key)
print(f"Client certificate saved to: {client_cert_path}")
print(f"Client private key saved to: {client_key_path}")

# Now you have a set of certificates for mTLS:
# - ca.crt: The CA certificate, used by both client and server to verify each other.
# - server.crt, server.key: The server's certificate and private key.
# - client.crt, client.key: The client's certificate and private key.
```

### Certificate Validation

Implement certificate validation:

```python
def validate_certificate_chain(cert_path: str, ca_path: str) -> bool:
    """Validate certificate against CA."""
    try:
        return Certificate.verify_certificate_chain(cert_path, ca_path)
    except Exception as e:
        logger.error("Certificate validation failed", error=str(e))
        return False

def check_certificate_expiry(cert_path: str, days_warning: int = 30) -> bool:
    """Check if certificate expires soon."""
    cert = Certificate.load_from_file(cert_path)
    days_until_expiry = cert.days_until_expiry()
    
    if days_until_expiry <= days_warning:
        logger.warning(
            "Certificate expiring soon",
            cert_path=cert_path,
            days_until_expiry=days_until_expiry
        )
        return True
    return False
```

### Certificate Rotation

Implement automated certificate rotation:

```python
import asyncio
from datetime import datetime, timedelta

class CertificateRotator:
    def __init__(self, ca_cert: Certificate):
        self.ca_cert = ca_cert
        self.rotation_threshold_days = 7
    
    async def rotate_certificate_if_needed(
        self, 
        cert_path: str,
        key_path: str,
        common_name: str,
        cert_type: str = "server"
    ) -> bool:
        """Rotate certificate if expiring soon."""
        
        current_cert = Certificate.load_from_file(cert_path)
        
        if current_cert.days_until_expiry() <= self.rotation_threshold_days:
            logger.info(
                "Rotating certificate",
                cert_path=cert_path,
                days_until_expiry=current_cert.days_until_expiry()
            )
            
            # Generate new certificate
            if cert_type == "server":
                new_cert = Certificate.create_signed_certificate( # Corrected method
                    ca_certificate=self.ca_cert, # Corrected parameter
                    common_name=common_name,
                    validity_days=90,
                    is_client_cert=False # Added parameter
                )
            else:
                new_cert = Certificate.create_signed_certificate( # Corrected method
                    ca_certificate=self.ca_cert, # Corrected parameter
                    common_name=common_name,
                    validity_days=30,
                    is_client_cert=True # Added parameter
                )
            
            # Atomic replacement
            temp_cert_path = f"{cert_path}.new"
            temp_key_path = f"{key_path}.new"
            
            new_cert.save_to_file(temp_cert_path, temp_key_path)
            
            # Atomic move
            os.rename(temp_cert_path, cert_path)
            os.rename(temp_key_path, key_path)
            
            logger.info("Certificate rotation completed", cert_path=cert_path)
            return True
        
        return False

# Setup automatic rotation
async def certificate_rotation_service():
    """Background service for certificate rotation."""
    
    rotator = CertificateRotator(ca_cert)
    
    while True:
        try:
            await rotator.rotate_certificate_if_needed(
                "/etc/ssl/certs/server.crt",
                "/etc/ssl/private/server.key", 
                "rpc-server.yourdomain.com",
                "server"
            )
            
            await rotator.rotate_certificate_if_needed(
                "/etc/ssl/certs/client.crt",
                "/etc/ssl/private/client.key",
                "rpc-client-001", 
                "client"
            )
            
        except Exception as e:
            logger.error("Certificate rotation failed", error=str(e))
        
        # Check daily
        await asyncio.sleep(24 * 60 * 60)
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

# Configure magic cookie (using correct PLUGIN_ prefixed keys)
configure(
    PLUGIN_MAGIC_COOKIE_VALUE="your-super-secret-cookie-value-2024",
    PLUGIN_PROTOCOL_VERSIONS=[1] # Protocol versions should be a list
)

# Magic cookie validation happens automatically during handshake if server/client use this config
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
    *   The client then uses this server certificate as its trusted root CA to validate the server.
    *   In this specific auto-generation scenario on both sides, the client *does not* present its own auto-generated client certificate to the server for validation.
    *   Similarly, the server, lacking specific `PLUGIN_CLIENT_ROOT_CERTS` to validate against, does not require or validate a client certificate.
    *   This results in a **server-only TLS authentication**, where the client verifies the server's identity using its auto-generated certificate, but the server does not authenticate the client via its certificate. The connection is still encrypted.

This behavior allows for secure, encrypted communication out-of-the-box without manual certificate setup, suitable for development or scenarios where both client and server are known entities launched within a controlled environment. For production scenarios requiring strict mutual client authentication, providing explicitly generated CA-signed certificates and configuring the appropriate root CAs on both client and server is recommended as detailed in other sections.
