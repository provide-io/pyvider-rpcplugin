# mTLS Configuration

Configure mutual TLS (mTLS) authentication for secure plugin communication. mTLS provides bidirectional authentication and encrypted channels between clients and servers.

## Overview

mTLS (mutual TLS) ensures that both client and server authenticate each other using X.509 certificates. This provides:

- **Mutual Authentication** - Both sides verify each other's identity
- **Encrypted Communication** - All data is encrypted in transit
- **Certificate-Based Identity** - Identity tied to cryptographic certificates
- **Non-repudiation** - Cryptographic proof of communication participants

```python
from pyvider.rpcplugin import plugin_server, plugin_client
from provide.foundation.crypto import Certificate

async def mtls_example():
    """Basic mTLS setup for server and client."""
    
    # Server with mTLS enabled
    server = plugin_server(
        services=[MyService()],
        enable_mtls=True,
        server_cert="server.pem",
        server_key="server.key", 
        ca_cert="ca.pem",
        require_client_cert=True  # Enforce client certificates
    )
    
    try:
        await server.start()
        print("🔒 mTLS server started")
        
        # Client with mTLS certificate
        async with plugin_client(
            host="127.0.0.1",
            port=server.port,
            enable_mtls=True,
            client_cert="client.pem",
            client_key="client.key",
            ca_cert="ca.pem"
        ) as client:
            
            result = await client.service.SecureMethod(data="sensitive")
            print(f"✅ Secure communication: {result.response}")
    
    finally:
        await server.stop()

# Usage
await mtls_example()
```

## Certificate Generation

### Creating a Certificate Authority (CA)

```python
from provide.foundation.crypto import Certificate
import asyncio

async def create_certificate_authority():
    """Create a new Certificate Authority for mTLS."""
    
    # Generate CA certificate
    ca_cert = await Certificate.generate_self_signed(
        common_name="Plugin CA",
        organization="My Company",
        country="US",
        validity_days=3650,  # 10 years
        key_size=4096
    )
    
    # Save CA certificate and private key
    await ca_cert.save_certificate("ca.pem")
    await ca_cert.save_private_key("ca.key")
    
    print("✅ CA certificate created: ca.pem")
    print("✅ CA private key created: ca.key")
    
    return ca_cert

# Usage
ca_cert = await create_certificate_authority()
```

### Generating Server Certificates

```python
async def create_server_certificate(ca_cert: Certificate):
    """Create server certificate signed by CA."""
    
    # Generate server certificate request
    server_cert = await Certificate.generate_certificate_request(
        common_name="plugin-server.local",
        organization="My Company", 
        country="US",
        subject_alternative_names=[
            "DNS:localhost",
            "DNS:plugin-server.local",
            "IP:127.0.0.1",
            "IP:::1"
        ],
        key_size=2048
    )
    
    # Sign with CA
    signed_server_cert = await ca_cert.sign_certificate(
        server_cert,
        validity_days=365,  # 1 year
        key_usage=["key_encipherment", "digital_signature"],
        extended_key_usage=["server_auth"]
    )
    
    # Save server certificate and key
    await signed_server_cert.save_certificate("server.pem")
    await signed_server_cert.save_private_key("server.key")
    
    print("✅ Server certificate created: server.pem")
    print("✅ Server private key created: server.key")
    
    return signed_server_cert

# Usage
server_cert = await create_server_certificate(ca_cert)
```

### Generating Client Certificates

```python
async def create_client_certificate(ca_cert: Certificate, client_name: str = "plugin-client"):
    """Create client certificate signed by CA."""
    
    # Generate client certificate request
    client_cert = await Certificate.generate_certificate_request(
        common_name=f"{client_name}@my-company.com",
        organization="My Company",
        organizational_unit="Plugin Clients",
        country="US",
        key_size=2048
    )
    
    # Sign with CA
    signed_client_cert = await ca_cert.sign_certificate(
        client_cert,
        validity_days=90,   # 3 months for client certs
        key_usage=["digital_signature", "key_agreement"],
        extended_key_usage=["client_auth"]
    )
    
    # Save client certificate and key
    client_cert_path = f"{client_name}.pem"
    client_key_path = f"{client_name}.key"
    
    await signed_client_cert.save_certificate(client_cert_path)
    await signed_client_cert.save_private_key(client_key_path)
    
    print(f"✅ Client certificate created: {client_cert_path}")
    print(f"✅ Client private key created: {client_key_path}")
    
    return signed_client_cert

# Usage  
client_cert = await create_client_certificate(ca_cert, "payment-processor")
```

## Server mTLS Configuration

### Basic mTLS Server

```python
from pyvider.rpcplugin import plugin_server
from pathlib import Path

class SecureServer:
    """Plugin server with comprehensive mTLS configuration."""
    
    def __init__(self, cert_dir: str = "./certs"):
        self.cert_dir = Path(cert_dir)
        
        # Certificate paths
        self.server_cert = self.cert_dir / "server.pem"
        self.server_key = self.cert_dir / "server.key"
        self.ca_cert = self.cert_dir / "ca.pem"
        
        # Validate certificates exist
        self._validate_certificates()
    
    def _validate_certificates(self):
        """Validate that all required certificates exist."""
        
        required_certs = [self.server_cert, self.server_key, self.ca_cert]
        
        for cert_path in required_certs:
            if not cert_path.exists():
                raise FileNotFoundError(f"Required certificate not found: {cert_path}")
        
        print("✅ All required certificates found")
    
    async def create_server(self, services: list, port: int = 0) -> plugin_server:
        """Create mTLS-enabled server."""
        
        server = plugin_server(
            services=services,
            port=port,
            
            # mTLS Configuration
            enable_mtls=True,
            server_cert=str(self.server_cert),
            server_key=str(self.server_key),
            ca_cert=str(self.ca_cert),
            
            # Security settings
            require_client_cert=True,        # Mandatory client certificates
            verify_client_cert=True,         # Verify client cert against CA
            cipher_suites=self._get_secure_cipher_suites(),
            min_tls_version="TLSv1.2",      # Minimum TLS version
            max_tls_version="TLSv1.3",      # Maximum TLS version
            
            # Advanced options
            client_cert_verify_depth=3,      # Certificate chain depth
            enable_cert_revocation_check=True,  # Check certificate revocation
            cert_reloading=True              # Enable certificate reloading
        )
        
        return server
    
    def _get_secure_cipher_suites(self) -> list[str]:
        """Get list of secure cipher suites."""
        
        return [
            # TLS 1.3 cipher suites (preferred)
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            
            # TLS 1.2 cipher suites (fallback)
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-CHACHA20-POLY1305",
            "ECDHE-ECDSA-AES128-GCM-SHA256"
        ]

# Example service with security decorators
from pyvider.rpcplugin.decorators import require_client_cert, audit_log

class SecurePaymentService:
    """Example secure service with mTLS requirements."""
    
    @require_client_cert(cn_pattern="payment-.*@my-company.com")
    @audit_log(operation="process_payment")
    async def ProcessPayment(self, request, context):
        """Process payment with certificate-based authorization."""
        
        # Extract client certificate information
        client_cert_info = context.peer_certificates[0]
        client_id = client_cert_info.common_name
        
        print(f"🔒 Processing payment for authenticated client: {client_id}")
        
        # Process payment logic here
        transaction_id = f"txn_{hash(request.amount + request.currency)}"
        
        return PaymentResponse(
            transaction_id=transaction_id,
            status="completed",
            client_id=client_id
        )
    
    @require_client_cert(organization="My Company")
    @audit_log(operation="get_balance")
    async def GetBalance(self, request, context):
        """Get account balance with organization-based access."""
        
        client_cert = context.peer_certificates[0]
        
        if client_cert.organization != "My Company":
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "Invalid organization")
        
        return BalanceResponse(
            account_id=request.account_id,
            balance=1000.00,
            currency="USD"
        )

# Usage example
async def secure_server_example():
    """Example of secure mTLS server setup."""
    
    secure_server = SecureServer(cert_dir="./production_certs")
    
    # Create services
    payment_service = SecurePaymentService()
    
    # Create and start server
    server = await secure_server.create_server([payment_service], port=8443)
    
    try:
        await server.start()
        print(f"🔒 Secure server started on port {server.port}")
        
        # Keep server running
        await asyncio.sleep(60)  # Run for 1 minute
    
    finally:
        await server.stop()
        print("🔌 Secure server stopped")

# Usage
await secure_server_example()
```

### Advanced Security Features

```python
from typing import Dict, List, Optional, Callable
from datetime import datetime, timedelta
import hashlib

class AdvancedSecurityServer:
    """Server with advanced mTLS security features."""
    
    def __init__(self, cert_dir: str = "./certs"):
        self.cert_dir = Path(cert_dir)
        
        # Certificate revocation list
        self.revoked_certificates: set[str] = set()
        
        # Client certificate allowlist
        self.allowed_certificates: Dict[str, Dict] = {}
        
        # Rate limiting per certificate
        self.cert_rate_limits: Dict[str, List[datetime]] = {}
        
        # Audit log
        self.audit_events: List[Dict] = []
    
    async def load_certificate_allowlist(self, allowlist_file: str):
        """Load allowed client certificates from file."""
        
        allowlist_path = Path(allowlist_file)
        if not allowlist_path.exists():
            print(f"⚠️  Allowlist file not found: {allowlist_file}")
            return
        
        with open(allowlist_path) as f:
            import json
            allowlist_data = json.load(f)
        
        for cert_info in allowlist_data.get("allowed_certificates", []):
            cert_fingerprint = cert_info["fingerprint"]
            self.allowed_certificates[cert_fingerprint] = {
                "common_name": cert_info["common_name"],
                "organization": cert_info.get("organization", ""),
                "permissions": cert_info.get("permissions", []),
                "valid_until": cert_info.get("valid_until"),
                "rate_limit": cert_info.get("rate_limit", 100)  # requests per minute
            }
        
        print(f"✅ Loaded {len(self.allowed_certificates)} allowed certificates")
    
    async def validate_client_certificate(self, cert_fingerprint: str) -> bool:
        """Validate client certificate against allowlist and revocation list."""
        
        # Check if certificate is revoked
        if cert_fingerprint in self.revoked_certificates:
            self._audit_log("certificate_revoked", {"fingerprint": cert_fingerprint})
            return False
        
        # Check if certificate is in allowlist
        if cert_fingerprint not in self.allowed_certificates:
            self._audit_log("certificate_not_allowed", {"fingerprint": cert_fingerprint})
            return False
        
        # Check certificate expiry
        cert_info = self.allowed_certificates[cert_fingerprint]
        if cert_info.get("valid_until"):
            valid_until = datetime.fromisoformat(cert_info["valid_until"])
            if datetime.now() > valid_until:
                self._audit_log("certificate_expired", {"fingerprint": cert_fingerprint})
                return False
        
        # Check rate limiting
        if not self._check_rate_limit(cert_fingerprint):
            self._audit_log("rate_limit_exceeded", {"fingerprint": cert_fingerprint})
            return False
        
        self._audit_log("certificate_validated", {"fingerprint": cert_fingerprint})
        return True
    
    def _check_rate_limit(self, cert_fingerprint: str) -> bool:
        """Check if certificate is within rate limits."""
        
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        
        # Get recent requests for this certificate
        if cert_fingerprint not in self.cert_rate_limits:
            self.cert_rate_limits[cert_fingerprint] = []
        
        recent_requests = self.cert_rate_limits[cert_fingerprint]
        
        # Remove old requests
        recent_requests[:] = [req_time for req_time in recent_requests if req_time > minute_ago]
        
        # Check rate limit
        cert_info = self.allowed_certificates.get(cert_fingerprint, {})
        rate_limit = cert_info.get("rate_limit", 100)
        
        if len(recent_requests) >= rate_limit:
            return False
        
        # Record this request
        recent_requests.append(now)
        return True
    
    def _audit_log(self, event_type: str, data: Dict):
        """Log security audit event."""
        
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "data": data
        }
        
        self.audit_events.append(event)
        print(f"🔍 Security audit: {event_type} - {data}")
    
    async def create_advanced_secure_server(self, services: list, port: int = 0):
        """Create server with advanced security features."""
        
        # Custom certificate validator
        async def custom_cert_validator(certificate, context):
            """Custom certificate validation logic."""
            
            # Calculate certificate fingerprint
            cert_der = certificate.public_bytes_der()
            fingerprint = hashlib.sha256(cert_der).hexdigest()
            
            # Validate certificate
            is_valid = await self.validate_client_certificate(fingerprint)
            
            if not is_valid:
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Certificate validation failed")
            
            # Add certificate info to context
            context.cert_fingerprint = fingerprint
            context.cert_info = self.allowed_certificates.get(fingerprint, {})
        
        # Create server with advanced security
        server = plugin_server(
            services=services,
            port=port,
            
            # Basic mTLS
            enable_mtls=True,
            server_cert=str(self.cert_dir / "server.pem"),
            server_key=str(self.cert_dir / "server.key"),
            ca_cert=str(self.cert_dir / "ca.pem"),
            
            # Advanced security
            require_client_cert=True,
            custom_cert_validator=custom_cert_validator,
            
            # Security options
            enable_session_resumption=False,  # Disable for maximum security
            enable_renegotiation=False,       # Prevent renegotiation attacks
            compression_disabled=True,        # Prevent CRIME attacks
            
            # Monitoring
            enable_security_monitoring=True,
            security_event_handler=self._handle_security_event
        )
        
        return server
    
    async def _handle_security_event(self, event_type: str, event_data: Dict):
        """Handle security monitoring events."""
        
        if event_type == "failed_handshake":
            self._audit_log("tls_handshake_failed", event_data)
        elif event_type == "certificate_error":
            self._audit_log("certificate_validation_error", event_data)
        elif event_type == "suspicious_activity":
            self._audit_log("suspicious_activity_detected", event_data)
    
    def get_security_report(self) -> Dict:
        """Generate security report."""
        
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        
        recent_events = [
            event for event in self.audit_events
            if datetime.fromisoformat(event["timestamp"]) > hour_ago
        ]
        
        # Count events by type
        event_counts = {}
        for event in recent_events:
            event_type = event["event_type"]
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        
        return {
            "timestamp": now.isoformat(),
            "total_allowed_certificates": len(self.allowed_certificates),
            "revoked_certificates": len(self.revoked_certificates),
            "recent_events_count": len(recent_events),
            "event_breakdown": event_counts,
            "active_rate_limited_clients": len(self.cert_rate_limits),
            "recent_audit_events": recent_events[-10:]  # Last 10 events
        }

# Usage example
async def advanced_security_example():
    """Example with advanced mTLS security."""
    
    security_server = AdvancedSecurityServer("./production_certs")
    
    # Load certificate allowlist
    await security_server.load_certificate_allowlist("./cert_allowlist.json")
    
    # Create secure services
    payment_service = SecurePaymentService()
    
    # Create server with advanced security
    server = await security_server.create_advanced_secure_server(
        services=[payment_service],
        port=8443
    )
    
    try:
        await server.start()
        print(f"🔒 Advanced secure server started on port {server.port}")
        
        # Run server and periodically report security status
        for i in range(6):  # Run for 30 seconds
            await asyncio.sleep(5)
            
            # Generate security report
            report = security_server.get_security_report()
            print(f"📊 Security Report #{i+1}:")
            print(f"  Recent events: {report['recent_events_count']}")
            print(f"  Event breakdown: {report['event_breakdown']}")
    
    finally:
        await server.stop()
        
        # Final security report
        final_report = security_server.get_security_report()
        print("📈 Final Security Report:")
        print(f"  Total allowed certificates: {final_report['total_allowed_certificates']}")
        print(f"  Recent security events: {final_report['recent_events_count']}")

# Usage
await advanced_security_example()
```

## Client mTLS Configuration

### Basic mTLS Client

```python
from pyvider.rpcplugin import plugin_client
from pathlib import Path
import ssl

class SecureClient:
    """Plugin client with comprehensive mTLS support."""
    
    def __init__(self, cert_dir: str = "./certs"):
        self.cert_dir = Path(cert_dir)
        
        # Certificate paths
        self.client_cert = self.cert_dir / "client.pem"
        self.client_key = self.cert_dir / "client.key"
        self.ca_cert = self.cert_dir / "ca.pem"
        
        # Validate certificates exist
        self._validate_certificates()
    
    def _validate_certificates(self):
        """Validate that all required certificates exist."""
        
        required_certs = [self.client_cert, self.client_key, self.ca_cert]
        
        for cert_path in required_certs:
            if not cert_path.exists():
                raise FileNotFoundError(f"Required certificate not found: {cert_path}")
        
        print("✅ All required client certificates found")
    
    async def connect(self, host: str, port: int, **kwargs) -> plugin_client:
        """Create secure mTLS connection to server."""
        
        client = plugin_client(
            host=host,
            port=port,
            
            # mTLS Configuration
            enable_mtls=True,
            client_cert=str(self.client_cert),
            client_key=str(self.client_key),
            ca_cert=str(self.ca_cert),
            
            # TLS settings
            verify_server_cert=True,           # Verify server certificate
            check_hostname=True,               # Verify server hostname
            min_tls_version="TLSv1.2",        # Minimum TLS version
            max_tls_version="TLSv1.3",        # Maximum TLS version
            cipher_suites=self._get_secure_cipher_suites(),
            
            # Connection security
            enable_compression=False,          # Disable compression for security
            enable_session_resumption=False,   # Disable session resumption
            
            # Verification options
            cert_verify_mode=ssl.CERT_REQUIRED,  # Require server certificate
            check_revocation=True,             # Check certificate revocation
            
            **kwargs
        )
        
        return client
    
    def _get_secure_cipher_suites(self) -> list[str]:
        """Get secure cipher suites for client."""
        
        return [
            # TLS 1.3 (preferred)
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
            
            # TLS 1.2 (fallback)
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-RSA-CHACHA20-POLY1305",
            "ECDHE-RSA-AES128-GCM-SHA256"
        ]
    
    async def secure_call(self, host: str, port: int, 
                         service_method: str, **kwargs):
        """Make secure call with automatic connection management."""
        
        async with self.connect(host, port) as client:
            # Verify secure connection
            connection_info = client.get_connection_info()
            
            print(f"🔒 Secure connection established:")
            print(f"  TLS Version: {connection_info.tls_version}")
            print(f"  Cipher Suite: {connection_info.cipher_suite}")
            print(f"  Server Certificate: {connection_info.server_cert_subject}")
            
            # Make RPC call
            service_name, method_name = service_method.split('.')
            service = getattr(client, service_name.lower())
            method = getattr(service, method_name)
            
            return await method(**kwargs)

# Usage example
async def secure_client_example():
    """Example of secure mTLS client."""
    
    secure_client = SecureClient("./production_certs")
    
    try:
        # Make secure payment call
        result = await secure_client.secure_call(
            host="plugin-server.my-company.com",
            port=8443,
            service_method="payment.ProcessPayment",
            amount=100.00,
            currency="USD",
            payment_method="credit_card"
        )
        
        print(f"✅ Payment processed: {result.transaction_id}")
        
        # Make secure balance inquiry
        balance = await secure_client.secure_call(
            host="plugin-server.my-company.com",
            port=8443,
            service_method="payment.GetBalance",
            account_id="acc_123456"
        )
        
        print(f"💰 Account balance: {balance.balance} {balance.currency}")
    
    except Exception as e:
        print(f"❌ Secure communication failed: {e}")

# Usage
await secure_client_example()
```

### Client Certificate Management

```python
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

class ClientCertificateManager:
    """Manages client certificates with automatic renewal."""
    
    def __init__(self, cert_dir: str, ca_cert_path: str, ca_key_path: str):
        self.cert_dir = Path(cert_dir)
        self.ca_cert_path = Path(ca_cert_path)
        self.ca_key_path = Path(ca_key_path)
        
        # Certificate store
        self.certificates: Dict[str, Certificate] = {}
        
        # Renewal settings
        self.renewal_threshold = timedelta(days=30)  # Renew 30 days before expiry
        self.renewal_check_interval = timedelta(hours=12)  # Check every 12 hours
        self.last_renewal_check = datetime.now()
    
    async def get_or_create_certificate(self, client_id: str, 
                                      common_name: str = None,
                                      organization: str = None,
                                      validity_days: int = 90) -> tuple[str, str]:
        """Get existing certificate or create new one."""
        
        cert_path = self.cert_dir / f"{client_id}.pem"
        key_path = self.cert_dir / f"{client_id}.key"
        
        # Check if certificate exists and is valid
        if cert_path.exists() and key_path.exists():
            try:
                cert = await Certificate.load_from_file(cert_path)
                
                # Check if certificate is still valid
                if cert.not_after > datetime.now() + self.renewal_threshold:
                    print(f"✅ Using existing certificate for {client_id}")
                    return str(cert_path), str(key_path)
                else:
                    print(f"🔄 Certificate for {client_id} needs renewal")
            
            except Exception as e:
                print(f"⚠️  Error loading certificate for {client_id}: {e}")
        
        # Create new certificate
        return await self._create_new_certificate(
            client_id, common_name, organization, validity_days
        )
    
    async def _create_new_certificate(self, client_id: str,
                                    common_name: str = None,
                                    organization: str = None,
                                    validity_days: int = 90) -> tuple[str, str]:
        """Create new client certificate."""
        
        # Load CA certificate
        ca_cert = await Certificate.load_from_file(self.ca_cert_path, self.ca_key_path)
        
        # Set default values
        if not common_name:
            common_name = f"{client_id}@my-company.com"
        if not organization:
            organization = "My Company"
        
        # Generate new certificate
        client_cert = await Certificate.generate_certificate_request(
            common_name=common_name,
            organization=organization,
            organizational_unit="Plugin Clients",
            country="US",
            key_size=2048
        )
        
        # Sign with CA
        signed_cert = await ca_cert.sign_certificate(
            client_cert,
            validity_days=validity_days,
            key_usage=["digital_signature", "key_agreement"],
            extended_key_usage=["client_auth"]
        )
        
        # Save certificate and key
        cert_path = self.cert_dir / f"{client_id}.pem"
        key_path = self.cert_dir / f"{client_id}.key"
        
        await signed_cert.save_certificate(cert_path)
        await signed_cert.save_private_key(key_path)
        
        # Store in memory
        self.certificates[client_id] = signed_cert
        
        print(f"✅ Created new certificate for {client_id}")
        print(f"   Certificate: {cert_path}")
        print(f"   Private key: {key_path}")
        print(f"   Valid until: {signed_cert.not_after}")
        
        return str(cert_path), str(key_path)
    
    async def check_and_renew_certificates(self):
        """Check all certificates and renew if needed."""
        
        now = datetime.now()
        
        # Only check if enough time has passed
        if now - self.last_renewal_check < self.renewal_check_interval:
            return
        
        self.last_renewal_check = now
        print("🔍 Checking certificates for renewal...")
        
        # Check all certificate files
        for cert_file in self.cert_dir.glob("*.pem"):
            client_id = cert_file.stem
            
            try:
                cert = await Certificate.load_from_file(cert_file)
                
                # Check if renewal is needed
                if cert.not_after <= now + self.renewal_threshold:
                    print(f"🔄 Renewing certificate for {client_id}")
                    
                    await self._create_new_certificate(
                        client_id,
                        common_name=cert.subject.common_name,
                        organization=cert.subject.organization,
                        validity_days=90
                    )
                    
                else:
                    days_until_expiry = (cert.not_after - now).days
                    print(f"✅ Certificate for {client_id} valid for {days_until_expiry} more days")
            
            except Exception as e:
                print(f"❌ Error checking certificate {cert_file}: {e}")
    
    async def revoke_certificate(self, client_id: str):
        """Revoke a client certificate."""
        
        cert_path = self.cert_dir / f"{client_id}.pem"
        key_path = self.cert_dir / f"{client_id}.key"
        
        # Move to revoked directory
        revoked_dir = self.cert_dir / "revoked"
        revoked_dir.mkdir(exist_ok=True)
        
        if cert_path.exists():
            cert_path.rename(revoked_dir / f"{client_id}_{int(datetime.now().timestamp())}.pem")
        
        if key_path.exists():
            key_path.rename(revoked_dir / f"{client_id}_{int(datetime.now().timestamp())}.key")
        
        # Remove from memory
        self.certificates.pop(client_id, None)
        
        print(f"🚫 Certificate for {client_id} revoked")
    
    def get_certificate_status(self, client_id: str) -> Optional[Dict[str, Any]]:
        """Get status information for a certificate."""
        
        cert_path = self.cert_dir / f"{client_id}.pem"
        
        if not cert_path.exists():
            return None
        
        try:
            cert = Certificate.load_from_file(cert_path)
            
            now = datetime.now()
            days_until_expiry = (cert.not_after - now).days
            needs_renewal = cert.not_after <= now + self.renewal_threshold
            
            return {
                "client_id": client_id,
                "subject": {
                    "common_name": cert.subject.common_name,
                    "organization": cert.subject.organization
                },
                "valid_from": cert.not_before,
                "valid_until": cert.not_after,
                "days_until_expiry": days_until_expiry,
                "needs_renewal": needs_renewal,
                "is_expired": now > cert.not_after,
                "fingerprint": cert.fingerprint_sha256,
                "serial_number": cert.serial_number
            }
        
        except Exception as e:
            return {"error": str(e)}

# Usage example
async def certificate_management_example():
    """Example of client certificate management."""
    
    # Initialize certificate manager
    cert_manager = ClientCertificateManager(
        cert_dir="./client_certs",
        ca_cert_path="./ca.pem",
        ca_key_path="./ca.key"
    )
    
    # Get or create certificates for multiple clients
    clients = ["payment-processor", "order-manager", "inventory-service"]
    
    client_certs = {}
    
    for client_id in clients:
        cert_path, key_path = await cert_manager.get_or_create_certificate(
            client_id=client_id,
            common_name=f"{client_id}.my-company.com",
            organization="My Company",
            validity_days=180  # 6 months
        )
        
        client_certs[client_id] = (cert_path, key_path)
    
    # Check certificate renewal status
    await cert_manager.check_and_renew_certificates()
    
    # Get status for all certificates
    print("\n📊 Certificate Status Report:")
    for client_id in clients:
        status = cert_manager.get_certificate_status(client_id)
        if status:
            print(f"\n{client_id}:")
            print(f"  Common Name: {status['subject']['common_name']}")
            print(f"  Valid Until: {status['valid_until']}")
            print(f"  Days Until Expiry: {status['days_until_expiry']}")
            print(f"  Needs Renewal: {status['needs_renewal']}")
            print(f"  Fingerprint: {status['fingerprint'][:16]}...")
    
    # Example: Use certificate with secure client
    payment_cert, payment_key = client_certs["payment-processor"]
    
    client = plugin_client(
        host="secure-server.my-company.com",
        port=8443,
        enable_mtls=True,
        client_cert=payment_cert,
        client_key=payment_key,
        ca_cert="./ca.pem"
    )
    
    # Make secure call
    async with client:
        result = await client.payment.ProcessPayment(
            amount=500.00,
            currency="USD"
        )
        print(f"✅ Secure payment processed: {result.transaction_id}")

# Usage
await certificate_management_example()
```

## Production Deployment

### Container Deployment

```dockerfile
# Dockerfile for secure plugin server
FROM python:3.11-slim

WORKDIR /app

# Install security updates
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Create certificate directories with proper permissions
RUN mkdir -p /app/certs /app/private && \
    chmod 755 /app/certs && \
    chmod 700 /app/private

# Copy application
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash plugin && \
    chown -R plugin:plugin /app

USER plugin

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import grpc; grpc.channel_ready_future(grpc.insecure_channel('localhost:8080')).result(timeout=5)"

EXPOSE 8443

CMD ["python", "-m", "my_plugin_server", "--mtls", "--port=8443"]
```

### Kubernetes Deployment

```yaml
# k8s-secure-plugin.yaml
apiVersion: v1
kind: Secret
metadata:
  name: plugin-tls-certs
type: kubernetes.io/tls
data:
  tls.crt: # Base64 encoded server certificate
  tls.key: # Base64 encoded server private key
  ca.crt: # Base64 encoded CA certificate

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: plugin-security-config
data:
  cert_allowlist.json: |
    {
      "allowed_certificates": [
        {
          "fingerprint": "sha256:abc123...",
          "common_name": "payment-processor@my-company.com",
          "organization": "My Company",
          "permissions": ["process_payment", "get_balance"],
          "rate_limit": 100
        }
      ]
    }

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-plugin-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-plugin-server
  template:
    metadata:
      labels:
        app: secure-plugin-server
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: plugin-server
        image: my-company/secure-plugin-server:latest
        ports:
        - containerPort: 8443
          name: https
        env:
        - name: SERVER_CERT
          value: "/certs/tls.crt"
        - name: SERVER_KEY
          value: "/certs/tls.key"
        - name: CA_CERT
          value: "/certs/ca.crt"
        - name: CERT_ALLOWLIST
          value: "/config/cert_allowlist.json"
        volumeMounts:
        - name: tls-certs
          mountPath: /certs
          readOnly: true
        - name: security-config
          mountPath: /config
          readOnly: true
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "250m"
        livenessProbe:
          exec:
            command:
            - python
            - -c
            - "import grpc; grpc.channel_ready_future(grpc.insecure_channel('localhost:8443')).result(timeout=5)"
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          exec:
            command:
            - python
            - -c
            - "import grpc; grpc.channel_ready_future(grpc.insecure_channel('localhost:8443')).result(timeout=2)"
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: tls-certs
        secret:
          secretName: plugin-tls-certs
          defaultMode: 0400
      - name: security-config
        configMap:
          name: plugin-security-config

---
apiVersion: v1
kind: Service
metadata:
  name: secure-plugin-service
spec:
  selector:
    app: secure-plugin-server
  ports:
  - port: 8443
    targetPort: 8443
    name: https
  type: LoadBalancer
```

## Best Practices

### Security Checklist

```python
class SecurityAudit:
    """Security audit checklist for mTLS deployment."""
    
    @staticmethod
    def audit_certificates(cert_dir: str) -> Dict[str, Any]:
        """Audit certificate security."""
        
        audit_results = {
            "certificate_checks": [],
            "security_score": 0,
            "recommendations": [],
            "critical_issues": []
        }
        
        cert_dir_path = Path(cert_dir)
        
        # Check certificate files
        for cert_file in cert_dir_path.glob("*.pem"):
            cert_audit = SecurityAudit._audit_single_certificate(cert_file)
            audit_results["certificate_checks"].append(cert_audit)
        
        # Calculate overall security score
        if audit_results["certificate_checks"]:
            avg_score = sum(c["score"] for c in audit_results["certificate_checks"])
            audit_results["security_score"] = avg_score / len(audit_results["certificate_checks"])
        
        return audit_results
    
    @staticmethod
    def _audit_single_certificate(cert_file: Path) -> Dict[str, Any]:
        """Audit a single certificate file."""
        
        audit = {
            "certificate": str(cert_file),
            "checks": [],
            "score": 0,
            "issues": []
        }
        
        try:
            cert = Certificate.load_from_file(cert_file)
            
            # Check 1: Key size
            if cert.key_size >= 2048:
                audit["checks"].append("✅ Key size adequate (≥2048 bits)")
                audit["score"] += 20
            else:
                audit["checks"].append("❌ Key size inadequate (<2048 bits)")
                audit["issues"].append("Upgrade to at least 2048-bit keys")
            
            # Check 2: Validity period
            now = datetime.now()
            validity_period = cert.not_after - cert.not_before
            
            if validity_period <= timedelta(days=365):
                audit["checks"].append("✅ Certificate validity period reasonable (≤1 year)")
                audit["score"] += 15
            else:
                audit["checks"].append("⚠️  Certificate validity period too long (>1 year)")
                audit["issues"].append("Consider shorter certificate validity periods")
            
            # Check 3: Expiry
            days_until_expiry = (cert.not_after - now).days
            
            if days_until_expiry > 30:
                audit["checks"].append("✅ Certificate not expiring soon")
                audit["score"] += 10
            elif days_until_expiry > 0:
                audit["checks"].append("⚠️  Certificate expires within 30 days")
                audit["issues"].append("Schedule certificate renewal")
            else:
                audit["checks"].append("❌ Certificate expired")
                audit["issues"].append("CRITICAL: Certificate has expired")
            
            # Check 4: Signature algorithm
            if cert.signature_algorithm in ["sha256WithRSAEncryption", "ecdsa-with-SHA256"]:
                audit["checks"].append("✅ Strong signature algorithm")
                audit["score"] += 15
            else:
                audit["checks"].append("⚠️  Weak signature algorithm")
                audit["issues"].append("Use SHA-256 or stronger signature algorithm")
            
            # Check 5: Extensions
            if hasattr(cert, 'extensions') and cert.extensions:
                audit["checks"].append("✅ Certificate has extensions")
                audit["score"] += 10
            else:
                audit["checks"].append("⚠️  Certificate lacks extensions")
                audit["issues"].append("Add appropriate certificate extensions")
            
            # Check 6: Subject Alternative Names (for server certs)
            if cert.subject_alternative_names:
                audit["checks"].append("✅ Subject Alternative Names present")
                audit["score"] += 10
            
            # Check 7: Key usage
            if cert.key_usage:
                audit["checks"].append("✅ Key usage extension present")
                audit["score"] += 10
            
            # Check 8: Extended key usage
            if cert.extended_key_usage:
                audit["checks"].append("✅ Extended key usage extension present")
                audit["score"] += 10
        
        except Exception as e:
            audit["checks"].append(f"❌ Error loading certificate: {e}")
            audit["issues"].append(f"Certificate loading error: {e}")
        
        return audit
    
    @staticmethod
    def generate_security_report(audit_results: Dict[str, Any]) -> str:
        """Generate human-readable security report."""
        
        report = []
        report.append("🔒 mTLS Security Audit Report")
        report.append("=" * 40)
        
        # Overall score
        score = audit_results["security_score"]
        if score >= 80:
            score_icon = "✅"
            score_desc = "Excellent"
        elif score >= 60:
            score_icon = "⚠️"
            score_desc = "Good"
        else:
            score_icon = "❌"
            score_desc = "Needs Improvement"
        
        report.append(f"\nOverall Security Score: {score_icon} {score:.1f}/100 ({score_desc})")
        
        # Certificate details
        report.append(f"\n📋 Certificate Analysis:")
        report.append(f"  Certificates checked: {len(audit_results['certificate_checks'])}")
        
        for cert_audit in audit_results["certificate_checks"]:
            report.append(f"\n  📄 {Path(cert_audit['certificate']).name}:")
            report.append(f"     Score: {cert_audit['score']}/100")
            
            for check in cert_audit["checks"]:
                report.append(f"     {check}")
            
            if cert_audit["issues"]:
                report.append("     Issues:")
                for issue in cert_audit["issues"]:
                    report.append(f"     - {issue}")
        
        return "\n".join(report)

# Usage example
async def security_audit_example():
    """Example security audit."""
    
    # Audit certificates
    audit_results = SecurityAudit.audit_certificates("./production_certs")
    
    # Generate and print report
    report = SecurityAudit.generate_security_report(audit_results)
    print(report)
    
    # Check for critical issues
    all_issues = []
    for cert_audit in audit_results["certificate_checks"]:
        all_issues.extend(cert_audit["issues"])
    
    critical_issues = [issue for issue in all_issues if "CRITICAL" in issue]
    
    if critical_issues:
        print("\n🚨 CRITICAL SECURITY ISSUES:")
        for issue in critical_issues:
            print(f"  - {issue}")
    else:
        print("\n✅ No critical security issues found")

# Usage
await security_audit_example()
```

## Next Steps

- **[Certificate Management](certificates.md)** - Deep dive into certificate lifecycle management
- **[Magic Cookies](magic-cookies.md)** - Learn magic cookie authentication
- **[Process Isolation](process-isolation.md)** - Understand process-level security