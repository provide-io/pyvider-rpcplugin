# Certificate Management

Comprehensive guide to X.509 certificate lifecycle management for plugin security. Learn certificate generation, validation, rotation, revocation, and monitoring.

## Overview

Certificate management is critical for maintaining secure plugin communication. This includes creating certificate authorities, generating certificates, implementing automatic rotation, and monitoring certificate health.

```python
from provide.foundation.crypto import Certificate
from pathlib import Path
import asyncio
from datetime import datetime, timedelta

async def basic_certificate_workflow():
    """Basic certificate lifecycle example."""
    
    # 1. Create Certificate Authority
    ca_cert = await Certificate.generate_self_signed(
        common_name="My Plugin CA",
        organization="My Company",
        validity_days=3650  # 10 years for CA
    )
    
    # 2. Save CA certificate and key
    await ca_cert.save_certificate("ca.pem")
    await ca_cert.save_private_key("ca.key")
    
    # 3. Generate server certificate
    server_cert = await Certificate.generate_certificate_request(
        common_name="plugin-server.local",
        organization="My Company",
        subject_alternative_names=["DNS:localhost", "IP:127.0.0.1"]
    )
    
    # 4. Sign server certificate with CA
    signed_server_cert = await ca_cert.sign_certificate(
        server_cert,
        validity_days=365,
        extended_key_usage=["server_auth"]
    )
    
    # 5. Save server certificate
    await signed_server_cert.save_certificate("server.pem")
    await signed_server_cert.save_private_key("server.key")
    
    print("✅ Certificate workflow completed")
    print(f"   CA Certificate: ca.pem (expires: {ca_cert.not_after})")
    print(f"   Server Certificate: server.pem (expires: {signed_server_cert.not_after})")

# Usage
await basic_certificate_workflow()
```

## Certificate Authority Management

### Creating a Root CA

```python
from typing import Dict, List, Optional
from dataclasses import dataclass
import json
from pathlib import Path

@dataclass
class CAConfig:
    """Configuration for Certificate Authority."""
    
    common_name: str
    organization: str
    organizational_unit: str = "Plugin Security"
    country: str = "US"
    state: str = "CA"
    locality: str = "San Francisco"
    
    # Security settings
    key_size: int = 4096
    validity_days: int = 3650  # 10 years
    hash_algorithm: str = "sha256"
    
    # Path constraints
    max_path_length: Optional[int] = 0  # CA can't issue sub-CAs
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization."""
        return {
            "subject": {
                "common_name": self.common_name,
                "organization": self.organization,
                "organizational_unit": self.organizational_unit,
                "country": self.country,
                "state": self.state,
                "locality": self.locality
            },
            "key_size": self.key_size,
            "validity_days": self.validity_days,
            "hash_algorithm": self.hash_algorithm,
            "max_path_length": self.max_path_length
        }

class CertificateAuthority:
    """Certificate Authority for plugin ecosystem."""
    
    def __init__(self, config: CAConfig, ca_dir: str = "./ca"):
        self.config = config
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(exist_ok=True)
        
        # CA file paths
        self.ca_cert_path = self.ca_dir / "ca.pem"
        self.ca_key_path = self.ca_dir / "ca.key"
        self.ca_config_path = self.ca_dir / "ca_config.json"
        
        # Certificate tracking
        self.issued_certificates: Dict[str, Dict] = {}
        self.serial_number_counter = 1
        
        # Load existing CA if available
        self.ca_certificate: Optional[Certificate] = None
    
    async def initialize(self) -> Certificate:
        """Initialize or load existing CA."""
        
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            # Load existing CA
            print("📂 Loading existing CA certificate...")
            self.ca_certificate = await Certificate.load_from_file(
                self.ca_cert_path, 
                self.ca_key_path
            )
            
            # Load existing configuration and certificate registry
            await self._load_certificate_registry()
            
        else:
            # Create new CA
            print("🆕 Creating new CA certificate...")
            await self._create_new_ca()
        
        return self.ca_certificate
    
    async def _create_new_ca(self):
        """Create new Certificate Authority."""
        
        # Generate self-signed CA certificate
        self.ca_certificate = await Certificate.generate_self_signed(
            common_name=self.config.common_name,
            organization=self.config.organization,
            organizational_unit=self.config.organizational_unit,
            country=self.config.country,
            state=self.config.state,
            locality=self.config.locality,
            key_size=self.config.key_size,
            validity_days=self.config.validity_days,
            hash_algorithm=self.config.hash_algorithm,
            
            # CA-specific extensions
            basic_constraints={"ca": True, "path_length": self.config.max_path_length},
            key_usage=["key_cert_sign", "crl_sign", "digital_signature"],
            subject_key_identifier=True,
            authority_key_identifier=True
        )
        
        # Save CA certificate and private key
        await self.ca_certificate.save_certificate(self.ca_cert_path)
        await self.ca_certificate.save_private_key(self.ca_key_path, mode=0o600)  # Secure permissions
        
        # Save CA configuration
        with open(self.ca_config_path, 'w') as f:
            json.dump(self.config.to_dict(), f, indent=2, default=str)
        
        print(f"✅ CA certificate created and saved to {self.ca_cert_path}")
        print(f"   Validity: {self.ca_certificate.not_before} to {self.ca_certificate.not_after}")
        print(f"   Fingerprint: {self.ca_certificate.fingerprint_sha256}")
    
    async def _load_certificate_registry(self):
        """Load registry of issued certificates."""
        
        registry_path = self.ca_dir / "certificate_registry.json"
        
        if registry_path.exists():
            with open(registry_path) as f:
                registry_data = json.load(f)
                self.issued_certificates = registry_data.get("certificates", {})
                self.serial_number_counter = registry_data.get("next_serial", 1)
        
        print(f"📋 Loaded registry with {len(self.issued_certificates)} issued certificates")
    
    async def _save_certificate_registry(self):
        """Save registry of issued certificates."""
        
        registry_path = self.ca_dir / "certificate_registry.json"
        
        registry_data = {
            "ca_fingerprint": self.ca_certificate.fingerprint_sha256,
            "next_serial": self.serial_number_counter,
            "certificates": self.issued_certificates
        }
        
        with open(registry_path, 'w') as f:
            json.dump(registry_data, f, indent=2, default=str)
    
    async def issue_server_certificate(self, 
                                     common_name: str,
                                     san_list: List[str] = None,
                                     organization: str = None,
                                     validity_days: int = 365) -> tuple[Certificate, str]:
        """Issue server certificate."""
        
        if not self.ca_certificate:
            raise ValueError("CA not initialized")
        
        # Generate certificate request
        server_cert_request = await Certificate.generate_certificate_request(
            common_name=common_name,
            organization=organization or self.config.organization,
            organizational_unit="Plugin Servers",
            country=self.config.country,
            subject_alternative_names=san_list or [],
            key_size=2048
        )
        
        # Sign with CA
        signed_cert = await self.ca_certificate.sign_certificate(
            server_cert_request,
            validity_days=validity_days,
            serial_number=self.serial_number_counter,
            
            # Server certificate extensions
            key_usage=["key_encipherment", "digital_signature"],
            extended_key_usage=["server_auth"],
            basic_constraints={"ca": False},
            
            # Subject and Authority Key Identifiers
            subject_key_identifier=True,
            authority_key_identifier=True
        )
        
        # Record certificate issuance
        cert_id = f"server_{self.serial_number_counter:06d}"
        self.issued_certificates[cert_id] = {
            "type": "server",
            "common_name": common_name,
            "serial_number": self.serial_number_counter,
            "issued_at": datetime.now().isoformat(),
            "expires_at": signed_cert.not_after.isoformat(),
            "fingerprint": signed_cert.fingerprint_sha256,
            "status": "active"
        }
        
        self.serial_number_counter += 1
        await self._save_certificate_registry()
        
        print(f"✅ Server certificate issued for {common_name}")
        print(f"   Serial: {signed_cert.serial_number}")
        print(f"   Expires: {signed_cert.not_after}")
        
        return signed_cert, cert_id
    
    async def issue_client_certificate(self,
                                     common_name: str,
                                     organization: str = None,
                                     validity_days: int = 90,
                                     permissions: List[str] = None) -> tuple[Certificate, str]:
        """Issue client certificate."""
        
        if not self.ca_certificate:
            raise ValueError("CA not initialized")
        
        # Generate certificate request
        client_cert_request = await Certificate.generate_certificate_request(
            common_name=common_name,
            organization=organization or self.config.organization,
            organizational_unit="Plugin Clients",
            country=self.config.country,
            key_size=2048
        )
        
        # Sign with CA
        signed_cert = await self.ca_certificate.sign_certificate(
            client_cert_request,
            validity_days=validity_days,
            serial_number=self.serial_number_counter,
            
            # Client certificate extensions
            key_usage=["digital_signature", "key_agreement"],
            extended_key_usage=["client_auth"],
            basic_constraints={"ca": False},
            
            # Identifiers
            subject_key_identifier=True,
            authority_key_identifier=True
        )
        
        # Record certificate issuance
        cert_id = f"client_{self.serial_number_counter:06d}"
        self.issued_certificates[cert_id] = {
            "type": "client",
            "common_name": common_name,
            "serial_number": self.serial_number_counter,
            "issued_at": datetime.now().isoformat(),
            "expires_at": signed_cert.not_after.isoformat(),
            "fingerprint": signed_cert.fingerprint_sha256,
            "permissions": permissions or [],
            "status": "active"
        }
        
        self.serial_number_counter += 1
        await self._save_certificate_registry()
        
        print(f"✅ Client certificate issued for {common_name}")
        print(f"   Serial: {signed_cert.serial_number}")
        print(f"   Expires: {signed_cert.not_after}")
        
        return signed_cert, cert_id
    
    async def revoke_certificate(self, cert_id: str, reason: str = "unspecified"):
        """Revoke a certificate."""
        
        if cert_id not in self.issued_certificates:
            raise ValueError(f"Certificate {cert_id} not found in registry")
        
        # Update certificate status
        self.issued_certificates[cert_id]["status"] = "revoked"
        self.issued_certificates[cert_id]["revoked_at"] = datetime.now().isoformat()
        self.issued_certificates[cert_id]["revocation_reason"] = reason
        
        await self._save_certificate_registry()
        
        # TODO: Generate/update Certificate Revocation List (CRL)
        await self._update_crl()
        
        print(f"🚫 Certificate {cert_id} revoked (reason: {reason})")
    
    async def _update_crl(self):
        """Update Certificate Revocation List."""
        
        # Get all revoked certificates
        revoked_certs = [
            {
                "serial_number": cert_info["serial_number"],
                "revoked_at": cert_info["revoked_at"],
                "reason": cert_info["revocation_reason"]
            }
            for cert_info in self.issued_certificates.values()
            if cert_info["status"] == "revoked"
        ]
        
        # Generate CRL (simplified - use proper CRL generation in production)
        crl_data = {
            "issuer": self.ca_certificate.subject.common_name,
            "issued_at": datetime.now().isoformat(),
            "next_update": (datetime.now() + timedelta(days=7)).isoformat(),  # Weekly CRL updates
            "revoked_certificates": revoked_certs
        }
        
        # Save CRL
        crl_path = self.ca_dir / "crl.json"
        with open(crl_path, 'w') as f:
            json.dump(crl_data, f, indent=2)
        
        print(f"📄 CRL updated with {len(revoked_certs)} revoked certificates")
    
    def get_certificate_status(self, cert_id: str) -> Optional[Dict]:
        """Get status of issued certificate."""
        
        return self.issued_certificates.get(cert_id)
    
    def list_certificates(self, status: str = None, cert_type: str = None) -> List[Dict]:
        """List certificates with optional filtering."""
        
        certificates = []
        
        for cert_id, cert_info in self.issued_certificates.items():
            # Apply filters
            if status and cert_info["status"] != status:
                continue
            
            if cert_type and cert_info["type"] != cert_type:
                continue
            
            certificates.append({
                "id": cert_id,
                **cert_info
            })
        
        return certificates
    
    def get_ca_info(self) -> Dict:
        """Get CA information."""
        
        if not self.ca_certificate:
            return {"status": "not_initialized"}
        
        return {
            "common_name": self.ca_certificate.subject.common_name,
            "organization": self.ca_certificate.subject.organization,
            "valid_from": self.ca_certificate.not_before.isoformat(),
            "valid_until": self.ca_certificate.not_after.isoformat(),
            "fingerprint": self.ca_certificate.fingerprint_sha256,
            "serial_number": self.ca_certificate.serial_number,
            "issued_certificates": len(self.issued_certificates),
            "active_certificates": len([c for c in self.issued_certificates.values() if c["status"] == "active"]),
            "revoked_certificates": len([c for c in self.issued_certificates.values() if c["status"] == "revoked"])
        }

# Usage example
async def certificate_authority_example():
    """Example of Certificate Authority usage."""
    
    # Configure CA
    ca_config = CAConfig(
        common_name="Plugin Infrastructure CA",
        organization="My Company Inc",
        organizational_unit="Security Team",
        validity_days=3650,  # 10 years
        key_size=4096
    )
    
    # Initialize CA
    ca = CertificateAuthority(ca_config, ca_dir="./production_ca")
    ca_cert = await ca.initialize()
    
    # Issue server certificate
    server_cert, server_cert_id = await ca.issue_server_certificate(
        common_name="plugin-api.my-company.com",
        san_list=[
            "DNS:plugin-api.my-company.com",
            "DNS:api.plugin-service.svc.cluster.local",
            "IP:10.0.1.100"
        ],
        validity_days=365
    )
    
    # Issue client certificates
    client_cert1, client1_id = await ca.issue_client_certificate(
        common_name="payment-processor@my-company.com",
        permissions=["process_payment", "query_balance"],
        validity_days=90
    )
    
    client_cert2, client2_id = await ca.issue_client_certificate(
        common_name="order-manager@my-company.com", 
        permissions=["create_order", "update_order"],
        validity_days=90
    )
    
    # Save certificates
    await server_cert.save_certificate("server.pem")
    await server_cert.save_private_key("server.key")
    
    await client_cert1.save_certificate("payment-client.pem")
    await client_cert1.save_private_key("payment-client.key")
    
    await client_cert2.save_certificate("order-client.pem")
    await client_cert2.save_private_key("order-client.key")
    
    # List all certificates
    print("\n📋 Certificate Registry:")
    all_certs = ca.list_certificates()
    for cert in all_certs:
        print(f"  {cert['id']}: {cert['common_name']} ({cert['type']}, {cert['status']})")
    
    # Get CA information
    ca_info = ca.get_ca_info()
    print(f"\n🏛️  CA Information:")
    print(f"  Name: {ca_info['common_name']}")
    print(f"  Active certificates: {ca_info['active_certificates']}")
    print(f"  Fingerprint: {ca_info['fingerprint'][:32]}...")
    
    # Example revocation
    print(f"\n🚫 Revoking client certificate {client2_id}...")
    await ca.revoke_certificate(client2_id, reason="key_compromise")
    
    # List active certificates
    active_certs = ca.list_certificates(status="active")
    print(f"\n✅ Active certificates: {len(active_certs)}")

# Usage
await certificate_authority_example()
```

## Automatic Certificate Rotation

### Certificate Rotation Manager

```python
import asyncio
from typing import Callable, Dict, List
from dataclasses import dataclass
import logging

@dataclass
class RotationPolicy:
    """Certificate rotation policy configuration."""
    
    rotation_threshold: timedelta = timedelta(days=30)  # Rotate 30 days before expiry
    check_interval: timedelta = timedelta(hours=6)      # Check every 6 hours
    notification_threshold: timedelta = timedelta(days=7)  # Notify 7 days before rotation
    
    # Rotation strategy
    overlap_period: timedelta = timedelta(minutes=5)    # Keep old cert for 5 minutes
    max_rotation_attempts: int = 3                      # Max retry attempts
    rotation_backoff: float = 300.0                     # 5 minute backoff between retries

class CertificateRotationManager:
    """Manages automatic certificate rotation."""
    
    def __init__(self, ca: CertificateAuthority, rotation_policy: RotationPolicy):
        self.ca = ca
        self.policy = rotation_policy
        self.rotation_tasks: Dict[str, asyncio.Task] = {}
        self.rotation_callbacks: Dict[str, Callable] = {}
        
        # Setup logging
        self.logger = logging.getLogger("cert_rotation")
        self.logger.setLevel(logging.INFO)
        
        # Rotation statistics
        self.stats = {
            "total_rotations": 0,
            "successful_rotations": 0,
            "failed_rotations": 0,
            "notifications_sent": 0
        }
        
        # Running flag
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
    
    def register_certificate(self, cert_id: str, 
                           cert_path: str, 
                           key_path: str,
                           rotation_callback: Callable = None):
        """Register certificate for automatic rotation."""
        
        self.managed_certificates[cert_id] = {
            "cert_path": Path(cert_path),
            "key_path": Path(key_path),
            "rotation_callback": rotation_callback,
            "last_check": datetime.now(),
            "next_rotation": None,
            "rotation_attempts": 0
        }
        
        if rotation_callback:
            self.rotation_callbacks[cert_id] = rotation_callback
        
        self.logger.info(f"Registered certificate {cert_id} for rotation monitoring")
    
    async def start_monitoring(self):
        """Start certificate rotation monitoring."""
        
        if self._running:
            return
        
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self.logger.info("Certificate rotation monitoring started")
    
    async def stop_monitoring(self):
        """Stop certificate rotation monitoring."""
        
        self._running = False
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        # Cancel all rotation tasks
        for task in self.rotation_tasks.values():
            task.cancel()
        
        self.rotation_tasks.clear()
        self.logger.info("Certificate rotation monitoring stopped")
    
    async def _monitor_loop(self):
        """Main monitoring loop for certificate rotation."""
        
        while self._running:
            try:
                await self._check_all_certificates()
                await asyncio.sleep(self.policy.check_interval.total_seconds())
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in rotation monitoring loop: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retry
    
    async def _check_all_certificates(self):
        """Check all managed certificates for rotation needs."""
        
        self.logger.debug("Checking all certificates for rotation needs")
        
        for cert_id in list(self.managed_certificates.keys()):
            try:
                await self._check_single_certificate(cert_id)
            except Exception as e:
                self.logger.error(f"Error checking certificate {cert_id}: {e}")
    
    async def _check_single_certificate(self, cert_id: str):
        """Check single certificate for rotation needs."""
        
        cert_info = self.managed_certificates[cert_id]
        cert_path = cert_info["cert_path"]
        
        if not cert_path.exists():
            self.logger.warning(f"Certificate file not found: {cert_path}")
            return
        
        # Load certificate
        try:
            cert = await Certificate.load_from_file(cert_path)
        except Exception as e:
            self.logger.error(f"Failed to load certificate {cert_path}: {e}")
            return
        
        # Check if rotation is needed
        now = datetime.now()
        time_until_expiry = cert.not_after - now
        
        # Update last check time
        cert_info["last_check"] = now
        
        if time_until_expiry <= self.policy.rotation_threshold:
            # Need to rotate
            if cert_id not in self.rotation_tasks:
                self.logger.info(f"Scheduling rotation for certificate {cert_id} (expires in {time_until_expiry})")
                self.rotation_tasks[cert_id] = asyncio.create_task(
                    self._rotate_certificate(cert_id)
                )
        
        elif time_until_expiry <= self.policy.notification_threshold:
            # Send notification
            await self._send_rotation_notification(cert_id, time_until_expiry)
    
    async def _rotate_certificate(self, cert_id: str):
        """Rotate a specific certificate."""
        
        cert_info = self.managed_certificates[cert_id]
        
        try:
            self.logger.info(f"Starting rotation for certificate {cert_id}")
            self.stats["total_rotations"] += 1
            
            # Get certificate info from CA registry
            ca_cert_info = self.ca.get_certificate_status(cert_id)
            if not ca_cert_info:
                raise ValueError(f"Certificate {cert_id} not found in CA registry")
            
            # Generate new certificate
            if ca_cert_info["type"] == "server":
                new_cert, new_cert_id = await self._rotate_server_certificate(cert_id, ca_cert_info)
            elif ca_cert_info["type"] == "client":
                new_cert, new_cert_id = await self._rotate_client_certificate(cert_id, ca_cert_info)
            else:
                raise ValueError(f"Unknown certificate type: {ca_cert_info['type']}")
            
            # Save new certificate
            await new_cert.save_certificate(cert_info["cert_path"])
            await new_cert.save_private_key(cert_info["key_path"])
            
            # Call rotation callback
            if cert_info["rotation_callback"]:
                await cert_info["rotation_callback"](cert_id, new_cert_id, new_cert)
            
            # Update certificate info
            cert_info["rotation_attempts"] = 0
            cert_info["next_rotation"] = new_cert.not_after - self.policy.rotation_threshold
            
            self.stats["successful_rotations"] += 1
            self.logger.info(f"Successfully rotated certificate {cert_id} -> {new_cert_id}")
            
        except Exception as e:
            cert_info["rotation_attempts"] += 1
            self.stats["failed_rotations"] += 1
            
            self.logger.error(f"Failed to rotate certificate {cert_id} (attempt {cert_info['rotation_attempts']}): {e}")
            
            # Retry with backoff
            if cert_info["rotation_attempts"] < self.policy.max_rotation_attempts:
                self.logger.info(f"Retrying rotation for {cert_id} in {self.policy.rotation_backoff} seconds")
                await asyncio.sleep(self.policy.rotation_backoff)
                
                # Schedule retry
                self.rotation_tasks[cert_id] = asyncio.create_task(
                    self._rotate_certificate(cert_id)
                )
            else:
                self.logger.error(f"Max rotation attempts exceeded for certificate {cert_id}")
        
        finally:
            # Clean up rotation task
            self.rotation_tasks.pop(cert_id, None)
    
    async def _rotate_server_certificate(self, old_cert_id: str, cert_info: Dict) -> tuple[Certificate, str]:
        """Rotate server certificate."""
        
        # Extract SAN list from existing certificate if available
        old_cert_path = self.managed_certificates[old_cert_id]["cert_path"]
        old_cert = await Certificate.load_from_file(old_cert_path)
        san_list = old_cert.subject_alternative_names if hasattr(old_cert, 'subject_alternative_names') else []
        
        # Issue new server certificate
        new_cert, new_cert_id = await self.ca.issue_server_certificate(
            common_name=cert_info["common_name"],
            san_list=san_list,
            validity_days=365
        )
        
        return new_cert, new_cert_id
    
    async def _rotate_client_certificate(self, old_cert_id: str, cert_info: Dict) -> tuple[Certificate, str]:
        """Rotate client certificate."""
        
        # Issue new client certificate
        new_cert, new_cert_id = await self.ca.issue_client_certificate(
            common_name=cert_info["common_name"],
            permissions=cert_info.get("permissions", []),
            validity_days=90
        )
        
        return new_cert, new_cert_id
    
    async def _send_rotation_notification(self, cert_id: str, time_until_expiry: timedelta):
        """Send rotation notification."""
        
        # Implement notification logic (email, webhook, etc.)
        # For now, just log
        self.logger.warning(f"Certificate {cert_id} expires in {time_until_expiry} - rotation scheduled")
        self.stats["notifications_sent"] += 1
    
    def get_rotation_status(self) -> Dict:
        """Get rotation status and statistics."""
        
        return {
            "monitoring_active": self._running,
            "managed_certificates": len(self.managed_certificates),
            "active_rotations": len(self.rotation_tasks),
            "statistics": self.stats.copy(),
            "policy": {
                "rotation_threshold_days": self.policy.rotation_threshold.days,
                "check_interval_hours": self.policy.check_interval.total_seconds() / 3600,
                "notification_threshold_days": self.policy.notification_threshold.days
            }
        }
    
    async def force_rotation(self, cert_id: str):
        """Force immediate rotation of a certificate."""
        
        if cert_id not in self.managed_certificates:
            raise ValueError(f"Certificate {cert_id} not managed by rotation system")
        
        if cert_id in self.rotation_tasks:
            # Cancel existing rotation task
            self.rotation_tasks[cert_id].cancel()
        
        # Start immediate rotation
        self.logger.info(f"Force rotating certificate {cert_id}")
        self.rotation_tasks[cert_id] = asyncio.create_task(
            self._rotate_certificate(cert_id)
        )

# Usage example with plugin server
async def automatic_rotation_example():
    """Example of automatic certificate rotation."""
    
    # Setup CA
    ca_config = CAConfig(
        common_name="Auto-Rotation CA",
        organization="My Company"
    )
    ca = CertificateAuthority(ca_config)
    await ca.initialize()
    
    # Create rotation policy
    rotation_policy = RotationPolicy(
        rotation_threshold=timedelta(minutes=30),  # For demo - rotate 30 minutes before expiry
        check_interval=timedelta(minutes=5),       # Check every 5 minutes
        notification_threshold=timedelta(minutes=10)  # Notify 10 minutes before
    )
    
    # Create rotation manager
    rotation_manager = CertificateRotationManager(ca, rotation_policy)
    
    # Issue initial certificates with short validity for demo
    server_cert, server_cert_id = await ca.issue_server_certificate(
        common_name="demo-server.local",
        validity_days=1  # 1 day validity for demo
    )
    
    # Save certificates
    await server_cert.save_certificate("demo-server.pem")
    await server_cert.save_private_key("demo-server.key")
    
    # Callback function for server restart
    async def server_restart_callback(old_cert_id: str, new_cert_id: str, new_cert: Certificate):
        """Callback to restart server with new certificate."""
        print(f"🔄 Server certificate rotated: {old_cert_id} -> {new_cert_id}")
        print(f"   New certificate expires: {new_cert.not_after}")
        # Here you would restart your server with new certificate
        # await server.reload_certificate("demo-server.pem", "demo-server.key")
    
    # Register certificate for automatic rotation
    rotation_manager.register_certificate(
        cert_id=server_cert_id,
        cert_path="demo-server.pem",
        key_path="demo-server.key",
        rotation_callback=server_restart_callback
    )
    
    try:
        # Start monitoring
        await rotation_manager.start_monitoring()
        
        # Simulate running for a while
        print("🔄 Certificate rotation monitoring started...")
        print(f"   Server certificate expires: {server_cert.not_after}")
        
        # Run for a few minutes to see rotation in action
        for i in range(10):  # 10 * 30 seconds = 5 minutes
            await asyncio.sleep(30)
            
            status = rotation_manager.get_rotation_status()
            print(f"   Rotation status: {status['active_rotations']} active, "
                  f"{status['statistics']['successful_rotations']} successful")
        
    finally:
        await rotation_manager.stop_monitoring()
    
    # Final statistics
    final_status = rotation_manager.get_rotation_status()
    print(f"\n📊 Final Rotation Statistics:")
    print(f"   Total rotations: {final_status['statistics']['total_rotations']}")
    print(f"   Successful: {final_status['statistics']['successful_rotations']}")
    print(f"   Failed: {final_status['statistics']['failed_rotations']}")

# Usage
await automatic_rotation_example()
```

## Certificate Validation and Monitoring

### Certificate Health Monitor

```python
from typing import List, Dict, Any, Optional
from enum import Enum
import ssl
import socket
from dataclasses import dataclass

class CertificateStatus(Enum):
    """Certificate health status."""
    HEALTHY = "healthy"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    INVALID = "invalid"
    REVOKED = "revoked"
    UNKNOWN = "unknown"

@dataclass
class CertificateHealthCheck:
    """Result of certificate health check."""
    
    cert_id: str
    status: CertificateStatus
    expires_in_days: int
    issues: List[str]
    recommendations: List[str]
    last_check: datetime
    fingerprint: str
    
    def is_healthy(self) -> bool:
        """Check if certificate is healthy."""
        return self.status == CertificateStatus.HEALTHY
    
    def needs_attention(self) -> bool:
        """Check if certificate needs attention."""
        return self.status in [
            CertificateStatus.EXPIRING_SOON,
            CertificateStatus.EXPIRED,
            CertificateStatus.INVALID,
            CertificateStatus.REVOKED
        ]

class CertificateHealthMonitor:
    """Monitors certificate health across the infrastructure."""
    
    def __init__(self, ca: CertificateAuthority):
        self.ca = ca
        self.monitored_certificates: Dict[str, Dict] = {}
        self.health_history: List[CertificateHealthCheck] = []
        
        # Health check thresholds
        self.expiry_warning_days = 30
        self.expiry_critical_days = 7
        
        # Setup logging
        self.logger = logging.getLogger("cert_health_monitor")
    
    def add_certificate_endpoint(self, cert_id: str, host: str, port: int, 
                               expected_common_name: str = None):
        """Add remote certificate endpoint to monitor."""
        
        self.monitored_certificates[cert_id] = {
            "type": "remote",
            "host": host,
            "port": port,
            "expected_cn": expected_common_name,
            "last_check": None,
            "check_failures": 0
        }
        
        self.logger.info(f"Added remote certificate endpoint: {host}:{port}")
    
    def add_certificate_file(self, cert_id: str, cert_path: str, 
                           private_key_path: str = None):
        """Add local certificate file to monitor."""
        
        self.monitored_certificates[cert_id] = {
            "type": "local",
            "cert_path": Path(cert_path),
            "key_path": Path(private_key_path) if private_key_path else None,
            "last_check": None,
            "check_failures": 0
        }
        
        self.logger.info(f"Added local certificate file: {cert_path}")
    
    async def check_all_certificates(self) -> List[CertificateHealthCheck]:
        """Check health of all monitored certificates."""
        
        health_checks = []
        
        for cert_id, cert_info in self.monitored_certificates.items():
            try:
                health_check = await self._check_certificate_health(cert_id, cert_info)
                health_checks.append(health_check)
                
                # Reset failure counter on success
                cert_info["check_failures"] = 0
                
            except Exception as e:
                cert_info["check_failures"] += 1
                self.logger.error(f"Health check failed for {cert_id}: {e}")
                
                # Create failure health check
                health_checks.append(CertificateHealthCheck(
                    cert_id=cert_id,
                    status=CertificateStatus.UNKNOWN,
                    expires_in_days=-1,
                    issues=[f"Health check failed: {e}"],
                    recommendations=["Investigate connectivity or certificate file access"],
                    last_check=datetime.now(),
                    fingerprint="unknown"
                ))
        
        # Store health history
        self.health_history.extend(health_checks)
        
        # Keep only recent history (last 1000 checks)
        self.health_history = self.health_history[-1000:]
        
        return health_checks
    
    async def _check_certificate_health(self, cert_id: str, cert_info: Dict) -> CertificateHealthCheck:
        """Check health of individual certificate."""
        
        cert_info["last_check"] = datetime.now()
        
        if cert_info["type"] == "local":
            return await self._check_local_certificate(cert_id, cert_info)
        elif cert_info["type"] == "remote":
            return await self._check_remote_certificate(cert_id, cert_info)
        else:
            raise ValueError(f"Unknown certificate type: {cert_info['type']}")
    
    async def _check_local_certificate(self, cert_id: str, cert_info: Dict) -> CertificateHealthCheck:
        """Check local certificate file."""
        
        cert_path = cert_info["cert_path"]
        
        # Check file exists
        if not cert_path.exists():
            return CertificateHealthCheck(
                cert_id=cert_id,
                status=CertificateStatus.INVALID,
                expires_in_days=-1,
                issues=["Certificate file not found"],
                recommendations=[f"Verify certificate file exists at {cert_path}"],
                last_check=datetime.now(),
                fingerprint="unknown"
            )
        
        # Load and validate certificate
        try:
            cert = await Certificate.load_from_file(cert_path)
        except Exception as e:
            return CertificateHealthCheck(
                cert_id=cert_id,
                status=CertificateStatus.INVALID,
                expires_in_days=-1,
                issues=[f"Failed to load certificate: {e}"],
                recommendations=["Check certificate format and permissions"],
                last_check=datetime.now(),
                fingerprint="unknown"
            )
        
        return self._analyze_certificate_health(cert_id, cert)
    
    async def _check_remote_certificate(self, cert_id: str, cert_info: Dict) -> CertificateHealthCheck:
        """Check remote certificate via TLS connection."""
        
        host = cert_info["host"]
        port = cert_info["port"]
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # We'll validate manually
            
            # Connect and get certificate
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    peer_cert_der = ssock.getpeercert(binary_form=True)
            
            # Parse certificate
            cert = Certificate.from_der(peer_cert_der)
            
            # Additional checks for remote certificates
            issues = []
            recommendations = []
            
            # Check common name if specified
            expected_cn = cert_info.get("expected_cn")
            if expected_cn and cert.subject.common_name != expected_cn:
                issues.append(f"Common name mismatch: expected {expected_cn}, got {cert.subject.common_name}")
                recommendations.append("Verify server certificate configuration")
            
            health_check = self._analyze_certificate_health(cert_id, cert)
            health_check.issues.extend(issues)
            health_check.recommendations.extend(recommendations)
            
            return health_check
            
        except Exception as e:
            return CertificateHealthCheck(
                cert_id=cert_id,
                status=CertificateStatus.UNKNOWN,
                expires_in_days=-1,
                issues=[f"Connection failed: {e}"],
                recommendations=[f"Check connectivity to {host}:{port}"],
                last_check=datetime.now(),
                fingerprint="unknown"
            )
    
    def _analyze_certificate_health(self, cert_id: str, cert: Certificate) -> CertificateHealthCheck:
        """Analyze certificate health."""
        
        now = datetime.now()
        time_until_expiry = cert.not_after - now
        days_until_expiry = time_until_expiry.days
        
        issues = []
        recommendations = []
        status = CertificateStatus.HEALTHY
        
        # Check expiry
        if days_until_expiry < 0:
            status = CertificateStatus.EXPIRED
            issues.append(f"Certificate expired {abs(days_until_expiry)} days ago")
            recommendations.append("Renew certificate immediately")
        
        elif days_until_expiry <= self.expiry_critical_days:
            status = CertificateStatus.EXPIRING_SOON
            issues.append(f"Certificate expires in {days_until_expiry} days (critical)")
            recommendations.append("Renew certificate urgently")
        
        elif days_until_expiry <= self.expiry_warning_days:
            status = CertificateStatus.EXPIRING_SOON
            issues.append(f"Certificate expires in {days_until_expiry} days")
            recommendations.append("Schedule certificate renewal")
        
        # Check if certificate is not yet valid
        if now < cert.not_before:
            status = CertificateStatus.INVALID
            issues.append("Certificate not yet valid")
            recommendations.append("Check system clock or certificate validity period")
        
        # Check key strength
        if hasattr(cert, 'key_size') and cert.key_size < 2048:
            issues.append(f"Weak key size: {cert.key_size} bits")
            recommendations.append("Use at least 2048-bit RSA keys")
        
        # Check signature algorithm
        if hasattr(cert, 'signature_algorithm'):
            weak_algorithms = ["sha1", "md5"]
            if any(weak in cert.signature_algorithm.lower() for weak in weak_algorithms):
                issues.append(f"Weak signature algorithm: {cert.signature_algorithm}")
                recommendations.append("Use SHA-256 or stronger signature algorithm")
        
        # Check revocation status (simplified check against CA)
        ca_cert_info = self.ca.get_certificate_status(cert_id)
        if ca_cert_info and ca_cert_info.get("status") == "revoked":
            status = CertificateStatus.REVOKED
            issues.append("Certificate has been revoked")
            recommendations.append("Replace with new certificate")
        
        return CertificateHealthCheck(
            cert_id=cert_id,
            status=status,
            expires_in_days=days_until_expiry,
            issues=issues,
            recommendations=recommendations,
            last_check=now,
            fingerprint=cert.fingerprint_sha256
        )
    
    def generate_health_report(self, health_checks: List[CertificateHealthCheck]) -> str:
        """Generate human-readable health report."""
        
        report = []
        report.append("🏥 Certificate Health Report")
        report.append("=" * 40)
        
        # Summary
        total = len(health_checks)
        healthy = sum(1 for hc in health_checks if hc.is_healthy())
        needs_attention = sum(1 for hc in health_checks if hc.needs_attention())
        
        report.append(f"\n📊 Summary:")
        report.append(f"  Total certificates: {total}")
        report.append(f"  Healthy: ✅ {healthy}")
        report.append(f"  Needs attention: ⚠️  {needs_attention}")
        
        # Health breakdown
        status_counts = {}
        for hc in health_checks:
            status_counts[hc.status] = status_counts.get(hc.status, 0) + 1
        
        report.append(f"\n🔍 Status Breakdown:")
        for status, count in status_counts.items():
            icon = "✅" if status == CertificateStatus.HEALTHY else "⚠️"
            report.append(f"  {icon} {status.value}: {count}")
        
        # Detailed issues
        problem_certs = [hc for hc in health_checks if hc.needs_attention()]
        
        if problem_certs:
            report.append(f"\n🚨 Certificates Needing Attention:")
            
            for hc in problem_certs:
                report.append(f"\n  📄 {hc.cert_id} ({hc.status.value})")
                report.append(f"     Expires in: {hc.expires_in_days} days")
                report.append(f"     Fingerprint: {hc.fingerprint[:16]}...")
                
                if hc.issues:
                    report.append("     Issues:")
                    for issue in hc.issues:
                        report.append(f"       - {issue}")
                
                if hc.recommendations:
                    report.append("     Recommendations:")
                    for rec in hc.recommendations:
                        report.append(f"       - {rec}")
        
        else:
            report.append(f"\n✅ All certificates are healthy!")
        
        return "\n".join(report)
    
    def get_certificates_expiring_soon(self, days: int = 30) -> List[CertificateHealthCheck]:
        """Get certificates expiring within specified days."""
        
        recent_checks = {}
        
        # Get most recent check for each certificate
        for check in reversed(self.health_history):
            if check.cert_id not in recent_checks:
                recent_checks[check.cert_id] = check
        
        # Filter by expiry
        return [
            check for check in recent_checks.values()
            if 0 <= check.expires_in_days <= days
        ]

# Usage example
async def certificate_monitoring_example():
    """Example of certificate health monitoring."""
    
    # Setup CA
    ca_config = CAConfig(
        common_name="Monitoring CA",
        organization="My Company"
    )
    ca = CertificateAuthority(ca_config)
    await ca.initialize()
    
    # Create health monitor
    health_monitor = CertificateHealthMonitor(ca)
    
    # Issue some certificates for monitoring
    server_cert, server_id = await ca.issue_server_certificate(
        common_name="monitor-test.local",
        validity_days=45  # Will show as expiring soon
    )
    
    client_cert, client_id = await ca.issue_client_certificate(
        common_name="test-client@my-company.com",
        validity_days=5   # Will show as critical
    )
    
    # Save certificates
    await server_cert.save_certificate("monitor-server.pem")
    await client_cert.save_certificate("monitor-client.pem")
    
    # Add certificates to monitoring
    health_monitor.add_certificate_file(
        cert_id="server-cert",
        cert_path="monitor-server.pem"
    )
    
    health_monitor.add_certificate_file(
        cert_id="client-cert", 
        cert_path="monitor-client.pem"
    )
    
    # Add remote endpoint monitoring (this will fail since no server is running)
    health_monitor.add_certificate_endpoint(
        cert_id="remote-api",
        host="api.example.com",
        port=443,
        expected_common_name="api.example.com"
    )
    
    # Perform health checks
    print("🔍 Performing certificate health checks...")
    health_checks = await health_monitor.check_all_certificates()
    
    # Generate and display report
    report = health_monitor.generate_health_report(health_checks)
    print(report)
    
    # Check for expiring certificates
    expiring_soon = health_monitor.get_certificates_expiring_soon(days=30)
    
    if expiring_soon:
        print(f"\n⏰ Certificates expiring in next 30 days:")
        for cert in expiring_soon:
            print(f"  - {cert.cert_id}: {cert.expires_in_days} days")
    
    # Simulate some time passing and check again
    print("\n🔄 Simulating passage of time and checking again...")
    
    # In real usage, you'd run this periodically
    health_checks_2 = await health_monitor.check_all_certificates()
    
    # Count issues
    total_issues = sum(len(hc.issues) for hc in health_checks_2)
    print(f"   Found {total_issues} total issues across all certificates")

# Usage
await certificate_monitoring_example()
```

## Best Practices

### Security Hardening Checklist

```python
class CertificateSecurityAuditor:
    """Audits certificate security practices."""
    
    @staticmethod
    def audit_certificate_security(cert_dir: str) -> Dict[str, Any]:
        """Comprehensive certificate security audit."""
        
        audit_result = {
            "timestamp": datetime.now().isoformat(),
            "certificate_files": [],
            "security_score": 0,
            "critical_issues": [],
            "recommendations": [],
            "compliance_status": {}
        }
        
        cert_path = Path(cert_dir)
        
        # Check directory permissions
        dir_audit = CertificateSecurityAuditor._audit_directory_security(cert_path)
        audit_result["directory_security"] = dir_audit
        
        # Check individual certificates
        for cert_file in cert_path.glob("*.pem"):
            cert_audit = CertificateSecurityAuditor._audit_certificate_file(cert_file)
            audit_result["certificate_files"].append(cert_audit)
        
        # Calculate overall security score
        if audit_result["certificate_files"]:
            avg_score = sum(c["security_score"] for c in audit_result["certificate_files"])
            avg_score += dir_audit["security_score"]
            audit_result["security_score"] = avg_score / (len(audit_result["certificate_files"]) + 1)
        
        # Compile critical issues and recommendations
        for cert_audit in audit_result["certificate_files"]:
            audit_result["critical_issues"].extend(cert_audit["critical_issues"])
            audit_result["recommendations"].extend(cert_audit["recommendations"])
        
        audit_result["critical_issues"].extend(dir_audit["critical_issues"])
        audit_result["recommendations"].extend(dir_audit["recommendations"])
        
        # Compliance check
        audit_result["compliance_status"] = CertificateSecurityAuditor._check_compliance(audit_result)
        
        return audit_result
    
    @staticmethod
    def _audit_directory_security(cert_dir: Path) -> Dict[str, Any]:
        """Audit certificate directory security."""
        
        audit = {
            "directory": str(cert_dir),
            "security_score": 0,
            "critical_issues": [],
            "recommendations": [],
            "permissions": {}
        }
        
        try:
            # Check directory permissions
            stat_info = cert_dir.stat()
            mode = oct(stat_info.st_mode)[-3:]
            
            audit["permissions"] = {
                "mode": mode,
                "owner_readable": bool(stat_info.st_mode & 0o400),
                "owner_writable": bool(stat_info.st_mode & 0o200), 
                "group_readable": bool(stat_info.st_mode & 0o040),
                "group_writable": bool(stat_info.st_mode & 0o020),
                "other_readable": bool(stat_info.st_mode & 0o004),
                "other_writable": bool(stat_info.st_mode & 0o002)
            }
            
            # Score based on permissions
            if mode == "700":  # Owner read/write/execute only
                audit["security_score"] += 30
            elif mode in ["750", "755"]:  # Reasonable permissions
                audit["security_score"] += 20
            else:
                audit["critical_issues"].append(f"Insecure directory permissions: {mode}")
                audit["recommendations"].append("Set directory permissions to 700 or 750")
            
            # Check for group/other write access
            if audit["permissions"]["group_writable"] or audit["permissions"]["other_writable"]:
                audit["critical_issues"].append("Directory is writable by group or others")
                audit["recommendations"].append("Remove write access for group and others")
            
            # Check if directory is world-readable
            if audit["permissions"]["other_readable"]:
                audit["recommendations"].append("Consider removing read access for others")
        
        except Exception as e:
            audit["critical_issues"].append(f"Failed to check directory permissions: {e}")
        
        return audit
    
    @staticmethod
    def _audit_certificate_file(cert_file: Path) -> Dict[str, Any]:
        """Audit individual certificate file security."""
        
        audit = {
            "file": str(cert_file),
            "security_score": 0,
            "critical_issues": [],
            "recommendations": [],
            "certificate_info": {},
            "file_permissions": {}
        }
        
        try:
            # Check file permissions
            stat_info = cert_file.stat()
            mode = oct(stat_info.st_mode)[-3:]
            
            audit["file_permissions"] = {
                "mode": mode,
                "owner_readable": bool(stat_info.st_mode & 0o400),
                "owner_writable": bool(stat_info.st_mode & 0o200),
                "group_readable": bool(stat_info.st_mode & 0o040),
                "group_writable": bool(stat_info.st_mode & 0o020),
                "other_readable": bool(stat_info.st_mode & 0o004),
                "other_writable": bool(stat_info.st_mode & 0o002)
            }
            
            # Private keys should have restrictive permissions
            if cert_file.name.endswith('.key'):
                if mode == "600":  # Owner read/write only
                    audit["security_score"] += 25
                else:
                    audit["critical_issues"].append(f"Private key has insecure permissions: {mode}")
                    audit["recommendations"].append("Set private key permissions to 600")
            
            # Certificate files can be more permissive
            elif cert_file.name.endswith('.pem'):
                if mode in ["600", "644", "640"]:
                    audit["security_score"] += 15
                else:
                    audit["recommendations"].append(f"Consider more restrictive permissions for certificate: {mode}")
            
            # Check if writable by others
            if audit["file_permissions"]["group_writable"] or audit["file_permissions"]["other_writable"]:
                audit["critical_issues"].append("File is writable by group or others")
                audit["recommendations"].append("Remove write access for group and others")
            
            # Load and analyze certificate if it's a certificate file
            if cert_file.name.endswith('.pem') and not cert_file.name.endswith('.key'):
                cert_analysis = CertificateSecurityAuditor._analyze_certificate_security(cert_file)
                audit["certificate_info"] = cert_analysis
                audit["security_score"] += cert_analysis["security_score"]
                audit["critical_issues"].extend(cert_analysis["critical_issues"])
                audit["recommendations"].extend(cert_analysis["recommendations"])
        
        except Exception as e:
            audit["critical_issues"].append(f"Failed to audit certificate file: {e}")
        
        return audit
    
    @staticmethod
    def _analyze_certificate_security(cert_file: Path) -> Dict[str, Any]:
        """Analyze certificate content for security issues."""
        
        analysis = {
            "security_score": 0,
            "critical_issues": [],
            "recommendations": [],
            "certificate_details": {}
        }
        
        try:
            cert = Certificate.load_from_file(cert_file)
            
            # Basic certificate info
            analysis["certificate_details"] = {
                "subject": cert.subject.common_name,
                "issuer": cert.issuer.common_name,
                "valid_from": cert.not_before.isoformat(),
                "valid_until": cert.not_after.isoformat(),
                "serial_number": str(cert.serial_number),
                "fingerprint": cert.fingerprint_sha256
            }
            
            # Check key size
            if hasattr(cert, 'key_size'):
                if cert.key_size >= 4096:
                    analysis["security_score"] += 25
                elif cert.key_size >= 2048:
                    analysis["security_score"] += 15
                else:
                    analysis["critical_issues"].append(f"Weak key size: {cert.key_size} bits")
                    analysis["recommendations"].append("Use at least 2048-bit keys (4096 recommended)")
            
            # Check signature algorithm
            if hasattr(cert, 'signature_algorithm'):
                if 'sha256' in cert.signature_algorithm.lower():
                    analysis["security_score"] += 15
                elif 'sha1' in cert.signature_algorithm.lower():
                    analysis["critical_issues"].append("Weak signature algorithm: SHA-1")
                    analysis["recommendations"].append("Use SHA-256 or stronger")
                elif 'md5' in cert.signature_algorithm.lower():
                    analysis["critical_issues"].append("Very weak signature algorithm: MD5")
                    analysis["recommendations"].append("Replace certificate with SHA-256 or stronger")
            
            # Check validity period
            now = datetime.now()
            validity_period = cert.not_after - cert.not_before
            days_until_expiry = (cert.not_after - now).days
            
            if days_until_expiry < 0:
                analysis["critical_issues"].append("Certificate has expired")
                analysis["recommendations"].append("Renew certificate immediately")
            elif days_until_expiry <= 7:
                analysis["critical_issues"].append(f"Certificate expires in {days_until_expiry} days")
                analysis["recommendations"].append("Renew certificate urgently")
            elif days_until_expiry <= 30:
                analysis["recommendations"].append(f"Certificate expires in {days_until_expiry} days - schedule renewal")
            else:
                analysis["security_score"] += 10
            
            # Check validity period length
            if validity_period > timedelta(days=825):  # Apple's 825 day limit
                analysis["recommendations"].append("Certificate validity period exceeds recommended 825 days")
            elif validity_period <= timedelta(days=90):
                analysis["security_score"] += 10
            
            # Check extensions
            if hasattr(cert, 'extensions') and cert.extensions:
                analysis["security_score"] += 5
            else:
                analysis["recommendations"].append("Certificate lacks security extensions")
            
            # Check for weak configurations
            if hasattr(cert, 'subject_alternative_names'):
                if cert.subject_alternative_names:
                    analysis["security_score"] += 5
            
        except Exception as e:
            analysis["critical_issues"].append(f"Failed to analyze certificate: {e}")
        
        return analysis
    
    @staticmethod
    def _check_compliance(audit_result: Dict[str, Any]) -> Dict[str, bool]:
        """Check compliance with security standards."""
        
        compliance = {
            "pci_dss": True,
            "fips_140_2": True,
            "common_criteria": True,
            "nist_cybersecurity": True
        }
        
        # Check for compliance violations
        critical_issues = audit_result["critical_issues"]
        
        # PCI DSS requirements
        pci_violations = [
            "weak key size",
            "sha-1",
            "md5",
            "expired",
            "insecure permissions"
        ]
        
        for issue in critical_issues:
            issue_lower = issue.lower()
            if any(violation in issue_lower for violation in pci_violations):
                compliance["pci_dss"] = False
                break
        
        # FIPS 140-2 requirements
        fips_violations = ["weak key size", "sha-1", "md5"]
        for issue in critical_issues:
            issue_lower = issue.lower()
            if any(violation in issue_lower for violation in fips_violations):
                compliance["fips_140_2"] = False
                break
        
        # Set other compliance based on overall security score
        if audit_result["security_score"] < 70:
            compliance["common_criteria"] = False
            compliance["nist_cybersecurity"] = False
        
        return compliance
    
    @staticmethod
    def generate_security_report(audit_result: Dict[str, Any]) -> str:
        """Generate security audit report."""
        
        report = []
        report.append("🔒 Certificate Security Audit Report")
        report.append("=" * 50)
        report.append(f"Generated: {audit_result['timestamp']}")
        
        # Overall security score
        score = audit_result["security_score"]
        if score >= 80:
            score_icon = "🟢"
            score_rating = "Excellent"
        elif score >= 60:
            score_icon = "🟡"
            score_rating = "Good"
        else:
            score_icon = "🔴"
            score_rating = "Poor"
        
        report.append(f"\n🎯 Overall Security Score: {score_icon} {score:.1f}/100 ({score_rating})")
        
        # Compliance status
        compliance = audit_result["compliance_status"]
        report.append(f"\n📋 Compliance Status:")
        for standard, compliant in compliance.items():
            icon = "✅" if compliant else "❌"
            report.append(f"  {icon} {standard.replace('_', ' ').title()}: {'Compliant' if compliant else 'Non-compliant'}")
        
        # Critical issues
        critical_issues = audit_result["critical_issues"]
        if critical_issues:
            report.append(f"\n🚨 Critical Security Issues ({len(critical_issues)}):")
            for issue in critical_issues[:10]:  # Show top 10
                report.append(f"  • {issue}")
            
            if len(critical_issues) > 10:
                report.append(f"  ... and {len(critical_issues) - 10} more issues")
        
        # Recommendations
        recommendations = audit_result["recommendations"][:5]  # Top 5
        if recommendations:
            report.append(f"\n💡 Top Recommendations:")
            for i, rec in enumerate(recommendations, 1):
                report.append(f"  {i}. {rec}")
        
        # Certificate summary
        cert_files = audit_result["certificate_files"]
        if cert_files:
            report.append(f"\n📄 Certificate Summary:")
            report.append(f"  Total files audited: {len(cert_files)}")
            
            secure_files = sum(1 for cf in cert_files if cf["security_score"] >= 60)
            report.append(f"  Secure files: {secure_files}/{len(cert_files)}")
            
            # Show problematic files
            problem_files = [cf for cf in cert_files if cf["critical_issues"]]
            if problem_files:
                report.append(f"\n⚠️  Files with issues:")
                for cf in problem_files[:5]:  # Show top 5
                    report.append(f"  • {Path(cf['file']).name}: {len(cf['critical_issues'])} issues")
        
        return "\n".join(report)

# Usage example
async def security_audit_example():
    """Example of certificate security auditing."""
    
    # Create some certificates for auditing
    ca_config = CAConfig(
        common_name="Security Audit CA",
        organization="My Company"
    )
    ca = CertificateAuthority(ca_config, ca_dir="./audit_ca")
    await ca.initialize()
    
    # Issue certificates with different security characteristics
    good_cert, _ = await ca.issue_server_certificate(
        common_name="secure-server.my-company.com",
        validity_days=90  # Short validity period (good)
    )
    
    weak_cert, _ = await ca.issue_client_certificate(
        common_name="legacy-client@my-company.com",
        validity_days=730  # Long validity period (not ideal)
    )
    
    # Save certificates
    audit_dir = Path("./security_audit")
    audit_dir.mkdir(exist_ok=True)
    
    await good_cert.save_certificate(audit_dir / "good-server.pem")
    await good_cert.save_private_key(audit_dir / "good-server.key")
    
    await weak_cert.save_certificate(audit_dir / "weak-client.pem")
    await weak_cert.save_private_key(audit_dir / "weak-client.key")
    
    # Set insecure permissions for demonstration
    (audit_dir / "weak-client.key").chmod(0o644)  # Insecure permissions
    
    # Perform security audit
    print("🔍 Performing certificate security audit...")
    audit_result = CertificateSecurityAuditor.audit_certificate_security(str(audit_dir))
    
    # Generate and display report
    security_report = CertificateSecurityAuditor.generate_security_report(audit_result)
    print(security_report)
    
    # Save audit results
    audit_report_path = audit_dir / "security_audit_report.json"
    with open(audit_report_path, 'w') as f:
        json.dump(audit_result, f, indent=2, default=str)
    
    print(f"\n📊 Full audit results saved to: {audit_report_path}")

# Usage
await security_audit_example()
```

## Next Steps

- **[mTLS Configuration](mtls.md)** - Configure mutual TLS authentication
- **[Magic Cookies](magic-cookies.md)** - Learn magic cookie authentication
- **[Process Isolation](process-isolation.md)** - Implement process-level security