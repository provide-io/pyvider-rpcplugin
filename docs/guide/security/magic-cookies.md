# Magic Cookies

Learn magic cookie authentication for lightweight plugin security. Magic cookies provide process-to-process authentication without the overhead of full certificate management.

## Overview

Magic cookies are cryptographically secure random tokens used for authenticating plugin connections. They provide a lightweight alternative to certificates while maintaining strong security for local process communication.

```python
from pyvider.rpcplugin import plugin_server, plugin_client
from pyvider.rpcplugin.security import MagicCookie
import os

async def basic_magic_cookie_example():
    """Basic magic cookie authentication example."""
    
    # Generate secure magic cookie
    magic_cookie = MagicCookie.generate()
    
    # Server with magic cookie authentication
    server = plugin_server(
        services=[MyService()],
        magic_cookie=magic_cookie.value,
        require_magic_cookie=True
    )
    
    try:
        await server.start()
        print(f"🔐 Server started with magic cookie authentication")
        
        # Client must provide matching magic cookie
        async with plugin_client(
            command=["python", "client.py"],
            magic_cookie=magic_cookie.value
        ) as client:
            
            result = await client.service.AuthenticatedMethod(data="secure")
            print(f"✅ Authenticated request: {result.response}")
    
    finally:
        await server.stop()

# Usage
await basic_magic_cookie_example()
```

## Magic Cookie Generation

### Secure Cookie Creation

```python
import secrets
import hashlib
import base64
from typing import Optional, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
import json

@dataclass
class MagicCookieConfig:
    """Configuration for magic cookie generation."""
    
    length: int = 32                    # Cookie length in bytes
    encoding: str = "base64"            # Encoding format
    hash_algorithm: str = "sha256"      # Hash algorithm for validation
    expiry_duration: Optional[timedelta] = None  # Cookie expiry (None = no expiry)
    include_metadata: bool = False      # Include metadata in cookie
    namespace: Optional[str] = None     # Namespace for cookie uniqueness

class MagicCookie:
    """Secure magic cookie implementation."""
    
    def __init__(self, value: str, config: MagicCookieConfig = None, 
                 metadata: Dict[str, Any] = None):
        self.value = value
        self.config = config or MagicCookieConfig()
        self.metadata = metadata or {}
        self.created_at = datetime.now()
    
    @classmethod
    def generate(cls, config: MagicCookieConfig = None, 
                metadata: Dict[str, Any] = None) -> 'MagicCookie':
        """Generate new secure magic cookie."""
        
        config = config or MagicCookieConfig()
        
        # Generate cryptographically secure random bytes
        random_bytes = secrets.token_bytes(config.length)
        
        # Add namespace if specified
        if config.namespace:
            namespace_bytes = config.namespace.encode('utf-8')
            random_bytes = hashlib.sha256(namespace_bytes + random_bytes).digest()
        
        # Encode cookie value
        if config.encoding == "base64":
            cookie_value = base64.urlsafe_b64encode(random_bytes).decode('ascii')
        elif config.encoding == "hex":
            cookie_value = random_bytes.hex()
        else:
            raise ValueError(f"Unsupported encoding: {config.encoding}")
        
        # Include metadata in cookie if requested
        if config.include_metadata and metadata:
            metadata_str = base64.b64encode(json.dumps(metadata).encode()).decode()
            cookie_value = f"{cookie_value}.{metadata_str}"
        
        return cls(cookie_value, config, metadata)
    
    @classmethod
    def from_string(cls, cookie_str: str, config: MagicCookieConfig = None) -> 'MagicCookie':
        """Create magic cookie from string value."""
        
        config = config or MagicCookieConfig()
        metadata = {}
        
        # Extract metadata if present
        if config.include_metadata and '.' in cookie_str:
            cookie_value, metadata_str = cookie_str.rsplit('.', 1)
            try:
                metadata_bytes = base64.b64decode(metadata_str.encode())
                metadata = json.loads(metadata_bytes.decode())
            except Exception:
                # Invalid metadata, use original string
                cookie_value = cookie_str
        else:
            cookie_value = cookie_str
        
        return cls(cookie_value, config, metadata)
    
    def validate(self) -> bool:
        """Validate magic cookie."""
        
        try:
            # Check cookie format
            if self.config.encoding == "base64":
                base64.urlsafe_b64decode(self.value.encode())
            elif self.config.encoding == "hex":
                bytes.fromhex(self.value)
            else:
                return False
            
            # Check expiry if set
            if self.config.expiry_duration:
                if datetime.now() - self.created_at > self.config.expiry_duration:
                    return False
            
            return True
            
        except Exception:
            return False
    
    def hash(self) -> str:
        """Generate hash of magic cookie for storage/comparison."""
        
        hash_func = getattr(hashlib, self.config.hash_algorithm)
        return hash_func(self.value.encode()).hexdigest()
    
    def is_expired(self) -> bool:
        """Check if magic cookie has expired."""
        
        if not self.config.expiry_duration:
            return False
        
        return datetime.now() - self.created_at > self.config.expiry_duration
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert magic cookie to dictionary."""
        
        return {
            "value": self.value,
            "hash": self.hash(),
            "created_at": self.created_at.isoformat(),
            "expires_at": (self.created_at + self.config.expiry_duration).isoformat() 
                         if self.config.expiry_duration else None,
            "metadata": self.metadata,
            "config": {
                "length": self.config.length,
                "encoding": self.config.encoding,
                "hash_algorithm": self.config.hash_algorithm,
                "namespace": self.config.namespace
            }
        }
    
    def __str__(self) -> str:
        """String representation of magic cookie."""
        return self.value
    
    def __eq__(self, other) -> bool:
        """Compare magic cookies."""
        if isinstance(other, MagicCookie):
            return self.value == other.value
        elif isinstance(other, str):
            return self.value == other
        return False

# Usage examples
async def magic_cookie_generation_examples():
    """Examples of magic cookie generation."""
    
    # Basic cookie generation
    basic_cookie = MagicCookie.generate()
    print(f"📝 Basic cookie: {basic_cookie.value}")
    print(f"   Hash: {basic_cookie.hash()[:16]}...")
    print(f"   Valid: {basic_cookie.validate()}")
    
    # Custom configuration
    custom_config = MagicCookieConfig(
        length=64,                      # Longer cookie
        encoding="hex",                 # Hex encoding
        expiry_duration=timedelta(hours=1),  # 1 hour expiry
        namespace="payment-service"     # Service namespace
    )
    
    custom_cookie = MagicCookie.generate(
        config=custom_config,
        metadata={"service": "payment", "version": "1.0"}
    )
    
    print(f"\n🔧 Custom cookie: {custom_cookie.value}")
    print(f"   Namespace: {custom_cookie.config.namespace}")
    print(f"   Expires: {not custom_cookie.is_expired()}")
    
    # Cookie with metadata
    metadata_config = MagicCookieConfig(
        include_metadata=True,
        expiry_duration=timedelta(minutes=30)
    )
    
    metadata_cookie = MagicCookie.generate(
        config=metadata_config,
        metadata={
            "client_id": "payment-processor",
            "permissions": ["read", "write"],
            "issued_at": datetime.now().isoformat()
        }
    )
    
    print(f"\n📊 Metadata cookie: {metadata_cookie.value}")
    print(f"   Metadata: {metadata_cookie.metadata}")
    print(f"   Dictionary: {metadata_cookie.to_dict()}")

# Usage
await magic_cookie_generation_examples()
```

### Cookie Management System

```python
from typing import Dict, List, Set, Optional, Callable
import asyncio
import logging
from pathlib import Path

class MagicCookieManager:
    """Manages magic cookies for multiple services and clients."""
    
    def __init__(self, cookie_store_path: Optional[str] = None):
        self.cookie_store_path = Path(cookie_store_path) if cookie_store_path else None
        
        # Active cookies
        self.active_cookies: Dict[str, MagicCookie] = {}
        self.revoked_cookies: Set[str] = set()
        
        # Cookie metadata
        self.cookie_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Expiry monitoring
        self.expiry_check_interval = timedelta(minutes=5)
        self._expiry_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Callbacks
        self.expiry_callbacks: Dict[str, Callable] = {}
        
        # Setup logging
        self.logger = logging.getLogger("magic_cookie_manager")
    
    async def start(self):
        """Start cookie manager and expiry monitoring."""
        
        if self._running:
            return
        
        # Load existing cookies if store path is provided
        if self.cookie_store_path and self.cookie_store_path.exists():
            await self._load_cookies()
        
        # Start expiry monitoring
        self._running = True
        self._expiry_task = asyncio.create_task(self._expiry_monitor_loop())
        
        self.logger.info("Magic cookie manager started")
    
    async def stop(self):
        """Stop cookie manager."""
        
        self._running = False
        
        if self._expiry_task:
            self._expiry_task.cancel()
            try:
                await self._expiry_task
            except asyncio.CancelledError:
                pass
        
        # Save cookies if store path is provided
        if self.cookie_store_path:
            await self._save_cookies()
        
        self.logger.info("Magic cookie manager stopped")
    
    def generate_cookie(self, cookie_id: str, 
                       config: MagicCookieConfig = None,
                       metadata: Dict[str, Any] = None,
                       expiry_callback: Callable = None) -> MagicCookie:
        """Generate and register new magic cookie."""
        
        # Generate cookie
        cookie = MagicCookie.generate(config, metadata)
        
        # Register cookie
        self.active_cookies[cookie_id] = cookie
        
        # Store metadata
        self.cookie_metadata[cookie_id] = {
            "created_at": datetime.now().isoformat(),
            "last_used": None,
            "use_count": 0,
            "client_info": metadata or {}
        }
        
        # Register expiry callback
        if expiry_callback:
            self.expiry_callbacks[cookie_id] = expiry_callback
        
        self.logger.info(f"Generated magic cookie: {cookie_id}")
        return cookie
    
    def validate_cookie(self, cookie_value: str) -> Optional[str]:
        """Validate magic cookie and return cookie ID if valid."""
        
        # Check if cookie is revoked
        cookie_hash = hashlib.sha256(cookie_value.encode()).hexdigest()
        if cookie_hash in self.revoked_cookies:
            self.logger.warning(f"Attempted use of revoked cookie: {cookie_hash[:16]}...")
            return None
        
        # Find matching active cookie
        for cookie_id, cookie in self.active_cookies.items():
            if cookie.value == cookie_value:
                # Validate cookie
                if not cookie.validate():
                    self.logger.warning(f"Invalid magic cookie format: {cookie_id}")
                    return None
                
                # Check expiry
                if cookie.is_expired():
                    self.logger.warning(f"Expired magic cookie: {cookie_id}")
                    await self._expire_cookie(cookie_id)
                    return None
                
                # Update usage statistics
                self._update_cookie_usage(cookie_id)
                
                return cookie_id
        
        self.logger.warning("Unknown magic cookie attempted")
        return None
    
    def _update_cookie_usage(self, cookie_id: str):
        """Update cookie usage statistics."""
        
        if cookie_id in self.cookie_metadata:
            metadata = self.cookie_metadata[cookie_id]
            metadata["last_used"] = datetime.now().isoformat()
            metadata["use_count"] += 1
    
    def revoke_cookie(self, cookie_id: str, reason: str = "manual_revocation"):
        """Revoke a magic cookie."""
        
        if cookie_id not in self.active_cookies:
            raise ValueError(f"Cookie {cookie_id} not found")
        
        cookie = self.active_cookies[cookie_id]
        cookie_hash = cookie.hash()
        
        # Move to revoked list
        self.revoked_cookies.add(cookie_hash)
        del self.active_cookies[cookie_id]
        
        # Update metadata
        if cookie_id in self.cookie_metadata:
            self.cookie_metadata[cookie_id]["revoked_at"] = datetime.now().isoformat()
            self.cookie_metadata[cookie_id]["revocation_reason"] = reason
        
        self.logger.info(f"Revoked magic cookie: {cookie_id} (reason: {reason})")
    
    def get_cookie_info(self, cookie_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific cookie."""
        
        if cookie_id not in self.active_cookies:
            return None
        
        cookie = self.active_cookies[cookie_id]
        metadata = self.cookie_metadata.get(cookie_id, {})
        
        return {
            "cookie_id": cookie_id,
            "cookie_hash": cookie.hash()[:16] + "...",
            "created_at": metadata.get("created_at"),
            "last_used": metadata.get("last_used"),
            "use_count": metadata.get("use_count", 0),
            "expires_at": (cookie.created_at + cookie.config.expiry_duration).isoformat() 
                         if cookie.config.expiry_duration else None,
            "is_expired": cookie.is_expired(),
            "metadata": cookie.metadata,
            "client_info": metadata.get("client_info", {})
        }
    
    def list_active_cookies(self) -> List[Dict[str, Any]]:
        """List all active cookies."""
        
        return [
            self.get_cookie_info(cookie_id) 
            for cookie_id in self.active_cookies.keys()
        ]
    
    async def _expiry_monitor_loop(self):
        """Monitor and handle cookie expiry."""
        
        while self._running:
            try:
                await self._check_expired_cookies()
                await asyncio.sleep(self.expiry_check_interval.total_seconds())
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in expiry monitor: {e}")
                await asyncio.sleep(60)  # Wait 1 minute on error
    
    async def _check_expired_cookies(self):
        """Check for and handle expired cookies."""
        
        expired_cookies = []
        
        for cookie_id, cookie in self.active_cookies.items():
            if cookie.is_expired():
                expired_cookies.append(cookie_id)
        
        # Handle expired cookies
        for cookie_id in expired_cookies:
            await self._expire_cookie(cookie_id)
    
    async def _expire_cookie(self, cookie_id: str):
        """Handle cookie expiry."""
        
        self.logger.info(f"Magic cookie expired: {cookie_id}")
        
        # Call expiry callback if registered
        if cookie_id in self.expiry_callbacks:
            try:
                callback = self.expiry_callbacks[cookie_id]
                await callback(cookie_id)
            except Exception as e:
                self.logger.error(f"Error in expiry callback for {cookie_id}: {e}")
        
        # Remove cookie
        if cookie_id in self.active_cookies:
            del self.active_cookies[cookie_id]
        
        # Update metadata
        if cookie_id in self.cookie_metadata:
            self.cookie_metadata[cookie_id]["expired_at"] = datetime.now().isoformat()
    
    async def _save_cookies(self):
        """Save cookies to persistent store."""
        
        if not self.cookie_store_path:
            return
        
        cookie_data = {
            "active_cookies": {
                cookie_id: cookie.to_dict() 
                for cookie_id, cookie in self.active_cookies.items()
            },
            "revoked_cookies": list(self.revoked_cookies),
            "cookie_metadata": self.cookie_metadata,
            "saved_at": datetime.now().isoformat()
        }
        
        try:
            with open(self.cookie_store_path, 'w') as f:
                json.dump(cookie_data, f, indent=2)
            
            self.logger.info(f"Saved {len(self.active_cookies)} cookies to {self.cookie_store_path}")
        
        except Exception as e:
            self.logger.error(f"Failed to save cookies: {e}")
    
    async def _load_cookies(self):
        """Load cookies from persistent store."""
        
        try:
            with open(self.cookie_store_path) as f:
                cookie_data = json.load(f)
            
            # Load active cookies
            for cookie_id, cookie_dict in cookie_data.get("active_cookies", {}).items():
                config = MagicCookieConfig(
                    length=cookie_dict["config"]["length"],
                    encoding=cookie_dict["config"]["encoding"],
                    hash_algorithm=cookie_dict["config"]["hash_algorithm"],
                    namespace=cookie_dict["config"]["namespace"]
                )
                
                cookie = MagicCookie.from_string(cookie_dict["value"], config)
                cookie.created_at = datetime.fromisoformat(cookie_dict["created_at"])
                cookie.metadata = cookie_dict["metadata"]
                
                # Only load non-expired cookies
                if not cookie.is_expired():
                    self.active_cookies[cookie_id] = cookie
            
            # Load revoked cookies
            self.revoked_cookies = set(cookie_data.get("revoked_cookies", []))
            
            # Load metadata
            self.cookie_metadata = cookie_data.get("cookie_metadata", {})
            
            self.logger.info(f"Loaded {len(self.active_cookies)} active cookies from {self.cookie_store_path}")
        
        except Exception as e:
            self.logger.error(f"Failed to load cookies: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get cookie manager statistics."""
        
        total_cookies = len(self.active_cookies)
        expired_cookies = sum(1 for c in self.active_cookies.values() if c.is_expired())
        
        # Usage statistics
        total_uses = sum(
            metadata.get("use_count", 0) 
            for metadata in self.cookie_metadata.values()
        )
        
        # Recently used cookies (last hour)
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recently_used = 0
        
        for metadata in self.cookie_metadata.values():
            last_used_str = metadata.get("last_used")
            if last_used_str:
                last_used = datetime.fromisoformat(last_used_str)
                if last_used > one_hour_ago:
                    recently_used += 1
        
        return {
            "active_cookies": total_cookies,
            "revoked_cookies": len(self.revoked_cookies),
            "expired_cookies": expired_cookies,
            "total_usage_count": total_uses,
            "recently_used_cookies": recently_used,
            "running": self._running
        }

# Usage example
async def magic_cookie_management_example():
    """Example of magic cookie management."""
    
    # Create cookie manager with persistent storage
    manager = MagicCookieManager("./cookies.json")
    
    try:
        await manager.start()
        
        # Generate cookies for different services
        services = [
            ("payment-service", {"service": "payment", "permissions": ["read", "write"]}),
            ("order-service", {"service": "orders", "permissions": ["read"]}),
            ("admin-console", {"service": "admin", "permissions": ["admin"]})
        ]
        
        generated_cookies = {}
        
        for service_id, metadata in services:
            # Configure cookie with expiry
            config = MagicCookieConfig(
                length=32,
                expiry_duration=timedelta(hours=2),  # 2 hour expiry
                namespace=service_id
            )
            
            # Expiry callback
            async def cookie_expired(cookie_id: str):
                print(f"⏰ Cookie expired: {cookie_id}")
            
            cookie = manager.generate_cookie(
                cookie_id=service_id,
                config=config,
                metadata=metadata,
                expiry_callback=cookie_expired
            )
            
            generated_cookies[service_id] = cookie
            print(f"🍪 Generated cookie for {service_id}: {cookie.value[:16]}...")
        
        # Simulate cookie usage
        print("\n🔍 Testing cookie validation...")
        
        for service_id, cookie in generated_cookies.items():
            # Test valid cookie
            validated_id = manager.validate_cookie(cookie.value)
            if validated_id:
                print(f"✅ Valid cookie: {service_id}")
            else:
                print(f"❌ Invalid cookie: {service_id}")
        
        # Test invalid cookie
        fake_cookie = "invalid_cookie_value_123"
        validated_id = manager.validate_cookie(fake_cookie)
        print(f"❌ Fake cookie validation: {'Valid' if validated_id else 'Invalid'}")
        
        # List active cookies
        print(f"\n📋 Active cookies:")
        active_cookies = manager.list_active_cookies()
        for cookie_info in active_cookies:
            print(f"  • {cookie_info['cookie_id']}: used {cookie_info['use_count']} times")
        
        # Revoke a cookie
        print(f"\n🚫 Revoking admin-console cookie...")
        manager.revoke_cookie("admin-console", "security_policy_change")
        
        # Test revoked cookie
        admin_cookie = generated_cookies["admin-console"]
        validated_id = manager.validate_cookie(admin_cookie.value)
        print(f"   Revoked cookie validation: {'Valid' if validated_id else 'Invalid'}")
        
        # Get statistics
        stats = manager.get_statistics()
        print(f"\n📊 Cookie Manager Statistics:")
        for key, value in stats.items():
            print(f"  {key}: {value}")
        
        # Wait a bit to see expiry monitoring in action
        print(f"\n⏳ Running for 30 seconds to demonstrate monitoring...")
        await asyncio.sleep(30)
    
    finally:
        await manager.stop()

# Usage
await magic_cookie_management_example()
```

## Server-Side Integration

### Magic Cookie Authentication

```python
from pyvider.rpcplugin import plugin_server
from pyvider.rpcplugin.decorators import require_magic_cookie, audit_log
import grpc
from typing import Dict, Any, Optional

class MagicCookieAuthenticator:
    """Server-side magic cookie authentication."""
    
    def __init__(self, cookie_manager: MagicCookieManager):
        self.cookie_manager = cookie_manager
        self.logger = logging.getLogger("cookie_authenticator")
        
        # Authentication statistics
        self.auth_stats = {
            "successful_authentications": 0,
            "failed_authentications": 0,
            "revoked_cookie_attempts": 0,
            "unknown_cookie_attempts": 0
        }
    
    async def authenticate_request(self, context) -> Optional[Dict[str, Any]]:
        """Authenticate incoming request using magic cookie."""
        
        # Extract magic cookie from metadata
        magic_cookie = self._extract_magic_cookie(context)
        
        if not magic_cookie:
            self.auth_stats["failed_authentications"] += 1
            self.logger.warning("No magic cookie provided in request")
            return None
        
        # Validate cookie
        cookie_id = self.cookie_manager.validate_cookie(magic_cookie)
        
        if not cookie_id:
            self.auth_stats["failed_authentications"] += 1
            self.auth_stats["unknown_cookie_attempts"] += 1
            self.logger.warning(f"Invalid magic cookie: {magic_cookie[:16]}...")
            return None
        
        # Get cookie information
        cookie_info = self.cookie_manager.get_cookie_info(cookie_id)
        
        if not cookie_info:
            self.auth_stats["failed_authentications"] += 1
            self.logger.error(f"Cookie info not found for validated cookie: {cookie_id}")
            return None
        
        # Successful authentication
        self.auth_stats["successful_authentications"] += 1
        self.logger.info(f"Successful authentication: {cookie_id}")
        
        return {
            "cookie_id": cookie_id,
            "client_info": cookie_info["client_info"],
            "permissions": cookie_info["metadata"].get("permissions", []),
            "service": cookie_info["metadata"].get("service")
        }
    
    def _extract_magic_cookie(self, context) -> Optional[str]:
        """Extract magic cookie from gRPC context."""
        
        # Check for magic cookie in metadata
        metadata = context.invocation_metadata()
        
        for key, value in metadata:
            if key.lower() == "magic-cookie":
                return value
            elif key.lower() == "authorization":
                # Support "Bearer <cookie>" format
                if value.startswith("Bearer "):
                    return value[7:]  # Remove "Bearer " prefix
        
        return None
    
    def require_permissions(self, required_permissions: List[str], 
                          auth_info: Dict[str, Any]) -> bool:
        """Check if authenticated client has required permissions."""
        
        client_permissions = auth_info.get("permissions", [])
        
        # Check if client has all required permissions
        return all(perm in client_permissions for perm in required_permissions)
    
    def get_auth_stats(self) -> Dict[str, Any]:
        """Get authentication statistics."""
        
        total_attempts = (
            self.auth_stats["successful_authentications"] + 
            self.auth_stats["failed_authentications"]
        )
        
        success_rate = (
            self.auth_stats["successful_authentications"] / max(1, total_attempts)
        )
        
        return {
            **self.auth_stats,
            "total_attempts": total_attempts,
            "success_rate": success_rate
        }

# Example service with magic cookie authentication
class SecurePaymentService:
    """Payment service with magic cookie authentication."""
    
    def __init__(self, authenticator: MagicCookieAuthenticator):
        self.authenticator = authenticator
        self.logger = logging.getLogger("secure_payment_service")
    
    @audit_log(operation="process_payment")
    async def ProcessPayment(self, request, context):
        """Process payment with magic cookie authentication."""
        
        # Authenticate request
        auth_info = await self.authenticator.authenticate_request(context)
        
        if not auth_info:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing magic cookie")
        
        # Check permissions
        if not self.authenticator.require_permissions(["write", "process_payment"], auth_info):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "Insufficient permissions")
        
        # Log authenticated request
        client_service = auth_info["service"]
        cookie_id = auth_info["cookie_id"]
        
        self.logger.info(f"Processing payment for {client_service} (cookie: {cookie_id})")
        
        # Process payment logic
        transaction_id = f"txn_{hash(str(request.amount) + str(request.currency))}"
        
        return PaymentResponse(
            transaction_id=transaction_id,
            amount=request.amount,
            currency=request.currency,
            status="completed",
            authenticated_service=client_service
        )
    
    @audit_log(operation="get_balance")
    async def GetBalance(self, request, context):
        """Get balance with read-only authentication."""
        
        # Authenticate request
        auth_info = await self.authenticator.authenticate_request(context)
        
        if not auth_info:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing magic cookie")
        
        # Check read permissions
        if not self.authenticator.require_permissions(["read"], auth_info):
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "Insufficient permissions")
        
        # Return balance
        return BalanceResponse(
            account_id=request.account_id,
            balance=1500.00,
            currency="USD"
        )

# Server setup with magic cookie authentication
async def secure_server_example():
    """Example of server with magic cookie authentication."""
    
    # Setup cookie manager
    cookie_manager = MagicCookieManager("./server_cookies.json")
    await cookie_manager.start()
    
    # Generate cookies for different clients
    clients = [
        ("payment-processor", {"service": "payment", "permissions": ["read", "write", "process_payment"]}),
        ("order-manager", {"service": "orders", "permissions": ["read", "write"]}),
        ("reporting-service", {"service": "reporting", "permissions": ["read"]})
    ]
    
    client_cookies = {}
    
    for client_id, metadata in clients:
        config = MagicCookieConfig(
            expiry_duration=timedelta(hours=24),  # 24 hour cookies
            namespace="payment-api"
        )
        
        cookie = cookie_manager.generate_cookie(client_id, config, metadata)
        client_cookies[client_id] = cookie
        
        print(f"🔑 Generated cookie for {client_id}: {cookie.value}")
    
    # Setup authenticator
    authenticator = MagicCookieAuthenticator(cookie_manager)
    
    # Create secure service
    payment_service = SecurePaymentService(authenticator)
    
    # Create server
    server = plugin_server(
        services=[payment_service],
        port=8080,
        
        # Magic cookie configuration
        magic_cookie_required=True,
        magic_cookie_header="magic-cookie",  # Custom header name
        
        # Additional security
        enable_auth_logging=True,
        max_auth_failures_per_minute=10
    )
    
    try:
        await server.start()
        print(f"🔐 Secure server started on port {server.port}")
        print("   Magic cookie authentication enabled")
        
        # Simulate some requests (would normally come from clients)
        # Here we'll just run the server
        await asyncio.sleep(60)  # Run for 1 minute
        
        # Show authentication statistics
        auth_stats = authenticator.get_auth_stats()
        print(f"\n📊 Authentication Statistics:")
        for key, value in auth_stats.items():
            if isinstance(value, float):
                print(f"   {key}: {value:.2f}")
            else:
                print(f"   {key}: {value}")
    
    finally:
        await server.stop()
        await cookie_manager.stop()

# Usage
await secure_server_example()
```

## Client-Side Integration

### Magic Cookie Client

```python
from pyvider.rpcplugin import plugin_client
from typing import Optional, Dict, Any
import os

class MagicCookieClient:
    """Client with magic cookie authentication support."""
    
    def __init__(self, magic_cookie: str, client_id: str = None):
        self.magic_cookie = magic_cookie
        self.client_id = client_id or "unknown_client"
        self.logger = logging.getLogger(f"cookie_client_{self.client_id}")
        
        # Request statistics
        self.request_stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "auth_failures": 0,
            "permission_denials": 0
        }
    
    async def connect(self, host: str, port: int, **kwargs) -> plugin_client:
        """Create authenticated connection to server."""
        
        # Create client with magic cookie
        client = plugin_client(
            host=host,
            port=port,
            
            # Magic cookie authentication
            magic_cookie=self.magic_cookie,
            
            # Additional metadata
            client_metadata={
                "client-id": self.client_id,
                "magic-cookie": self.magic_cookie
            },
            
            **kwargs
        )
        
        return client
    
    async def make_authenticated_request(self, host: str, port: int,
                                       service_method: str, **kwargs) -> Any:
        """Make authenticated request to server."""
        
        self.request_stats["total_requests"] += 1
        
        try:
            async with await self.connect(host, port) as client:
                # Parse service and method
                service_name, method_name = service_method.split('.')
                service = getattr(client, service_name.lower())
                method = getattr(service, method_name)
                
                # Make request
                result = await method(**kwargs)
                
                self.request_stats["successful_requests"] += 1
                self.logger.info(f"Successful request: {service_method}")
                
                return result
        
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.UNAUTHENTICATED:
                self.request_stats["auth_failures"] += 1
                self.logger.error(f"Authentication failed: {e.details()}")
                raise Exception(f"Authentication failed: {e.details()}")
            
            elif e.code() == grpc.StatusCode.PERMISSION_DENIED:
                self.request_stats["permission_denials"] += 1
                self.logger.error(f"Permission denied: {e.details()}")
                raise Exception(f"Permission denied: {e.details()}")
            
            else:
                self.logger.error(f"Request failed: {e.code()} - {e.details()}")
                raise
        
        except Exception as e:
            self.logger.error(f"Request error: {e}")
            raise
    
    def get_request_stats(self) -> Dict[str, Any]:
        """Get request statistics."""
        
        total = self.request_stats["total_requests"]
        success_rate = self.request_stats["successful_requests"] / max(1, total)
        
        return {
            **self.request_stats,
            "success_rate": success_rate
        }

# Client usage examples
async def magic_cookie_client_examples():
    """Examples of magic cookie clients."""
    
    # Simulate having magic cookies from server setup
    client_cookies = {
        "payment-processor": "secure_cookie_payment_123",
        "order-manager": "secure_cookie_orders_456", 
        "reporting-service": "secure_cookie_reports_789"
    }
    
    # Create authenticated clients
    payment_client = MagicCookieClient(
        magic_cookie=client_cookies["payment-processor"],
        client_id="payment-processor"
    )
    
    order_client = MagicCookieClient(
        magic_cookie=client_cookies["order-manager"],
        client_id="order-manager"
    )
    
    reporting_client = MagicCookieClient(
        magic_cookie=client_cookies["reporting-service"],
        client_id="reporting-service"
    )
    
    server_host = "127.0.0.1"
    server_port = 8080
    
    try:
        # Payment processor - has full permissions
        print("💳 Payment processor client:")
        
        payment_result = await payment_client.make_authenticated_request(
            server_host, server_port,
            "payment.ProcessPayment",
            amount=100.00,
            currency="USD",
            payment_method="credit_card"
        )
        
        print(f"   Payment processed: {payment_result.transaction_id}")
        
        balance_result = await payment_client.make_authenticated_request(
            server_host, server_port,
            "payment.GetBalance",
            account_id="acc_12345"
        )
        
        print(f"   Balance retrieved: ${balance_result.balance}")
        
        # Reporting service - read-only permissions
        print("\n📊 Reporting service client:")
        
        reporting_balance = await reporting_client.make_authenticated_request(
            server_host, server_port,
            "payment.GetBalance",
            account_id="acc_67890"
        )
        
        print(f"   Balance for reporting: ${reporting_balance.balance}")
        
        # Try to process payment with reporting client (should fail)
        try:
            await reporting_client.make_authenticated_request(
                server_host, server_port,
                "payment.ProcessPayment",
                amount=50.00,
                currency="USD"
            )
        except Exception as e:
            print(f"   Expected permission denial: {e}")
        
        # Show client statistics
        print(f"\n📈 Client Statistics:")
        
        for client_name, client in [
            ("Payment Processor", payment_client),
            ("Reporting Service", reporting_client)
        ]:
            stats = client.get_request_stats()
            print(f"   {client_name}:")
            print(f"     Total requests: {stats['total_requests']}")
            print(f"     Success rate: {stats['success_rate']:.2f}")
            print(f"     Auth failures: {stats['auth_failures']}")
            print(f"     Permission denials: {stats['permission_denials']}")
    
    except Exception as e:
        print(f"❌ Client example failed: {e}")

# Usage
await magic_cookie_client_examples()
```

## Environment Integration

### Configuration Management

```python
import os
from typing import Dict, Optional, List
from dataclasses import dataclass

@dataclass
class MagicCookieEnvironmentConfig:
    """Environment-based magic cookie configuration."""
    
    # Cookie generation settings
    cookie_length: int = int(os.environ.get("MAGIC_COOKIE_LENGTH", "32"))
    cookie_encoding: str = os.environ.get("MAGIC_COOKIE_ENCODING", "base64")
    cookie_hash_algorithm: str = os.environ.get("MAGIC_COOKIE_HASH_ALGORITHM", "sha256")
    
    # Expiry settings
    default_expiry_hours: int = int(os.environ.get("MAGIC_COOKIE_EXPIRY_HOURS", "24"))
    enable_expiry: bool = os.environ.get("MAGIC_COOKIE_ENABLE_EXPIRY", "true").lower() == "true"
    
    # Storage settings
    cookie_store_path: Optional[str] = os.environ.get("MAGIC_COOKIE_STORE_PATH")
    enable_persistent_store: bool = os.environ.get("MAGIC_COOKIE_PERSISTENT", "false").lower() == "true"
    
    # Security settings
    enable_namespace: bool = os.environ.get("MAGIC_COOKIE_NAMESPACE", "true").lower() == "true"
    namespace_prefix: str = os.environ.get("MAGIC_COOKIE_NAMESPACE_PREFIX", "plugin")
    
    # Monitoring settings
    expiry_check_minutes: int = int(os.environ.get("MAGIC_COOKIE_EXPIRY_CHECK_MINUTES", "5"))
    enable_usage_tracking: bool = os.environ.get("MAGIC_COOKIE_USAGE_TRACKING", "true").lower() == "true"
    
    @classmethod
    def from_environment(cls, prefix: str = "MAGIC_COOKIE_") -> 'MagicCookieEnvironmentConfig':
        """Create configuration from environment variables with custom prefix."""
        
        config = cls()
        
        # Override with custom prefix if provided
        if prefix != "MAGIC_COOKIE_":
            for field_name in config.__dataclass_fields__:
                env_var_name = f"{prefix}{field_name.upper()}"
                env_value = os.environ.get(env_var_name)
                
                if env_value is not None:
                    field_type = config.__dataclass_fields__[field_name].type
                    
                    if field_type == int:
                        setattr(config, field_name, int(env_value))
                    elif field_type == bool:
                        setattr(config, field_name, env_value.lower() == "true")
                    else:
                        setattr(config, field_name, env_value)
        
        return config
    
    def create_cookie_config(self, namespace: str = None) -> MagicCookieConfig:
        """Create MagicCookieConfig from environment configuration."""
        
        expiry_duration = None
        if self.enable_expiry:
            expiry_duration = timedelta(hours=self.default_expiry_hours)
        
        final_namespace = None
        if self.enable_namespace:
            final_namespace = f"{self.namespace_prefix}_{namespace}" if namespace else self.namespace_prefix
        
        return MagicCookieConfig(
            length=self.cookie_length,
            encoding=self.cookie_encoding,
            hash_algorithm=self.cookie_hash_algorithm,
            expiry_duration=expiry_duration,
            namespace=final_namespace
        )
    
    def get_store_path(self, service_name: str = None) -> Optional[str]:
        """Get cookie store path for service."""
        
        if not self.enable_persistent_store:
            return None
        
        if self.cookie_store_path:
            if service_name:
                store_path = Path(self.cookie_store_path)
                return str(store_path.parent / f"{service_name}_{store_path.name}")
            else:
                return self.cookie_store_path
        
        # Default store path
        default_name = f"{service_name}_cookies.json" if service_name else "cookies.json"
        return os.path.join(os.getcwd(), default_name)

class EnvironmentMagicCookieManager:
    """Magic cookie manager with environment configuration."""
    
    def __init__(self, service_name: str, env_prefix: str = "MAGIC_COOKIE_"):
        self.service_name = service_name
        self.env_config = MagicCookieEnvironmentConfig.from_environment(env_prefix)
        
        # Create cookie manager
        store_path = self.env_config.get_store_path(service_name)
        self.cookie_manager = MagicCookieManager(store_path)
        
        # Service-specific configuration
        self.cookie_config = self.env_config.create_cookie_config(service_name)
        
        self.logger = logging.getLogger(f"env_cookie_manager_{service_name}")
    
    async def start(self):
        """Start environment-configured cookie manager."""
        
        await self.cookie_manager.start()
        self.logger.info(f"Started magic cookie manager for {self.service_name}")
        self.logger.info(f"Configuration: {self.env_config}")
    
    async def stop(self):
        """Stop cookie manager."""
        
        await self.cookie_manager.stop()
        self.logger.info(f"Stopped magic cookie manager for {self.service_name}")
    
    def generate_service_cookie(self, client_id: str, 
                              client_metadata: Dict[str, Any] = None) -> MagicCookie:
        """Generate cookie for client with service-specific configuration."""
        
        return self.cookie_manager.generate_cookie(
            cookie_id=client_id,
            config=self.cookie_config,
            metadata=client_metadata or {}
        )
    
    def validate_service_cookie(self, cookie_value: str) -> Optional[str]:
        """Validate cookie with service configuration."""
        
        return self.cookie_manager.validate_cookie(cookie_value)
    
    def get_service_configuration(self) -> Dict[str, Any]:
        """Get service cookie configuration."""
        
        return {
            "service_name": self.service_name,
            "cookie_length": self.cookie_config.length,
            "cookie_encoding": self.cookie_config.encoding,
            "expiry_hours": self.env_config.default_expiry_hours if self.env_config.enable_expiry else None,
            "namespace": self.cookie_config.namespace,
            "persistent_storage": self.env_config.enable_persistent_store,
            "store_path": self.env_config.get_store_path(self.service_name)
        }

# Usage example with environment configuration
async def environment_magic_cookie_example():
    """Example using environment-based magic cookie configuration."""
    
    # Set up environment variables
    os.environ.update({
        "MAGIC_COOKIE_LENGTH": "64",
        "MAGIC_COOKIE_ENCODING": "hex",
        "MAGIC_COOKIE_EXPIRY_HOURS": "12",
        "MAGIC_COOKIE_ENABLE_EXPIRY": "true",
        "MAGIC_COOKIE_PERSISTENT": "true",
        "MAGIC_COOKIE_STORE_PATH": "./production_cookies.json",
        "MAGIC_COOKIE_NAMESPACE_PREFIX": "prod"
    })
    
    # Create service-specific cookie managers
    services = ["payment-api", "order-api", "user-api"]
    
    cookie_managers = {}
    
    for service_name in services:
        manager = EnvironmentMagicCookieManager(service_name)
        await manager.start()
        cookie_managers[service_name] = manager
        
        # Show service configuration
        config = manager.get_service_configuration()
        print(f"🔧 {service_name} configuration:")
        for key, value in config.items():
            print(f"   {key}: {value}")
        print()
    
    try:
        # Generate cookies for different clients per service
        generated_cookies = {}
        
        for service_name, manager in cookie_managers.items():
            # Generate cookies for this service
            clients = ["web-frontend", "mobile-app", "admin-panel"]
            service_cookies = {}
            
            for client_id in clients:
                metadata = {
                    "client_type": client_id,
                    "service": service_name,
                    "generated_at": datetime.now().isoformat()
                }
                
                cookie = manager.generate_service_cookie(
                    client_id=f"{service_name}_{client_id}",
                    client_metadata=metadata
                )
                
                service_cookies[client_id] = cookie
                print(f"🍪 Generated {service_name} cookie for {client_id}: {cookie.value[:20]}...")
            
            generated_cookies[service_name] = service_cookies
        
        # Test cookie validation across services
        print(f"\n🔍 Testing cross-service cookie validation:")
        
        # Test valid cookies
        for service_name, service_cookies in generated_cookies.items():
            manager = cookie_managers[service_name]
            
            for client_id, cookie in service_cookies.items():
                validated_id = manager.validate_service_cookie(cookie.value)
                status = "✅ Valid" if validated_id else "❌ Invalid"
                print(f"   {service_name}/{client_id}: {status}")
        
        # Test cross-service validation (should fail due to namespace)
        payment_cookie = generated_cookies["payment-api"]["web-frontend"]
        order_manager = cookie_managers["order-api"]
        
        cross_validated = order_manager.validate_service_cookie(payment_cookie.value)
        print(f"\n🔒 Cross-service validation: {'❌ Correctly blocked' if not cross_validated else '⚠️ Unexpectedly allowed'}")
        
        # Show manager statistics
        print(f"\n📊 Service Statistics:")
        for service_name, manager in cookie_managers.items():
            stats = manager.cookie_manager.get_statistics()
            print(f"   {service_name}:")
            print(f"     Active cookies: {stats['active_cookies']}")
            print(f"     Total usage: {stats['total_usage_count']}")
    
    finally:
        # Clean up all managers
        for manager in cookie_managers.values():
            await manager.stop()

# Usage
await environment_magic_cookie_example()
```

## Best Practices

### Security Recommendations

```python
class MagicCookieSecurityAuditor:
    """Security auditor for magic cookie implementation."""
    
    @staticmethod
    def audit_magic_cookie_security(cookie_manager: MagicCookieManager) -> Dict[str, Any]:
        """Audit magic cookie security practices."""
        
        audit_result = {
            "timestamp": datetime.now().isoformat(),
            "security_score": 0,
            "findings": [],
            "recommendations": [],
            "compliance_status": {}
        }
        
        # Check active cookies
        active_cookies = cookie_manager.list_active_cookies()
        
        if not active_cookies:
            audit_result["findings"].append("No active cookies found")
            return audit_result
        
        # Security checks
        total_score = 0
        max_score = 0
        
        # Check 1: Cookie length and entropy
        cookie_lengths = [len(cookie["cookie_hash"]) for cookie in active_cookies]
        avg_length = sum(cookie_lengths) / len(cookie_lengths)
        
        max_score += 20
        if avg_length >= 32:  # Assuming hash length correlates with original length
            total_score += 20
            audit_result["findings"].append("✅ Cookie length adequate")
        else:
            audit_result["findings"].append("⚠️ Weak cookie length")
            audit_result["recommendations"].append("Use at least 32-byte cookies")
        
        # Check 2: Expiry configuration
        max_score += 15
        cookies_with_expiry = [c for c in active_cookies if c["expires_at"]]
        
        if cookies_with_expiry:
            total_score += 15
            audit_result["findings"].append("✅ Cookie expiry configured")
        else:
            audit_result["findings"].append("⚠️ No cookie expiry set")
            audit_result["recommendations"].append("Configure reasonable cookie expiry times")
        
        # Check 3: Usage monitoring
        max_score += 10
        cookies_with_usage = [c for c in active_cookies if c["use_count"] > 0]
        
        if len(cookies_with_usage) > 0:
            total_score += 10
            audit_result["findings"].append("✅ Usage monitoring active")
        else:
            audit_result["findings"].append("ℹ️ No cookie usage detected yet")
        
        # Check 4: Recent activity
        max_score += 10
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent_activity = 0
        
        for cookie in active_cookies:
            if cookie["last_used"]:
                last_used = datetime.fromisoformat(cookie["last_used"])
                if last_used > one_hour_ago:
                    recent_activity += 1
        
        if recent_activity > 0:
            total_score += 10
            audit_result["findings"].append("✅ Recent authentication activity")
        
        # Check 5: Cookie diversity
        max_score += 15
        unique_services = set()
        for cookie in active_cookies:
            service = cookie["metadata"].get("service")
            if service:
                unique_services.add(service)
        
        if len(unique_services) > 1:
            total_score += 15
            audit_result["findings"].append("✅ Multiple services using cookies")
        elif len(unique_services) == 1:
            total_score += 10
            audit_result["findings"].append("ℹ️ Single service using cookies")
        
        # Check 6: Metadata completeness
        max_score += 10
        cookies_with_metadata = [
            c for c in active_cookies 
            if c["metadata"] and len(c["metadata"]) > 0
        ]
        
        if len(cookies_with_metadata) == len(active_cookies):
            total_score += 10
            audit_result["findings"].append("✅ All cookies have metadata")
        elif len(cookies_with_metadata) > 0:
            total_score += 5
            audit_result["findings"].append("⚠️ Some cookies missing metadata")
            audit_result["recommendations"].append("Ensure all cookies include client metadata")
        else:
            audit_result["findings"].append("⚠️ No cookie metadata found")
            audit_result["recommendations"].append("Add client identification metadata to cookies")
        
        # Check 7: Permission management
        max_score += 20
        cookies_with_permissions = [
            c for c in active_cookies
            if "permissions" in c["metadata"]
        ]
        
        if len(cookies_with_permissions) == len(active_cookies):
            total_score += 20
            audit_result["findings"].append("✅ All cookies have permission metadata")
        elif len(cookies_with_permissions) > 0:
            total_score += 10
            audit_result["findings"].append("⚠️ Some cookies missing permissions")
            audit_result["recommendations"].append("Define permissions for all authenticated clients")
        else:
            audit_result["findings"].append("⚠️ No permission-based access control")
            audit_result["recommendations"].append("Implement permission-based authentication")
        
        # Calculate final score
        audit_result["security_score"] = (total_score / max_score) * 100 if max_score > 0 else 0
        
        # Compliance assessment
        audit_result["compliance_status"] = {
            "basic_security": audit_result["security_score"] >= 70,
            "production_ready": audit_result["security_score"] >= 80,
            "high_security": audit_result["security_score"] >= 90
        }
        
        # Overall recommendations
        if audit_result["security_score"] < 70:
            audit_result["recommendations"].append("Security score below 70% - review implementation")
        
        if not cookies_with_expiry:
            audit_result["recommendations"].append("CRITICAL: Implement cookie expiration")
        
        if not cookies_with_permissions:
            audit_result["recommendations"].append("HIGH: Implement role-based permissions")
        
        return audit_result
    
    @staticmethod
    def generate_security_report(audit_result: Dict[str, Any]) -> str:
        """Generate security audit report."""
        
        report = []
        report.append("🔒 Magic Cookie Security Audit")
        report.append("=" * 40)
        report.append(f"Generated: {audit_result['timestamp']}")
        
        # Security score
        score = audit_result["security_score"]
        if score >= 90:
            score_icon = "🟢"
            score_rating = "Excellent"
        elif score >= 80:
            score_icon = "🟡"
            score_rating = "Good"
        elif score >= 70:
            score_icon = "🟠"
            score_rating = "Acceptable"
        else:
            score_icon = "🔴"
            score_rating = "Poor"
        
        report.append(f"\n🎯 Security Score: {score_icon} {score:.1f}/100 ({score_rating})")
        
        # Compliance status
        compliance = audit_result["compliance_status"]
        report.append(f"\n📋 Compliance:")
        for level, status in compliance.items():
            icon = "✅" if status else "❌"
            report.append(f"  {icon} {level.replace('_', ' ').title()}: {'Pass' if status else 'Fail'}")
        
        # Findings
        if audit_result["findings"]:
            report.append(f"\n🔍 Security Findings:")
            for finding in audit_result["findings"]:
                report.append(f"  • {finding}")
        
        # Recommendations
        if audit_result["recommendations"]:
            report.append(f"\n💡 Recommendations:")
            for i, rec in enumerate(audit_result["recommendations"], 1):
                report.append(f"  {i}. {rec}")
        
        return "\n".join(report)

# Usage example
async def security_audit_example():
    """Example of magic cookie security auditing."""
    
    # Create cookie manager with various security configurations
    manager = MagicCookieManager("./audit_cookies.json")
    await manager.start()
    
    # Generate cookies with different security characteristics
    cookies = [
        # Good security
        {
            "id": "secure-client",
            "config": MagicCookieConfig(
                length=64,
                expiry_duration=timedelta(hours=2)
            ),
            "metadata": {
                "service": "payment",
                "permissions": ["read", "write"],
                "client_type": "web"
            }
        },
        
        # Moderate security
        {
            "id": "moderate-client", 
            "config": MagicCookieConfig(
                length=32,
                expiry_duration=timedelta(hours=24)
            ),
            "metadata": {
                "service": "orders",
                "permissions": ["read"]
            }
        },
        
        # Poor security (no expiry, no permissions)
        {
            "id": "weak-client",
            "config": MagicCookieConfig(
                length=16,  # Weak length
                expiry_duration=None  # No expiry
            ),
            "metadata": {
                "service": "reporting"
                # No permissions defined
            }
        }
    ]
    
    # Generate cookies
    for cookie_data in cookies:
        manager.generate_cookie(
            cookie_id=cookie_data["id"],
            config=cookie_data["config"],
            metadata=cookie_data["metadata"]
        )
    
    # Simulate some usage
    active_cookies = manager.list_active_cookies()
    for cookie_info in active_cookies[:2]:  # Use first 2 cookies
        manager.validate_cookie(cookie_info["cookie_id"])
    
    try:
        # Perform security audit
        print("🔍 Performing magic cookie security audit...")
        audit_result = MagicCookieSecurityAuditor.audit_magic_cookie_security(manager)
        
        # Generate and display report
        security_report = MagicCookieSecurityAuditor.generate_security_report(audit_result)
        print(security_report)
        
        # Save audit results
        with open("magic_cookie_audit.json", "w") as f:
            json.dump(audit_result, f, indent=2, default=str)
        
        print(f"\n📊 Full audit results saved to: magic_cookie_audit.json")
        
        # Show improvement suggestions based on score
        score = audit_result["security_score"]
        
        if score < 70:
            print(f"\n🚨 URGENT: Security score is {score:.1f}% - immediate improvements needed")
        elif score < 80:
            print(f"\n⚠️ WARNING: Security score is {score:.1f}% - consider improvements")
        elif score < 90:
            print(f"\n✅ GOOD: Security score is {score:.1f}% - minor improvements possible")
        else:
            print(f"\n🎉 EXCELLENT: Security score is {score:.1f}% - well configured")
    
    finally:
        await manager.stop()

# Usage
await security_audit_example()
```

## Next Steps

- **[mTLS Configuration](mtls.md)** - Configure mutual TLS authentication for maximum security
- **[Process Isolation](process-isolation.md)** - Implement process-level security boundaries
- **[Certificate Management](certificates.md)** - Learn comprehensive certificate lifecycle management