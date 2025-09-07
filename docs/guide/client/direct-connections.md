# Direct Connections

Connect directly to running plugin servers without launching subprocess, ideal for microservices, distributed systems, and server-to-server communication.

## Overview

Direct connections enable clients to connect to already-running plugin servers via network protocols (TCP or Unix sockets), bypassing subprocess management.

**Use Cases:**
- Microservice architectures
- Load-balanced plugin pools
- Cross-machine communication
- Containerized deployments
- Development and testing

## Basic Direct Connection

### TCP Connection

```python
from pyvider.rpcplugin import plugin_client
from provide.foundation import logger

async def connect_to_server():
    """Connect directly to a TCP server."""
    
    # Connect to running server
    client = await plugin_client(
        host="localhost",
        port=50051,
        skip_subprocess=True  # Direct connection
    )
    
    try:
        logger.info("Connected to server")
        
        # Make RPC calls
        response = await client.call("Echo", message="Hello")
        logger.info(f"Response: {response.message}")
        
    finally:
        await client.close()

# Run
await connect_to_server()
```

### Unix Socket Connection

```python
async def connect_unix_socket():
    """Connect via Unix domain socket."""
    
    client = await plugin_client(
        unix_socket="/tmp/plugin.sock",
        skip_subprocess=True
    )
    
    try:
        response = await client.call("Process", data={"key": "value"})
        return response
    finally:
        await client.close()
```

## Configuration

### Environment-Based Setup

```python
import os
from dataclasses import dataclass

@dataclass
class DirectConnectionConfig:
    """Configuration for direct connections."""
    
    host: str = os.environ.get("PLUGIN_SERVER_HOST", "localhost")
    port: int = int(os.environ.get("PLUGIN_SERVER_PORT", "50051"))
    use_tls: bool = os.environ.get("PLUGIN_USE_TLS", "false").lower() == "true"
    timeout: float = float(os.environ.get("PLUGIN_TIMEOUT", "30.0"))
    
    # mTLS configuration
    client_cert: str | None = os.environ.get("PLUGIN_CLIENT_CERT")
    client_key: str | None = os.environ.get("PLUGIN_CLIENT_KEY")
    ca_cert: str | None = os.environ.get("PLUGIN_CA_CERT")

# Usage
config = DirectConnectionConfig()
client = await plugin_client(
    host=config.host,
    port=config.port,
    skip_subprocess=True,
    timeout=config.timeout,
    client_cert=config.client_cert,
    client_key=config.client_key
)
```

## Advanced Patterns

### Connection Pool

```python
import asyncio
from collections import deque
from provide.foundation import logger

class ConnectionPool:
    """Manage pool of direct connections."""
    
    def __init__(self, host: str, port: int, size: int = 5):
        self.host = host
        self.port = port
        self.size = size
        self.available = deque()
        self.in_use = set()
        self._lock = asyncio.Lock()
    
    async def initialize(self):
        """Create initial connections."""
        for _ in range(self.size):
            client = await plugin_client(
                host=self.host,
                port=self.port,
                skip_subprocess=True
            )
            self.available.append(client)
        logger.info(f"Pool initialized with {self.size} connections")
    
    async def acquire(self):
        """Get connection from pool."""
        async with self._lock:
            if self.available:
                client = self.available.popleft()
                self.in_use.add(client)
                return client
            
            # Create new connection if under limit
            if len(self.in_use) < self.size * 2:
                client = await plugin_client(
                    host=self.host,
                    port=self.port,
                    skip_subprocess=True
                )
                self.in_use.add(client)
                return client
            
            # Wait for available connection
            while not self.available:
                await asyncio.sleep(0.1)
            
            client = self.available.popleft()
            self.in_use.add(client)
            return client
    
    async def release(self, client):
        """Return connection to pool."""
        async with self._lock:
            self.in_use.discard(client)
            
            # Check health before returning to pool
            try:
                await client.health_check()
                self.available.append(client)
            except:
                await client.close()
                logger.warning("Unhealthy connection removed from pool")
    
    async def close_all(self):
        """Close all connections."""
        all_clients = list(self.available) + list(self.in_use)
        for client in all_clients:
            await client.close()
        self.available.clear()
        self.in_use.clear()

# Usage
pool = ConnectionPool("localhost", 50051, size=10)
await pool.initialize()

# Use connections
client = await pool.acquire()
try:
    result = await client.call("Process", data={"test": "data"})
finally:
    await pool.release(client)
```

### Load Balancing

```python
import random
from typing import Any

class LoadBalancedClient:
    """Client with load balancing across servers."""
    
    def __init__(self, endpoints: list[dict[str, Any]]):
        """
        Args:
            endpoints: List of server configurations
                [{"host": "server1", "port": 50051, "weight": 2},
                 {"host": "server2", "port": 50052, "weight": 1}]
        """
        self.endpoints = endpoints
        self.clients = []
        self.weights = []
    
    async def connect_all(self):
        """Connect to all endpoints."""
        for endpoint in self.endpoints:
            client = await plugin_client(
                host=endpoint["host"],
                port=endpoint["port"],
                skip_subprocess=True
            )
            self.clients.append(client)
            self.weights.append(endpoint.get("weight", 1))
        
        logger.info(f"Connected to {len(self.clients)} servers")
    
    def select_client(self, strategy: str = "weighted"):
        """Select client based on strategy."""
        if strategy == "random":
            return random.choice(self.clients)
        elif strategy == "weighted":
            return random.choices(self.clients, weights=self.weights)[0]
        elif strategy == "round_robin":
            # Rotate through clients
            client = self.clients.pop(0)
            self.clients.append(client)
            return client
        else:
            return self.clients[0]
    
    async def call(self, method: str, **kwargs):
        """Make load-balanced RPC call."""
        client = self.select_client()
        
        try:
            return await client.call(method, **kwargs)
        except Exception as e:
            logger.error(f"Call failed on {client.host}:{client.port}: {e}")
            
            # Retry on different server
            for other_client in self.clients:
                if other_client != client:
                    try:
                        return await other_client.call(method, **kwargs)
                    except:
                        continue
            
            raise Exception("All servers failed")
    
    async def close_all(self):
        """Close all client connections."""
        for client in self.clients:
            await client.close()

# Usage
endpoints = [
    {"host": "server1.internal", "port": 50051, "weight": 3},
    {"host": "server2.internal", "port": 50051, "weight": 2},
    {"host": "server3.internal", "port": 50051, "weight": 1}
]

lb_client = LoadBalancedClient(endpoints)
await lb_client.connect_all()

result = await lb_client.call("Process", data={"request": "data"})
```

## Secure Connections

### mTLS Direct Connection

```python
from provide.foundation.crypto import Certificate, PrivateKey
import ssl

async def secure_direct_connection():
    """Establish mTLS direct connection."""
    
    # Load certificates using Foundation
    client_cert = Certificate.load_from_file("/etc/ssl/client.pem")
    client_key = PrivateKey.load_from_file("/etc/ssl/client.key")
    ca_cert = Certificate.load_from_file("/etc/ssl/ca.pem")
    
    # Create SSL context
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_cert_chain(client_cert.path, client_key.path)
    ssl_context.load_verify_locations(ca_cert.path)
    ssl_context.check_hostname = True
    
    # Connect with mTLS
    client = await plugin_client(
        host="secure.example.com",
        port=443,
        skip_subprocess=True,
        ssl_context=ssl_context
    )
    
    try:
        response = await client.call("SecureMethod", sensitive_data="...")
        return response
    finally:
        await client.close()
```

### Authentication

```python
class AuthenticatedDirectClient:
    """Direct client with authentication."""
    
    def __init__(self, host: str, port: int, api_key: str):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.client = None
        self.token = None
    
    async def connect(self):
        """Connect and authenticate."""
        self.client = await plugin_client(
            host=self.host,
            port=self.port,
            skip_subprocess=True
        )
        
        # Authenticate
        auth_response = await self.client.call(
            "auth.Authenticate",
            api_key=self.api_key
        )
        
        self.token = auth_response.token
        logger.info("Authenticated successfully")
    
    async def call(self, method: str, **kwargs):
        """Make authenticated call."""
        if not self.token:
            await self.connect()
        
        # Add auth token to metadata
        metadata = [("authorization", f"Bearer {self.token}")]
        
        return await self.client.call(
            method,
            metadata=metadata,
            **kwargs
        )
    
    async def close(self):
        """Close connection."""
        if self.client:
            await self.client.close()
```

## Service Discovery

### Consul Integration

```python
import consul.aio

class ConsulServiceDiscovery:
    """Discover plugin servers via Consul."""
    
    def __init__(self, consul_host: str = "localhost", consul_port: int = 8500):
        self.consul = consul.aio.Consul(host=consul_host, port=consul_port)
        self.services = {}
    
    async def discover_service(self, service_name: str):
        """Discover service endpoints from Consul."""
        _, services = await self.consul.health.service(
            service_name,
            passing=True  # Only healthy instances
        )
        
        endpoints = []
        for service in services:
            endpoints.append({
                "host": service["Service"]["Address"],
                "port": service["Service"]["Port"],
                "id": service["Service"]["ID"]
            })
        
        self.services[service_name] = endpoints
        logger.info(f"Discovered {len(endpoints)} {service_name} instances")
        return endpoints
    
    async def connect_to_service(self, service_name: str):
        """Connect to discovered service."""
        if service_name not in self.services:
            await self.discover_service(service_name)
        
        endpoints = self.services[service_name]
        if not endpoints:
            raise Exception(f"No healthy {service_name} instances found")
        
        # Connect to first available
        for endpoint in endpoints:
            try:
                client = await plugin_client(
                    host=endpoint["host"],
                    port=endpoint["port"],
                    skip_subprocess=True
                )
                logger.info(f"Connected to {service_name} at {endpoint['host']}:{endpoint['port']}")
                return client
            except Exception as e:
                logger.warning(f"Failed to connect to {endpoint['id']}: {e}")
                continue
        
        raise Exception(f"Could not connect to any {service_name} instance")

# Usage
discovery = ConsulServiceDiscovery()
client = await discovery.connect_to_service("payment-processor")
```

## Health Monitoring

### Health Check Client

```python
class HealthMonitoringClient:
    """Client with health monitoring."""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.client = None
        self.healthy = False
        self.last_health_check = 0
    
    async def ensure_connected(self):
        """Ensure healthy connection."""
        current_time = time.time()
        
        # Check health periodically
        if current_time - self.last_health_check > 30:
            await self.health_check()
        
        if not self.healthy:
            await self.reconnect()
    
    async def health_check(self):
        """Check server health."""
        try:
            if self.client:
                response = await self.client.call("health.Check", service="")
                self.healthy = response.status == "SERVING"
                self.last_health_check = time.time()
                
                if not self.healthy:
                    logger.warning(f"Server unhealthy: {response.status}")
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            self.healthy = False
    
    async def reconnect(self):
        """Reconnect to server."""
        if self.client:
            await self.client.close()
        
        try:
            self.client = await plugin_client(
                host=self.host,
                port=self.port,
                skip_subprocess=True
            )
            await self.health_check()
            logger.info("Reconnected successfully")
        except Exception as e:
            logger.error(f"Reconnection failed: {e}")
            self.healthy = False
    
    async def call(self, method: str, **kwargs):
        """Make monitored call."""
        await self.ensure_connected()
        
        if not self.healthy:
            raise Exception("Server is not healthy")
        
        return await self.client.call(method, **kwargs)
```

## Testing

### Mock Direct Server

```python
import pytest
from unittest.mock import AsyncMock

@pytest.fixture
async def mock_direct_server():
    """Create mock server for testing."""
    
    class MockServer:
        def __init__(self):
            self.host = "localhost"
            self.port = 50051
            self.calls = []
        
        async def handle_call(self, method: str, **kwargs):
            self.calls.append((method, kwargs))
            return {"success": True, "method": method}
    
    server = MockServer()
    
    # Start mock server (implementation depends on framework)
    # ...
    
    yield server
    
    # Cleanup
    # ...

@pytest.mark.asyncio
async def test_direct_connection(mock_direct_server):
    """Test direct connection."""
    
    client = await plugin_client(
        host=mock_direct_server.host,
        port=mock_direct_server.port,
        skip_subprocess=True
    )
    
    result = await client.call("TestMethod", param="value")
    
    assert result["success"] == True
    assert len(mock_direct_server.calls) == 1
    assert mock_direct_server.calls[0] == ("TestMethod", {"param": "value"})
```

## Best Practices

1. **Connection Management**: Always use connection pools for production
2. **Health Checks**: Implement regular health monitoring
3. **Retry Logic**: Add retry with exponential backoff for resilience
4. **Load Balancing**: Distribute load across multiple servers
5. **Security**: Use mTLS for secure connections
6. **Service Discovery**: Integrate with service registries
7. **Monitoring**: Track connection metrics and performance
8. **Graceful Shutdown**: Close connections properly

## See Also

- [Client Configuration](../client/)
- [Connection Management](connections.md)
- [Retry Logic](retry-logic.md)
- [Security Guide](../../security/)