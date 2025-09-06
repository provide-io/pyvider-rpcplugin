# Direct Connections

Connect to existing plugin servers without launching new processes. Ideal for service discovery, load balancing, and connecting to long-running plugin services.

## Overview

Direct connections allow clients to connect to already-running plugin servers using established communication channels. This pattern is useful for microservice architectures, service registries, and distributed systems where plugin servers run independently.

```python
import asyncio
from pyvider.rpcplugin import plugin_client

async def direct_connection_example():
    # Connect to existing server via TCP
    async with plugin_client(
        host="127.0.0.1", 
        port=8080
    ) as client:
        # Server is already running - no process launch
        result = await client.calculator.Add(a=10, b=5)
        print(f"Result from existing server: {result.result}")

# Usage
await direct_connection_example()
```

## Connection Methods

### TCP Direct Connection

```python
from pyvider.rpcplugin import plugin_client

async def tcp_direct_connection():
    """Connect directly to TCP server."""
    
    # Basic TCP connection
    async with plugin_client(
        host="127.0.0.1",
        port=8080,
        timeout=30.0
    ) as client:
        
        # Verify connection
        if client.is_connected():
            print("Connected to TCP server")
        
        # Use service
        result = await client.service.Method(param="value")
        return result

async def secure_tcp_connection():
    """Connect with mTLS security."""
    
    async with plugin_client(
        host="plugin.example.com",
        port=8443,
        enable_mtls=True,
        client_cert="client.pem",
        client_key="client.key",
        ca_cert="ca.pem"
    ) as client:
        
        print("Secure connection established")
        result = await client.secure_service.ProcessData(data="sensitive")
        return result

# Usage
result = await tcp_direct_connection()
secure_result = await secure_tcp_connection()
```

### Unix Socket Direct Connection

```python
async def unix_socket_direct_connection():
    """Connect to Unix socket server."""
    
    async with plugin_client(
        unix_socket="/tmp/my_plugin.sock",
        timeout=15.0
    ) as client:
        
        print("Connected via Unix socket")
        
        # Check available services
        services = client.get_available_services()
        print(f"Available services: {services}")
        
        # Use service
        result = await client.file_processor.ProcessFile(
            path="/data/input.txt"
        )
        
        return result

# Usage
result = await unix_socket_direct_connection()
```

## Service Discovery Integration

### Registry-Based Discovery

```python
import asyncio
import json
from pathlib import Path

class ServiceRegistry:
    """Simple file-based service registry."""
    
    def __init__(self, registry_path: str = "/tmp/plugin_registry.json"):
        self.registry_path = Path(registry_path)
    
    def register_service(self, name: str, host: str, port: int, 
                        services: list[str], metadata: dict | None = None):
        """Register a plugin service."""
        registry = self._load_registry()
        
        registry[name] = {
            "host": host,
            "port": port,
            "services": services,
            "metadata": metadata or {},
            "registered_at": asyncio.get_event_loop().time()
        }
        
        self._save_registry(registry)
    
    def discover_service(self, name: str) -> dict | None:
        """Discover service by name."""
        registry = self._load_registry()
        return registry.get(name)
    
    def _load_registry(self) -> dict:
        if not self.registry_path.exists():
            return {}
        
        with open(self.registry_path) as f:
            return json.load(f)
    
    def _save_registry(self, registry: dict):
        with open(self.registry_path, "w") as f:
            json.dump(registry, f, indent=2)

class DiscoveryClient:
    """Client with integrated service discovery."""
    
    def __init__(self, registry: ServiceRegistry):
        self.registry = registry
    
    async def connect_to_service(self, service_name: str):
        """Connect to service by name via discovery."""
        
        # Discover service
        service_info = self.registry.discover_service(service_name)
        if not service_info:
            raise ValueError(f"Service '{service_name}' not found in registry")
        
        # Connect using discovered information
        client = plugin_client(
            host=service_info["host"],
            port=service_info["port"],
            timeout=30.0
        )
        
        await client.start()
        print(f"Connected to '{service_name}' at {service_info['host']}:{service_info['port']}")
        
        return client

# Usage example
async def service_discovery_example():
    registry = ServiceRegistry()
    
    # Register services (normally done by servers)
    registry.register_service(
        "calculator", "127.0.0.1", 8080, 
        ["calculator.Calculator"], {"version": "1.0"}
    )
    
    # Use discovery client
    discovery = DiscoveryClient(registry)
    
    try:
        calc_client = await discovery.connect_to_service("calculator")
        result = await calc_client.calculator.Add(a=15, b=25)
        print(f"Calculator result: {result.result}")
    finally:
        await calc_client.close()
```

### External Service Discovery

```python
import consul

class ConsulServiceDiscovery:
    """Service discovery using HashiCorp Consul."""
    
    def __init__(self, consul_host: str = "localhost", consul_port: int = 8500):
        self.consul = consul.Consul(host=consul_host, port=consul_port)
    
    def discover_plugin_services(self, service_prefix: str = "plugin-") -> list[tuple[str, str, int]]:
        """Discover plugin services from Consul."""
        
        services = []
        _, all_services = self.consul.catalog.services()
        
        # Filter plugin services
        for service_name in all_services:
            if service_name.startswith(service_prefix):
                _, service_instances = self.consul.health.service(service_name, passing=True)
                
                for instance in service_instances:
                    service_info = instance['Service']
                    services.append((
                        service_name,
                        service_info['Address'],
                        service_info['Port']
                    ))
        
        return services
    
    async def create_clients_from_discovery(self, service_prefix: str = "plugin-") -> dict[str, plugin_client]:
        """Create clients for all discovered services."""
        
        services = self.discover_plugin_services(service_prefix)
        clients = {}
        
        for service_name, host, port in services:
            try:
                client = plugin_client(host=host, port=port)
                await client.start()
                clients[service_name] = client
                print(f"Connected to {service_name} at {host}:{port}")
            except Exception as e:
                print(f"Failed to connect to {service_name}: {e}")
        
        return clients
```

## Load Balancing and Connection Pools

### Load Balancing Client

```python
import asyncio
from itertools import cycle
import random

class LoadBalancedClient:
    """Client with built-in load balancing across multiple servers."""
    
    def __init__(self, endpoints: list[dict], strategy: str = "round_robin"):
        self.endpoints = endpoints
        self.strategy = strategy
        self.clients = []
        self.round_robin_cycle = cycle(range(len(endpoints)))
    
    async def initialize(self):
        """Initialize connections to all endpoints."""
        
        for endpoint in self.endpoints:
            try:
                client = plugin_client(**endpoint)
                await client.start()
                self.clients.append(client)
                print(f"Connected to {endpoint.get('host', endpoint.get('unix_socket'))}")
            except Exception as e:
                print(f"Failed to connect to {endpoint}: {e}")
                self.clients.append(None)  # Placeholder for failed connection
    
    def _select_client(self) -> plugin_client:
        """Select client based on load balancing strategy."""
        
        available_clients = [(i, c) for i, c in enumerate(self.clients) if c is not None]
        
        if not available_clients:
            raise Exception("No available clients")
        
        if self.strategy == "round_robin":
            # Get next client in round-robin fashion
            while True:
                index = next(self.round_robin_cycle)
                if self.clients[index] is not None:
                    return self.clients[index]
        
        elif self.strategy == "random":
            # Select random available client
            _, client = random.choice(available_clients)
            return client
        
        else:
            raise ValueError(f"Unknown strategy: {self.strategy}")
    
    async def call_with_load_balancing(self, service_method: str, **kwargs):
        """Make RPC call with automatic load balancing."""
        
        max_attempts = len([c for c in self.clients if c is not None])
        
        for attempt in range(max_attempts):
            try:
                client = self._select_client()
                
                # Parse service and method
                service_name, method_name = service_method.split('.')
                service = getattr(client, service_name.lower())
                method = getattr(service, method_name)
                
                # Make the call
                result = await method(**kwargs)
                return result
                
            except Exception as e:
                print(f"Attempt {attempt + 1} failed: {e}")
                if attempt == max_attempts - 1:
                    raise e
                # Continue to next client
    
    async def close_all(self):
        """Close all client connections."""
        for client in self.clients:
            if client is not None:
                await client.close()

# Usage example
async def load_balancing_example():
    endpoints = [
        {"host": "127.0.0.1", "port": 8080},
        {"host": "127.0.0.1", "port": 8081},
        {"host": "127.0.0.1", "port": 8082},
    ]
    
    lb_client = LoadBalancedClient(endpoints, strategy="round_robin")
    
    try:
        await lb_client.initialize()
        
        for i in range(5):
            result = await lb_client.call_with_load_balancing(
                "calculator.Add", a=i, b=i*2
            )
            print(f"Request {i}: {i} + {i*2} = {result.result}")
    finally:
        await lb_client.close_all()
```

## Health Monitoring and Failover

### Health-Monitored Connection

```python
import asyncio
import time
import grpc

class HealthMonitoredClient:
    """Client with built-in health monitoring for direct connections."""
    
    def __init__(self, host: str, port: int, health_check_interval: float = 30.0):
        self.host = host
        self.port = port
        self.health_check_interval = health_check_interval
        self.client = None
        self.is_healthy = False
        self.last_health_check = 0
        self._health_monitor_task = None
    
    async def connect(self):
        """Establish connection with health monitoring."""
        
        self.client = plugin_client(host=self.host, port=self.port)
        await self.client.start()
        
        # Start health monitoring
        self._health_monitor_task = asyncio.create_task(self._health_monitor_loop())
        
        print(f"Connected to {self.host}:{self.port} with health monitoring")
    
    async def _health_monitor_loop(self):
        """Background health monitoring loop."""
        
        while True:
            try:
                await self._perform_health_check()
                await asyncio.sleep(self.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Health monitor error: {e}")
                await asyncio.sleep(5)  # Brief retry delay
    
    async def _perform_health_check(self):
        """Perform health check on connection."""
        
        try:
            if self.client and hasattr(self.client, 'health'):
                # Use gRPC health service if available
                health_response = await self.client.health.Check(service="")
                self.is_healthy = health_response.status == "SERVING"
            else:
                # Fallback: simple connection check
                self.is_healthy = self.client and self.client.is_connected()
            
            self.last_health_check = time.time()
            
            if self.is_healthy:
                print(f"Health check passed for {self.host}:{self.port}")
            else:
                print(f"Health check failed for {self.host}:{self.port}")
        
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                self.is_healthy = False
                print(f"Server unavailable: {self.host}:{self.port}")
            else:
                print(f"Health check RPC error: {e.code()}")
        except Exception as e:
            self.is_healthy = False
            print(f"Health check failed: {e}")
    
    async def safe_call(self, service_method: str, **kwargs):
        """Make RPC call with health checking."""
        
        # Check health before call
        if not self.is_healthy:
            raise Exception(f"Client unhealthy: {self.host}:{self.port}")
        
        try:
            # Parse service and method
            service_name, method_name = service_method.split('.')
            service = getattr(self.client, service_name.lower())
            method = getattr(service, method_name)
            
            return await method(**kwargs)
        
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.UNAVAILABLE:
                self.is_healthy = False
            raise
    
    async def close(self):
        """Close connection and stop monitoring."""
        
        if self._health_monitor_task:
            self._health_monitor_task.cancel()
            try:
                await self._health_monitor_task
            except asyncio.CancelledError:
                pass
        
        if self.client:
            await self.client.close()
        
        print(f"Disconnected from {self.host}:{self.port}")
```

### Automatic Failover Client

```python
import asyncio
import time

class FailoverClient:
    """Client with automatic failover to backup servers."""
    
    def __init__(self, primary_endpoint: dict, 
                 backup_endpoints: list[dict],
                 failover_timeout: float = 5.0):
        self.primary_endpoint = primary_endpoint
        self.backup_endpoints = backup_endpoints
        self.failover_timeout = failover_timeout
        self.current_client = None
        self.current_endpoint_index = -1  # -1 = primary, 0+ = backup index
        self.last_failover = 0
    
    async def connect(self):
        """Connect with automatic failover capability."""
        await self._try_connect_primary()
    
    async def _try_connect_primary(self):
        """Attempt to connect to primary server."""
        try:
            self.current_client = plugin_client(**self.primary_endpoint)
            await self.current_client.start()
            self.current_endpoint_index = -1
            print(f"Connected to primary: {self.primary_endpoint}")
            return True
        except Exception as e:
            print(f"Primary connection failed: {e}")
            return await self._try_connect_backup()
    
    async def _try_connect_backup(self) -> bool:
        """Try connecting to backup servers in order."""
        
        for i, backup_endpoint in enumerate(self.backup_endpoints):
            try:
                if self.current_client:
                    await self.current_client.close()
                
                self.current_client = plugin_client(**backup_endpoint)
                await self.current_client.start()
                self.current_endpoint_index = i
                print(f"Failed over to backup {i}: {backup_endpoint}")
                return True
                
            except Exception as e:
                print(f"Backup {i} connection failed: {e}")
                continue
        
        print("All servers unavailable")
        return False
    
    async def _handle_connection_failure(self):
        """Handle connection failure with intelligent failover."""
        
        current_time = time.time()
        
        # Prevent rapid failover attempts
        if current_time - self.last_failover < self.failover_timeout:
            print("Failover timeout active, waiting...")
            raise Exception("Failover timeout active")
        
        self.last_failover = current_time
        
        # If we're on primary, try backups
        if self.current_endpoint_index == -1:
            success = await self._try_connect_backup()
        else:
            # If on backup, try primary first, then other backups
            success = await self._try_connect_primary()
        
        if not success:
            raise Exception("All failover attempts exhausted")
    
    async def resilient_call(self, service_method: str, max_retries: int = 2, **kwargs):
        """Make RPC call with automatic failover on failure."""
        
        for attempt in range(max_retries + 1):
            try:
                if not self.current_client:
                    await self.connect()
                
                # Parse service and method
                service_name, method_name = service_method.split('.')
                service = getattr(self.current_client, service_name.lower())
                method = getattr(service, method_name)
                
                return await method(**kwargs)
            
            except (grpc.aio.AioRpcError, Exception) as e:
                print(f"Call attempt {attempt + 1} failed: {e}")
                
                if attempt < max_retries:
                    try:
                        await self._handle_connection_failure()
                        print("Retrying call on failover connection...")
                    except Exception as failover_error:
                        print(f"Failover failed: {failover_error}")
                        if attempt == max_retries - 1:
                            raise e
                else:
                    raise e
    
    async def close(self):
        """Close current connection."""
        if self.current_client:
            await self.current_client.close()
            print("Failover client disconnected")

# Usage example
async def failover_client_example():
    primary = {"host": "127.0.0.1", "port": 8080}
    backups = [
        {"host": "127.0.0.1", "port": 8081},
        {"host": "127.0.0.1", "port": 8082}
    ]
    
    failover_client = FailoverClient(primary, backups, failover_timeout=3.0)
    
    try:
        await failover_client.connect()
        
        for i in range(3):
            try:
                result = await failover_client.resilient_call(
                    "calculator.Multiply", a=i, b=2, max_retries=2
                )
                print(f"Resilient call {i}: {i} * 2 = {result.result}")
            except Exception as e:
                print(f"All attempts failed for call {i}: {e}")
            await asyncio.sleep(1)
    finally:
        await failover_client.close()
```

## Configuration and Best Practices

### Connection Configuration

```python
import os
from dataclasses import dataclass

@dataclass
class DirectConnectionConfig:
    """Configuration for direct connections."""
    
    # Connection settings
    host: str | None = None
    port: int | None = None
    unix_socket: str | None = None
    
    # Timeouts
    connect_timeout: float = 10.0
    request_timeout: float = 30.0
    
    # Security
    enable_mtls: bool = False
    client_cert: str | None = None
    client_key: str | None = None
    ca_cert: str | None = None
    
    # Performance
    compression: str = "gzip"
    max_message_size: int = 4 * 1024 * 1024
    keepalive_time: float = 30.0
    
    @classmethod
    def from_environment(cls, prefix: str = "PLUGIN_CLIENT_") -> 'DirectConnectionConfig':
        """Create config from environment variables."""
        
        config = cls()
        
        # Connection
        if host := os.environ.get(f"{prefix}HOST"):
            config.host = host
        if port := os.environ.get(f"{prefix}PORT"):
            config.port = int(port)
        if socket := os.environ.get(f"{prefix}UNIX_SOCKET"):
            config.unix_socket = socket
        
        # Timeouts
        if timeout := os.environ.get(f"{prefix}CONNECT_TIMEOUT"):
            config.connect_timeout = float(timeout)
        if timeout := os.environ.get(f"{prefix}REQUEST_TIMEOUT"):
            config.request_timeout = float(timeout)
        
        # Security
        config.enable_mtls = os.environ.get(f"{prefix}ENABLE_MTLS", "false").lower() == "true"
        config.client_cert = os.environ.get(f"{prefix}CLIENT_CERT")
        config.client_key = os.environ.get(f"{prefix}CLIENT_KEY")
        config.ca_cert = os.environ.get(f"{prefix}CA_CERT")
        
        return config
    
    def create_client_kwargs(self) -> dict:
        """Convert config to plugin_client kwargs."""
        
        kwargs = {
            "timeout": self.connect_timeout,
            "compression": self.compression,
            "max_message_size": self.max_message_size,
            "keepalive_time": self.keepalive_time
        }
        
        # Connection method
        if self.unix_socket:
            kwargs["unix_socket"] = self.unix_socket
        elif self.host and self.port:
            kwargs["host"] = self.host
            kwargs["port"] = self.port
        else:
            raise ValueError("Must specify either unix_socket or host+port")
        
        # Security
        if self.enable_mtls and self.client_cert and self.client_key:
            kwargs.update({
                "enable_mtls": True,
                "client_cert": self.client_cert,
                "client_key": self.client_key
            })
            if self.ca_cert:
                kwargs["ca_cert"] = self.ca_cert
        
        return kwargs

# Usage
config = DirectConnectionConfig.from_environment()
client_kwargs = config.create_client_kwargs()

async with plugin_client(**client_kwargs) as client:
    result = await client.service.Method(param="value")
```

### Production Deployment

```python
import asyncio
import logging
from contextlib import asynccontextmanager

class ProductionDirectClient:
    """Production-ready direct connection client."""
    
    def __init__(self, 
                 endpoints: list[dict],
                 service_name: str,
                 enable_metrics: bool = True,
                 enable_logging: bool = True):
        
        self.endpoints = endpoints
        self.service_name = service_name
        self.enable_metrics = enable_metrics
        
        # Setup logging
        if enable_logging:
            self.logger = logging.getLogger(f"plugin_client.{service_name}")
            self.logger.setLevel(logging.INFO)
        
        # Metrics
        if enable_metrics:
            self.metrics = {
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "average_response_time": 0.0,
                "active_connections": 0
            }
    
    @asynccontextmanager
    async def get_client(self):
        """Get client with proper resource management."""
        
        client = None
        start_time = time.time()
        
        try:
            # Try endpoints in order
            for endpoint in self.endpoints:
                try:
                    client = plugin_client(**endpoint)
                    await client.start()
                    
                    if self.enable_metrics:
                        self.metrics["active_connections"] += 1
                    
                    if hasattr(self, 'logger'):
                        self.logger.info(f"Connected to {endpoint}")
                    
                    yield client
                    break
                    
                except Exception as e:
                    if hasattr(self, 'logger'):
                        self.logger.warning(f"Failed to connect to {endpoint}: {e}")
                    continue
            else:
                raise Exception("All endpoints failed")
        
        finally:
            # Update metrics
            if self.enable_metrics:
                self.metrics["total_requests"] += 1
                duration = time.time() - start_time
                
                if client and client.is_connected():
                    self.metrics["successful_requests"] += 1
                else:
                    self.metrics["failed_requests"] += 1
                
                # Update average response time
                self.metrics["average_response_time"] = (
                    (self.metrics["average_response_time"] * (self.metrics["total_requests"] - 1) + duration) 
                    / self.metrics["total_requests"]
                )
                
                if client:
                    self.metrics["active_connections"] -= 1
            
            # Cleanup
            if client:
                await client.close()
    
    async def call(self, service_method: str, **kwargs):
        """Make production RPC call."""
        
        async with self.get_client() as client:
            service_name, method_name = service_method.split('.')
            service = getattr(client, service_name.lower())
            method = getattr(service, method_name)
            
            return await method(**kwargs)
    
    def get_metrics(self) -> dict:
        """Get client metrics."""
        if not self.enable_metrics:
            return {}
        
        return self.metrics.copy()

# Usage in production
async def production_usage_example():
    endpoints = [
        {
            "host": "plugin-primary.internal", 
            "port": 8080,
            "enable_mtls": True,
            "client_cert": "/etc/ssl/client.pem",
            "client_key": "/etc/ssl/client.key"
        },
        {
            "host": "plugin-backup.internal",
            "port": 8080, 
            "enable_mtls": True,
            "client_cert": "/etc/ssl/client.pem",
            "client_key": "/etc/ssl/client.key"
        }
    ]
    
    prod_client = ProductionDirectClient(
        endpoints=endpoints,
        service_name="payment_processor",
        enable_metrics=True,
        enable_logging=True
    )
    
    try:
        result = await prod_client.call(
            "payment.ProcessPayment",
            amount=100.00,
            currency="USD",
            payment_method="credit_card"
        )
        
        print(f"Payment processed: {result.transaction_id}")
        metrics = prod_client.get_metrics()
        print(f"Client metrics: {metrics}")
        
    except Exception as e:
        print(f"Production call failed: {e}")
```

## Debugging and Troubleshooting

### Connection Diagnostics

```python
import asyncio
import grpc
from pyvider.rpcplugin import plugin_client

async def diagnose_connection(host: str, port: int):
    """Diagnose connection issues."""
    
    print(f"Diagnosing connection to {host}:{port}")
    
    try:
        # Test basic connectivity
        print("Testing basic connectivity...")
        client = plugin_client(host=host, port=port, timeout=5.0)
        await client.start()
        
        print("Connection established successfully")
        
        # Test service availability
        try:
            services = client.get_available_services()
            print(f"Available services: {services}")
        except Exception as e:
            print(f"Service discovery failed: {e}")
        
        # Test health endpoint if available
        if hasattr(client, 'health'):
            try:
                health = await client.health.Check(service="")
                print(f"Health status: {health.status}")
            except Exception as e:
                print(f"Health check failed: {e}")
        
        await client.close()
        print("Connection diagnostic completed successfully")
        
    except grpc.aio.AioRpcError as e:
        print(f"gRPC error: {e.code()} - {e.details()}")
    except Exception as e:
        print(f"Connection failed: {e}")

# Usage
await diagnose_connection("127.0.0.1", 8080)
```

### Performance Monitoring

```python
import time
import asyncio

class PerformanceMonitor:
    """Monitor connection performance."""
    
    def __init__(self):
        self.request_times = []
        self.error_count = 0
        self.total_requests = 0
    
    async def timed_call(self, client, service_method: str, **kwargs):
        """Make a timed RPC call."""
        
        start_time = time.time()
        self.total_requests += 1
        
        try:
            service_name, method_name = service_method.split('.')
            service = getattr(client, service_name.lower())
            method = getattr(service, method_name)
            
            result = await method(**kwargs)
            
            # Record timing
            duration = time.time() - start_time
            self.request_times.append(duration)
            
            return result
            
        except Exception as e:
            self.error_count += 1
            duration = time.time() - start_time
            self.request_times.append(duration)
            raise
    
    def get_stats(self) -> dict:
        """Get performance statistics."""
        
        if not self.request_times:
            return {}
        
        return {
            "total_requests": self.total_requests,
            "error_count": self.error_count,
            "error_rate": self.error_count / self.total_requests,
            "avg_response_time": sum(self.request_times) / len(self.request_times),
            "min_response_time": min(self.request_times),
            "max_response_time": max(self.request_times)
        }

# Usage
async def performance_test():
    monitor = PerformanceMonitor()
    
    async with plugin_client(host="127.0.0.1", port=8080) as client:
        # Run performance test
        for i in range(100):
            try:
                await monitor.timed_call(client, "calculator.Add", a=i, b=1)
            except Exception as e:
                print(f"Request {i} failed: {e}")
        
        # Print stats
        stats = monitor.get_stats()
        print(f"Performance stats: {stats}")
```

## Next Steps

- **[Connection Management](connections.md)** - Master connection lifecycle and pooling
- **[Retry Logic](retry-logic.md)** - Implement resilient error handling and retry patterns  
- **[Basic Client Setup](basic-setup.md)** - Review client fundamentals and configuration