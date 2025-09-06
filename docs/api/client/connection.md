# Connection Management API

The Connection Management API provides robust connection handling for RPC clients including connection pooling, health monitoring, automatic reconnection, and load balancing across multiple endpoints.

## Overview

The connection management system includes:

- **Connection Pooling** - Efficient reuse of connections
- **Health Monitoring** - Continuous connection health checks
- **Automatic Reconnection** - Transparent reconnection on failures
- **Load Balancing** - Distribution across multiple endpoints
- **Circuit Breaking** - Fault tolerance and failover
- **Metrics Collection** - Connection performance monitoring

## Class Reference

### `Connection`

Core connection wrapper with health monitoring and automatic recovery.

```python
from pyvider.client.connection import Connection
import grpc
from typing import Any

class Connection:
    """Managed gRPC connection with health monitoring."""
```

#### Constructor

```python
def __init__(
    self,
    target: str,
    credentials: grpc.ChannelCredentials | None = None,
    options: list[tuple[str, Any]] | None = None,
    compression: grpc.Compression | None = None
):
```

**Parameters:**
- `target` (str): gRPC server target (host:port)
- `credentials` (grpc.ChannelCredentials | None): Channel credentials for secure connections
- `options` (list[tuple] | None): gRPC channel options
- `compression` (grpc.Compression | None): Compression algorithm

**Example:**
```python
import grpc
from pyvider.client.connection import Connection

# Insecure connection
conn = Connection("localhost:50051")

# Secure connection with TLS
credentials = grpc.ssl_channel_credentials()
secure_conn = Connection(
    "api.example.com:443",
    credentials=credentials,
    options=[
        ('grpc.keepalive_time_ms', 30000),
        ('grpc.keepalive_timeout_ms', 5000),
        ('grpc.http2.max_pings_without_data', 0),
        ('grpc.http2.min_ping_interval_without_data_ms', 300000),
    ],
    compression=grpc.Compression.Gzip
)
```

#### Properties

##### `channel`

```python
@property
def channel(self) -> grpc.aio.Channel:
```

Get the underlying gRPC channel.

##### `is_healthy`

```python
@property
def is_healthy(self) -> bool:
```

Check if connection is currently healthy.

##### `stats`

```python
@property
def stats(self) -> dict[str, Any]:
```

Get connection statistics and metrics.

**Returns:**
- `dict[str, Any]`: Connection statistics including:
  - `total_requests`: Total number of requests
  - `failed_requests`: Number of failed requests
  - `avg_latency`: Average request latency
  - `last_used`: Timestamp of last usage
  - `created_at`: Connection creation time

#### Methods

##### `connect`

```python
async def connect(self, timeout: float = 10.0) -> None:
```

Establish connection to the target server.

**Parameters:**
- `timeout` (float): Connection timeout in seconds

**Raises:**
- `ConnectionError`: If connection cannot be established

**Example:**
```python
try:
    await conn.connect(timeout=15.0)
    print("Connection established successfully")
except ConnectionError as e:
    print(f"Connection failed: {e}")
```

##### `disconnect`

```python
async def disconnect(self) -> None:
```

Close the connection gracefully.

##### `health_check`

```python
async def health_check(self, timeout: float = 5.0) -> bool:
```

Perform health check on the connection.

**Parameters:**
- `timeout` (float): Health check timeout in seconds

**Returns:**
- `bool`: True if connection is healthy

##### `wait_for_ready`

```python
async def wait_for_ready(self, timeout: float | None = None) -> bool:
```

Wait for connection to be ready for requests.

**Parameters:**
- `timeout` (float | None): Maximum time to wait (None for indefinite)

**Returns:**
- `bool`: True if connection became ready

### `ConnectionPool`

Connection pool for efficient connection management and reuse.

```python
from pyvider.client.connection import ConnectionPool

class ConnectionPool:
    """Connection pool with load balancing and health monitoring."""
```

#### Constructor

```python
def __init__(
    self,
    targets: list[str],
    max_connections_per_target: int = 5,
    health_check_interval: int = 30,
    max_idle_time: int = 300,
    credentials: grpc.ChannelCredentials | None = None,
    options: list[tuple[str, Any]] | None = None
):
```

**Parameters:**
- `targets` (list[str]): List of server targets
- `max_connections_per_target` (int): Maximum connections per target
- `health_check_interval` (int): Health check interval in seconds
- `max_idle_time` (int): Maximum idle time before connection cleanup
- `credentials` (grpc.ChannelCredentials | None): Default credentials
- `options` (list[tuple] | None): Default channel options

**Example:**
```python
# Connection pool with multiple targets
targets = ["server1.example.com:50051", "server2.example.com:50051"]
pool = ConnectionPool(
    targets=targets,
    max_connections_per_target=10,
    health_check_interval=15,
    credentials=grpc.ssl_channel_credentials()
)
```

#### Methods

##### `get_connection`

```python
async def get_connection(
    self, 
    target: str | None = None,
    load_balance: bool = True
) -> Connection:
```

Get a connection from the pool.

**Parameters:**
- `target` (str | None): Specific target or None for load balancing
- `load_balance` (bool): Enable load balancing across targets

**Returns:**
- `Connection`: Available connection from the pool

**Example:**
```python
# Get any available connection (load balanced)
conn = await pool.get_connection()

# Get connection to specific target
specific_conn = await pool.get_connection("server1.example.com:50051")
```

##### `return_connection`

```python
async def return_connection(self, connection: Connection) -> None:
```

Return connection to the pool for reuse.

##### `get_pool_stats`

```python
def get_pool_stats(self) -> dict[str, Any]:
```

Get comprehensive pool statistics.

**Returns:**
- `dict[str, Any]`: Pool statistics including:
  - `total_connections`: Total connections in pool
  - `active_connections`: Currently active connections
  - `healthy_targets`: Number of healthy targets
  - `pool_utilization`: Connection pool utilization percentage

### `ConnectionManager`

High-level connection manager with advanced features.

```python
from pyvider.client.connection import ConnectionManager

class ConnectionManager:
    """Advanced connection management with circuit breaking and retries."""
```

#### Constructor

```python
def __init__(
    self,
    targets: list[str] | str,
    pool_size: int = 10,
    circuit_breaker_enabled: bool = True,
    retry_policy: dict[str, Any] | None = None,
    health_check_enabled: bool = True
):
```

**Parameters:**
- `targets` (list[str] | str): Server targets or single target
- `pool_size` (int): Connection pool size
- `circuit_breaker_enabled` (bool): Enable circuit breaker pattern
- `retry_policy` (dict | None): Retry policy configuration
- `health_check_enabled` (bool): Enable health monitoring

**Example:**
```python
# Advanced connection manager
manager = ConnectionManager(
    targets=["primary.example.com:50051", "backup.example.com:50051"],
    pool_size=20,
    circuit_breaker_enabled=True,
    retry_policy={
        'max_attempts': 3,
        'backoff_multiplier': 2.0,
        'max_backoff': 60.0,
        'retryable_status_codes': ['UNAVAILABLE', 'DEADLINE_EXCEEDED']
    },
    health_check_enabled=True
)
```

#### Methods

##### `execute_with_retry`

```python
async def execute_with_retry(
    self,
    method: Callable,
    *args,
    **kwargs
) -> Any:
```

Execute method with automatic retry and circuit breaking.

**Parameters:**
- `method` (Callable): Method to execute
- `*args`: Positional arguments for the method
- `**kwargs`: Keyword arguments for the method

**Returns:**
- `Any`: Result of the method execution

**Example:**
```python
# Execute RPC call with retry
async def make_rpc_call():
    conn = await manager.get_connection()
    stub = MyServiceStub(conn.channel)
    return await stub.MyMethod(request)

result = await manager.execute_with_retry(make_rpc_call)
```

## Load Balancing Strategies

### `LoadBalancer`

Base class for load balancing implementations.

```python
from abc import ABC, abstractmethod

class LoadBalancer(ABC):
    """Abstract base class for load balancers."""
    
    @abstractmethod
    def select_target(self, targets: list[str]) -> str:
        """Select target from available targets."""
        pass
```

### `RoundRobinLoadBalancer`

Round-robin load balancing implementation.

```python
from pyvider.client.loadbalancer import RoundRobinLoadBalancer

class RoundRobinLoadBalancer(LoadBalancer):
    """Round-robin load balancing strategy."""
    
    def __init__(self):
        self._current_index = 0
    
    def select_target(self, targets: list[str]) -> str:
        """Select next target in round-robin fashion."""
        if not targets:
            raise ValueError("No targets available")
        
        target = targets[self._current_index % len(targets)]
        self._current_index += 1
        return target
```

### `WeightedLoadBalancer`

Weighted load balancing with target priorities.

```python
from pyvider.client.loadbalancer import WeightedLoadBalancer
import random

class WeightedLoadBalancer(LoadBalancer):
    """Weighted random load balancing strategy."""
    
    def __init__(self, weights: dict[str, int]):
        self.weights = weights
    
    def select_target(self, targets: list[str]) -> str:
        """Select target based on weights."""
        weighted_targets = []
        for target in targets:
            weight = self.weights.get(target, 1)
            weighted_targets.extend([target] * weight)
        
        return random.choice(weighted_targets)

# Usage
weights = {
    "primary.example.com:50051": 3,    # 3x weight
    "secondary.example.com:50051": 1   # 1x weight
}
load_balancer = WeightedLoadBalancer(weights)
```

## Circuit Breaker Integration

### `CircuitBreaker`

Circuit breaker for connection fault tolerance.

```python
from pyvider.client.circuit_breaker import CircuitBreaker
import time

class CircuitBreaker:
    """Circuit breaker for connection management."""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: type = Exception
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        
        self.failure_count = 0
        self.last_failure_time: float | None = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection."""
        
        if self.state == 'OPEN':
            if (self.last_failure_time and 
                time.time() - self.last_failure_time > self.recovery_timeout):
                self.state = 'HALF_OPEN'
            else:
                raise ConnectionError("Circuit breaker is OPEN")
        
        try:
            result = await func(*args, **kwargs)
            
            # Reset on success
            if self.state == 'HALF_OPEN':
                self.state = 'CLOSED'
                self.failure_count = 0
            
            return result
        
        except self.expected_exception as e:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = 'OPEN'
            
            raise
```

## Advanced Usage Examples

### Connection with Custom Health Checks

```python
from pyvider.client.connection import Connection
from grpc_health.v1 import health_pb2, health_pb2_grpc

class HealthAwareConnection(Connection):
    """Connection with custom health check logic."""
    
    async def health_check(self, timeout: float = 5.0) -> bool:
        """Enhanced health check using gRPC health protocol."""
        try:
            health_stub = health_pb2_grpc.HealthStub(self.channel)
            request = health_pb2.HealthCheckRequest()
            
            response = await asyncio.wait_for(
                health_stub.Check(request),
                timeout=timeout
            )
            
            return response.status == health_pb2.HealthCheckResponse.SERVING
        
        except Exception as e:
            logger.warning(f"Health check failed: {e}")
            return False
```

### Connection Pool with Metrics

```python
from prometheus_client import Counter, Gauge, Histogram
import time

# Prometheus metrics
connection_requests = Counter('connection_requests_total', 'Total connection requests')
active_connections = Gauge('active_connections', 'Currently active connections')
connection_duration = Histogram('connection_duration_seconds', 'Connection usage duration')

class MonitoredConnectionPool(ConnectionPool):
    """Connection pool with Prometheus metrics."""
    
    async def get_connection(self, target: str | None = None, load_balance: bool = True) -> Connection:
        """Get connection with metrics tracking."""
        connection_requests.inc()
        start_time = time.time()
        
        try:
            conn = await super().get_connection(target, load_balance)
            active_connections.inc()
            
            # Wrap connection to track usage duration
            original_disconnect = conn.disconnect
            
            async def tracked_disconnect():
                duration = time.time() - start_time
                connection_duration.observe(duration)
                active_connections.dec()
                await original_disconnect()
            
            conn.disconnect = tracked_disconnect
            return conn
        
        except Exception:
            connection_requests.inc()  # Track failed requests
            raise
```

### Adaptive Connection Management

```python
class AdaptiveConnectionManager(ConnectionManager):
    """Connection manager that adapts to server load and performance."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_latencies: dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.adaptive_weights: dict[str, float] = {}
    
    async def execute_with_retry(self, method: Callable, *args, **kwargs) -> Any:
        """Execute with performance-based target selection."""
        
        # Update target weights based on recent performance
        self._update_adaptive_weights()
        
        # Select best performing target
        target = self._select_best_target()
        
        start_time = time.time()
        
        try:
            result = await super().execute_with_retry(method, *args, **kwargs)
            
            # Record successful latency
            latency = time.time() - start_time
            self.target_latencies[target].append(latency)
            
            return result
        
        except Exception:
            # Record failure (high latency penalty)
            self.target_latencies[target].append(float('inf'))
            raise
    
    def _update_adaptive_weights(self):
        """Update target weights based on performance."""
        for target, latencies in self.target_latencies.items():
            if latencies:
                # Calculate average latency (excluding failures)
                valid_latencies = [l for l in latencies if l != float('inf')]
                if valid_latencies:
                    avg_latency = sum(valid_latencies) / len(valid_latencies)
                    # Lower latency = higher weight
                    self.adaptive_weights[target] = 1.0 / (1.0 + avg_latency)
                else:
                    self.adaptive_weights[target] = 0.1  # Low weight for failing targets
    
    def _select_best_target(self) -> str:
        """Select target with best performance."""
        if not self.adaptive_weights:
            return random.choice(self.targets)
        
        # Weighted random selection based on performance
        targets, weights = zip(*self.adaptive_weights.items())
        return random.choices(targets, weights=weights)[0]
```

## Configuration Examples

### YAML Configuration

```yaml
connection_management:
  # Connection pool settings
  pool:
    max_connections_per_target: 10
    health_check_interval: 30
    max_idle_time: 300
    connection_timeout: 10.0
  
  # Load balancing
  load_balancing:
    strategy: weighted  # round_robin, weighted, least_connections
    weights:
      "primary.example.com:50051": 3
      "secondary.example.com:50051": 1
  
  # Circuit breaker
  circuit_breaker:
    enabled: true
    failure_threshold: 5
    recovery_timeout: 60
  
  # Retry policy
  retry:
    max_attempts: 3
    backoff_multiplier: 2.0
    max_backoff: 60.0
    retryable_status_codes:
      - UNAVAILABLE
      - DEADLINE_EXCEEDED
      - RESOURCE_EXHAUSTED
  
  # Health monitoring
  health_check:
    enabled: true
    timeout: 5.0
    use_grpc_health_protocol: true
  
  # gRPC channel options
  channel_options:
    - name: grpc.keepalive_time_ms
      value: 30000
    - name: grpc.keepalive_timeout_ms
      value: 5000
    - name: grpc.http2.max_pings_without_data
      value: 0
```

### Loading Configuration

```python
from pyvider.client.connection import create_connection_manager
import yaml

def setup_connection_manager(config_path: str) -> ConnectionManager:
    """Setup connection manager from configuration."""
    
    with open(config_path) as f:
        config = yaml.safe_load(f)
    
    conn_config = config.get('connection_management', {})
    
    return create_connection_manager(
        targets=config['targets'],
        pool_config=conn_config.get('pool', {}),
        load_balancing_config=conn_config.get('load_balancing', {}),
        circuit_breaker_config=conn_config.get('circuit_breaker', {}),
        retry_config=conn_config.get('retry', {}),
        health_check_config=conn_config.get('health_check', {})
    )
```

## Best Practices

1. **Connection Pooling**
   - Use appropriate pool sizes for your workload
   - Monitor pool utilization and adjust as needed
   - Implement proper connection lifecycle management

2. **Health Monitoring**
   - Enable continuous health checks
   - Use appropriate health check intervals
   - Implement graceful degradation for unhealthy connections

3. **Load Balancing**
   - Choose the right strategy for your use case
   - Consider server capacity and performance differences
   - Monitor and adjust weights based on performance

4. **Error Handling**
   - Implement circuit breakers for fault tolerance
   - Use appropriate retry policies
   - Handle network partitions gracefully

5. **Monitoring**
   - Track connection metrics and performance
   - Set up alerts for connection failures
   - Monitor pool utilization and health

The Connection Management API provides robust, production-ready connection handling that scales from simple client applications to complex distributed systems.