# Connection Management

Master connection lifecycle, health monitoring, reconnection strategies, and advanced connection patterns for robust plugin clients.

## Connection Lifecycle

### Manual Connection Management

```python
import asyncio
from pyvider.rpcplugin import plugin_client

class ManagedConnection:
    def __init__(self, command: list[str]):
        self.command = command
        self.client = None
        self.connected = False
        self.connection_attempts = 0
    
    async def connect(self):
        """Establish connection with retry logic."""
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                self.client = plugin_client(command=self.command)
                await self.client.start()
                
                self.connected = True
                self.connection_attempts = 0
                print(f" Connected on attempt {attempt + 1}")
                return
                
            except Exception as e:
                self.connection_attempts += 1
                print(f"L Connection attempt {attempt + 1} failed: {e}")
                
                if attempt < max_attempts - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    print(f"� Waiting {wait_time}s before retry...")
                    await asyncio.sleep(wait_time)
        
        raise ConnectionError("Failed to connect after all attempts")
    
    async def disconnect(self):
        """Clean disconnect."""
        if self.client:
            await self.client.close()
            self.client = None
            self.connected = False
            print("= Disconnected")
    
    async def ensure_connected(self):
        """Ensure connection is active."""
        if not self.connected or not self.client.is_connected():
            await self.connect()
    
    async def call_with_connection_check(self, service_method, **kwargs):
        """Make RPC call with connection verification."""
        await self.ensure_connected()
        
        try:
            # Parse service.method
            service_name, method_name = service_method.split('.')
            service = getattr(self.client, service_name.lower())
            method = getattr(service, method_name)
            
            return await method(**kwargs)
            
        except Exception as e:
            # Connection may have failed, mark as disconnected
            self.connected = False
            raise e

# Usage
async def managed_connection_example():
    connection = ManagedConnection(["python", "calculator.py"])
    
    try:
        await connection.connect()
        
        # Make calls with automatic connection checking
        result1 = await connection.call_with_connection_check("calculator.Add", a=5, b=3)
        result2 = await connection.call_with_connection_check("calculator.Multiply", a=4, b=7)
        
        print(f"Results: {result1.result}, {result2.result}")
        
    finally:
        await connection.disconnect()

await managed_connection_example()
```

## Connection Health Monitoring

### Health Check Integration

```python
import asyncio
import time
from datetime import datetime, timedelta

class HealthMonitoredClient:
    """Client with built-in health monitoring."""
    
    def __init__(self, command: list[str]):
        self.command = command
        self.client = None
        self.health_stats = {
            "connected_at": None,
            "last_successful_call": None,
            "total_calls": 0,
            "failed_calls": 0,
            "reconnect_count": 0
        }
        self.monitoring_task = None
        self.shutdown_event = asyncio.Event()
    
    async def connect(self):
        """Connect with health tracking."""
        self.client = plugin_client(command=self.command)
        await self.client.start()
        
        self.health_stats["connected_at"] = datetime.now()
        print(" Client connected")
        
        # Start health monitoring
        self.monitoring_task = asyncio.create_task(self._health_monitor())
    
    async def disconnect(self):
        """Disconnect and stop monitoring."""
        self.shutdown_event.set()
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        if self.client:
            await self.client.close()
            self.client = None
        
        print("= Client disconnected")
    
    async def _health_monitor(self):
        """Background health monitoring."""
        while not self.shutdown_event.is_set():
            try:
                # Check every 30 seconds
                await asyncio.wait_for(self.shutdown_event.wait(), timeout=30.0)
                break  # Shutdown requested
                
            except asyncio.TimeoutError:
                # Perform health check
                await self._perform_health_check()
    
    async def _perform_health_check(self):
        """Perform health check on connection."""
        try:
            if not self.client or not self.client.is_connected():
                print("� Connection lost, attempting reconnection...")
                await self._reconnect()
                return
            
            # Try to call health check if available
            if hasattr(self.client, 'health'):
                start_time = time.time()
                await self.client.health.Check(service="")
                latency = (time.time() - start_time) * 1000
                print(f"=� Health check OK (latency: {latency:.1f}ms)")
            
        except Exception as e:
            print(f"d=% Health check failed: {e}")
            await self._reconnect()
    
    async def _reconnect(self):
        """Attempt to reconnect."""
        try:
            if self.client:
                await self.client.close()
            
            await self.connect()
            self.health_stats["reconnect_count"] += 1
            print(f"= Reconnected (attempt #{self.health_stats['reconnect_count']})")
            
        except Exception as e:
            print(f"L Reconnection failed: {e}")
    
    async def call_with_health_tracking(self, service_method: str, **kwargs):
        """Make RPC call with health tracking."""
        start_time = time.time()
        self.health_stats["total_calls"] += 1
        
        try:
            # Parse and call method
            service_name, method_name = service_method.split('.')
            service = getattr(self.client, service_name.lower())
            method = getattr(service, method_name)
            
            result = await method(**kwargs)
            
            # Update success stats
            self.health_stats["last_successful_call"] = datetime.now()
            latency = (time.time() - start_time) * 1000
            print(f"=� Call {service_method} succeeded (latency: {latency:.1f}ms)")
            
            return result
            
        except Exception as e:
            # Update failure stats
            self.health_stats["failed_calls"] += 1
            print(f"=�L Call {service_method} failed: {e}")
            raise
    
    def get_health_report(self) -> Dict:
        """Get comprehensive health report."""
        now = datetime.now()
        connected_duration = None
        
        if self.health_stats["connected_at"]:
            connected_duration = (now - self.health_stats["connected_at"]).total_seconds()
        
        success_rate = 0.0
        if self.health_stats["total_calls"] > 0:
            success_rate = ((self.health_stats["total_calls"] - self.health_stats["failed_calls"]) / 
                           self.health_stats["total_calls"]) * 100
        
        return {
            "connected": self.client is not None and self.client.is_connected(),
            "connected_duration_seconds": connected_duration,
            "total_calls": self.health_stats["total_calls"],
            "failed_calls": self.health_stats["failed_calls"],
            "success_rate_percent": round(success_rate, 2),
            "reconnect_count": self.health_stats["reconnect_count"],
            "last_successful_call": self.health_stats["last_successful_call"].isoformat() 
                                  if self.health_stats["last_successful_call"] else None
        }

# Usage
async def health_monitored_example():
    client = HealthMonitoredClient(["python", "calculator.py"])
    
    try:
        await client.connect()
        
        # Make some calls
        for i in range(5):
            result = await client.call_with_health_tracking("calculator.Add", a=i, b=i+1)
            print(f"Result {i}: {result.result}")
            await asyncio.sleep(1)
        
        # Check health report
        health = client.get_health_report()
        print(f"=� Health Report: {health}")
        
    finally:
        await client.disconnect()

await health_monitored_example()
```

## Connection Pooling

### Client Pool Implementation

```python
import asyncio
from contextlib import asynccontextmanager

class ConnectionPool:
    """Pool of plugin client connections for high-throughput scenarios."""
    
    def __init__(self, command: list[str], pool_size: int = 5, max_overflow: int = 2):
        self.command = command
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        
        self.pool = asyncio.Queue(maxsize=pool_size)
        self.overflow_connections = 0
        self.total_connections = 0
        
        self.pool_stats = {
            "connections_created": 0,
            "connections_reused": 0,
            "pool_hits": 0,
            "pool_misses": 0,
            "overflow_used": 0
        }
    
    async def initialize(self):
        """Initialize the connection pool."""
        for _ in range(self.pool_size):
            client = await self._create_connection()
            await self.pool.put(client)
    
    async def _create_connection(self):
        """Create a new client connection."""
        client = plugin_client(command=self.command)
        await client.start()
        
        self.total_connections += 1
        self.pool_stats["connections_created"] += 1
        
        return client
    
    @asynccontextmanager
    async def acquire(self):
        """Acquire a connection from the pool."""
        client = None
        is_overflow = False
        
        try:
            # Try to get from pool
            try:
                client = await asyncio.wait_for(self.pool.get(), timeout=1.0)
                self.pool_stats["pool_hits"] += 1
                self.pool_stats["connections_reused"] += 1
                
            except asyncio.TimeoutError:
                # Pool is empty, try overflow
                if self.overflow_connections < self.max_overflow:
                    client = await self._create_connection()
                    self.overflow_connections += 1
                    is_overflow = True
                    self.pool_stats["pool_misses"] += 1
                    self.pool_stats["overflow_used"] += 1
                else:
                    # Wait for pool connection
                    client = await self.pool.get()
                    self.pool_stats["pool_hits"] += 1
                    self.pool_stats["connections_reused"] += 1
            
            # Verify connection is healthy
            if not client.is_connected():
                if is_overflow:
                    self.overflow_connections -= 1
                # Create new connection
                await client.close()
                client = await self._create_connection()
                if not is_overflow:
                    is_overflow = True
                    self.overflow_connections += 1
            
            yield client
            
        finally:
            if client:
                if is_overflow:
                    # Close overflow connection
                    await client.close()
                    self.overflow_connections -= 1
                    self.total_connections -= 1
                else:
                    # Return to pool
                    await self.pool.put(client)
    
    async def close_all(self):
        """Close all connections in the pool."""
        # Close all pooled connections
        connections_closed = 0
        while not self.pool.empty():
            try:
                client = self.pool.get_nowait()
                await client.close()
                connections_closed += 1
            except asyncio.QueueEmpty:
                break
        
        self.total_connections = 0
        print(f"= Closed {connections_closed} pooled connections")
    
    def get_pool_stats(self) -> Dict:
        """Get connection pool statistics."""
        return {
            "pool_size": self.pool_size,
            "total_connections": self.total_connections,
            "overflow_connections": self.overflow_connections,
            "available_in_pool": self.pool.qsize(),
            "stats": self.pool_stats
        }

# Usage
async def connection_pool_example():
    """Example using connection pool for high-throughput operations."""
    
    pool = ConnectionPool(["python", "calculator.py"], pool_size=3, max_overflow=2)
    await pool.initialize()
    
    try:
        # Concurrent operations using pool
        async def calculate(operation_id: int):
            async with pool.acquire() as client:
                result = await client.calculator.Add(a=operation_id, b=operation_id * 2)
                print(f"Operation {operation_id}: {operation_id} + {operation_id * 2} = {result.result}")
                return result.result
        
        # Launch 10 concurrent calculations
        tasks = [calculate(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        print(f"=� Completed {len(results)} calculations")
        print(f"=� Pool stats: {pool.get_pool_stats()}")
        
    finally:
        await pool.close_all()

await connection_pool_example()
```

## Automatic Reconnection

### Smart Reconnection Strategy

```python
import asyncio
import time
import random
from typing import Callable, Any, Optional

class AutoReconnectClient:
    """Client with intelligent automatic reconnection."""
    
    def __init__(self, command: list[str]):
        self.command = command
        self.client: plugin_client | None = None
        
        # Reconnection settings
        self.max_reconnect_attempts = 5
        self.base_reconnect_delay = 1.0
        self.max_reconnect_delay = 60.0
        self.reconnect_backoff_factor = 2.0
        self.jitter_enabled = True
        
        # State tracking
        self.reconnect_attempts = 0
        self.last_disconnect_time = 0
        self.consecutive_failures = 0
        
    async def connect(self):
        """Initial connection."""
        await self._attempt_connection()
    
    async def _attempt_connection(self):
        """Attempt to establish connection."""
        try:
            if self.client:
                await self.client.close()
            
            self.client = plugin_client(command=self.command)
            await self.client.start()
            
            # Reset failure counters on successful connection
            self.reconnect_attempts = 0
            self.consecutive_failures = 0
            
            print(" Connection established")
            
        except Exception as e:
            print(f"L Connection failed: {e}")
            self.client = None
            raise
    
    async def _reconnect_with_backoff(self):
        """Reconnect with exponential backoff and jitter."""
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            raise ConnectionError("Maximum reconnection attempts exceeded")
        
        # Calculate delay with exponential backoff
        delay = min(
            self.base_reconnect_delay * (self.reconnect_backoff_factor ** self.reconnect_attempts),
            self.max_reconnect_delay
        )
        
        # Add jitter to prevent thundering herd
        if self.jitter_enabled:
            delay *= (0.5 + random.random() * 0.5)
        
        print(f"= Reconnecting in {delay:.1f}s (attempt {self.reconnect_attempts + 1}/{self.max_reconnect_attempts})")
        await asyncio.sleep(delay)
        
        self.reconnect_attempts += 1
        await self._attempt_connection()
    
    async def call_with_auto_reconnect(self, service_method: str, **kwargs) -> Any:
        """Make RPC call with automatic reconnection on failure."""
        
        while True:
            try:
                # Ensure we have a connection
                if not self.client or not self.client.is_connected():
                    await self._reconnect_with_backoff()
                
                # Parse and execute method call
                service_name, method_name = service_method.split('.')
                service = getattr(self.client, service_name.lower())
                method = getattr(service, method_name)
                
                result = await method(**kwargs)
                
                # Reset failure count on success
                self.consecutive_failures = 0
                return result
                
            except Exception as e:
                self.consecutive_failures += 1
                self.last_disconnect_time = time.time()
                
                print(f"=�L Call failed: {e}")
                
                # Check if we should give up
                if self.consecutive_failures > 3:
                    print(f"=� Too many consecutive failures ({self.consecutive_failures})")
                    raise
                
                # Try to reconnect
                try:
                    await self._reconnect_with_backoff()
                except Exception as reconnect_error:
                    print(f"=L Reconnection failed: {reconnect_error}")
                    if self.reconnect_attempts >= self.max_reconnect_attempts:
                        raise
                    continue
    
    async def close(self):
        """Close connection."""
        if self.client:
            await self.client.close()
            self.client = None
        print("= Connection closed")

# Usage
async def auto_reconnect_example():
    """Example with automatic reconnection handling."""
    
    client = AutoReconnectClient(["python", "flaky_calculator.py"])
    
    try:
        await client.connect()
        
        # Make multiple calls, some may trigger reconnections
        for i in range(10):
            try:
                result = await client.call_with_auto_reconnect("calculator.Add", a=i, b=i+1)
                print(f" Call {i}: {i} + {i+1} = {result.result}")
                
            except Exception as e:
                print(f"L Call {i} permanently failed: {e}")
            
            await asyncio.sleep(1)
    
    finally:
        await client.close()

await auto_reconnect_example()
```

## Connection State Management

### Connection State Machine

```python
from enum import Enum
import asyncio
from typing import Callable

class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    RECONNECTING = "reconnecting"
    FAILED = "failed"

class StatefulConnection:
    """Connection with explicit state management."""
    
    def __init__(self, command: list[str]):
        self.command = command
        self.client: plugin_client | None = None
        self.state = ConnectionState.DISCONNECTED
        
        # State change callbacks
        self.state_callbacks: dict[ConnectionState, list[Callable]] = {
            state: [] for state in ConnectionState
        }
        
        # Connection metrics
        self.metrics = {
            "connection_count": 0,
            "disconnection_count": 0,
            "failed_connection_count": 0,
            "total_calls": 0
        }
    
    def on_state_change(self, state: ConnectionState, callback: Callable):
        """Register callback for state changes."""
        self.state_callbacks[state].append(callback)
    
    async def _change_state(self, new_state: ConnectionState):
        """Change connection state and notify callbacks."""
        old_state = self.state
        self.state = new_state
        
        print(f"= State change: {old_state.value} -> {new_state.value}")
        
        # Notify callbacks
        for callback in self.state_callbacks[new_state]:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(old_state, new_state)
                else:
                    callback(old_state, new_state)
            except Exception as e:
                print(f"� State callback error: {e}")
    
    async def connect(self):
        """Connect with state management."""
        if self.state in [ConnectionState.CONNECTING, ConnectionState.CONNECTED]:
            return  # Already connecting or connected
        
        await self._change_state(ConnectionState.CONNECTING)
        
        try:
            self.client = plugin_client(command=self.command)
            await self.client.start()
            
            self.metrics["connection_count"] += 1
            await self._change_state(ConnectionState.CONNECTED)
            
        except Exception as e:
            self.metrics["failed_connection_count"] += 1
            await self._change_state(ConnectionState.FAILED)
            raise e
    
    async def disconnect(self):
        """Disconnect with state management."""
        if self.state == ConnectionState.DISCONNECTED:
            return
        
        await self._change_state(ConnectionState.DISCONNECTING)
        
        try:
            if self.client:
                await self.client.close()
                self.client = None
            
            self.metrics["disconnection_count"] += 1
            await self._change_state(ConnectionState.DISCONNECTED)
            
        except Exception as e:
            await self._change_state(ConnectionState.FAILED)
            raise e
    
    async def reconnect(self):
        """Reconnect with state management."""
        await self._change_state(ConnectionState.RECONNECTING)
        
        try:
            if self.client:
                await self.client.close()
                self.client = None
            
            await self.connect()
            
        except Exception as e:
            await self._change_state(ConnectionState.FAILED)
            raise e
    
    async def call_method(self, service_method: str, **kwargs):
        """Make method call with state checking."""
        if self.state != ConnectionState.CONNECTED:
            raise RuntimeError(f"Cannot call method in state: {self.state.value}")
        
        self.metrics["total_calls"] += 1
        
        try:
            service_name, method_name = service_method.split('.')
            service = getattr(self.client, service_name.lower())
            method = getattr(service, method_name)
            
            return await method(**kwargs)
            
        except Exception as e:
            # Connection may have failed
            if not self.client.is_connected():
                await self._change_state(ConnectionState.FAILED)
            raise e
    
    def get_state_info(self) -> Dict:
        """Get current state and metrics."""
        return {
            "current_state": self.state.value,
            "is_connected": self.state == ConnectionState.CONNECTED,
            "can_make_calls": self.state == ConnectionState.CONNECTED,
            "metrics": self.metrics
        }

# Usage with state callbacks
async def stateful_connection_example():
    """Example with stateful connection management."""
    
    connection = StatefulConnection(["python", "calculator.py"])
    
    # Register state change callbacks
    async def on_connected(old_state, new_state):
        print(f"<� Successfully connected!")
    
    async def on_failed(old_state, new_state):
        print(f"=� Connection failed!")
    
    connection.on_state_change(ConnectionState.CONNECTED, on_connected)
    connection.on_state_change(ConnectionState.FAILED, on_failed)
    
    try:
        # Connect and make calls
        await connection.connect()
        
        result = await connection.call_method("calculator.Add", a=5, b=3)
        print(f"Result: {result.result}")
        
        # Check state
        state_info = connection.get_state_info()
        print(f"=� Connection info: {state_info}")
        
    finally:
        await connection.disconnect()

await stateful_connection_example()
```

## Next Steps

- **[Direct Connections](direct-connections.md)** - Connect to existing servers
- **[Retry Logic](retry-logic.md)** - Build resilient error handling
- **[Basic Setup](basic-setup.md)** - Review fundamentals