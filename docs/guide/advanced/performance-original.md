# Performance Tuning

Optimize plugin performance for production workloads. Learn profiling, benchmarking, connection pooling, memory management, and scaling techniques for high-throughput systems.

## Overview

Performance tuning is crucial for production plugin systems handling high traffic loads. This includes CPU optimization, memory management, network efficiency, and scaling strategies to achieve maximum throughput with minimal latency.

```python
from pyvider.rpcplugin import plugin_server, plugin_client
from pyvider.rpcplugin.performance import (
    PerformanceProfiler, ConnectionPool, MemoryOptimizer, CPUOptimizer
)
import asyncio
import time

async def high_performance_server_example():
    """Example of optimized high-performance server."""
    
    # Performance profiler
    profiler = PerformanceProfiler(
        enable_cpu_profiling=True,
        enable_memory_profiling=True,
        enable_io_profiling=True,
        sample_rate=0.1,  # 10% sampling for production
        metrics_port=9090
    )
    
    # Connection pool optimization
    connection_pool = ConnectionPool(
        max_connections=10000,
        connection_timeout=5.0,
        keepalive_time=30.0,
        keepalive_timeout=5.0,
        max_idle_connections=1000,
        connection_reuse=True
    )
    
    # Memory optimizer
    memory_optimizer = MemoryOptimizer(
        gc_threshold=(700, 10, 10),  # Aggressive GC
        object_pooling=True,
        zero_copy_buffers=True,
        preallocate_buffers=True
    )
    
    # CPU optimizer
    cpu_optimizer = CPUOptimizer(
        worker_threads=8,  # Match CPU cores
        async_io_threads=4,
        enable_uvloop=True,  # Use fast event loop
        cpu_affinity=True
    )
    
    # High-performance server
    server = plugin_server(
        services=[OptimizedTradingService()],
        profiler=profiler,
        connection_pool=connection_pool,
        memory_optimizer=memory_optimizer,
        cpu_optimizer=cpu_optimizer,
        
        # Performance settings
        max_concurrent_requests=5000,
        request_queue_size=10000,
        enable_compression=True,
        compression_level=1,  # Fast compression
        
        # Protocol optimization
        tcp_nodelay=True,
        tcp_keepalive=True,
        so_reuseport=True,
        
        port=8080
    )
    
    try:
        await server.start()
        print("⚡ High-performance server started")
        
        # Monitor performance
        async def performance_monitor():
            while True:
                stats = profiler.get_current_stats()
                print(f"🔄 RPS: {stats['requests_per_second']:.0f}, "
                      f"Latency p95: {stats['latency_p95_ms']:.1f}ms, "
                      f"Memory: {stats['memory_usage_mb']:.1f}MB")
                await asyncio.sleep(10)
        
        monitor_task = asyncio.create_task(performance_monitor())
        
        # Run for demonstration
        await asyncio.sleep(60)
        monitor_task.cancel()
    
    finally:
        await server.stop()

# Usage
await high_performance_server_example()
```

## Profiling and Benchmarking

### Comprehensive Performance Profiler

```python
import cProfile
import pstats
import tracemalloc
import psutil
import time
import asyncio
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from collections import deque
import statistics

@dataclass
class PerformanceMetrics:
    """Performance metrics snapshot."""
    
    timestamp: float
    requests_per_second: float
    latency_avg_ms: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    cpu_usage_percent: float
    memory_usage_mb: float
    active_connections: int
    queue_depth: int
    error_rate: float

class PerformanceProfiler:
    """Comprehensive performance profiler for plugin systems."""
    
    def __init__(self, 
                 enable_cpu_profiling: bool = True,
                 enable_memory_profiling: bool = True,
                 enable_io_profiling: bool = True,
                 sample_rate: float = 0.1,
                 metrics_port: int = 9090):
        
        self.enable_cpu_profiling = enable_cpu_profiling
        self.enable_memory_profiling = enable_memory_profiling
        self.enable_io_profiling = enable_io_profiling
        self.sample_rate = sample_rate
        self.metrics_port = metrics_port
        
        # Profiling state
        self.cpu_profiler: Optional[cProfile.Profile] = None
        self.memory_profiler_started = False
        
        # Metrics collection
        self.request_times: deque = deque(maxlen=10000)
        self.request_count = 0
        self.error_count = 0
        self.start_time = time.time()
        
        # Performance history
        self.metrics_history: List[PerformanceMetrics] = []
        self.max_history_size = 1000
        
        # Monitoring
        self.monitoring_task: Optional[asyncio.Task] = None
        self._monitoring = False
    
    async def start(self):
        """Start performance profiling."""
        
        # Start CPU profiling
        if self.enable_cpu_profiling:
            self.cpu_profiler = cProfile.Profile()
            self.cpu_profiler.enable()
        
        # Start memory profiling
        if self.enable_memory_profiling:
            tracemalloc.start()
            self.memory_profiler_started = True
        
        # Start monitoring loop
        self._monitoring = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        print("📊 Performance profiling started")
    
    async def stop(self):
        """Stop performance profiling."""
        
        self._monitoring = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        # Stop CPU profiling
        if self.cpu_profiler:
            self.cpu_profiler.disable()
        
        # Stop memory profiling
        if self.memory_profiler_started:
            tracemalloc.stop()
        
        print("📊 Performance profiling stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop."""
        
        while self._monitoring:
            try:
                # Collect metrics
                metrics = self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # Limit history size
                if len(self.metrics_history) > self.max_history_size:
                    self.metrics_history.pop(0)
                
                await asyncio.sleep(1.0)  # Collect every second
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                await asyncio.sleep(5.0)
    
    def _collect_metrics(self) -> PerformanceMetrics:
        """Collect current performance metrics."""
        
        now = time.time()
        
        # Calculate RPS over last 10 seconds
        recent_requests = [t for t in self.request_times if now - t <= 10]
        rps = len(recent_requests) / 10 if recent_requests else 0
        
        # Calculate latency statistics
        if recent_requests:
            # For simplicity, using request timestamps as latencies
            # In real implementation, track actual response times
            latency_samples = [1.0] * len(recent_requests)  # Placeholder
            latency_avg = statistics.mean(latency_samples)
            latency_p50 = statistics.median(latency_samples)
            latency_p95 = statistics.quantiles(latency_samples, n=20)[18] if len(latency_samples) > 20 else latency_avg
            latency_p99 = statistics.quantiles(latency_samples, n=100)[98] if len(latency_samples) > 100 else latency_avg
        else:
            latency_avg = latency_p50 = latency_p95 = latency_p99 = 0.0
        
        # System metrics
        process = psutil.Process()
        cpu_percent = process.cpu_percent()
        memory_mb = process.memory_info().rss / 1024 / 1024
        
        # Error rate
        total_requests = max(1, self.request_count)
        error_rate = self.error_count / total_requests
        
        return PerformanceMetrics(
            timestamp=now,
            requests_per_second=rps,
            latency_avg_ms=latency_avg,
            latency_p50_ms=latency_p50,
            latency_p95_ms=latency_p95,
            latency_p99_ms=latency_p99,
            cpu_usage_percent=cpu_percent,
            memory_usage_mb=memory_mb,
            active_connections=100,  # Placeholder
            queue_depth=0,  # Placeholder
            error_rate=error_rate
        )
    
    def record_request(self, duration_ms: float = None):
        """Record a request for metrics."""
        
        self.request_count += 1
        self.request_times.append(time.time())
        
        # Optionally record actual duration
        if duration_ms:
            # Store in separate structure for latency analysis
            pass
    
    def record_error(self):
        """Record an error for metrics."""
        
        self.error_count += 1
    
    def get_current_stats(self) -> Dict[str, Any]:
        """Get current performance statistics."""
        
        if not self.metrics_history:
            return {}
        
        latest = self.metrics_history[-1]
        
        return {
            'requests_per_second': latest.requests_per_second,
            'latency_avg_ms': latest.latency_avg_ms,
            'latency_p95_ms': latest.latency_p95_ms,
            'latency_p99_ms': latest.latency_p99_ms,
            'cpu_usage_percent': latest.cpu_usage_percent,
            'memory_usage_mb': latest.memory_usage_mb,
            'error_rate': latest.error_rate,
            'total_requests': self.request_count,
            'total_errors': self.error_count,
            'uptime_seconds': time.time() - self.start_time
        }
    
    def get_cpu_profile(self) -> str:
        """Get CPU profiling results."""
        
        if not self.cpu_profiler:
            return "CPU profiling not enabled"
        
        stats = pstats.Stats(self.cpu_profiler)
        stats.sort_stats('cumulative')
        
        # Capture output
        import io
        output = io.StringIO()
        stats.print_stats(20, file=output)  # Top 20 functions
        
        return output.getvalue()
    
    def get_memory_profile(self) -> str:
        """Get memory profiling results."""
        
        if not self.memory_profiler_started:
            return "Memory profiling not enabled"
        
        snapshot = tracemalloc.take_snapshot()
        top_stats = snapshot.statistics('lineno')
        
        output = ["Top 10 memory allocations:"]
        for index, stat in enumerate(top_stats[:10], 1):
            output.append(f"{index}. {stat.traceback.format()[-1]} "
                         f"- {stat.size / 1024 / 1024:.1f} MB")
        
        return '\n'.join(output)
    
    def generate_performance_report(self) -> str:
        """Generate comprehensive performance report."""
        
        stats = self.get_current_stats()
        if not stats:
            return "No performance data available"
        
        report = []
        report.append("⚡ Performance Report")
        report.append("=" * 40)
        report.append(f"Uptime: {stats['uptime_seconds']:.0f}s")
        report.append(f"Total Requests: {stats['total_requests']:,}")
        report.append(f"Total Errors: {stats['total_errors']:,}")
        report.append("")
        
        report.append("📊 Current Metrics:")
        report.append(f"  RPS: {stats['requests_per_second']:.1f}")
        report.append(f"  Avg Latency: {stats['latency_avg_ms']:.1f}ms")
        report.append(f"  P95 Latency: {stats['latency_p95_ms']:.1f}ms")
        report.append(f"  P99 Latency: {stats['latency_p99_ms']:.1f}ms")
        report.append(f"  CPU Usage: {stats['cpu_usage_percent']:.1f}%")
        report.append(f"  Memory Usage: {stats['memory_usage_mb']:.1f}MB")
        report.append(f"  Error Rate: {stats['error_rate']:.3f}")
        report.append("")
        
        # Historical trends
        if len(self.metrics_history) > 10:
            recent_metrics = self.metrics_history[-10:]
            avg_rps = statistics.mean(m.requests_per_second for m in recent_metrics)
            avg_latency = statistics.mean(m.latency_p95_ms for m in recent_metrics)
            avg_cpu = statistics.mean(m.cpu_usage_percent for m in recent_metrics)
            
            report.append("📈 Recent Trends (last 10 samples):")
            report.append(f"  Avg RPS: {avg_rps:.1f}")
            report.append(f"  Avg P95 Latency: {avg_latency:.1f}ms")
            report.append(f"  Avg CPU: {avg_cpu:.1f}%")
        
        return '\n'.join(report)

# Load testing framework
class LoadTester:
    """Load testing framework for plugin performance."""
    
    def __init__(self, target_host: str, target_port: int):
        self.target_host = target_host
        self.target_port = target_port
        self.results: List[Dict] = []
    
    async def run_load_test(self,
                           concurrent_users: int = 100,
                           duration_seconds: int = 60,
                           ramp_up_seconds: int = 10) -> Dict[str, Any]:
        """Run load test against plugin server."""
        
        print(f"🔥 Starting load test: {concurrent_users} users, {duration_seconds}s duration")
        
        # Ramp up gradually
        user_tasks = []
        ramp_up_delay = ramp_up_seconds / concurrent_users
        
        start_time = time.time()
        
        for user_id in range(concurrent_users):
            # Start user with delay
            await asyncio.sleep(ramp_up_delay)
            
            user_task = asyncio.create_task(
                self._simulate_user(user_id, start_time + duration_seconds)
            )
            user_tasks.append(user_task)
        
        print(f"🔥 All {concurrent_users} users started, running for {duration_seconds}s")
        
        # Wait for all users to complete
        try:
            await asyncio.gather(*user_tasks)
        except Exception as e:
            print(f"Load test error: {e}")
        
        # Analyze results
        return self._analyze_results()
    
    async def _simulate_user(self, user_id: int, end_time: float):
        """Simulate individual user load."""
        
        while time.time() < end_time:
            try:
                # Make request
                start_time = time.perf_counter()
                
                async with plugin_client(
                    host=self.target_host,
                    port=self.target_port
                ) as client:
                    # Simulate realistic request
                    result = await client.trading.GetQuote(symbol="AAPL")
                
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                # Record result
                self.results.append({
                    'user_id': user_id,
                    'timestamp': time.time(),
                    'duration_ms': duration_ms,
                    'success': True,
                    'error': None
                })
                
                # Realistic think time
                await asyncio.sleep(0.1)  # 100ms between requests
            
            except Exception as e:
                # Record error
                self.results.append({
                    'user_id': user_id,
                    'timestamp': time.time(),
                    'duration_ms': 0,
                    'success': False,
                    'error': str(e)
                })
                
                await asyncio.sleep(1.0)  # Wait longer after error
    
    def _analyze_results(self) -> Dict[str, Any]:
        """Analyze load test results."""
        
        if not self.results:
            return {"error": "No results collected"}
        
        # Separate successful and failed requests
        successful = [r for r in self.results if r['success']]
        failed = [r for r in self.results if not r['success']]
        
        total_requests = len(self.results)
        success_rate = len(successful) / total_requests if total_requests > 0 else 0
        
        # Latency analysis
        if successful:
            latencies = [r['duration_ms'] for r in successful]
            avg_latency = statistics.mean(latencies)
            p50_latency = statistics.median(latencies)
            p95_latency = statistics.quantiles(latencies, n=20)[18] if len(latencies) > 20 else avg_latency
            p99_latency = statistics.quantiles(latencies, n=100)[98] if len(latencies) > 100 else avg_latency
            max_latency = max(latencies)
        else:
            avg_latency = p50_latency = p95_latency = p99_latency = max_latency = 0
        
        # Calculate throughput
        if successful:
            time_span = max(r['timestamp'] for r in successful) - min(r['timestamp'] for r in successful)
            rps = len(successful) / time_span if time_span > 0 else 0
        else:
            rps = 0
        
        return {
            'total_requests': total_requests,
            'successful_requests': len(successful),
            'failed_requests': len(failed),
            'success_rate': success_rate,
            'requests_per_second': rps,
            'latency': {
                'avg_ms': avg_latency,
                'p50_ms': p50_latency,
                'p95_ms': p95_latency,
                'p99_ms': p99_latency,
                'max_ms': max_latency
            },
            'errors': [r['error'] for r in failed][:10]  # First 10 errors
        }

# Usage example
async def performance_testing_example():
    """Example of comprehensive performance testing."""
    
    # Start profiler
    profiler = PerformanceProfiler(
        enable_cpu_profiling=True,
        enable_memory_profiling=True,
        sample_rate=1.0  # 100% for testing
    )
    
    await profiler.start()
    
    try:
        # Simulate some work
        for i in range(1000):
            profiler.record_request(duration_ms=random.uniform(1, 10))
            
            if i % 100 == 0:
                # Show progress
                stats = profiler.get_current_stats()
                print(f"Progress: {i}/1000, RPS: {stats.get('requests_per_second', 0):.1f}")
            
            await asyncio.sleep(0.001)  # 1ms delay
        
        # Generate performance report
        report = profiler.generate_performance_report()
        print("\n" + report)
        
        # Get detailed profiling results
        print("\n🔍 CPU Profile (top functions):")
        cpu_profile = profiler.get_cpu_profile()
        print(cpu_profile)
        
        print("\n🧠 Memory Profile:")
        memory_profile = profiler.get_memory_profile()
        print(memory_profile)
    
    finally:
        await profiler.stop()

# Usage
await performance_testing_example()
```

## Connection Pool Optimization

### Advanced Connection Pool

```python
import asyncio
from typing import Dict, List, Optional, Set, Callable, Any
from dataclasses import dataclass
import time
import weakref
from enum import Enum

class ConnectionState(Enum):
    """Connection states."""
    CONNECTING = "connecting"
    ACTIVE = "active"
    IDLE = "idle"
    CLOSING = "closing"
    CLOSED = "closed"
    ERROR = "error"

@dataclass
class ConnectionStats:
    """Connection statistics."""
    
    created_at: float
    last_used: float
    total_requests: int
    total_bytes_sent: int
    total_bytes_received: int
    error_count: int
    state: ConnectionState

class PooledConnection:
    """Wrapper for pooled connections."""
    
    def __init__(self, connection_id: str, client: plugin_client, pool: 'ConnectionPool'):
        self.connection_id = connection_id
        self.client = client
        self.pool = weakref.ref(pool)  # Avoid circular reference
        
        # State management
        self.state = ConnectionState.CONNECTING
        self.created_at = time.time()
        self.last_used = time.time()
        
        # Usage statistics
        self.total_requests = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0
        self.error_count = 0
        
        # Health monitoring
        self.health_check_failures = 0
        self.max_health_check_failures = 3
    
    async def __aenter__(self) -> plugin_client:
        """Context manager entry."""
        
        self.state = ConnectionState.ACTIVE
        self.last_used = time.time()
        return self.client
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        
        if exc_type:
            self.error_count += 1
            self.state = ConnectionState.ERROR
        else:
            self.state = ConnectionState.IDLE
        
        self.total_requests += 1
        
        # Return to pool
        pool = self.pool()
        if pool:
            await pool._return_connection(self)
    
    async def health_check(self) -> bool:
        """Perform connection health check."""
        
        try:
            # Simple health check - try to connect
            if not self.client.is_connected():
                return False
            
            # Optional: ping/echo test
            # result = await self.client.health.Check(service="")
            # return result.status == "SERVING"
            
            self.health_check_failures = 0
            return True
        
        except Exception:
            self.health_check_failures += 1
            return self.health_check_failures <= self.max_health_check_failures
    
    async def close(self):
        """Close the connection."""
        
        self.state = ConnectionState.CLOSING
        
        try:
            await self.client.close()
        except Exception:
            pass
        
        self.state = ConnectionState.CLOSED
    
    def get_stats(self) -> ConnectionStats:
        """Get connection statistics."""
        
        return ConnectionStats(
            created_at=self.created_at,
            last_used=self.last_used,
            total_requests=self.total_requests,
            total_bytes_sent=self.total_bytes_sent,
            total_bytes_received=self.total_bytes_received,
            error_count=self.error_count,
            state=self.state
        )
    
    def should_retire(self, max_age_seconds: float, max_requests: int) -> bool:
        """Check if connection should be retired."""
        
        age = time.time() - self.created_at
        
        return (
            age > max_age_seconds or
            self.total_requests > max_requests or
            self.error_count > 10 or
            self.health_check_failures > self.max_health_check_failures
        )

class ConnectionPool:
    """High-performance connection pool."""
    
    def __init__(self,
                 target_host: str,
                 target_port: int,
                 max_connections: int = 100,
                 min_connections: int = 10,
                 max_idle_time: float = 300.0,  # 5 minutes
                 max_connection_age: float = 3600.0,  # 1 hour
                 max_requests_per_connection: int = 10000,
                 health_check_interval: float = 30.0,
                 connection_timeout: float = 5.0):
        
        self.target_host = target_host
        self.target_port = target_port
        self.max_connections = max_connections
        self.min_connections = min_connections
        self.max_idle_time = max_idle_time
        self.max_connection_age = max_connection_age
        self.max_requests_per_connection = max_requests_per_connection
        self.health_check_interval = health_check_interval
        self.connection_timeout = connection_timeout
        
        # Connection management
        self.idle_connections: asyncio.Queue = asyncio.Queue()
        self.active_connections: Dict[str, PooledConnection] = {}
        self.all_connections: Dict[str, PooledConnection] = {}
        
        # Pool state
        self.total_connections = 0
        self.connection_counter = 0
        self.pool_lock = asyncio.Lock()
        
        # Background tasks
        self.health_check_task: Optional[asyncio.Task] = None
        self.cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Statistics
        self.stats = {
            'connections_created': 0,
            'connections_closed': 0,
            'requests_served': 0,
            'pool_hits': 0,
            'pool_misses': 0,
            'health_check_failures': 0
        }
    
    async def start(self):
        """Start connection pool."""
        
        self._running = True
        
        # Create minimum connections
        for _ in range(self.min_connections):
            await self._create_connection()
        
        # Start background tasks
        self.health_check_task = asyncio.create_task(self._health_check_loop())
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        print(f"🏊 Connection pool started: {self.min_connections} initial connections")
    
    async def stop(self):
        """Stop connection pool."""
        
        self._running = False
        
        # Cancel background tasks
        if self.health_check_task:
            self.health_check_task.cancel()
        if self.cleanup_task:
            self.cleanup_task.cancel()
        
        # Close all connections
        async with self.pool_lock:
            for connection in list(self.all_connections.values()):
                await connection.close()
            
            self.all_connections.clear()
            self.active_connections.clear()
            
            # Clear queue
            while not self.idle_connections.empty():
                try:
                    self.idle_connections.get_nowait()
                except asyncio.QueueEmpty:
                    break
        
        print("🏊 Connection pool stopped")
    
    async def get_connection(self) -> PooledConnection:
        """Get connection from pool."""
        
        async with self.pool_lock:
            # Try to get idle connection
            try:
                connection = self.idle_connections.get_nowait()
                
                # Verify connection is still healthy
                if await connection.health_check():
                    self.active_connections[connection.connection_id] = connection
                    self.stats['pool_hits'] += 1
                    return connection
                else:
                    # Connection unhealthy, close it
                    await connection.close()
                    del self.all_connections[connection.connection_id]
                    self.total_connections -= 1
            
            except asyncio.QueueEmpty:
                pass
            
            # Create new connection if under limit
            if self.total_connections < self.max_connections:
                connection = await self._create_connection()
                self.active_connections[connection.connection_id] = connection
                self.stats['pool_misses'] += 1
                return connection
            
            # Pool exhausted, wait for connection
            self.stats['pool_misses'] += 1
            
        # Wait for connection to become available
        connection = await self.idle_connections.get()
        
        async with self.pool_lock:
            self.active_connections[connection.connection_id] = connection
        
        return connection
    
    async def _create_connection(self) -> PooledConnection:
        """Create new pooled connection."""
        
        connection_id = f"conn_{self.connection_counter}"
        self.connection_counter += 1
        
        try:
            # Create client connection
            client = plugin_client(
                host=self.target_host,
                port=self.target_port,
                timeout=self.connection_timeout
            )
            
            await client.start()
            
            # Create pooled connection wrapper
            connection = PooledConnection(connection_id, client, self)
            connection.state = ConnectionState.IDLE
            
            self.all_connections[connection_id] = connection
            self.total_connections += 1
            self.stats['connections_created'] += 1
            
            return connection
        
        except Exception as e:
            print(f"Failed to create connection: {e}")
            raise
    
    async def _return_connection(self, connection: PooledConnection):
        """Return connection to pool."""
        
        async with self.pool_lock:
            # Remove from active connections
            if connection.connection_id in self.active_connections:
                del self.active_connections[connection.connection_id]
            
            # Check if connection should be retired
            if connection.should_retire(
                self.max_connection_age,
                self.max_requests_per_connection
            ):
                await connection.close()
                if connection.connection_id in self.all_connections:
                    del self.all_connections[connection.connection_id]
                self.total_connections -= 1
                self.stats['connections_closed'] += 1
                return
            
            # Return to idle pool
            if connection.state != ConnectionState.ERROR:
                connection.state = ConnectionState.IDLE
                await self.idle_connections.put(connection)
    
    async def _health_check_loop(self):
        """Background health check loop."""
        
        while self._running:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Health check error: {e}")
                await asyncio.sleep(30)
    
    async def _perform_health_checks(self):
        """Perform health checks on idle connections."""
        
        unhealthy_connections = []
        
        # Check idle connections
        idle_connections = []
        while not self.idle_connections.empty():
            try:
                connection = self.idle_connections.get_nowait()
                idle_connections.append(connection)
            except asyncio.QueueEmpty:
                break
        
        for connection in idle_connections:
            if await connection.health_check():
                # Healthy connection, return to pool
                await self.idle_connections.put(connection)
            else:
                # Unhealthy connection
                unhealthy_connections.append(connection)
                self.stats['health_check_failures'] += 1
        
        # Clean up unhealthy connections
        async with self.pool_lock:
            for connection in unhealthy_connections:
                await connection.close()
                if connection.connection_id in self.all_connections:
                    del self.all_connections[connection.connection_id]
                self.total_connections -= 1
                self.stats['connections_closed'] += 1
    
    async def _cleanup_loop(self):
        """Background cleanup loop."""
        
        while self._running:
            try:
                await self._cleanup_idle_connections()
                await asyncio.sleep(60)  # Cleanup every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Cleanup error: {e}")
                await asyncio.sleep(60)
    
    async def _cleanup_idle_connections(self):
        """Clean up idle connections that have exceeded max idle time."""
        
        now = time.time()
        connections_to_remove = []
        
        # Check idle connections for timeout
        idle_connections = []
        while not self.idle_connections.empty():
            try:
                connection = self.idle_connections.get_nowait()
                idle_connections.append(connection)
            except asyncio.QueueEmpty:
                break
        
        for connection in idle_connections:
            idle_time = now - connection.last_used
            
            if idle_time > self.max_idle_time and self.total_connections > self.min_connections:
                connections_to_remove.append(connection)
            else:
                # Keep connection
                await self.idle_connections.put(connection)
        
        # Remove timed-out connections
        async with self.pool_lock:
            for connection in connections_to_remove:
                await connection.close()
                if connection.connection_id in self.all_connections:
                    del self.all_connections[connection.connection_id]
                self.total_connections -= 1
                self.stats['connections_closed'] += 1
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics."""
        
        return {
            'total_connections': self.total_connections,
            'active_connections': len(self.active_connections),
            'idle_connections': self.idle_connections.qsize(),
            'pool_stats': self.stats.copy(),
            'connection_details': [
                conn.get_stats() for conn in self.all_connections.values()
            ]
        }

# Usage example
async def connection_pool_example():
    """Example of optimized connection pooling."""
    
    # Create connection pool
    pool = ConnectionPool(
        target_host="127.0.0.1",
        target_port=8080,
        max_connections=50,
        min_connections=5,
        max_idle_time=300.0,
        health_check_interval=30.0
    )
    
    try:
        await pool.start()
        
        # Simulate high-load scenario
        async def make_requests():
            for i in range(100):
                async with await pool.get_connection() as client:
                    try:
                        result = await client.trading.GetQuote(symbol="AAPL")
                        if i % 20 == 0:
                            print(f"Request {i}: {result.price}")
                    except Exception as e:
                        print(f"Request {i} failed: {e}")
                
                await asyncio.sleep(0.01)  # 10ms between requests
        
        # Run multiple concurrent request generators
        tasks = [make_requests() for _ in range(5)]
        await asyncio.gather(*tasks)
        
        # Show pool statistics
        stats = pool.get_pool_stats()
        print(f"\n🏊 Pool Statistics:")
        print(f"  Total connections: {stats['total_connections']}")
        print(f"  Active connections: {stats['active_connections']}")
        print(f"  Idle connections: {stats['idle_connections']}")
        print(f"  Pool hits: {stats['pool_stats']['pool_hits']}")
        print(f"  Pool misses: {stats['pool_stats']['pool_misses']}")
        print(f"  Hit rate: {stats['pool_stats']['pool_hits'] / (stats['pool_stats']['pool_hits'] + stats['pool_stats']['pool_misses']) * 100:.1f}%")
    
    finally:
        await pool.stop()

# Usage
await connection_pool_example()
```

## Memory Management and Optimization

### Memory Optimizer

```python
import gc
import sys
import weakref
from typing import Dict, List, Any, Optional, Type, Callable
import tracemalloc
import psutil
import asyncio

class ObjectPool:
    """Generic object pool for reducing allocations."""
    
    def __init__(self, obj_type: Type, max_size: int = 1000):
        self.obj_type = obj_type
        self.max_size = max_size
        self.pool: List[Any] = []
        self.created_count = 0
        self.reused_count = 0
    
    def get(self, *args, **kwargs):
        """Get object from pool or create new one."""
        
        if self.pool:
            obj = self.pool.pop()
            self.reused_count += 1
            
            # Reset object if it has a reset method
            if hasattr(obj, 'reset'):
                obj.reset(*args, **kwargs)
            
            return obj
        else:
            # Create new object
            self.created_count += 1
            return self.obj_type(*args, **kwargs)
    
    def return_object(self, obj):
        """Return object to pool."""
        
        if len(self.pool) < self.max_size:
            # Clear object state if possible
            if hasattr(obj, 'clear'):
                obj.clear()
            
            self.pool.append(obj)
    
    def get_stats(self) -> Dict[str, int]:
        """Get pool statistics."""
        
        return {
            'pool_size': len(self.pool),
            'created_count': self.created_count,
            'reused_count': self.reused_count,
            'reuse_rate': self.reused_count / max(1, self.created_count + self.reused_count)
        }

class MemoryOptimizer:
    """Advanced memory optimizer for plugin systems."""
    
    def __init__(self,
                 gc_threshold: tuple = (700, 10, 10),
                 enable_object_pooling: bool = True,
                 enable_weak_references: bool = True,
                 enable_memory_profiling: bool = False,
                 memory_limit_mb: Optional[int] = None):
        
        self.gc_threshold = gc_threshold
        self.enable_object_pooling = enable_object_pooling
        self.enable_weak_references = enable_weak_references
        self.enable_memory_profiling = enable_memory_profiling
        self.memory_limit_mb = memory_limit_mb
        
        # Object pools
        self.object_pools: Dict[str, ObjectPool] = {}
        
        # Memory monitoring
        self.memory_stats: List[Dict] = []
        self.max_memory_stats = 1000
        
        # Weak reference registry
        self.weak_refs: Dict[str, weakref.ref] = {}
        
        # Memory pressure callbacks
        self.pressure_callbacks: List[Callable] = []
        
        # Monitoring task
        self.monitoring_task: Optional[asyncio.Task] = None
        self._monitoring = False
    
    async def start(self):
        """Start memory optimization."""
        
        # Configure garbage collection
        gc.set_threshold(*self.gc_threshold)
        
        # Start memory profiling if enabled
        if self.enable_memory_profiling:
            tracemalloc.start()
        
        # Setup object pools for common types
        if self.enable_object_pooling:
            self._setup_object_pools()
        
        # Start memory monitoring
        self._monitoring = True
        self.monitoring_task = asyncio.create_task(self._memory_monitoring_loop())
        
        print("🧠 Memory optimizer started")
    
    async def stop(self):
        """Stop memory optimization."""
        
        self._monitoring = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        # Stop memory profiling
        if self.enable_memory_profiling:
            tracemalloc.stop()
        
        print("🧠 Memory optimizer stopped")
    
    def _setup_object_pools(self):
        """Setup object pools for common types."""
        
        # Pool for byte arrays
        self.object_pools['bytearray'] = ObjectPool(bytearray, max_size=500)
        
        # Pool for lists
        self.object_pools['list'] = ObjectPool(list, max_size=500)
        
        # Pool for dicts
        self.object_pools['dict'] = ObjectPool(dict, max_size=500)
    
    async def _memory_monitoring_loop(self):
        """Monitor memory usage and trigger optimizations."""
        
        while self._monitoring:
            try:
                # Collect memory statistics
                memory_stats = self._collect_memory_stats()
                self.memory_stats.append(memory_stats)
                
                # Limit stats history
                if len(self.memory_stats) > self.max_memory_stats:
                    self.memory_stats.pop(0)
                
                # Check for memory pressure
                await self._check_memory_pressure(memory_stats)
                
                await asyncio.sleep(5.0)  # Check every 5 seconds
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Memory monitoring error: {e}")
                await asyncio.sleep(10.0)
    
    def _collect_memory_stats(self) -> Dict[str, Any]:
        """Collect current memory statistics."""
        
        process = psutil.Process()
        memory_info = process.memory_info()
        
        stats = {
            'timestamp': time.time(),
            'rss_mb': memory_info.rss / 1024 / 1024,
            'vms_mb': memory_info.vms / 1024 / 1024,
            'percent': process.memory_percent(),
            'gc_counts': gc.get_count(),
            'gc_stats': gc.get_stats(),
        }
        
        # Add tracemalloc stats if available
        if self.enable_memory_profiling:
            current, peak = tracemalloc.get_traced_memory()
            stats.update({
                'traced_current_mb': current / 1024 / 1024,
                'traced_peak_mb': peak / 1024 / 1024
            })
        
        # Add object pool stats
        if self.enable_object_pooling:
            pool_stats = {}
            for name, pool in self.object_pools.items():
                pool_stats[name] = pool.get_stats()
            stats['object_pools'] = pool_stats
        
        return stats
    
    async def _check_memory_pressure(self, stats: Dict[str, Any]):
        """Check for memory pressure and trigger optimizations."""
        
        memory_mb = stats['rss_mb']
        memory_percent = stats['percent']
        
        # Check against memory limit
        if self.memory_limit_mb and memory_mb > self.memory_limit_mb:
            print(f"⚠️  Memory limit exceeded: {memory_mb:.1f}MB > {self.memory_limit_mb}MB")
            await self._handle_memory_pressure()
        
        # Check against system memory percentage
        elif memory_percent > 80:  # Using more than 80% of system memory
            print(f"⚠️  High memory usage: {memory_percent:.1f}%")
            await self._handle_memory_pressure()
    
    async def _handle_memory_pressure(self):
        """Handle memory pressure by triggering optimizations."""
        
        print("🧠 Handling memory pressure...")
        
        # Force garbage collection
        collected = gc.collect()
        print(f"   Garbage collected {collected} objects")
        
        # Call pressure callbacks
        for callback in self.pressure_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback()
                else:
                    callback()
            except Exception as e:
                print(f"Memory pressure callback error: {e}")
        
        # Clear object pools partially
        if self.enable_object_pooling:
            for name, pool in self.object_pools.items():
                # Clear half of each pool
                pool_size = len(pool.pool)
                if pool_size > 10:
                    for _ in range(pool_size // 2):
                        if pool.pool:
                            pool.pool.pop()
                    print(f"   Cleared {pool_size // 2} objects from {name} pool")
    
    def get_pooled_object(self, obj_type: str, *args, **kwargs):
        """Get object from pool."""
        
        if not self.enable_object_pooling:
            # Object pooling disabled, create directly
            if obj_type == 'bytearray':
                return bytearray(*args, **kwargs)
            elif obj_type == 'list':
                return list(*args, **kwargs)
            elif obj_type == 'dict':
                return dict(*args, **kwargs)
        
        pool = self.object_pools.get(obj_type)
        if pool:
            return pool.get(*args, **kwargs)
        else:
            # Fallback to direct creation
            if obj_type == 'bytearray':
                return bytearray(*args, **kwargs)
            elif obj_type == 'list':
                return list(*args, **kwargs)
            elif obj_type == 'dict':
                return dict(*args, **kwargs)
    
    def return_pooled_object(self, obj_type: str, obj):
        """Return object to pool."""
        
        if not self.enable_object_pooling:
            return
        
        pool = self.object_pools.get(obj_type)
        if pool:
            pool.return_object(obj)
    
    def register_weak_reference(self, name: str, obj, callback: Callable = None):
        """Register weak reference to object."""
        
        if not self.enable_weak_references:
            return
        
        self.weak_refs[name] = weakref.ref(obj, callback)
    
    def get_weak_reference(self, name: str):
        """Get object from weak reference."""
        
        weak_ref = self.weak_refs.get(name)
        if weak_ref:
            return weak_ref()  # May return None if object was garbage collected
        return None
    
    def add_pressure_callback(self, callback: Callable):
        """Add callback to be called during memory pressure."""
        
        self.pressure_callbacks.append(callback)
    
    def get_memory_report(self) -> str:
        """Generate memory usage report."""
        
        if not self.memory_stats:
            return "No memory statistics available"
        
        latest = self.memory_stats[-1]
        
        report = []
        report.append("🧠 Memory Usage Report")
        report.append("=" * 30)
        
        report.append(f"Current Memory Usage:")
        report.append(f"  RSS: {latest['rss_mb']:.1f} MB")
        report.append(f"  VMS: {latest['vms_mb']:.1f} MB")
        report.append(f"  Percent: {latest['percent']:.1f}%")
        
        if 'traced_current_mb' in latest:
            report.append(f"  Traced: {latest['traced_current_mb']:.1f} MB")
            report.append(f"  Peak: {latest['traced_peak_mb']:.1f} MB")
        
        # Garbage collection stats
        gc_counts = latest['gc_counts']
        report.append(f"\nGarbage Collection:")
        report.append(f"  Gen 0: {gc_counts[0]} objects")
        report.append(f"  Gen 1: {gc_counts[1]} objects") 
        report.append(f"  Gen 2: {gc_counts[2]} objects")
        
        # Object pool stats
        if 'object_pools' in latest:
            report.append(f"\nObject Pools:")
            for name, stats in latest['object_pools'].items():
                reuse_rate = stats['reuse_rate'] * 100
                report.append(f"  {name}: {stats['pool_size']} pooled, "
                             f"{reuse_rate:.1f}% reuse rate")
        
        # Memory trend analysis
        if len(self.memory_stats) > 10:
            recent_stats = self.memory_stats[-10:]
            memory_trend = [s['rss_mb'] for s in recent_stats]
            
            if len(memory_trend) > 1:
                trend = "increasing" if memory_trend[-1] > memory_trend[0] else "decreasing"
                change = abs(memory_trend[-1] - memory_trend[0])
                report.append(f"\nMemory Trend (last 10 samples):")
                report.append(f"  {trend.title()} by {change:.1f} MB")
        
        return '\n'.join(report)
    
    def force_gc(self) -> int:
        """Force garbage collection and return number of objects collected."""
        
        return gc.collect()
    
    def get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB."""
        
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024

# Usage example with memory optimization
class MemoryOptimizedService:
    """Example service with memory optimizations."""
    
    def __init__(self, memory_optimizer: MemoryOptimizer):
        self.memory_optimizer = memory_optimizer
        self.message_cache: Dict[str, Any] = {}
        
        # Register memory pressure callback
        memory_optimizer.add_pressure_callback(self._clear_cache)
    
    async def process_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process data with memory optimizations."""
        
        # Use pooled objects
        result_buffer = self.memory_optimizer.get_pooled_object('list')
        temp_data = self.memory_optimizer.get_pooled_object('dict')
        
        try:
            # Process data
            for key, value in data.items():
                processed_value = self._process_value(value)
                temp_data[key] = processed_value
                result_buffer.append(processed_value)
            
            # Create result
            result = {
                'processed_items': len(result_buffer),
                'total_size': sum(len(str(item)) for item in result_buffer),
                'data': temp_data.copy()
            }
            
            return result
        
        finally:
            # Return objects to pool
            self.memory_optimizer.return_pooled_object('list', result_buffer)
            self.memory_optimizer.return_pooled_object('dict', temp_data)
    
    def _process_value(self, value: Any) -> Any:
        """Process individual value."""
        
        # Simulate processing
        return str(value).upper()
    
    async def _clear_cache(self):
        """Clear cache during memory pressure."""
        
        cleared_items = len(self.message_cache)
        self.message_cache.clear()
        print(f"   Cleared {cleared_items} cached messages")

# Usage example
async def memory_optimization_example():
    """Example of comprehensive memory optimization."""
    
    # Setup memory optimizer
    memory_optimizer = MemoryOptimizer(
        gc_threshold=(700, 10, 10),
        enable_object_pooling=True,
        enable_memory_profiling=True,
        memory_limit_mb=500  # 500MB limit
    )
    
    await memory_optimizer.start()
    
    try:
        # Create memory-optimized service
        service = MemoryOptimizedService(memory_optimizer)
        
        print(f"🧠 Starting memory optimization test...")
        print(f"Initial memory: {memory_optimizer.get_memory_usage_mb():.1f} MB")
        
        # Simulate heavy memory usage
        for i in range(100):
            # Create large data structure
            large_data = {
                f"key_{j}": f"value_{j}" * 100  # Create some data
                for j in range(1000)
            }
            
            # Process with memory optimization
            result = await service.process_data(large_data)
            
            if i % 20 == 0:
                current_memory = memory_optimizer.get_memory_usage_mb()
                print(f"Iteration {i}: {current_memory:.1f} MB, "
                      f"processed {result['processed_items']} items")
                
                # Show memory report
                if i == 60:  # Show detailed report partway through
                    report = memory_optimizer.get_memory_report()
                    print(f"\n{report}\n")
            
            # Small delay
            await asyncio.sleep(0.01)
        
        # Final memory report
        final_memory = memory_optimizer.get_memory_usage_mb()
        print(f"\n🏁 Final memory usage: {final_memory:.1f} MB")
        
        final_report = memory_optimizer.get_memory_report()
        print(f"\n{final_report}")
        
        # Force garbage collection
        collected = memory_optimizer.force_gc()
        after_gc_memory = memory_optimizer.get_memory_usage_mb()
        print(f"\nAfter GC: {after_gc_memory:.1f} MB (collected {collected} objects)")
    
    finally:
        await memory_optimizer.stop()

# Usage
await memory_optimization_example()
```

## CPU Optimization and Scaling

### Multi-Core CPU Optimization

```python
import asyncio
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from typing import List, Dict, Any, Callable, Optional
import uvloop  # Fast event loop
import time
import psutil

class CPUOptimizer:
    """CPU optimization for plugin systems."""
    
    def __init__(self,
                 worker_processes: Optional[int] = None,
                 worker_threads: Optional[int] = None,
                 enable_uvloop: bool = True,
                 cpu_affinity: bool = False,
                 enable_process_pool: bool = True):
        
        self.worker_processes = worker_processes or mp.cpu_count()
        self.worker_threads = worker_threads or min(32, (mp.cpu_count() or 1) + 4)
        self.enable_uvloop = enable_uvloop
        self.cpu_affinity = cpu_affinity
        self.enable_process_pool = enable_process_pool
        
        # Executors
        self.process_pool: Optional[ProcessPoolExecutor] = None
        self.thread_pool: Optional[ThreadPoolExecutor] = None
        
        # CPU monitoring
        self.cpu_stats: List[Dict] = []
        self.monitoring_task: Optional[asyncio.Task] = None
        self._monitoring = False
    
    async def start(self):
        """Start CPU optimization."""
        
        # Setup fast event loop
        if self.enable_uvloop:
            try:
                uvloop.install()
                print("⚡ UV loop installed for better performance")
            except ImportError:
                print("⚠️  UV loop not available, using default event loop")
        
        # Setup process pool
        if self.enable_process_pool:
            self.process_pool = ProcessPoolExecutor(
                max_workers=self.worker_processes,
                mp_context=mp.get_context('spawn')  # More reliable on all platforms
            )
            print(f"🔧 Process pool started with {self.worker_processes} workers")
        
        # Setup thread pool
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.worker_threads,
            thread_name_prefix="plugin_worker"
        )
        print(f"🧵 Thread pool started with {self.worker_threads} workers")
        
        # Set CPU affinity if enabled
        if self.cpu_affinity:
            self._set_cpu_affinity()
        
        # Start CPU monitoring
        self._monitoring = True
        self.monitoring_task = asyncio.create_task(self._cpu_monitoring_loop())
        
        print("🔥 CPU optimizer started")
    
    async def stop(self):
        """Stop CPU optimization."""
        
        self._monitoring = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        # Shutdown executors
        if self.process_pool:
            self.process_pool.shutdown(wait=True)
        
        if self.thread_pool:
            self.thread_pool.shutdown(wait=True)
        
        print("🔥 CPU optimizer stopped")
    
    def _set_cpu_affinity(self):
        """Set CPU affinity for better cache locality."""
        
        try:
            process = psutil.Process()
            available_cpus = list(range(psutil.cpu_count()))
            
            # Set affinity to all available CPUs
            process.cpu_affinity(available_cpus)
            print(f"📌 CPU affinity set to cores: {available_cpus}")
        
        except Exception as e:
            print(f"⚠️  Could not set CPU affinity: {e}")
    
    async def _cpu_monitoring_loop(self):
        """Monitor CPU usage."""
        
        while self._monitoring:
            try:
                # Collect CPU statistics
                cpu_stats = self._collect_cpu_stats()
                self.cpu_stats.append(cpu_stats)
                
                # Limit stats history
                if len(self.cpu_stats) > 1000:
                    self.cpu_stats.pop(0)
                
                await asyncio.sleep(5.0)  # Monitor every 5 seconds
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"CPU monitoring error: {e}")
                await asyncio.sleep(10.0)
    
    def _collect_cpu_stats(self) -> Dict[str, Any]:
        """Collect CPU statistics."""
        
        return {
            'timestamp': time.time(),
            'cpu_percent': psutil.cpu_percent(interval=None),
            'cpu_per_core': psutil.cpu_percent(interval=None, percpu=True),
            'load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None,
            'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
            'cpu_count': psutil.cpu_count(),
            'cpu_count_logical': psutil.cpu_count(logical=True)
        }
    
    async def run_cpu_bound_task(self, func: Callable, *args, **kwargs):
        """Run CPU-bound task in process pool."""
        
        if not self.process_pool:
            raise RuntimeError("Process pool not available")
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.process_pool, func, *args, **kwargs)
    
    async def run_io_bound_task(self, func: Callable, *args, **kwargs):
        """Run I/O-bound task in thread pool."""
        
        if not self.thread_pool:
            raise RuntimeError("Thread pool not available")
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.thread_pool, func, *args, **kwargs)
    
    async def run_parallel_tasks(self, tasks: List[tuple], task_type: str = "cpu") -> List[Any]:
        """Run multiple tasks in parallel."""
        
        if task_type == "cpu":
            executor = self.process_pool
        elif task_type == "io":
            executor = self.thread_pool
        else:
            raise ValueError(f"Unknown task type: {task_type}")
        
        if not executor:
            raise RuntimeError(f"{task_type.upper()} executor not available")
        
        # Create tasks
        loop = asyncio.get_event_loop()
        futures = []
        
        for func, args, kwargs in tasks:
            future = loop.run_in_executor(executor, func, *args, **kwargs)
            futures.append(future)
        
        # Wait for all tasks to complete
        return await asyncio.gather(*futures)
    
    def get_cpu_stats(self) -> Dict[str, Any]:
        """Get current CPU statistics."""
        
        if not self.cpu_stats:
            return {}
        
        latest = self.cpu_stats[-1]
        
        # Calculate averages
        if len(self.cpu_stats) > 10:
            recent_stats = self.cpu_stats[-10:]
            avg_cpu = sum(s['cpu_percent'] for s in recent_stats) / len(recent_stats)
        else:
            avg_cpu = latest['cpu_percent']
        
        return {
            'current_cpu_percent': latest['cpu_percent'],
            'average_cpu_percent': avg_cpu,
            'cpu_per_core': latest['cpu_per_core'],
            'cpu_count': latest['cpu_count'],
            'load_average': latest['load_average'],
            'worker_processes': self.worker_processes,
            'worker_threads': self.worker_threads
        }

# CPU-intensive task examples
def cpu_intensive_calculation(n: int) -> int:
    """CPU-intensive calculation for testing."""
    
    # Calculate fibonacci number (inefficient recursive version for CPU load)
    def fibonacci(n):
        if n <= 1:
            return n
        return fibonacci(n-1) + fibonacci(n-2)
    
    return fibonacci(n)

def parallel_matrix_multiply(size: int) -> float:
    """CPU-intensive matrix multiplication."""
    
    import random
    
    # Create random matrices
    matrix_a = [[random.random() for _ in range(size)] for _ in range(size)]
    matrix_b = [[random.random() for _ in range(size)] for _ in range(size)]
    
    # Multiply matrices
    result = [[0 for _ in range(size)] for _ in range(size)]
    
    for i in range(size):
        for j in range(size):
            for k in range(size):
                result[i][j] += matrix_a[i][k] * matrix_b[k][j]
    
    # Return sum of all elements
    return sum(sum(row) for row in result)

# Usage example
async def cpu_optimization_example():
    """Example of CPU optimization techniques."""
    
    # Setup CPU optimizer
    cpu_optimizer = CPUOptimizer(
        worker_processes=mp.cpu_count(),
        worker_threads=16,
        enable_uvloop=True,
        cpu_affinity=True
    )
    
    await cpu_optimizer.start()
    
    try:
        print("🔥 Testing CPU optimization...")
        
        # Test 1: Single-threaded performance
        start_time = time.perf_counter()
        
        single_result = cpu_intensive_calculation(30)
        
        single_time = time.perf_counter() - start_time
        print(f"Single-threaded: {single_time:.2f}s, result: {single_result}")
        
        # Test 2: Multi-process parallel execution
        start_time = time.perf_counter()
        
        # Create multiple CPU-bound tasks
        cpu_tasks = [
            (cpu_intensive_calculation, (25,), {}) for _ in range(8)
        ]
        
        parallel_results = await cpu_optimizer.run_parallel_tasks(cpu_tasks, "cpu")
        
        parallel_time = time.perf_counter() - start_time
        print(f"Multi-process: {parallel_time:.2f}s, results: {len(parallel_results)} tasks")
        print(f"Speedup: {single_time / parallel_time:.1f}x")
        
        # Test 3: Matrix multiplication comparison
        print("\n🔢 Matrix multiplication test:")
        
        # Single process
        start_time = time.perf_counter()
        single_matrix_result = parallel_matrix_multiply(100)
        single_matrix_time = time.perf_counter() - start_time
        
        # Multiple processes
        start_time = time.perf_counter()
        matrix_tasks = [
            (parallel_matrix_multiply, (50,), {}) for _ in range(4)
        ]
        parallel_matrix_results = await cpu_optimizer.run_parallel_tasks(matrix_tasks, "cpu")
        parallel_matrix_time = time.perf_counter() - start_time
        
        print(f"Single 100x100 matrix: {single_matrix_time:.2f}s")
        print(f"Four 50x50 matrices: {parallel_matrix_time:.2f}s")
        print(f"Parallel efficiency: {(single_matrix_time / parallel_matrix_time):.1f}x")
        
        # Test 4: Mixed workload (CPU + I/O)
        print("\n🔄 Mixed workload test:")
        
        def io_task(delay: float) -> str:
            """Simulate I/O-bound task."""
            import time
            time.sleep(delay)
            return f"IO task completed after {delay}s"
        
        # Mix CPU and I/O tasks
        start_time = time.perf_counter()
        
        # CPU tasks
        cpu_tasks = [
            (cpu_intensive_calculation, (20,), {}) for _ in range(4)
        ]
        
        # I/O tasks  
        io_tasks = [
            (io_task, (0.5,), {}) for _ in range(8)
        ]
        
        # Run CPU and I/O tasks concurrently
        cpu_results_future = cpu_optimizer.run_parallel_tasks(cpu_tasks, "cpu")
        io_results_future = cpu_optimizer.run_parallel_tasks(io_tasks, "io")
        
        cpu_results, io_results = await asyncio.gather(
            cpu_results_future,
            io_results_future
        )
        
        mixed_time = time.perf_counter() - start_time
        print(f"Mixed workload: {mixed_time:.2f}s")
        print(f"CPU tasks: {len(cpu_results)}, I/O tasks: {len(io_results)}")
        
        # Show CPU statistics
        cpu_stats = cpu_optimizer.get_cpu_stats()
        print(f"\n📊 CPU Statistics:")
        print(f"  Current CPU: {cpu_stats['current_cpu_percent']:.1f}%")
        print(f"  Average CPU: {cpu_stats['average_cpu_percent']:.1f}%")
        print(f"  CPU cores: {cpu_stats['cpu_count']}")
        print(f"  Worker processes: {cpu_stats['worker_processes']}")
        print(f"  Worker threads: {cpu_stats['worker_threads']}")
        
        if cpu_stats['load_average']:
            load_avg = cpu_stats['load_average']
            print(f"  Load average: {load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}")
    
    finally:
        await cpu_optimizer.stop()

# Usage
await cpu_optimization_example()
```

## Next Steps

- **[Middleware](middleware.md)** - Implement cross-cutting concerns with middleware patterns
- **[Plugin Lifecycle](lifecycle.md)** - Master plugin orchestration and lifecycle management  
- **[Custom Protocols](custom-protocols.md)** - Build domain-specific communication protocols
- **[Advanced Topics Overview](index.md)** - Explore other advanced plugin development topics