# Plugin Lifecycle

Understanding the plugin lifecycle is crucial for building robust RPC services with proper resource management, graceful startup/shutdown, and effective error handling. This guide covers the complete lifecycle from initialization to termination.

## Overview

The Pyvider RPC Plugin lifecycle consists of several distinct phases:

1. **Configuration** - Loading settings and validating parameters
2. **Initialization** - Setting up resources and dependencies  
3. **Registration** - Registering services with the server
4. **Startup** - Starting the server and accepting connections
5. **Operation** - Handling requests and managing connections
6. **Shutdown** - Graceful termination and resource cleanup
7. **Cleanup** - Final resource deallocation

## Lifecycle Phases

### 1. Configuration Phase

```python
import os
from pathlib import Path
from pyvider.config import ServerConfig, load_config_from_env

class PluginLifecycleManager:
    """Manages the complete lifecycle of an RPC plugin."""
    
    def __init__(self, config_path: Path | None = None):
        self.config_path = config_path
        self.config: ServerConfig | None = None
        self.server = None
        self.services: list[Any] = []
        self.resources: list[Any] = []
        self._shutdown_event = asyncio.Event()
    
    async def configure(self) -> ServerConfig:
        """Load and validate configuration."""
        print("📋 Loading configuration...")
        
        if self.config_path:
            self.config = ServerConfig.from_file(self.config_path)
        else:
            self.config = load_config_from_env()
        
        # Validate configuration
        await self._validate_config()
        
        print(f"✅ Configuration loaded: {self.config.host}:{self.config.port}")
        return self.config
    
    async def _validate_config(self):
        """Validate configuration parameters."""
        if not self.config:
            raise ValueError("Configuration not loaded")
        
        # Check network binding
        if self.config.host == "0.0.0.0":
            print("⚠️  Warning: Binding to all interfaces")
        
        # Validate TLS configuration
        if self.config.tls_enabled:
            if not os.path.exists(self.config.cert_file):
                raise FileNotFoundError(f"Certificate file not found: {self.config.cert_file}")
            if not os.path.exists(self.config.key_file):
                raise FileNotFoundError(f"Private key file not found: {self.config.key_file}")
        
        # Check for required environment variables
        required_env = getattr(self.config, 'required_environment', [])
        for env_var in required_env:
            if not os.getenv(env_var):
                raise EnvironmentError(f"Required environment variable not set: {env_var}")
```

### 2. Initialization Phase

```python
from pyvider.server import RPCPluginServer
from pyvider.transport import create_transport
from pyvider.protocol import ServiceProtocol

    async def initialize(self) -> None:
        """Initialize server and resources."""
        if not self.config:
            raise RuntimeError("Must configure before initializing")
        
        print("🚀 Initializing server...")
        
        # Initialize transport
        transport = await create_transport(self.config.transport_config)
        self.resources.append(transport)
        
        # Initialize protocol
        protocol = ServiceProtocol(self.config.protocol_config)
        self.resources.append(protocol)
        
        # Create server
        self.server = RPCPluginServer(
            config=self.config,
            transport=transport,
            protocol=protocol
        )
        
        # Initialize database connections
        if hasattr(self.config, 'database_url'):
            db_pool = await self._initialize_database()
            self.resources.append(db_pool)
        
        # Initialize caches
        if hasattr(self.config, 'redis_url'):
            redis_client = await self._initialize_cache()
            self.resources.append(redis_client)
        
        # Initialize external service clients
        await self._initialize_external_clients()
        
        print("✅ Server initialized successfully")
    
    async def _initialize_database(self):
        """Initialize database connection pool."""
        import asyncpg
        
        pool = await asyncpg.create_pool(
            self.config.database_url,
            min_size=1,
            max_size=10,
            command_timeout=30
        )
        
        # Test connection
        async with pool.acquire() as conn:
            await conn.fetchval('SELECT 1')
        
        print("✅ Database connection pool initialized")
        return pool
    
    async def _initialize_cache(self):
        """Initialize Redis cache client."""
        import aioredis
        
        redis = aioredis.from_url(
            self.config.redis_url,
            encoding="utf-8",
            decode_responses=True
        )
        
        # Test connection
        await redis.ping()
        
        print("✅ Cache client initialized")
        return redis
    
    async def _initialize_external_clients(self):
        """Initialize external service clients."""
        # Example: HTTP client for external APIs
        import aiohttp
        
        timeout = aiohttp.ClientTimeout(total=30)
        session = aiohttp.ClientSession(timeout=timeout)
        self.resources.append(session)
        
        print("✅ External clients initialized")
```

### 3. Registration Phase

```python
    async def register_services(self, services: list[Any]) -> None:
        """Register RPC services with the server."""
        if not self.server:
            raise RuntimeError("Must initialize server before registering services")
        
        print("📝 Registering services...")
        
        for service in services:
            # Validate service implementation
            await self._validate_service(service)
            
            # Register with server
            self.server.add_service(service)
            self.services.append(service)
            
            print(f"✅ Registered service: {service.__class__.__name__}")
        
        # Register health check service
        from pyvider.health import HealthServicer
        health_service = HealthServicer(self.services)
        self.server.add_service(health_service)
        
        print(f"📝 Registered {len(self.services)} services")
    
    async def _validate_service(self, service: Any) -> None:
        """Validate service implementation."""
        # Check for required methods
        required_methods = getattr(service, '__required_methods__', [])
        for method_name in required_methods:
            if not hasattr(service, method_name):
                raise AttributeError(f"Service {service.__class__.__name__} missing method: {method_name}")
        
        # Check for proper async methods
        for attr_name in dir(service):
            if not attr_name.startswith('_'):
                attr = getattr(service, attr_name)
                if callable(attr) and not asyncio.iscoroutinefunction(attr):
                    print(f"⚠️  Warning: {service.__class__.__name__}.{attr_name} is not async")
```

### 4. Startup Phase

```python
    async def start(self) -> None:
        """Start the server and begin accepting connections."""
        if not self.server:
            raise RuntimeError("Must initialize and register services before starting")
        
        print("🎯 Starting server...")
        
        try:
            # Pre-start validation
            await self._pre_start_checks()
            
            # Start server
            await self.server.start()
            
            # Post-start initialization
            await self._post_start_setup()
            
            print(f"🚀 Server started successfully on {self.config.host}:{self.config.port}")
            
            # Setup signal handlers for graceful shutdown
            self._setup_signal_handlers()
            
        except Exception as e:
            print(f"❌ Failed to start server: {e}")
            await self.cleanup()
            raise
    
    async def _pre_start_checks(self) -> None:
        """Perform pre-start validation checks."""
        # Check port availability
        import socket
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind((self.config.host, self.config.port))
        except OSError as e:
            if e.errno == 98:  # Address already in use
                raise RuntimeError(f"Port {self.config.port} already in use")
            raise
        
        # Test external dependencies
        await self._test_external_dependencies()
        
        print("✅ Pre-start checks completed")
    
    async def _test_external_dependencies(self) -> None:
        """Test connections to external dependencies."""
        # Test database
        if hasattr(self, 'db_pool'):
            try:
                async with self.db_pool.acquire() as conn:
                    await conn.fetchval('SELECT 1')
            except Exception as e:
                raise RuntimeError(f"Database connection failed: {e}")
        
        # Test cache
        if hasattr(self, 'redis_client'):
            try:
                await self.redis_client.ping()
            except Exception as e:
                raise RuntimeError(f"Cache connection failed: {e}")
    
    async def _post_start_setup(self) -> None:
        """Perform post-start setup tasks."""
        # Start background tasks
        asyncio.create_task(self._metrics_collector())
        asyncio.create_task(self._health_monitor())
        
        # Warm up caches
        await self._warm_up_caches()
        
        print("✅ Post-start setup completed")
    
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        import signal
        
        def signal_handler(signum, frame):
            print(f"📡 Received signal {signum}, initiating shutdown...")
            asyncio.create_task(self.shutdown())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        if hasattr(signal, 'SIGHUP'):  # Unix-specific
            signal.signal(signal.SIGHUP, signal_handler)
```

### 5. Operation Phase

```python
    async def run(self) -> None:
        """Run the server until shutdown is requested."""
        print("⚡ Server running - waiting for shutdown signal")
        
        try:
            # Wait for shutdown signal
            await self._shutdown_event.wait()
        except KeyboardInterrupt:
            print("📡 Keyboard interrupt received")
        finally:
            await self.shutdown()
    
    async def _metrics_collector(self) -> None:
        """Background task to collect and report metrics."""
        while not self._shutdown_event.is_set():
            try:
                # Collect metrics
                metrics = await self._collect_metrics()
                
                # Report to monitoring system
                await self._report_metrics(metrics)
                
                # Wait before next collection
                await asyncio.sleep(30)
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"⚠️  Metrics collection error: {e}")
                await asyncio.sleep(10)
    
    async def _health_monitor(self) -> None:
        """Background task to monitor service health."""
        while not self._shutdown_event.is_set():
            try:
                # Check service health
                healthy = await self._check_service_health()
                
                if not healthy:
                    print("⚠️  Service health check failed")
                    # Implement recovery logic here
                
                await asyncio.sleep(60)
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"⚠️  Health monitor error: {e}")
                await asyncio.sleep(30)
    
    async def _collect_metrics(self) -> dict[str, Any]:
        """Collect server metrics."""
        return {
            "active_connections": len(self.server.active_connections) if self.server else 0,
            "total_requests": getattr(self.server, 'total_requests', 0),
            "error_count": getattr(self.server, 'error_count', 0),
            "uptime": time.time() - getattr(self, 'start_time', time.time()),
        }
    
    async def _check_service_health(self) -> bool:
        """Check overall service health."""
        try:
            # Check database connection
            if hasattr(self, 'db_pool'):
                async with self.db_pool.acquire() as conn:
                    await conn.fetchval('SELECT 1')
            
            # Check cache connection
            if hasattr(self, 'redis_client'):
                await self.redis_client.ping()
            
            # Check service-specific health
            for service in self.services:
                if hasattr(service, 'health_check'):
                    healthy = await service.health_check()
                    if not healthy:
                        return False
            
            return True
        
        except Exception:
            return False
```

### 6. Shutdown Phase

```python
    async def shutdown(self, timeout: int = 30) -> None:
        """Gracefully shutdown the server."""
        print("🛑 Initiating graceful shutdown...")
        
        # Set shutdown event
        self._shutdown_event.set()
        
        shutdown_tasks = []
        
        # Stop accepting new connections
        if self.server:
            print("📋 Stopping server...")
            shutdown_tasks.append(self._graceful_server_shutdown(timeout))
        
        # Close external connections
        shutdown_tasks.append(self._close_external_connections())
        
        # Wait for all shutdown tasks
        try:
            await asyncio.wait_for(
                asyncio.gather(*shutdown_tasks, return_exceptions=True),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            print("⚠️  Graceful shutdown timeout, forcing shutdown")
        
        print("✅ Graceful shutdown completed")
    
    async def _graceful_server_shutdown(self, timeout: int) -> None:
        """Gracefully shutdown the server."""
        try:
            # Stop accepting new requests
            await self.server.stop_accepting()
            
            # Wait for active requests to complete
            active_count = len(self.server.active_connections) if self.server.active_connections else 0
            
            if active_count > 0:
                print(f"📋 Waiting for {active_count} active connections to complete...")
                
                start_time = time.time()
                while (self.server.active_connections and 
                       time.time() - start_time < timeout):
                    await asyncio.sleep(0.1)
                
                remaining = len(self.server.active_connections) if self.server.active_connections else 0
                if remaining > 0:
                    print(f"⚠️  {remaining} connections still active after timeout")
            
            # Stop the server
            await self.server.stop()
            
        except Exception as e:
            print(f"⚠️  Error during server shutdown: {e}")
    
    async def _close_external_connections(self) -> None:
        """Close external service connections."""
        for resource in self.resources:
            try:
                if hasattr(resource, 'close'):
                    if asyncio.iscoroutinefunction(resource.close):
                        await resource.close()
                    else:
                        resource.close()
                elif hasattr(resource, 'disconnect'):
                    await resource.disconnect()
                
            except Exception as e:
                print(f"⚠️  Error closing resource {resource}: {e}")
```

### 7. Cleanup Phase

```python
    async def cleanup(self) -> None:
        """Final cleanup of all resources."""
        print("🧹 Performing final cleanup...")
        
        # Cancel all background tasks
        tasks = [task for task in asyncio.all_tasks() if not task.done()]
        if tasks:
            print(f"📋 Cancelling {len(tasks)} remaining tasks...")
            for task in tasks:
                task.cancel()
            
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Clear service references
        self.services.clear()
        
        # Clear resource references
        self.resources.clear()
        
        # Reset state
        self.server = None
        self.config = None
        
        print("✅ Cleanup completed")

# Context manager interface
    async def __aenter__(self):
        """Async context manager entry."""
        await self.configure()
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.cleanup()
```

## Complete Usage Example

```python
from pyvider.services import EchoService, FileService
from pathlib import Path

async def main():
    """Complete plugin lifecycle example."""
    manager = PluginLifecycleManager(
        config_path=Path("config.json")
    )
    
    try:
        # Full lifecycle
        await manager.configure()
        await manager.initialize()
        
        # Register services
        services = [
            EchoService(),
            FileService(),
        ]
        await manager.register_services(services)
        
        # Start and run
        await manager.start()
        await manager.run()  # Blocks until shutdown
        
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        raise
    
    finally:
        await manager.cleanup()

# Alternative: Using context manager
async def main_with_context_manager():
    """Lifecycle using context manager."""
    config_path = Path("config.json")
    
    async with PluginLifecycleManager(config_path) as manager:
        # Register services
        services = [EchoService(), FileService()]
        await manager.register_services(services)
        
        # Start and run
        await manager.start()
        await manager.run()

if __name__ == "__main__":
    asyncio.run(main())
```

## Lifecycle Hooks

### Custom Lifecycle Events

```python
class LifecycleHooks:
    """Customizable lifecycle hooks for plugins."""
    
    async def on_configure(self, config: ServerConfig) -> None:
        """Called after configuration is loaded."""
        pass
    
    async def on_initialize(self, server: RPCPluginServer) -> None:
        """Called after server is initialized."""
        pass
    
    async def on_services_registered(self, services: list[Any]) -> None:
        """Called after all services are registered."""
        pass
    
    async def on_start(self, server: RPCPluginServer) -> None:
        """Called after server starts accepting connections."""
        pass
    
    async def on_request(self, request: Any) -> None:
        """Called for each incoming request."""
        pass
    
    async def on_error(self, error: Exception) -> None:
        """Called when errors occur."""
        pass
    
    async def on_shutdown(self) -> None:
        """Called when shutdown begins."""
        pass
    
    async def on_cleanup(self) -> None:
        """Called during final cleanup."""
        pass

class CustomPluginManager(PluginLifecycleManager):
    """Plugin manager with custom hooks."""
    
    def __init__(self, hooks: LifecycleHooks, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hooks = hooks
    
    async def configure(self) -> ServerConfig:
        config = await super().configure()
        await self.hooks.on_configure(config)
        return config
    
    async def initialize(self) -> None:
        await super().initialize()
        await self.hooks.on_initialize(self.server)
    
    # Override other methods similarly...
```

## Error Handling and Recovery

### Automatic Recovery

```python
class RobustLifecycleManager(PluginLifecycleManager):
    """Lifecycle manager with automatic recovery."""
    
    def __init__(self, *args, max_retries: int = 3, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_retries = max_retries
        self.retry_count = 0
    
    async def start_with_retry(self) -> None:
        """Start server with automatic retry on failure."""
        while self.retry_count < self.max_retries:
            try:
                await self.start()
                self.retry_count = 0  # Reset on success
                return
            
            except Exception as e:
                self.retry_count += 1
                print(f"❌ Start failed (attempt {self.retry_count}/{self.max_retries}): {e}")
                
                if self.retry_count >= self.max_retries:
                    raise
                
                # Cleanup and wait before retry
                await self.cleanup()
                await asyncio.sleep(5 * self.retry_count)  # Exponential backoff
                
                # Re-initialize for retry
                await self.initialize()
    
    async def run_with_recovery(self) -> None:
        """Run with automatic recovery from failures."""
        while True:
            try:
                await self.run()
                break  # Normal shutdown
            
            except Exception as e:
                print(f"❌ Runtime error: {e}")
                
                # Attempt recovery
                try:
                    await self._attempt_recovery()
                except Exception as recovery_error:
                    print(f"❌ Recovery failed: {recovery_error}")
                    break
    
    async def _attempt_recovery(self) -> None:
        """Attempt to recover from runtime errors."""
        print("🔄 Attempting recovery...")
        
        # Stop current server
        if self.server:
            try:
                await self.server.stop()
            except Exception:
                pass
        
        # Reinitialize
        await self.initialize()
        await self.register_services(self.services.copy())
        await self.start()
        
        print("✅ Recovery completed")
```

## Monitoring and Observability

### Lifecycle Metrics

```python
class ObservableLifecycleManager(PluginLifecycleManager):
    """Lifecycle manager with comprehensive observability."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.metrics = {
            'startup_time': 0,
            'shutdown_time': 0,
            'restarts': 0,
            'errors': 0,
            'uptime_start': 0,
        }
    
    async def start(self) -> None:
        """Start with timing metrics."""
        start_time = time.time()
        
        try:
            await super().start()
            self.metrics['startup_time'] = time.time() - start_time
            self.metrics['uptime_start'] = time.time()
            
            print(f"📊 Startup completed in {self.metrics['startup_time']:.2f}s")
        
        except Exception:
            self.metrics['errors'] += 1
            raise
    
    async def shutdown(self, timeout: int = 30) -> None:
        """Shutdown with timing metrics."""
        start_time = time.time()
        
        try:
            await super().shutdown(timeout)
            self.metrics['shutdown_time'] = time.time() - start_time
            
            uptime = time.time() - self.metrics['uptime_start']
            print(f"📊 Uptime: {uptime:.2f}s, Shutdown: {self.metrics['shutdown_time']:.2f}s")
        
        except Exception:
            self.metrics['errors'] += 1
            raise
    
    def get_lifecycle_metrics(self) -> dict[str, Any]:
        """Get lifecycle metrics."""
        current_time = time.time()
        uptime = current_time - self.metrics['uptime_start'] if self.metrics['uptime_start'] else 0
        
        return {
            **self.metrics,
            'current_uptime': uptime,
        }
```

Understanding and properly implementing the plugin lifecycle ensures your RPC services are robust, maintainable, and production-ready. Use these patterns to build services that start reliably, handle errors gracefully, and shut down cleanly.