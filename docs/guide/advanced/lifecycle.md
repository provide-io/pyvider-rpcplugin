# Plugin Lifecycle

Manage the complete lifecycle of RPC plugins with proper resource management, graceful startup/shutdown, and effective error handling.

## Overview

The plugin lifecycle consists of seven distinct phases: Configuration → Initialization → Registration → Startup → Operation → Shutdown → Cleanup. Understanding each phase ensures robust plugins that start reliably, handle errors gracefully, and shut down cleanly.

## Lifecycle Phases

### 1. Configuration Phase

Load and validate settings:

```python
from pyvider.rpcplugin.config import rpcplugin_config
from provide.foundation.logger import get_logger

logger = get_logger(__name__)

class PluginLifecycleManager:
    def __init__(self, config_path: Path | None = None):
        self.config_path = config_path
        self.config = None
        self.server = None
        self.services = []
        self.resources = []
        self._shutdown_event = asyncio.Event()

    async def configure(self):
        """Load and validate configuration."""
        logger.info("📋 Loading configuration...")

        if self.config_path:
            self.config = ServerConfig.from_file(self.config_path)
        else:
            self.config = load_config_from_env()

        await self._validate_config()
        logger.info(f"✅ Configuration loaded: {self.config.host}:{self.config.port}")
        return self.config

    async def _validate_config(self):
        if not self.config:
            raise ValueError("Configuration not loaded")

        # Check TLS configuration
        if self.config.tls_enabled:
            if not os.path.exists(self.config.cert_file):
                raise FileNotFoundError(f"Certificate not found: {self.config.cert_file}")
```

### 2. Initialization Phase

Set up resources and dependencies:

```python
async def initialize(self):
    """Initialize server and resources."""
    if not self.config:
        raise RuntimeError("Must configure before initializing")

    logger.info("🚀 Initializing server...")

    # Initialize transport and protocol
    transport = await create_transport(self.config.transport_config)
    self.resources.append(transport)

    protocol = ServiceProtocol(self.config.protocol_config)
    self.resources.append(protocol)

    # Create server
    self.server = RPCPluginServer(
        config=self.config,
        transport=transport,
        protocol=protocol
    )

    # Initialize external dependencies
    if hasattr(self.config, 'database_url'):
        db_pool = await self._initialize_database()
        self.resources.append(db_pool)

    logger.info("✅ Server initialized successfully")
```

### 3. Registration Phase

Register RPC services:

```python
async def register_services(self, services):
    """Register RPC services with server."""
    if not self.server:
        raise RuntimeError("Must initialize server first")

    logger.info("📝 Registering services...")

    for service in services:
        await self._validate_service(service)
        self.server.add_service(service)
        self.services.append(service)
        logger.info(f"✅ Registered: {service.__class__.__name__}")

    # Register health check service
    from pyvider.rpcplugin.health import HealthServicer
    health_service = HealthServicer(self.services)
    self.server.add_service(health_service)

    logger.info(f"📝 Registered {len(self.services)} services")
```

### 4. Startup Phase

Start server and accept connections:

```python
async def start(self):
    """Start server and begin accepting connections."""
    if not self.server:
        raise RuntimeError("Must initialize and register services first")

    logger.info("🎯 Starting server...")

    try:
        # Pre-start validation
        await self._pre_start_checks()

        # Start server
        await self.server.start()

        # Post-start setup
        await self._post_start_setup()

        logger.info(f"🚀 Server started on {self.config.host}:{self.config.port}")

        # Setup signal handlers
        self._setup_signal_handlers()

    except Exception as e:
        logger.error(f"❌ Failed to start: {e}")
        await self.cleanup()
        raise

async def _pre_start_checks(self):
    """Validate before starting."""
    # Check port availability
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((self.config.host, self.config.port))
    except OSError as e:
        if e.errno == 98:
            raise RuntimeError(f"Port {self.config.port} already in use")
        raise

    logger.info("✅ Pre-start checks completed")

def _setup_signal_handlers(self):
    """Setup graceful shutdown handlers."""
    import signal

    def signal_handler(signum, frame):
        logger.info(f"📡 Received signal {signum}, initiating shutdown...")
        asyncio.create_task(self.shutdown())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
```

### 5. Operation Phase

Handle requests and manage runtime:

```python
async def run(self):
    """Run server until shutdown requested."""
    logger.info("⚡ Server running - waiting for shutdown signal")

    try:
        await self._shutdown_event.wait()
    except KeyboardInterrupt:
        logger.info("📡 Keyboard interrupt received")
    finally:
        await self.shutdown()

async def _metrics_collector(self):
    """Background metrics collection."""
    while not self._shutdown_event.is_set():
        try:
            metrics = await self._collect_metrics()
            await self._report_metrics(metrics)
            await asyncio.sleep(30)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning(f"Metrics collection error: {e}")
            await asyncio.sleep(10)
```

### 6. Shutdown Phase

Graceful termination:

```python
async def shutdown(self, timeout: int = 30):
    """Gracefully shutdown server."""
    logger.info("🛑 Initiating graceful shutdown...")

    self._shutdown_event.set()

    shutdown_tasks = []

    # Stop accepting new connections
    if self.server:
        logger.info("📋 Stopping server...")
        shutdown_tasks.append(self._graceful_server_shutdown(timeout))

    # Close external connections
    shutdown_tasks.append(self._close_external_connections())

    # Wait for shutdown tasks
    try:
        await asyncio.wait_for(
            asyncio.gather(*shutdown_tasks, return_exceptions=True),
            timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.warning("⚠️  Shutdown timeout, forcing shutdown")

    logger.info("✅ Graceful shutdown completed")

async def _graceful_server_shutdown(self, timeout: int):
    """Gracefully shutdown server."""
    try:
        await self.server.stop_accepting()

        # Wait for active requests to complete
        active_count = len(self.server.active_connections) if self.server.active_connections else 0

        if active_count > 0:
            logger.info(f"📋 Waiting for {active_count} active connections...")

            start_time = time.time()
            while (self.server.active_connections and
                   time.time() - start_time < timeout):
                await asyncio.sleep(0.1)

        await self.server.stop()

    except Exception as e:
        logger.error(f"Error during shutdown: {e}")

async def _close_external_connections(self):
    """Close external service connections."""
    for resource in self.resources:
        try:
            if hasattr(resource, 'close'):
                if asyncio.iscoroutinefunction(resource.close):
                    await resource.close()
                else:
                    resource.close()
        except Exception as e:
            logger.warning(f"Error closing resource: {e}")
```

### 7. Cleanup Phase

Final resource cleanup:

```python
async def cleanup(self):
    """Final cleanup of all resources."""
    logger.info("🧹 Performing final cleanup...")

    # Cancel background tasks
    tasks = [task for task in asyncio.all_tasks() if not task.done()]
    if tasks:
        logger.info(f"📋 Cancelling {len(tasks)} tasks...")
        for task in tasks:
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)

    # Clear references
    self.services.clear()
    self.resources.clear()
    self.server = None
    self.config = None

    logger.info("✅ Cleanup completed")
```

## Complete Usage

=== "Full Lifecycle"

    ```python
    async def main():
        """Complete plugin lifecycle."""
        manager = PluginLifecycleManager(Path("config.json"))

        try:
            await manager.configure()
            await manager.initialize()

            services = [EchoService(), FileService()]
            await manager.register_services(services)

            await manager.start()
            await manager.run()

        except Exception as e:
            logger.error(f"❌ Fatal error: {e}")
            raise
        finally:
            await manager.cleanup()

    if __name__ == "__main__":
        asyncio.run(main())
    ```

=== "Context Manager"

    ```python
    # Context manager interface
    async def __aenter__(self):
        await self.configure()
        await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()

    # Usage
    async def main():
        config_path = Path("config.json")

        async with PluginLifecycleManager(config_path) as manager:
            services = [EchoService(), FileService()]
            await manager.register_services(services)

            await manager.start()
            await manager.run()
    ```

## Lifecycle Hooks

Customize lifecycle behavior:

```python
class LifecycleHooks:
    """Customizable lifecycle hooks."""

    async def on_configure(self, config):
        """Called after configuration loaded."""
        pass

    async def on_initialize(self, server):
        """Called after server initialized."""
        pass

    async def on_start(self, server):
        """Called after server starts."""
        pass

    async def on_shutdown(self):
        """Called when shutdown begins."""
        pass

class CustomPluginManager(PluginLifecycleManager):
    def __init__(self, hooks: LifecycleHooks, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.hooks = hooks

    async def configure(self):
        config = await super().configure()
        await self.hooks.on_configure(config)
        return config

    async def initialize(self):
        await super().initialize()
        await self.hooks.on_initialize(self.server)
```

## Error Handling and Recovery

### Automatic Recovery

```python
class RobustLifecycleManager(PluginLifecycleManager):
    """Lifecycle manager with retry and recovery."""

    def __init__(self, *args, max_retries: int = 3, **kwargs):
        super().__init__(*args, **kwargs)
        self.max_retries = max_retries
        self.retry_count = 0

    async def start_with_retry(self):
        """Start server with automatic retry."""
        while self.retry_count < self.max_retries:
            try:
                await self.start()
                self.retry_count = 0
                return
            except Exception as e:
                self.retry_count += 1
                logger.error(f"❌ Start failed ({self.retry_count}/{self.max_retries}): {e}")

                if self.retry_count >= self.max_retries:
                    raise

                await self.cleanup()
                await asyncio.sleep(5 * self.retry_count)
                await self.initialize()
```

## Monitoring

### Lifecycle Metrics

```python
class ObservableLifecycleManager(PluginLifecycleManager):
    """Lifecycle manager with observability."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.metrics = {
            'startup_time': 0,
            'shutdown_time': 0,
            'restarts': 0,
            'errors': 0,
            'uptime_start': 0,
        }

    async def start(self):
        start_time = time.time()

        try:
            await super().start()
            self.metrics['startup_time'] = time.time() - start_time
            self.metrics['uptime_start'] = time.time()

            logger.info(f"📊 Startup: {self.metrics['startup_time']:.2f}s")
        except Exception:
            self.metrics['errors'] += 1
            raise

    async def shutdown(self, timeout: int = 30):
        start_time = time.time()

        try:
            await super().shutdown(timeout)
            self.metrics['shutdown_time'] = time.time() - start_time

            uptime = time.time() - self.metrics['uptime_start']
            logger.info(f"📊 Uptime: {uptime:.2f}s, Shutdown: {self.metrics['shutdown_time']:.2f}s")
        except Exception:
            self.metrics['errors'] += 1
            raise
```

## Best Practices

1. **Validate configuration early** - catch errors before resource allocation
2. **Initialize resources in order** - ensure dependencies are available
3. **Handle signals gracefully** - respond to SIGTERM and SIGINT
4. **Wait for active requests** - don't forcefully terminate connections
5. **Clean up systematically** - release resources in reverse order
6. **Monitor lifecycle phases** - track startup/shutdown times
7. **Use context managers** - ensure cleanup happens automatically
8. **Log lifecycle events** - aid debugging and monitoring

## Related Topics

- [Server Configuration](../server/index.md) - Server setup and configuration
- [Health Checks](../server/health-checks.md) - Service health monitoring
- [Observability](observability.md) - Lifecycle metrics and tracing
- [Middleware](middleware.md) - Request/response lifecycle
