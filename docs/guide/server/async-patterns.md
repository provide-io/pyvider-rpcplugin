# Async Patterns

Master asynchronous programming patterns for building high-performance plugin servers with proper concurrency, resource management, and background task handling.

## Concurrent Request Handling

### Basic Async Service Handler

```python
import asyncio
import time

class AsyncHandler:
    def __init__(self):
        self.active_requests = {}
        self.request_counter = 0
    
    async def ProcessData(self, request, context):
        """Handle request asynchronously with tracking."""
        request_id = self.request_counter
        self.request_counter += 1
        
        # Track active request
        self.active_requests[request_id] = {
            'started': time.time(),
            'client': context.peer(),
            'method': 'ProcessData'
        }
        
        try:
            # Simulate async processing
            await asyncio.sleep(0.1)
            
            # Actual business logic
            result = await self.process_business_logic(request.data)
            
            return ProcessResponse(
                result=result,
                request_id=request_id,
                processing_time=time.time() - self.active_requests[request_id]['started']
            )
        
        finally:
            # Clean up tracking
            self.active_requests.pop(request_id, None)
    
    async def process_business_logic(self, data: str) -> str:
        """Simulate async business logic processing."""
        # Simulate database query
        await asyncio.sleep(0.05)
        
        # Simulate API call
        await asyncio.sleep(0.02)
        
        return f"Processed: {data}"
    
    def get_active_requests(self) -> Dict[str, Any]:
        """Get information about active requests."""
        return {
            'count': len(self.active_requests),
            'requests': list(self.active_requests.values())
        }
```

### Concurrent Batch Processing

```python
import asyncio
from typing import Callable, TypeVar, Awaitable

T = TypeVar('T')
R = TypeVar('R')

class BatchProcessor:
    """Process multiple items concurrently with controlled concurrency."""
    
    def __init__(self, max_concurrency: int = 10):
        self.max_concurrency = max_concurrency
        self.semaphore = asyncio.Semaphore(max_concurrency)
    
    async def process_batch(self, 
                           items: List[T], 
                           processor: Callable[[T], Awaitable[R]],
                           batch_size: int = None) -> List[R]:
        """Process items in batches with concurrency control."""
        if batch_size is None:
            batch_size = self.max_concurrency
        
        results = []
        
        # Process in batches
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            
            # Process batch concurrently
            batch_tasks = [
                self._process_with_semaphore(item, processor)
                for item in batch
            ]
            
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            results.extend(batch_results)
        
        return results
    
    async def _process_with_semaphore(self, item: T, processor: Callable[[T], Awaitable[R]]) -> R:
        """Process single item with semaphore control."""
        async with self.semaphore:
            return await processor(item)

# Usage in service handler
class BatchHandler:
    def __init__(self):
        self.batch_processor = BatchProcessor(max_concurrency=20)
    
    async def ProcessMultipleItems(self, request, context):
        """Process multiple items concurrently."""
        items = request.items
        
        # Define processing function
        async def process_single_item(item):
            # Simulate async processing
            await asyncio.sleep(0.1)
            return f"Processed: {item.data}"
        
        try:
            # Process all items concurrently
            results = await self.batch_processor.process_batch(
                items=items,
                processor=process_single_item,
                batch_size=10
            )
            
            # Filter out exceptions and create response
            successful_results = [
                result for result in results
                if not isinstance(result, Exception)
            ]
            
            errors = [
                str(result) for result in results
                if isinstance(result, Exception)
            ]
            
            return BatchResponse(
                results=successful_results,
                success_count=len(successful_results),
                error_count=len(errors),
                errors=errors
            )
        
        except Exception as e:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Batch processing failed: {e}")
            return BatchResponse()
```

## Background Task Management

### Background Task Manager

```python
import asyncio
import logging
from typing import Callable, Awaitable
from datetime import datetime, timedelta

class BackgroundTaskManager:
    """Manage long-running background tasks."""
    
    def __init__(self):
        self.tasks: Dict[str, asyncio.Task] = {}
        self.periodic_tasks: Dict[str, Dict] = {}
        self.shutdown_event = asyncio.Event()
        self.logger = logging.getLogger(__name__)
    
    async def start_periodic_task(self, 
                                 name: str, 
                                 coro_func: Callable[[], Awaitable], 
                                 interval: float,
                                 immediate: bool = False):
        """Start a periodic background task."""
        if name in self.tasks:
            self.logger.warning(f"Task {name} already running")
            return
        
        async def periodic_runner():
            try:
                if immediate:
                    await coro_func()
                
                while not self.shutdown_event.is_set():
                    try:
                        await asyncio.wait_for(
                            self.shutdown_event.wait(),
                            timeout=interval
                        )
                        # If we reach here, shutdown was requested
                        break
                    except asyncio.TimeoutError:
                        # Timeout occurred, run the task
                        try:
                            await coro_func()
                        except Exception as e:
                            self.logger.error(f"Error in periodic task {name}: {e}")
            
            except asyncio.CancelledError:
                self.logger.info(f"Periodic task {name} cancelled")
            except Exception as e:
                self.logger.error(f"Periodic task {name} failed: {e}")
        
        # Start the task
        task = asyncio.create_task(periodic_runner())
        self.tasks[name] = task
        self.periodic_tasks[name] = {
            'interval': interval,
            'started': datetime.now(),
            'immediate': immediate
        }
        
        self.logger.info(f"Started periodic task: {name} (interval: {interval}s)")
    
    async def start_background_task(self, name: str, coro: Awaitable):
        """Start a one-time background task."""
        if name in self.tasks:
            self.logger.warning(f"Task {name} already running")
            return
        
        async def task_wrapper():
            try:
                await coro
                self.logger.info(f"Background task completed: {name}")
            except asyncio.CancelledError:
                self.logger.info(f"Background task cancelled: {name}")
            except Exception as e:
                self.logger.error(f"Background task failed: {name} - {e}")
            finally:
                # Remove from active tasks
                self.tasks.pop(name, None)
        
        task = asyncio.create_task(task_wrapper())
        self.tasks[name] = task
        self.logger.info(f"Started background task: {name}")
    
    async def stop_task(self, name: str):
        """Stop a specific task."""
        if name in self.tasks:
            task = self.tasks[name]
            task.cancel()
            
            try:
                await task
            except asyncio.CancelledError:
                pass
            
            self.tasks.pop(name, None)
            self.periodic_tasks.pop(name, None)
            self.logger.info(f"Stopped task: {name}")
    
    async def shutdown_all(self):
        """Shutdown all background tasks."""
        self.shutdown_event.set()
        
        if not self.tasks:
            return
        
        self.logger.info(f"Shutting down {len(self.tasks)} background tasks...")
        
        # Cancel all tasks
        for name, task in self.tasks.items():
            task.cancel()
        
        # Wait for all tasks to complete
        if self.tasks:
            await asyncio.gather(*self.tasks.values(), return_exceptions=True)
        
        self.tasks.clear()
        self.periodic_tasks.clear()
        self.logger.info("All background tasks stopped")
    
    def get_task_status(self) -> Dict:
        """Get status of all background tasks."""
        return {
            'active_tasks': len(self.tasks),
            'periodic_tasks': len(self.periodic_tasks),
            'tasks': {
                name: {
                    'done': task.done(),
                    'cancelled': task.cancelled(),
                    'exception': str(task.exception()) if task.done() and task.exception() else None
                }
                for name, task in self.tasks.items()
            },
            'periodic_task_info': self.periodic_tasks
        }

# Usage in plugin server
class AsyncPluginHandler:
    def __init__(self):
        self.task_manager = BackgroundTaskManager()
    
    async def initialize(self):
        """Initialize background tasks."""
        # Start periodic cleanup task
        await self.task_manager.start_periodic_task(
            name="cleanup",
            coro_func=self.cleanup_resources,
            interval=300,  # Every 5 minutes
            immediate=False
        )
        
        # Start periodic health check
        await self.task_manager.start_periodic_task(
            name="health_check",
            coro_func=self.perform_health_check,
            interval=60,   # Every minute
            immediate=True
        )
    
    async def cleanup_resources(self):
        """Periodic cleanup task."""
        logging.info("Performing resource cleanup...")
        # Implement cleanup logic
        await asyncio.sleep(1)  # Simulate cleanup work
    
    async def perform_health_check(self):
        """Periodic health check."""
        logging.info("Performing health check...")
        # Implement health check logic
        await asyncio.sleep(0.5)  # Simulate health check
    
    async def StartLongRunningJob(self, request, context):
        """Start a long-running background job."""
        job_id = f"job_{request.job_name}_{int(time.time())}"
        
        async def long_running_job():
            for i in range(request.iterations):
                await asyncio.sleep(1)  # Simulate work
                logging.info(f"Job {job_id} progress: {i+1}/{request.iterations}")
        
        # Start the job in background
        await self.task_manager.start_background_task(job_id, long_running_job())
        
        return JobResponse(job_id=job_id, status="started")
    
    async def GetTaskStatus(self, request, context):
        """Get status of background tasks."""
        status = self.task_manager.get_task_status()
        return TaskStatusResponse(**status)
    
    async def shutdown(self):
        """Shutdown handler and all background tasks."""
        await self.task_manager.shutdown_all()
```

## Resource Pooling

### Database Connection Pool

```python
import asyncio
import aiosqlite
from contextlib import asynccontextmanager

class DatabasePool:
    """Async database connection pool."""
    
    def __init__(self, 
                 database_path: str, 
                 pool_size: int = 10,
                 max_overflow: int = 5,
                 timeout: float = 30.0):
        self.database_path = database_path
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.timeout = timeout
        
        self.pool = asyncio.Queue(maxsize=pool_size)
        self.current_connections = 0
        self.overflow_connections = 0
        self.connection_stats = {
            'total_created': 0,
            'total_closed': 0,
            'pool_hits': 0,
            'pool_misses': 0
        }
        
        self._initialized = False
    
    async def initialize(self):
        """Initialize the connection pool."""
        if self._initialized:
            return
        
        # Create initial connections
        for _ in range(self.pool_size):
            conn = await self._create_connection()
            await self.pool.put(conn)
        
        self._initialized = True
        logging.info(f"Database pool initialized with {self.pool_size} connections")
    
    async def _create_connection(self) -> aiosqlite.Connection:
        """Create a new database connection."""
        conn = await aiosqlite.connect(self.database_path)
        conn.row_factory = aiosqlite.Row  # Enable dict-like access
        self.current_connections += 1
        self.connection_stats['total_created'] += 1
        return conn
    
    @asynccontextmanager
    async def acquire(self):
        """Acquire a connection from the pool."""
        if not self._initialized:
            await self.initialize()
        
        conn = None
        try:
            # Try to get from pool
            try:
                conn = await asyncio.wait_for(
                    self.pool.get(), 
                    timeout=self.timeout
                )
                self.connection_stats['pool_hits'] += 1
                
            except asyncio.TimeoutError:
                # Pool is empty, check if we can create overflow connection
                if self.overflow_connections < self.max_overflow:
                    conn = await self._create_connection()
                    self.overflow_connections += 1
                    self.connection_stats['pool_misses'] += 1
                else:
                    raise Exception("Connection pool exhausted")
            
            yield conn
            
        finally:
            if conn:
                # Return connection to pool or close overflow connection
                if self.overflow_connections > 0:
                    await conn.close()
                    self.overflow_connections -= 1
                    self.current_connections -= 1
                    self.connection_stats['total_closed'] += 1
                else:
                    # Return to pool
                    await self.pool.put(conn)
    
    async def close_all(self):
        """Close all connections in pool."""
        connections_closed = 0
        
        # Close all pooled connections
        while not self.pool.empty():
            try:
                conn = self.pool.get_nowait()
                await conn.close()
                connections_closed += 1
            except asyncio.QueueEmpty:
                break
        
        self.current_connections = 0
        self.overflow_connections = 0
        self.connection_stats['total_closed'] += connections_closed
        
        logging.info(f"Closed {connections_closed} database connections")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics."""
        return {
            'pool_size': self.pool_size,
            'current_connections': self.current_connections,
            'overflow_connections': self.overflow_connections,
            'available_in_pool': self.pool.qsize(),
            'stats': self.connection_stats
        }

# Usage in service handler
class DatabaseHandler:
    def __init__(self, db_path: str):
        self.db_pool = DatabasePool(db_path, pool_size=15, max_overflow=5)
    
    async def initialize(self):
        """Initialize database resources."""
        await self.db_pool.initialize()
    
    async def QueryData(self, request, context):
        """Query data using connection pool."""
        try:
            async with self.db_pool.acquire() as conn:
                cursor = await conn.execute(
                    "SELECT * FROM items WHERE category = ?", 
                    (request.category,)
                )
                
                rows = await cursor.fetchall()
                
                results = [
                    {"id": row["id"], "name": row["name"], "value": row["value"]}
                    for row in rows
                ]
                
                return QueryResponse(results=results, count=len(results))
        
        except Exception as e:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Database query failed: {e}")
            return QueryResponse()
    
    async def shutdown(self):
        """Cleanup database resources."""
        await self.db_pool.close_all()
```

### HTTP Client Pool

```python
import aiohttp
import asyncio

class HTTPClientPool:
    """Async HTTP client connection pool."""
    
    def __init__(self, 
                 max_connections: int = 100,
                 timeout: float = 30.0,
                 connector_limit: int = 50):
        self.max_connections = max_connections
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        
        # Configure connector for connection pooling
        self.connector = aiohttp.TCPConnector(
            limit=max_connections,
            limit_per_host=connector_limit,
            enable_cleanup_closed=True,
            keepalive_timeout=60,
            ttl_dns_cache=300
        )
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.request_stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'timeout_errors': 0
        }
    
    async def initialize(self):
        """Initialize HTTP client session."""
        if self.session is None:
            self.session = aiohttp.ClientSession(
                connector=self.connector,
                timeout=self.timeout
            )
    
    async def get(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make GET request."""
        return await self._make_request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Dict[str, Any]:
        """Make POST request."""
        return await self._make_request('POST', url, **kwargs)
    
    async def _make_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Make HTTP request with connection pooling."""
        if not self.session:
            await self.initialize()
        
        self.request_stats['total_requests'] += 1
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                data = await response.text()
                
                self.request_stats['successful_requests'] += 1
                
                return {
                    'status': response.status,
                    'data': data,
                    'headers': dict(response.headers)
                }
        
        except asyncio.TimeoutError:
            self.request_stats['timeout_errors'] += 1
            self.request_stats['failed_requests'] += 1
            raise
        except Exception:
            self.request_stats['failed_requests'] += 1
            raise
    
    async def close(self):
        """Close HTTP client session."""
        if self.session:
            await self.session.close()
            self.session = None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        return {
            'connection_info': {
                'max_connections': self.max_connections,
                'timeout': self.timeout.total
            },
            'request_stats': self.request_stats
        }

# Usage in service handler  
class APIHandler:
    def __init__(self):
        self.http_client = HTTPClientPool(max_connections=50)
    
    async def initialize(self):
        await self.http_client.initialize()
    
    async def CallExternalAPI(self, request, context):
        """Call external API using connection pool."""
        try:
            response = await self.http_client.get(
                url=request.api_url,
                headers={'User-Agent': 'PluginServer/1.0'}
            )
            
            return APIResponse(
                status_code=response['status'],
                data=response['data'],
                success=True
            )
        
        except asyncio.TimeoutError:
            context.set_code(grpc.StatusCode.DEADLINE_EXCEEDED)
            context.set_details("External API timeout")
            return APIResponse(success=False)
        
        except Exception as e:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"API call failed: {e}")
            return APIResponse(success=False)
    
    async def shutdown(self):
        await self.http_client.close()
```

## Async Context Management

### Request Context Manager

```python
import asyncio
import contextvars
from datetime import datetime

# Context variables
request_id = contextvars.ContextVar('request_id')
user_context = contextvars.ContextVar('user_context') 
correlation_id = contextvars.ContextVar('correlation_id')

class RequestContextManager:
    """Manage request context across async operations."""
    
    def __init__(self):
        self.active_contexts: Dict[str, Dict[str, Any]] = {}
    
    @asynccontextmanager
    async def request_context(self, 
                            req_id: str, 
                            user_info: Dict[str, Any] = None,
                            correlation: str = None):
        """Create request context."""
        
        # Set context variables
        request_id.set(req_id)
        if user_info:
            user_context.set(user_info)
        if correlation:
            correlation_id.set(correlation)
        
        # Track active context
        context_info = {
            'request_id': req_id,
            'user_info': user_info or {},
            'correlation_id': correlation,
            'started_at': datetime.now(),
            'task_id': id(asyncio.current_task())
        }
        
        self.active_contexts[req_id] = context_info
        
        try:
            yield context_info
        finally:
            # Cleanup context
            self.active_contexts.pop(req_id, None)
    
    def get_current_request_id(self) -> Optional[str]:
        """Get current request ID."""
        try:
            return request_id.get()
        except LookupError:
            return None
    
    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """Get current user context."""
        try:
            return user_context.get()
        except LookupError:
            return None
    
    def get_correlation_id(self) -> Optional[str]:
        """Get current correlation ID."""
        try:
            return correlation_id.get()
        except LookupError:
            return None

# Global context manager
context_manager = RequestContextManager()

class ContextAwareHandler:
    """Handler with request context awareness."""
    
    async def ProcessWithContext(self, request, context):
        """Process request with full context management."""
        req_id = f"req_{int(time.time() * 1000)}"
        
        # Extract user info from gRPC metadata
        metadata = dict(context.invocation_metadata())
        user_info = {
            'user_id': metadata.get('user-id'),
            'session_id': metadata.get('session-id')
        }
        correlation = metadata.get('correlation-id')
        
        async with context_manager.request_context(req_id, user_info, correlation):
            # All async operations within this context have access to
            # request_id, user_context, and correlation_id
            
            result = await self.perform_business_logic(request.data)
            
            # Log with context
            self.log_with_context("Request processed successfully")
            
            return ProcessResponse(
                result=result,
                request_id=req_id,
                correlation_id=correlation
            )
    
    async def perform_business_logic(self, data: str) -> str:
        """Business logic with context access."""
        # Access context variables
        req_id = context_manager.get_current_request_id()
        user = context_manager.get_current_user()
        
        self.log_with_context(f"Processing data for user: {user.get('user_id')}")
        
        # Simulate async work
        await asyncio.sleep(0.1)
        
        return f"Processed: {data}"
    
    def log_with_context(self, message: str):
        """Log message with request context."""
        req_id = context_manager.get_current_request_id()
        user = context_manager.get_current_user()
        correlation = context_manager.get_correlation_id()
        
        logging.info(
            f"[{req_id}] [{correlation}] [{user.get('user_id', 'anonymous')}] {message}"
        )
```

## Error Handling in Async Operations

### Async Error Recovery

```python
import asyncio
from typing import TypeVar, Callable, Awaitable

T = TypeVar('T')

class AsyncErrorHandler:
    """Handle errors in async operations with retry and circuit breaker."""
    
    def __init__(self):
        self.circuit_breakers: Dict[str, Dict] = {}
        self.retry_stats: Dict[str, Dict] = {}
    
    async def with_retry(self,
                        operation: Callable[[], Awaitable[T]],
                        operation_name: str,
                        max_retries: int = 3,
                        base_delay: float = 1.0,
                        backoff_factor: float = 2.0,
                        jitter: bool = True) -> T:
        """Execute operation with retry logic."""
        
        for attempt in range(max_retries + 1):
            try:
                result = await operation()
                
                # Reset failure count on success
                if operation_name in self.retry_stats:
                    self.retry_stats[operation_name]['consecutive_failures'] = 0
                
                return result
                
            except Exception as e:
                # Track retry stats
                if operation_name not in self.retry_stats:
                    self.retry_stats[operation_name] = {
                        'total_attempts': 0,
                        'total_failures': 0,
                        'consecutive_failures': 0
                    }
                
                stats = self.retry_stats[operation_name]
                stats['total_attempts'] += 1
                stats['total_failures'] += 1
                stats['consecutive_failures'] += 1
                
                # Check if we should retry
                if attempt == max_retries:
                    logging.error(f"Operation {operation_name} failed after {max_retries} retries: {e}")
                    raise
                
                # Calculate delay with exponential backoff
                delay = base_delay * (backoff_factor ** attempt)
                
                # Add jitter to prevent thundering herd
                if jitter:
                    import random
                    delay *= (0.5 + random.random() * 0.5)
                
                logging.warning(f"Operation {operation_name} failed (attempt {attempt + 1}): {e}. Retrying in {delay:.2f}s")
                await asyncio.sleep(delay)
    
    async def with_circuit_breaker(self,
                                 operation: Callable[[], Awaitable[T]],
                                 operation_name: str,
                                 failure_threshold: int = 5,
                                 recovery_timeout: float = 60.0) -> T:
        """Execute operation with circuit breaker pattern."""
        
        # Initialize circuit breaker if not exists
        if operation_name not in self.circuit_breakers:
            self.circuit_breakers[operation_name] = {
                'state': 'closed',  # closed, open, half_open
                'failure_count': 0,
                'last_failure_time': 0,
                'success_count': 0
            }
        
        breaker = self.circuit_breakers[operation_name]
        current_time = time.time()
        
        # Check circuit breaker state
        if breaker['state'] == 'open':
            if current_time - breaker['last_failure_time'] >= recovery_timeout:
                # Try to recover
                breaker['state'] = 'half_open'
                breaker['success_count'] = 0
                logging.info(f"Circuit breaker for {operation_name} entering half-open state")
            else:
                raise Exception(f"Circuit breaker for {operation_name} is OPEN")
        
        try:
            result = await operation()
            
            # Success handling
            if breaker['state'] == 'half_open':
                breaker['success_count'] += 1
                if breaker['success_count'] >= 2:  # Require 2 successes to close
                    breaker['state'] = 'closed'
                    breaker['failure_count'] = 0
                    logging.info(f"Circuit breaker for {operation_name} CLOSED")
            elif breaker['state'] == 'closed':
                breaker['failure_count'] = 0  # Reset failure count
            
            return result
            
        except Exception as e:
            # Failure handling
            breaker['failure_count'] += 1
            breaker['last_failure_time'] = current_time
            
            if breaker['failure_count'] >= failure_threshold:
                breaker['state'] = 'open'
                logging.error(f"Circuit breaker for {operation_name} OPENED after {failure_threshold} failures")
            
            raise

# Usage in async handler
class ResilientHandler:
    def __init__(self):
        self.error_handler = AsyncErrorHandler()
    
    async def CallExternalService(self, request, context):
        """Call external service with resilience patterns."""
        
        async def make_api_call():
            # Simulate external API call
            async with aiohttp.ClientSession() as session:
                async with session.get(request.api_url) as response:
                    return await response.json()
        
        try:
            # Combine retry and circuit breaker
            result = await self.error_handler.with_circuit_breaker(
                operation=lambda: self.error_handler.with_retry(
                    operation=make_api_call,
                    operation_name="external_api_call",
                    max_retries=3
                ),
                operation_name="external_api_circuit",
                failure_threshold=3
            )
            
            return ExternalServiceResponse(
                data=result,
                success=True
            )
        
        except Exception as e:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"External service call failed: {e}")
            return ExternalServiceResponse(success=False)
```

## Next Steps

- **[Health Checks](health-checks.md)** - Implement comprehensive health monitoring
- **[Client Development](../client/)** - Learn client-side async patterns
- **[Configuration](../config/)** - Optimize async configurations