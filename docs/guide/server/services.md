# Service Implementation

Master the art of implementing robust gRPC service handlers with error handling, streaming, and validation patterns.

## Service Handler Patterns

### Unary RPC (Request-Response)

```python
import grpc
from calculator_pb2 import CalculationResponse
from provide.foundation import logger

class CalculatorHandler:
    async def Add(self, request, context):
        """Handle addition RPC with comprehensive error handling."""
        try:
            # Input validation
            if not hasattr(request, 'a') or not hasattr(request, 'b'):
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("Missing required fields 'a' and 'b'")
                return CalculationResponse()
            
            # Business logic
            result = request.a + request.b
            
            # Optional: Check for overflow
            if abs(result) > 1e15:
                context.set_code(grpc.StatusCode.OUT_OF_RANGE)
                context.set_details("Result too large")
                return CalculationResponse()
            
            logger.info(f"Addition: {request.a} + {request.b} = {result}")
            return CalculationResponse(result=result)
            
        except Exception as e:
            logger.error(f"Addition failed: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal calculation error")
            return CalculationResponse()
    
    async def Divide(self, request, context):
        """Division with domain-specific error handling."""
        try:
            if request.b == 0:
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("Division by zero")
                return CalculationResponse()
            
            result = request.a / request.b
            return CalculationResponse(result=result)
            
        except Exception as e:
            logger.error(f"Division error: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Division calculation failed")
            return CalculationResponse()
```

### Server Streaming RPC

```python
import asyncio
from data_pb2 import DataChunk

class DataHandler:
    async def StreamLargeData(self, request, context):
        """Stream large dataset in chunks."""
        try:
            total_chunks = request.chunk_count or 100
            chunk_size = request.chunk_size or 1024
            
            for i in range(total_chunks):
                # Check if client disconnected
                if context.cancelled():
                    logger.info("Client disconnected during streaming")
                    break
                
                # Generate data chunk
                chunk_data = f"Chunk {i}".ljust(chunk_size, 'x')
                chunk = DataChunk(
                    sequence_number=i,
                    data=chunk_data.encode(),
                    is_final=(i == total_chunks - 1)
                )
                
                yield chunk
                
                # Optional: Add delay to simulate processing
                await asyncio.sleep(0.01)
                
        except Exception as e:
            logger.error(f"Streaming error: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Streaming failed")
    
    async def StreamResults(self, request, context):
        """Stream query results with metadata."""
        try:
            # Set response metadata
            context.set_trailing_metadata([
                ('result-count', str(request.limit)),
                ('query-time', '123ms')
            ])
            
            for i in range(request.limit):
                if context.cancelled():
                    logger.info("Client cancelled stream")
                    return
                
                result = DataChunk(
                    sequence_number=i,
                    data=f"Result {i}".encode(),
                    is_final=(i == request.limit - 1)
                )
                
                yield result
                
        except Exception as e:
            logger.error(f"Results streaming error: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Results streaming failed")
```

### Client Streaming RPC

```python
class UploadHandler:
    async def UploadFile(self, request_iterator, context):
        """Handle file upload via client streaming."""
        try:
            total_bytes = 0
            chunk_count = 0
            file_data = bytearray()
            
            async for chunk in request_iterator:
                # Check chunk validity
                if not chunk.data:
                    context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                    context.set_details("Empty chunk received")
                    return UploadResponse()
                
                file_data.extend(chunk.data)
                total_bytes += len(chunk.data)
                chunk_count += 1
                
                # Optional: Size limit
                if total_bytes > 10 * 1024 * 1024:  # 10MB limit
                    context.set_code(grpc.StatusCode.RESOURCE_EXHAUSTED)
                    context.set_details("File too large")
                    return UploadResponse()
                
                logger.debug(f"Received chunk {chunk_count}: {len(chunk.data)} bytes")
            
            # Process uploaded data
            file_hash = self.compute_hash(file_data)
            
            logger.info(f"Upload complete: {total_bytes} bytes, {chunk_count} chunks")
            
            return UploadResponse(
                total_bytes=total_bytes,
                chunk_count=chunk_count,
                file_hash=file_hash
            )
            
        except Exception as e:
            logger.error(f"Upload error: {e}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Upload processing failed")
            return UploadResponse()
    
    def compute_hash(self, data: bytes) -> str:
        """Compute SHA-256 hash of data."""
        import hashlib
        return hashlib.sha256(data).hexdigest()
```

### Bidirectional Streaming RPC

```python
import json
from chat_pb2 import ChatMessage, ChatResponse

class ChatHandler:
    def __init__(self):
        self.active_sessions = {}
    
    async def Chat(self, request_iterator, context):
        """Handle bidirectional chat session."""
        session_id = context.peer()  # Use peer address as session ID
        logger.info(f"Chat session started: {session_id}")
        
        try:
            # Initialize session
            self.active_sessions[session_id] = {
                'message_count': 0,
                'start_time': time.time()
            }
            
            async for message in request_iterator:
                if context.cancelled():
                    logger.info(f"Chat session cancelled: {session_id}")
                    break
                
                # Process message
                response = await self.process_chat_message(message, session_id)
                
                # Send response
                yield response
                
                # Update session stats
                self.active_sessions[session_id]['message_count'] += 1
                
        except Exception as e:
            logger.error(f"Chat error: {e}")
            yield ChatResponse(
                message="Sorry, an error occurred",
                error=True
            )
        finally:
            # Cleanup session
            if session_id in self.active_sessions:
                session_info = self.active_sessions.pop(session_id)
                logger.info(f"Chat session ended: {session_id}, "
                          f"messages: {session_info['message_count']}")
    
    async def process_chat_message(self, message: ChatMessage, session_id: str) -> ChatResponse:
        """Process individual chat message."""
        try:
            # Simple echo with processing
            response_text = f"Echo: {message.content}"
            
            # Optional: Add AI/ML processing here
            # response_text = await self.ai_process(message.content)
            
            return ChatResponse(
                message=response_text,
                timestamp=int(time.time()),
                session_id=session_id
            )
            
        except Exception as e:
            logger.error(f"Message processing error: {e}")
            return ChatResponse(
                message="Failed to process message",
                error=True
            )
```

## Error Handling Patterns

### Comprehensive Error Handling Mixin

```python
import grpc
from typing import Any, Callable
from provide.foundation import logger

class ServiceErrorHandler:
    """Comprehensive error handling for gRPC services."""
    
    def handle_service_error(self, context, error: Exception, operation: str):
        """Standardized error handling."""
        
        error_mappings = {
            ValueError: (grpc.StatusCode.INVALID_ARGUMENT, "Invalid input"),
            FileNotFoundError: (grpc.StatusCode.NOT_FOUND, "Resource not found"),
            PermissionError: (grpc.StatusCode.PERMISSION_DENIED, "Access denied"),
            TimeoutError: (grpc.StatusCode.DEADLINE_EXCEEDED, "Operation timed out"),
            ConnectionError: (grpc.StatusCode.UNAVAILABLE, "Service unavailable"),
        }
        
        # Get appropriate status code and message
        status_code, default_message = error_mappings.get(
            type(error), 
            (grpc.StatusCode.INTERNAL, "Internal server error")
        )
        
        # Set gRPC status
        context.set_code(status_code)
        context.set_details(str(error) or default_message)
        
        # Log error with appropriate level
        if status_code == grpc.StatusCode.INTERNAL:
            logger.error(f"{operation} failed: {error}", exc_info=True)
        else:
            logger.warning(f"{operation} failed: {error}")
    
    def with_error_handling(self, operation: str):
        """Decorator for service methods."""
        def decorator(func: Callable) -> Callable:
            async def wrapper(self, request, context, *args, **kwargs):
                try:
                    return await func(self, request, context, *args, **kwargs)
                except Exception as e:
                    self.handle_service_error(context, e, operation)
                    # Return appropriate empty response
                    return self.get_empty_response(func.__name__)
            return wrapper
        return decorator
    
    def get_empty_response(self, method_name: str):
        """Get empty response for given method."""
        # This would be customized per service
        from calculator_pb2 import CalculationResponse
        return CalculationResponse()

# Usage
class CalculatorHandler(ServiceErrorHandler):
    @ServiceErrorHandler.with_error_handling("Addition")
    async def Add(self, request, context):
        result = request.a + request.b
        return CalculationResponse(result=result)
    
    @ServiceErrorHandler.with_error_handling("Division") 
    async def Divide(self, request, context):
        if request.b == 0:
            raise ValueError("Division by zero")
        
        result = request.a / request.b
        return CalculationResponse(result=result)
```

### Input Validation

```python
from typing import Any, List
import re

class InputValidator:
    """Input validation utilities for gRPC services."""
    
    @staticmethod
    def validate_required_fields(obj: Any, required_fields: List[str]):
        """Validate required fields are present."""
        missing = [field for field in required_fields if not hasattr(obj, field)]
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")
    
    @staticmethod
    def validate_string_length(value: str, min_len: int = 0, max_len: int = 1000):
        """Validate string length."""
        if len(value) < min_len:
            raise ValueError(f"String too short, minimum {min_len} characters")
        if len(value) > max_len:
            raise ValueError(f"String too long, maximum {max_len} characters")
    
    @staticmethod
    def validate_email(email: str):
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, email):
            raise ValueError("Invalid email format")
    
    @staticmethod
    def validate_range(value: float, min_val: float = None, max_val: float = None):
        """Validate numeric range."""
        if min_val is not None and value < min_val:
            raise ValueError(f"Value {value} below minimum {min_val}")
        if max_val is not None and value > max_val:
            raise ValueError(f"Value {value} above maximum {max_val}")

# Usage in service
class UserHandler(InputValidator, ServiceErrorHandler):
    @ServiceErrorHandler.with_error_handling("User creation")
    async def CreateUser(self, request, context):
        # Validate required fields
        self.validate_required_fields(request, ['name', 'email'])
        
        # Validate specific fields
        self.validate_string_length(request.name, min_len=2, max_len=50)
        self.validate_email(request.email)
        
        if hasattr(request, 'age'):
            self.validate_range(request.age, min_val=0, max_val=150)
        
        # Process valid request
        user = await self.create_user_in_db(request)
        return UserResponse(user=user)
```

## Stateful Services

### Session Management

```python
import time
from typing import Dict, Any
from datetime import datetime, timedelta

class SessionManager:
    """Manage user sessions in stateful services."""
    
    def __init__(self, session_timeout: float = 3600):  # 1 hour
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.session_timeout = session_timeout
    
    def create_session(self, user_id: str) -> str:
        """Create new session."""
        import uuid
        session_id = str(uuid.uuid4())
        
        self.sessions[session_id] = {
            'user_id': user_id,
            'created_at': time.time(),
            'last_access': time.time(),
            'data': {}
        }
        
        return session_id
    
    def get_session(self, session_id: str) -> Dict[str, Any]:
        """Get session data."""
        session = self.sessions.get(session_id)
        
        if not session:
            raise ValueError("Invalid session")
        
        # Check timeout
        if time.time() - session['last_access'] > self.session_timeout:
            self.cleanup_session(session_id)
            raise ValueError("Session expired")
        
        # Update last access
        session['last_access'] = time.time()
        return session
    
    def cleanup_session(self, session_id: str):
        """Remove session."""
        self.sessions.pop(session_id, None)
    
    def cleanup_expired_sessions(self):
        """Remove all expired sessions."""
        current_time = time.time()
        expired = [
            sid for sid, session in self.sessions.items()
            if current_time - session['last_access'] > self.session_timeout
        ]
        
        for sid in expired:
            self.cleanup_session(sid)

class StatefulHandler(ServiceErrorHandler):
    def __init__(self):
        self.session_manager = SessionManager()
        self.background_cleanup_task = None
    
    async def start_background_tasks(self):
        """Start background maintenance tasks."""
        async def cleanup_loop():
            while True:
                await asyncio.sleep(300)  # Every 5 minutes
                self.session_manager.cleanup_expired_sessions()
        
        self.background_cleanup_task = asyncio.create_task(cleanup_loop())
    
    @ServiceErrorHandler.with_error_handling("Login")
    async def Login(self, request, context):
        # Authenticate user
        user_id = await self.authenticate_user(request.username, request.password)
        
        # Create session
        session_id = self.session_manager.create_session(user_id)
        
        return LoginResponse(session_id=session_id)
    
    @ServiceErrorHandler.with_error_handling("Get profile")
    async def GetProfile(self, request, context):
        # Validate session
        session = self.session_manager.get_session(request.session_id)
        
        # Get user profile
        profile = await self.get_user_profile(session['user_id'])
        
        return ProfileResponse(profile=profile)
    
    async def authenticate_user(self, username: str, password: str) -> str:
        """Authenticate user and return user ID."""
        # Implementation depends on your auth system
        # This is a simplified example
        if username == "demo" and password == "password":
            return "user_123"
        
        raise PermissionError("Invalid credentials")
```

## Performance Optimization

### Connection Pooling and Resource Management

```python
import asyncio
from contextlib import asynccontextmanager

class ResourceManager:
    """Manage database connections and other resources."""
    
    def __init__(self, max_connections: int = 10):
        self.connection_pool = asyncio.Queue(maxsize=max_connections)
        self.initialized = False
    
    async def initialize(self):
        """Initialize connection pool."""
        if self.initialized:
            return
        
        # Create connection pool
        for _ in range(self.connection_pool.maxsize):
            conn = await self.create_connection()
            await self.connection_pool.put(conn)
        
        self.initialized = True
    
    async def create_connection(self):
        """Create database connection."""
        # Replace with actual database connection logic
        await asyncio.sleep(0.1)  # Simulate connection time
        return {"connected": True, "id": id(object())}
    
    @asynccontextmanager
    async def get_connection(self):
        """Get connection from pool."""
        if not self.initialized:
            await self.initialize()
        
        conn = await self.connection_pool.get()
        try:
            yield conn
        finally:
            await self.connection_pool.put(conn)

class OptimizedHandler(ServiceErrorHandler):
    def __init__(self):
        self.resource_manager = ResourceManager()
    
    @ServiceErrorHandler.with_error_handling("Database query")
    async def QueryData(self, request, context):
        async with self.resource_manager.get_connection() as conn:
            # Use connection for database operations
            result = await self.execute_query(conn, request.query)
            
            return QueryResponse(data=result)
    
    async def execute_query(self, conn, query: str):
        """Execute database query."""
        # Simulate database operation
        await asyncio.sleep(0.01)
        return f"Result for: {query}"
```

## Testing Service Handlers

### Unit Testing

```python
import pytest
import grpc
from grpc_testing import server_from_dictionary

@pytest.fixture
def calculator_handler():
    return CalculatorHandler()

@pytest.fixture
def grpc_server(calculator_handler):
    services = {
        "calculator.Calculator": calculator_handler
    }
    return server_from_dictionary(services, grpc.aio.server())

@pytest.mark.asyncio
async def test_successful_addition(calculator_handler):
    from calculator_pb2 import CalculationRequest
    
    request = CalculationRequest(a=5.0, b=3.0)
    context = MockContext()
    
    response = await calculator_handler.Add(request, context)
    
    assert response.result == 8.0
    assert context.code() is None  # No error

@pytest.mark.asyncio
async def test_division_by_zero(calculator_handler):
    from calculator_pb2 import CalculationRequest
    
    request = CalculationRequest(a=10.0, b=0.0)
    context = MockContext()
    
    response = await calculator_handler.Divide(request, context)
    
    assert context.code() == grpc.StatusCode.INVALID_ARGUMENT
    assert "Division by zero" in context.details()

class MockContext:
    def __init__(self):
        self._code = None
        self._details = None
    
    def set_code(self, code):
        self._code = code
    
    def set_details(self, details):
        self._details = details
    
    def code(self):
        return self._code
    
    def details(self):
        return self._details
```

## Next Steps

- **[Transport Configuration](transports.md)** - Optimize transport layers
- **[Async Patterns](async-patterns.md)** - Master concurrency patterns
- **[Health Checks](health-checks.md)** - Implement service monitoring