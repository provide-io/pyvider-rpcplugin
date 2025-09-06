# Troubleshooting

This guide helps you diagnose and resolve common issues when developing with the Pyvider RPC Plugin framework.

## Common Issues

### 1. Connection Issues

#### Problem: "Connection refused" errors

**Symptoms:**
```
ConnectionRefusedError: [Errno 111] Connection refused
grpc._channel._InactiveRpcError: <_InactiveRpcError of RPC that terminated with: status = StatusCode.UNAVAILABLE>
```

**Diagnosis:**
```python
# Debug connection issues
import asyncio
import socket
from pyvider.client import RPCPluginClient

async def diagnose_connection(host: str, port: int):
    """Diagnose connection issues."""
    print(f"🔍 Diagnosing connection to {host}:{port}")
    
    # Test basic network connectivity
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            print("✅ Network connection successful")
        else:
            print(f"❌ Network connection failed: {result}")
            return False
    except Exception as e:
        print(f"❌ Network error: {e}")
        return False
    finally:
        sock.close()
    
    # Test RPC connection
    try:
        client = RPCPluginClient(host=host, port=port)
        await client.connect()
        print("✅ RPC connection successful")
        await client.close()
        return True
    except Exception as e:
        print(f"❌ RPC connection failed: {e}")
        return False

# Usage
if __name__ == "__main__":
    asyncio.run(diagnose_connection("localhost", 50051))
```

**Solutions:**

1. **Server not running:**
   ```bash
   # Check if server process is running
   ps aux | grep python
   netstat -tlnp | grep :50051
   ```

2. **Wrong host/port:**
   ```python
   # Verify server configuration
   config = ServerConfig.from_env()
   print(f"Server should be on {config.transport.host}:{config.transport.port}")
   ```

3. **Firewall blocking connection:**
   ```bash
   # Check firewall rules (Linux)
   sudo iptables -L -n
   
   # Check firewall rules (macOS)
   sudo pfctl -sr
   ```

4. **Network interface binding:**
   ```python
   # Server binding to localhost only
   config = ServerConfig(
       transport=TransportConfig(
           host="0.0.0.0",  # Bind to all interfaces
           port=50051
       )
   )
   ```

#### Problem: "Address already in use"

**Symptoms:**
```
OSError: [Errno 98] Address already in use
```

**Solutions:**

1. **Find and kill process using the port:**
   ```bash
   # Find process using port
   lsof -i :50051
   
   # Kill the process
   kill -9 <PID>
   ```

2. **Use different port:**
   ```python
   config = ServerConfig(
       transport=TransportConfig(port=50052)  # Different port
   )
   ```

3. **Enable port reuse:**
   ```python
   import socket
   
   # In transport implementation
   sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
   ```

### 2. SSL/TLS Issues

#### Problem: SSL certificate verification failures

**Symptoms:**
```
ssl.SSLCertVerificationError: certificate verify failed
grpc._channel._InactiveRpcError: SSL handshake failed
```

**Diagnosis:**
```python
import ssl
import asyncio
from pyvider.security import SecurityManager

async def diagnose_ssl(host: str, port: int, cert_file: str | None = None):
    """Diagnose SSL/TLS issues."""
    print(f"🔍 Diagnosing SSL connection to {host}:{port}")
    
    # Test basic SSL connection
    context = ssl.create_default_context()
    if cert_file:
        context.load_verify_locations(cert_file)
    
    try:
        reader, writer = await asyncio.open_connection(
            host, port, ssl=context
        )
        print("✅ SSL connection successful")
        writer.close()
        await writer.wait_closed()
        return True
    except ssl.SSLError as e:
        print(f"❌ SSL error: {e}")
        return False
    except Exception as e:
        print(f"❌ Connection error: {e}")
        return False

# Certificate verification
def verify_certificate(cert_file: str):
    """Verify certificate file."""
    try:
        with open(cert_file, 'rb') as f:
            cert_data = f.read()
        
        cert = ssl.PEM_cert_to_DER_cert(cert_data.decode())
        print("✅ Certificate file is valid")
        return True
    except Exception as e:
        print(f"❌ Certificate error: {e}")
        return False
```

**Solutions:**

1. **Invalid certificate paths:**
   ```python
   from pathlib import Path
   
   cert_file = Path("certs/server.pem")
   if not cert_file.exists():
       print(f"❌ Certificate file not found: {cert_file}")
   ```

2. **Self-signed certificates:**
   ```python
   # Disable SSL verification (development only!)
   import ssl
   
   context = ssl.create_default_context()
   context.check_hostname = False
   context.verify_mode = ssl.CERT_NONE
   ```

3. **Certificate authority issues:**
   ```python
   # Specify custom CA
   context = ssl.create_default_context()
   context.load_verify_locations('ca-cert.pem')
   ```

4. **Generate test certificates:**
   ```bash
   # Generate self-signed certificate for testing
   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
   ```

### 3. Performance Issues

#### Problem: Slow RPC calls

**Diagnosis:**
```python
import time
import asyncio
import statistics
from typing import Any
from pyvider.client import RPCPluginClient

class PerformanceDiagnostics:
    """Performance diagnostics tools."""
    
    def __init__(self, client: RPCPluginClient):
        self.client = client
        self.call_times: list[float] = []
    
    async def benchmark_call(
        self, 
        method_name: str, 
        request: Any, 
        iterations: int = 100
    ):
        """Benchmark RPC call performance."""
        print(f"🏃 Benchmarking {method_name} ({iterations} iterations)")
        
        for i in range(iterations):
            start_time = time.perf_counter()
            
            try:
                await self.client.call(method_name, request)
                end_time = time.perf_counter()
                self.call_times.append(end_time - start_time)
            except Exception as e:
                print(f"❌ Call {i+1} failed: {e}")
        
        self._analyze_performance()
    
    def _analyze_performance(self):
        """Analyze performance metrics."""
        if not self.call_times:
            print("❌ No successful calls to analyze")
            return
        
        mean_time = statistics.mean(self.call_times)
        median_time = statistics.median(self.call_times)
        min_time = min(self.call_times)
        max_time = max(self.call_times)
        
        # Calculate percentiles
        sorted_times = sorted(self.call_times)
        p95 = sorted_times[int(0.95 * len(sorted_times))]
        p99 = sorted_times[int(0.99 * len(sorted_times))]
        
        print("\n📊 Performance Analysis:")
        print(f"  Mean:   {mean_time*1000:.2f}ms")
        print(f"  Median: {median_time*1000:.2f}ms")
        print(f"  Min:    {min_time*1000:.2f}ms")
        print(f"  Max:    {max_time*1000:.2f}ms")
        print(f"  P95:    {p95*1000:.2f}ms")
        print(f"  P99:    {p99*1000:.2f}ms")
        
        # Performance warnings
        if mean_time > 1.0:  # More than 1 second
            print("⚠️  Average call time is high (>1s)")
        
        if p95 > 5.0:  # 95th percentile over 5 seconds
            print("⚠️  95th percentile is very high (>5s)")
        
        if max_time > 10.0:  # Max over 10 seconds
            print("⚠️  Some calls are extremely slow (>10s)")

# Network latency test
async def test_network_latency(host: str, port: int):
    """Test network latency to server."""
    import ping3
    
    latency = ping3.ping(host)
    if latency:
        print(f"🌐 Network latency to {host}: {latency*1000:.2f}ms")
        if latency > 0.1:  # More than 100ms
            print("⚠️  High network latency detected")
    else:
        print(f"❌ Could not ping {host}")
```

**Solutions:**

1. **Connection pooling:**
   ```python
   from pyvider.client import ConnectionPool
   
   # Use connection pooling to reduce overhead
   pool = ConnectionPool(max_size=10)
   client = RPCPluginClient(connection_pool=pool)
   ```

2. **Request batching:**
   ```python
   # Batch multiple requests
   async def batch_requests(client, requests):
       tasks = []
       for request in requests:
           tasks.append(client.call("method", request))
       
       return await asyncio.gather(*tasks)
   ```

3. **Streaming for large data:**
   ```python
   # Use streaming for large responses
   async def stream_large_data(client):
       async for chunk in client.stream_call("get_large_data", request):
           process_chunk(chunk)
   ```

#### Problem: Memory leaks

**Diagnosis:**
```python
import psutil
import asyncio
import gc
from typing import Any

class MemoryMonitor:
    """Monitor memory usage."""
    
    def __init__(self):
        self.process = psutil.Process()
        self.initial_memory = self.process.memory_info().rss
    
    def get_memory_usage(self) -> dict[str, Any]:
        """Get current memory usage."""
        memory_info = self.process.memory_info()
        
        return {
            'rss': memory_info.rss,  # Resident Set Size
            'vms': memory_info.vms,  # Virtual Memory Size  
            'percent': self.process.memory_percent(),
            'increase': memory_info.rss - self.initial_memory,
        }
    
    def check_memory_leak(self, threshold_mb: int = 100):
        """Check for potential memory leaks."""
        usage = self.get_memory_usage()
        increase_mb = usage['increase'] / 1024 / 1024
        
        print(f"💾 Memory usage: {usage['rss']/1024/1024:.1f}MB ({usage['percent']:.1f}%)")
        print(f"📈 Memory increase: {increase_mb:.1f}MB")
        
        if increase_mb > threshold_mb:
            print(f"⚠️  Potential memory leak detected (+{increase_mb:.1f}MB)")
            
            # Force garbage collection
            collected = gc.collect()
            print(f"🗑️  Garbage collected {collected} objects")
            
            # Check again after GC
            new_usage = self.get_memory_usage()
            new_increase = new_usage['increase'] / 1024 / 1024
            print(f"📉 Memory after GC: {new_increase:.1f}MB")

# Usage in long-running tests
async def test_memory_usage():
    monitor = MemoryMonitor()
    
    for i in range(1000):
        # Perform operations
        client = RPCPluginClient()
        await client.connect()
        await client.call("test_method", request)
        await client.close()
        
        if i % 100 == 0:
            monitor.check_memory_leak()
```

**Solutions:**

1. **Proper resource cleanup:**
   ```python
   # Always use context managers
   async with RPCPluginClient() as client:
       result = await client.call("method", request)
   
   # Or explicit cleanup
   client = RPCPluginClient()
   try:
       await client.connect()
       result = await client.call("method", request)
   finally:
       await client.close()
   ```

2. **Connection pooling:**
   ```python
   # Reuse connections instead of creating new ones
   pool = ConnectionPool(max_size=10)
   # Use pool for multiple requests
   ```

3. **Garbage collection monitoring:**
   ```python
   import gc
   import weakref
   
   # Monitor object references
   def track_objects():
       for obj in gc.get_objects():
           if isinstance(obj, RPCPluginClient):
               print(f"Found client object: {id(obj)}")
   ```

### 4. Serialization Issues

#### Problem: Protobuf serialization errors

**Symptoms:**
```
google.protobuf.message.DecodeError: Error parsing message
TypeError: Couldn't build proto file into descriptor pool
```

**Diagnosis:**
```python
import json
from google.protobuf.json_format import MessageToJson, Parse
from google.protobuf.message import Message

def diagnose_protobuf_issue(message: Message, data: bytes | None = None):
    """Diagnose protobuf serialization issues."""
    print(f"🔍 Diagnosing protobuf message: {type(message).__name__}")
    
    try:
        # Test JSON serialization
        json_str = MessageToJson(message)
        print("✅ JSON serialization successful")
        print(f"JSON: {json_str}")
        
        # Test JSON deserialization
        parsed = Parse(json_str, type(message)())
        print("✅ JSON deserialization successful")
        
    except Exception as e:
        print(f"❌ JSON serialization error: {e}")
    
    try:
        # Test binary serialization
        binary_data = message.SerializeToString()
        print(f"✅ Binary serialization successful ({len(binary_data)} bytes)")
        
        # Test binary deserialization
        new_message = type(message)()
        new_message.ParseFromString(binary_data)
        print("✅ Binary deserialization successful")
        
    except Exception as e:
        print(f"❌ Binary serialization error: {e}")
    
    if data:
        try:
            # Test parsing provided data
            test_message = type(message)()
            test_message.ParseFromString(data)
            print("✅ Provided data parsing successful")
        except Exception as e:
            print(f"❌ Provided data parsing error: {e}")
```

**Solutions:**

1. **Version mismatches:**
   ```bash
   # Check protobuf versions
   pip list | grep protobuf
   python -c "import google.protobuf; print(google.protobuf.__version__)"
   
   # Regenerate protobuf files
   python -m grpc_tools.protoc --python_out=. --grpc_python_out=. *.proto
   ```

2. **Message validation:**
   ```python
   def validate_message(message):
       """Validate protobuf message."""
       try:
           message.SerializeToString()
           return True
       except Exception as e:
           print(f"Message validation failed: {e}")
           return False
   ```

3. **Field type mismatches:**
   ```python
   # Ensure correct field types
   request = MyRequest(
       id=int(user_id),  # Ensure integer
       name=str(name),   # Ensure string
       timestamp=int(time.time()),  # Ensure integer timestamp
   )
   ```

### 5. Authentication Issues

#### Problem: JWT token validation failures

**Symptoms:**
```
jwt.InvalidTokenError: Invalid token
grpc.RpcError: UNAUTHENTICATED: Invalid token
```

**Diagnosis:**
```python
import jwt
import time
from typing import Any

def diagnose_jwt_token(token: str, secret: str, algorithm: str = 'HS256'):
    """Diagnose JWT token issues."""
    print(f"🔍 Diagnosing JWT token")
    
    try:
        # Decode without verification first
        unverified = jwt.decode(token, options={"verify_signature": False})
        print("✅ Token structure is valid")
        print(f"Header: {jwt.get_unverified_header(token)}")
        print(f"Payload: {unverified}")
        
        # Check expiration
        if 'exp' in unverified:
            exp_time = unverified['exp']
            current_time = time.time()
            
            if exp_time < current_time:
                print(f"❌ Token expired at {time.ctime(exp_time)}")
            else:
                print(f"✅ Token valid until {time.ctime(exp_time)}")
        
        # Try to verify signature
        verified = jwt.decode(token, secret, algorithms=[algorithm])
        print("✅ Token signature is valid")
        return verified
        
    except jwt.ExpiredSignatureError:
        print("❌ Token has expired")
    except jwt.InvalidSignatureError:
        print("❌ Token signature is invalid")
    except jwt.InvalidTokenError as e:
        print(f"❌ Token is invalid: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
    
    return None

# Test token generation
def generate_test_token(secret: str, payload: dict[str, Any]) -> str:
    """Generate test JWT token."""
    # Add standard claims
    payload.update({
        'iat': int(time.time()),
        'exp': int(time.time()) + 3600,  # 1 hour
        'iss': 'test-server',
    })
    
    token = jwt.encode(payload, secret, algorithm='HS256')
    print(f"🎫 Generated test token: {token}")
    return token
```

**Solutions:**

1. **Token expiration:**
   ```python
   # Generate token with longer expiration
   payload = {
       'user_id': 123,
       'exp': int(time.time()) + 7200  # 2 hours
   }
   ```

2. **Secret key mismatches:**
   ```python
   # Ensure consistent secret across client and server
   SECRET_KEY = os.getenv('JWT_SECRET_KEY')
   if not SECRET_KEY:
       raise ValueError("JWT_SECRET_KEY environment variable not set")
   ```

3. **Algorithm mismatches:**
   ```python
   # Use consistent algorithm
   token = jwt.encode(payload, secret, algorithm='HS256')
   decoded = jwt.decode(token, secret, algorithms=['HS256'])
   ```

## Debugging Tools

### 1. Enable Debug Logging

```python
import logging

# Enable debug logging for pyvider
logging.getLogger('pyvider').setLevel(logging.DEBUG)

# Enable gRPC debug logging
logging.getLogger('grpc').setLevel(logging.DEBUG)

# Format debug output
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

### 2. Network Debugging

```python
import asyncio
import socket
from typing import Any

async def debug_network_connection(host: str, port: int):
    """Debug network connectivity."""
    print(f"🌐 Testing connection to {host}:{port}")
    
    # Test DNS resolution
    try:
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        print(f"✅ DNS resolution: {addr_info[0][4]}")
    except Exception as e:
        print(f"❌ DNS resolution failed: {e}")
        return
    
    # Test TCP connection
    try:
        reader, writer = await asyncio.open_connection(host, port)
        print("✅ TCP connection successful")
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(f"❌ TCP connection failed: {e}")
```

### 3. RPC Call Tracing

```python
import functools
import time
from typing import Any, Callable

def trace_rpc_calls(func: Callable) -> Callable:
    """Decorator to trace RPC calls."""
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        method_name = getattr(func, '__name__', 'unknown')
        
        print(f"🚀 Starting RPC call: {method_name}")
        print(f"   Args: {args}")
        print(f"   Kwargs: {kwargs}")
        
        try:
            result = await func(*args, **kwargs)
            end_time = time.perf_counter()
            duration = end_time - start_time
            
            print(f"✅ RPC call completed: {method_name} ({duration:.3f}s)")
            print(f"   Result: {result}")
            return result
            
        except Exception as e:
            end_time = time.perf_counter()
            duration = end_time - start_time
            
            print(f"❌ RPC call failed: {method_name} ({duration:.3f}s)")
            print(f"   Error: {e}")
            raise
    
    return wrapper

# Usage
class MyService:
    @trace_rpc_calls
    async def my_method(self, request):
        # Your method implementation
        pass
```

## Getting Help

### 1. Community Resources

- **GitHub Issues**: Report bugs and request features
- **GitHub Discussions**: Ask questions and share solutions  
- **Documentation**: Comprehensive guides and API reference

### 2. Diagnostic Information Collection

When reporting issues, include this diagnostic information:

```python
import sys
import platform
import pyvider
import grpc
import google.protobuf

def collect_diagnostic_info():
    """Collect system diagnostic information."""
    info = {
        'pyvider_version': pyvider.__version__,
        'python_version': sys.version,
        'platform': platform.platform(),
        'grpc_version': grpc.__version__,
        'protobuf_version': google.protobuf.__version__,
    }
    
    print("🔧 Diagnostic Information:")
    for key, value in info.items():
        print(f"  {key}: {value}")
    
    return info

# Include this output when reporting issues
collect_diagnostic_info()
```

### 3. Minimal Reproduction Case

When reporting bugs, provide a minimal reproduction case:

```python
import asyncio
from pyvider.server import RPCPluginServer
from pyvider.client import RPCPluginClient

async def reproduce_issue():
    """Minimal case reproducing the issue."""
    # Server setup
    server = RPCPluginServer()
    # ... minimal server configuration
    
    # Client setup
    client = RPCPluginClient()
    # ... minimal client configuration
    
    # Reproduce the issue
    try:
        result = await client.call("method", request)
        print(f"Expected error, but got: {result}")
    except Exception as e:
        print(f"Issue reproduced: {e}")

if __name__ == "__main__":
    asyncio.run(reproduce_issue())
```

Remember: the key to effective troubleshooting is systematic diagnosis, starting with the most likely causes and working through less common issues. Always check the basics first: network connectivity, configuration, and resource availability.