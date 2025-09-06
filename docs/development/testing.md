# Testing Guide

Comprehensive testing guidance for Pyvider RPC Plugin applications, covering unit testing, integration testing, mocking strategies, and best practices for servers, clients, transports, and configurations.

## Overview

The Pyvider RPC Plugin system provides:
- **pytest Framework**: Modern async Python testing
- **Configuration Isolation**: Automatic config reset between tests
- **Transport Testing**: Specialized fixtures for Unix/TCP testing
- **Mock Support**: Comprehensive mocking for components
- **Security Testing**: mTLS and authentication testing

Testing philosophy: Test components in isolation with integration testing support.

## Test Structure

```
tests/
├── conftest.py              # Global fixtures and configuration
├── fixtures/                # Reusable test fixtures
│   ├── mocks.py            # Mock implementations
│   └── crypto.py           # Certificate fixtures
├── unit/                   # Unit tests
├── integration/            # Integration tests
└── transport/              # Transport-specific tests
```

**Dependencies**: pytest, pytest-asyncio, pytest-cov, pytest-mock

## Configuration Management

### Automatic Reset and Test Configuration

```python
# conftest.py - Automatic config isolation
@pytest.fixture(autouse=True, scope="function")
def reset_rpcplugin_config_singleton():
    """Reset RPCPluginConfig singleton before each test."""
    # Handles environment cleanup and state reset

@pytest.fixture
def test_config():
    """Test-specific configuration with cleanup."""
    original_env = {}
    test_vars = {
        'PLUGIN_LOG_LEVEL': 'WARNING',
        'PLUGIN_AUTO_MTLS': 'true',
        'PLUGIN_HANDSHAKE_TIMEOUT': '5.0',
        'PLUGIN_CLIENT_RETRY_ENABLED': 'false',
        'PLUGIN_RATE_LIMIT_ENABLED': 'false',
    }
    
    for key, value in test_vars.items():
        original_env[key] = os.environ.get(key)
        os.environ[key] = value
    
    yield
    
    # Restore environment
    for key, original_value in original_env.items():
        if original_value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = original_value
```

## Transport Testing

### Transport Factory Fixture

```python
import pytest
import pytest_asyncio
from pathlib import Path
import tempfile
import uuid
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport

@pytest_asyncio.fixture(scope="function")
async def transport_factory(tmp_path: Path):
    """Factory fixture for creating isolated transport instances."""
    created_transports = []

    async def create(transport_type: str, **kwargs):
        if transport_type == "unix":
            socket_path = kwargs.pop('path', None)
            if not socket_path:
                socket_name = f"test_{uuid.uuid4().hex[:8]}.sock"
                socket_path = str(tmp_path / socket_name)
            transport = UnixSocketTransport(path=socket_path)
        
        elif transport_type == "tcp":
            port = kwargs.get('port', 0)  # 0 = auto-assign
            host = kwargs.get('host', '127.0.0.1')
            transport = TCPSocketTransport(host=host, port=port)
        
        else:
            raise ValueError(f"Unknown transport type: {transport_type}")

        created_transports.append(transport)
        return transport

    yield create

    # Cleanup all created transports
    for transport in created_transports:
        try:
            await transport.close()
        except Exception as e:
            print(f"Error closing transport: {e}")

# Usage
@pytest.mark.asyncio
async def test_transport_creation(transport_factory):
    # Create Unix socket transport
    unix_transport = await transport_factory("unix")
    endpoint = await unix_transport.listen()
    assert endpoint.endswith(".sock")
    
    # Create TCP transport
    tcp_transport = await transport_factory("tcp")
    endpoint = await tcp_transport.listen()
    assert ":" in endpoint  # host:port format
```

### Unix Socket Testing

```python
@pytest.mark.asyncio
async def test_unix_socket_lifecycle(transport_factory):
    """Test complete Unix socket lifecycle."""
    transport = await transport_factory("unix", path="/tmp/test.sock")
    
    # Test listening
    endpoint = await transport.listen()
    assert endpoint == "/tmp/test.sock"
    assert os.path.exists("/tmp/test.sock")
    
    # Test socket properties
    stat_result = os.stat("/tmp/test.sock")
    assert stat.S_ISSOCK(stat_result.st_mode)
    
    # Test connection
    client_transport = await transport_factory("unix")
    await client_transport.connect("/tmp/test.sock")
    assert client_transport.endpoint == "/tmp/test.sock"
    
    # Test cleanup
    await transport.close()
    # Socket file should be cleaned up

@pytest.mark.asyncio
async def test_unix_socket_permissions(transport_factory):
    """Test Unix socket file permissions."""
    transport = await transport_factory("unix")
    
    await transport.listen()
    socket_path = transport.endpoint
    
    # Check permissions
    stat_result = os.stat(socket_path)
    mode = stat_result.st_mode
    
    # Should be readable/writable by owner and group
    assert mode & stat.S_IRUSR  # Owner read
    assert mode & stat.S_IWUSR  # Owner write
    assert mode & stat.S_IRGRP  # Group read
    assert mode & stat.S_IWGRP  # Group write
```

### TCP Transport Testing

```python
@pytest.fixture
def unused_tcp_port():
    """Find an unused TCP port."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

@pytest.mark.asyncio
async def test_tcp_transport_lifecycle(transport_factory, unused_tcp_port):
    """Test complete TCP transport lifecycle."""
    transport = await transport_factory("tcp", port=unused_tcp_port)
    
    # Test listening
    endpoint = await transport.listen()
    assert endpoint == f"127.0.0.1:{unused_tcp_port}"
    
    # Test connection
    client_transport = await transport_factory("tcp")
    await client_transport.connect(endpoint)
    assert client_transport.endpoint == endpoint
    
    # Test cleanup
    await transport.close()

@pytest.mark.asyncio
async def test_tcp_auto_port_assignment(transport_factory):
    """Test automatic port assignment."""
    transport = await transport_factory("tcp", port=0)
    
    endpoint = await transport.listen()
    host, port_str = endpoint.split(":")
    port = int(port_str)
    
    assert host == "127.0.0.1"
    assert port > 0  # Should be assigned a port
    assert transport.port == port
```

## Server Testing

### Mock Protocol and Handler

```python
# tests/fixtures/mocks.py
from typing import Any
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol

class MockProtocol(RPCPluginProtocol):
    """Mock protocol for testing."""
    
    def __init__(self, service_name="TestService"):
        super().__init__()
        self.service_name = service_name
        self.add_to_server_called = False
    
    async def get_grpc_descriptors(self):
        return None, self.service_name
    
    async def add_to_server(self, server: Any, handler: Any):
        self.add_to_server_called = True
    
    def get_method_type(self, method_name: str) -> str:
        return "unary_unary"

class MockHandler:
    """Mock handler for testing."""
    
    def __init__(self):
        self.method_calls = []
    
    async def test_method(self, request, context):
        self.method_calls.append(("test_method", request))
        return {"result": "test_response"}

# Test fixtures
@pytest.fixture
def mock_protocol():
    return MockProtocol(service_name="TestService")

@pytest.fixture
def mock_handler():
    return MockHandler()
```

### Server Testing Patterns

```python
import pytest
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.factories import plugin_server

@pytest.mark.asyncio
async def test_server_creation(mock_protocol, mock_handler, transport_factory):
    """Test server creation and initialization."""
    transport = await transport_factory("unix")
    
    server = RPCPluginServer(
        protocol=mock_protocol,
        handler=mock_handler,
        transport=transport
    )
    
    assert server.protocol == mock_protocol
    assert server.handler == mock_handler
    assert server.transport == transport

@pytest.mark.asyncio
async def test_server_factory_creation(mock_protocol, mock_handler):
    """Test server creation via factory."""
    server = plugin_server(
        protocol=mock_protocol,
        handler=mock_handler,
        transport="unix",
        config={
            "PLUGIN_LOG_LEVEL": "WARNING",
            "PLUGIN_HANDSHAKE_TIMEOUT": "5.0"
        }
    )
    
    assert server.protocol == mock_protocol
    assert server.handler == mock_handler

@pytest.mark.asyncio
async def test_server_configuration_override(mock_protocol, mock_handler):
    """Test server with configuration overrides."""
    server = plugin_server(
        protocol=mock_protocol,
        handler=mock_handler,
        transport="tcp",
        port=0,  # Auto-assign port
        config={
            "PLUGIN_RATE_LIMIT_ENABLED": True,
            "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": 10.0,
            "PLUGIN_HEALTH_SERVICE_ENABLED": True,
        }
    )
    
    # Verify configuration was applied
    # This tests that the config parameter is properly passed
    assert server.config["PLUGIN_RATE_LIMIT_ENABLED"] == True
```

### Server Lifecycle Testing

```python
import asyncio

@pytest.mark.asyncio
async def test_server_startup_shutdown(mock_protocol, mock_handler, transport_factory):
    """Test server startup and shutdown lifecycle."""
    transport = await transport_factory("unix")
    server = RPCPluginServer(
        protocol=mock_protocol,
        handler=mock_handler,
        transport=transport,
        config={"PLUGIN_HANDSHAKE_TIMEOUT": "2.0"}
    )
    
    # Start server in background
    server_task = asyncio.create_task(server.serve())
    
    try:
        # Wait for server to be ready
        await server.wait_for_server_ready(timeout=5.0)
        assert server._running
        
        # Verify transport is listening
        assert transport.endpoint is not None
        
        # Test graceful shutdown
        await server.stop()
        
        # Wait for serve task to complete
        await asyncio.wait_for(server_task, timeout=5.0)
        
    except Exception:
        # Ensure cleanup even if test fails
        server_task.cancel()
        try:
            await asyncio.wait_for(server_task, timeout=1.0)
        except asyncio.TimeoutError:
            pass
        raise

@pytest.mark.asyncio
async def test_server_ready_check(mock_protocol, mock_handler, transport_factory):
    """Test server readiness checking."""
    transport = await transport_factory("unix")
    server = RPCPluginServer(
        protocol=mock_protocol,
        handler=mock_handler,
        transport=transport
    )
    
    # Server should not be ready before starting
    with pytest.raises(Exception):  # TransportError or similar
        await server.wait_for_server_ready(timeout=0.1)
    
    # Start server
    serve_task = asyncio.create_task(server.serve())
    
    try:
        # Server should become ready
        await server.wait_for_server_ready(timeout=5.0)
        
        # Verify readiness
        assert server._running
        assert transport.endpoint is not None
        
    finally:
        await server.stop()
        await asyncio.wait_for(serve_task, timeout=5.0)
```

## Client Testing

### Mock Client Testing

```python
from unittest.mock import AsyncMock, patch
from pyvider.rpcplugin.client import RPCPluginClient
from pyvider.rpcplugin.factories import plugin_client

@pytest.fixture
def mock_client():
    """Create a mock client for testing."""
    client = plugin_client(
        command=["echo", "test"],
        config={"PLUGIN_LOG_LEVEL": "WARNING"}
    )
    
    # Mock the async methods to avoid real process creation
    client.start = AsyncMock()
    client.shutdown_plugin = AsyncMock()
    client.close = AsyncMock()
    client.grpc_channel = AsyncMock()
    
    return client

@pytest.mark.asyncio
async def test_mock_client_lifecycle(mock_client):
    """Test client lifecycle with mocks."""
    # Test start
    await mock_client.start()
    assert mock_client.start.called
    
    # Test usage (would normally use gRPC channel)
    assert mock_client.grpc_channel is not None
    
    # Test shutdown
    await mock_client.shutdown_plugin()
    await mock_client.close()
    
    assert mock_client.shutdown_plugin.called
    assert mock_client.close.called

@pytest.mark.asyncio 
async def test_client_configuration(test_config):
    """Test client with configuration overrides."""
    client = plugin_client(
        command=["python", "-c", "print('test')"],
        config={
            "env": {
                "PLUGIN_LOG_LEVEL": "DEBUG",
                "TEST_VAR": "test_value"
            }
        }
    )
    
    # Verify configuration was set
    assert client.config["env"]["PLUGIN_LOG_LEVEL"] == "DEBUG"
    assert client.config["env"]["TEST_VAR"] == "test_value"
```

### Integration Testing with Real Processes

```python
import subprocess
import tempfile

@pytest.fixture
async def echo_server_process():
    """Create a simple echo server process for testing."""
    # Create a simple Python script that implements basic handshake
    echo_server_script = '''
import sys
import time

# Output handshake (simplified)
sys.stdout.write("1|1|unix|/tmp/echo.sock|\\n")
sys.stdout.flush()

# Keep running
time.sleep(10)
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(echo_server_script)
        script_path = f.name
    
    process = None
    try:
        # Note: This is a simplified example
        # Real integration tests would need proper handshake implementation
        yield script_path
    finally:
        if process:
            process.terminate()
            process.wait()
        os.unlink(script_path)

@pytest.mark.asyncio
async def test_client_server_integration(mock_protocol, mock_handler, echo_server_process):
    """Test client-server integration (simplified)."""
    # This is a complex test that would require:
    # 1. Real server implementation
    # 2. Proper handshake protocol
    # 3. gRPC service setup
    # For now, we test the components separately
    
    # Create server
    server = plugin_server(
        protocol=mock_protocol,
        handler=mock_handler,
        transport="unix"
    )
    
    # Create client (with mock for now)
    client = plugin_client(command=["python", echo_server_process])
    
    # Test would involve:
    # 1. Starting server
    # 2. Starting client
    # 3. Making RPC calls
    # 4. Verifying responses
    # 5. Clean shutdown
    
    assert server is not None
    assert client is not None
```

## Exception Testing

### Exception Hierarchy Testing

```python
import pytest
from pyvider.rpcplugin.exception import *

def test_exception_hierarchy():
    """Test exception inheritance hierarchy."""
    # All specific exceptions should inherit from RPCPluginError
    config_error = ConfigError("test")
    transport_error = TransportError("test")
    handshake_error = HandshakeError("test")
    protocol_error = ProtocolError("test")
    security_error = SecurityError("test")
    
    assert isinstance(config_error, RPCPluginError)
    assert isinstance(transport_error, RPCPluginError)
    assert isinstance(handshake_error, RPCPluginError)
    assert isinstance(protocol_error, RPCPluginError)
    assert isinstance(security_error, RPCPluginError)

def test_exception_attributes():
    """Test exception attribute handling."""
    error = TransportError(
        message="Connection failed",
        hint="Check network connectivity",
        code="TRANSPORT_001"
    )
    
    assert error.message == "Connection failed"
    assert error.hint == "Check network connectivity" 
    assert error.code == "TRANSPORT_001"
    
    # Test string representation
    error_str = str(error)
    assert "TransportError" in error_str
    assert "Connection failed" in error_str
    assert "Check network connectivity" in error_str
    assert "TRANSPORT_001" in error_str

def test_exception_chaining():
    """Test exception chaining with 'from' clause."""
    original_error = OSError("Network unreachable")
    
    try:
        raise TransportError(
            message="Failed to connect",
            hint="Check network settings"
        ) from original_error
    except TransportError as e:
        assert e.__cause__ is original_error
        assert str(original_error) in str(e.__cause__)
```

### Error Simulation Testing

```python
@pytest.mark.asyncio
async def test_transport_error_simulation(transport_factory):
    """Test transport error conditions."""
    
    # Test connection to non-existent Unix socket
    transport = await transport_factory("unix")
    
    with pytest.raises(TransportError) as exc_info:
        await transport.connect("/tmp/nonexistent.sock")
    
    error = exc_info.value
    assert "does not exist" in error.message.lower()

@pytest.mark.asyncio
async def test_port_conflict_simulation(transport_factory):
    """Test TCP port conflict handling."""
    # Create first transport on specific port
    transport1 = await transport_factory("tcp", port=0)
    endpoint = await transport1.listen()
    
    # Extract port from endpoint
    port = int(endpoint.split(":")[1])
    
    # Try to create second transport on same port
    transport2 = await transport_factory("tcp", port=port)
    
    with pytest.raises(TransportError) as exc_info:
        await transport2.listen()
    
    error = exc_info.value
    # Error message should indicate port conflict
    assert "already" in error.message.lower() or "use" in error.message.lower()

def test_config_error_simulation():
    """Test configuration error simulation."""
    
    # Test invalid protocol version
    with pytest.raises(Exception):  # Would be ValidationError or ConfigError
        os.environ["PLUGIN_PROTOCOL_VERSIONS"] = "[0, 8]"  # Invalid range
        # Force config reload if needed
    
    # Clean up
    os.environ.pop("PLUGIN_PROTOCOL_VERSIONS", None)
```

## Performance Testing

### Load Testing

```python
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

@pytest.mark.asyncio
async def test_concurrent_connections(transport_factory):
    """Test multiple concurrent connections."""
    # Create server transport
    server_transport = await transport_factory("unix")
    endpoint = await server_transport.listen()
    
    # Create multiple client connections
    num_clients = 10
    client_tasks = []
    
    for i in range(num_clients):
        client_transport = await transport_factory("unix")
        task = asyncio.create_task(
            client_transport.connect(endpoint)
        )
        client_tasks.append(task)
    
    # Wait for all connections
    start_time = time.time()
    await asyncio.gather(*client_tasks)
    duration = time.time() - start_time
    
    # Verify reasonable performance
    assert duration < 5.0  # All connections within 5 seconds
    print(f"Connected {num_clients} clients in {duration:.2f}s")

@pytest.mark.asyncio
async def test_server_performance(mock_protocol, mock_handler, transport_factory):
    """Test basic server performance metrics."""
    server = plugin_server(
        protocol=mock_protocol,
        handler=mock_handler,
        transport="unix"
    )
    
    # Measure startup time
    start_time = time.time()
    
    server_task = asyncio.create_task(server.serve())
    await server.wait_for_server_ready(timeout=10.0)
    
    startup_time = time.time() - start_time
    
    try:
        # Verify reasonable startup time
        assert startup_time < 2.0  # Should start within 2 seconds
        print(f"Server startup time: {startup_time:.2f}s")
        
        # Test shutdown time
        shutdown_start = time.time()
        await server.stop()
        await asyncio.wait_for(server_task, timeout=5.0)
        shutdown_time = time.time() - shutdown_start
        
        assert shutdown_time < 1.0  # Should shutdown within 1 second
        print(f"Server shutdown time: {shutdown_time:.2f}s")
        
    except Exception:
        await server.stop()
        server_task.cancel()
        raise
```

### Memory Testing

```python
import gc
import psutil
import os

def test_memory_usage():
    """Test memory usage patterns."""
    process = psutil.Process(os.getpid())
    
    # Measure initial memory
    initial_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    # Create and destroy many transports
    transports = []
    for _ in range(100):
        transport = UnixSocketTransport()
        transports.append(transport)
    
    peak_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    # Clean up
    transports.clear()
    gc.collect()
    
    final_memory = process.memory_info().rss / 1024 / 1024  # MB
    
    print(f"Memory usage - Initial: {initial_memory:.1f}MB, "
          f"Peak: {peak_memory:.1f}MB, Final: {final_memory:.1f}MB")
    
    # Memory should return close to initial after cleanup
    memory_growth = final_memory - initial_memory
    assert memory_growth < 10.0  # Less than 10MB growth
```

## Security Testing

### Certificate Testing

```python
from provide.foundation.crypto import Certificate

@pytest.fixture
def test_certificates():
    """Generate test certificates for security testing."""
    # Create CA certificate
    ca_cert = Certificate.create_self_signed_ca(
        common_name="Test CA",
        organization_name="Test Org"
    )
    
    # Create server certificate
    server_cert = Certificate.create_self_signed_server_cert(
        common_name="test-server",
        organization_name="Test Org",
        alt_names=["localhost", "127.0.0.1"]
    )
    
    # Create client certificate
    client_cert = Certificate(generate_keypair=True, key_type="ecdsa")
    
    return {
        "ca": ca_cert,
        "server": server_cert,
        "client": client_cert
    }

def test_certificate_generation(test_certificates):
    """Test certificate generation and validation."""
    certs = test_certificates
    
    # Verify certificates were generated
    assert certs["ca"].cert is not None
    assert certs["ca"].key is not None
    
    assert certs["server"].cert is not None
    assert certs["server"].key is not None
    
    assert certs["client"].cert is not None
    assert certs["client"].key is not None
    
    # Verify certificate format
    assert "-----BEGIN CERTIFICATE-----" in certs["server"].cert
    assert "-----BEGIN PRIVATE KEY-----" in certs["server"].key

@pytest.mark.asyncio
async def test_mtls_configuration(test_certificates, mock_protocol, mock_handler):
    """Test mTLS configuration."""
    certs = test_certificates
    
    server = plugin_server(
        protocol=mock_protocol,
        handler=mock_handler,
        transport="tcp",
        port=0,
        config={
            "PLUGIN_AUTO_MTLS": False,
            "PLUGIN_SERVER_CERT": certs["server"].cert,
            "PLUGIN_SERVER_KEY": certs["server"].key,
            "PLUGIN_CLIENT_ROOT_CERTS": certs["ca"].cert,
        }
    )
    
    # Verify mTLS configuration
    assert server.config["PLUGIN_AUTO_MTLS"] == False
    assert certs["server"].cert in server.config["PLUGIN_SERVER_CERT"]
```

### Authentication Testing

```python
def test_magic_cookie_validation():
    """Test magic cookie authentication."""
    
    # Test with valid cookie
    with patch.dict(os.environ, {
        'PLUGIN_MAGIC_COOKIE_KEY': 'TEST_COOKIE',
        'PLUGIN_MAGIC_COOKIE_VALUE': 'valid-cookie-123',
        'TEST_COOKIE': 'valid-cookie-123'
    }):
        from pyvider.rpcplugin.config import rpcplugin_config
        
        assert rpcplugin_config.plugin_magic_cookie_key == 'TEST_COOKIE'
        assert rpcplugin_config.plugin_magic_cookie_value == 'valid-cookie-123'
    
    # Test with missing cookie
    with patch.dict(os.environ, {
        'PLUGIN_MAGIC_COOKIE_KEY': 'MISSING_COOKIE',
        'PLUGIN_MAGIC_COOKIE_VALUE': 'test-value'
    }, clear=True):
        # This would be tested in actual handshake validation
        # Test implementation depends on handshake logic
        pass
```

## Best Practices

### Test Organization

```python
# ✅ Good: Organize tests by component and functionality
class TestUnixSocketTransport:
    """Test suite for Unix socket transport."""
    
    @pytest.mark.asyncio
    async def test_basic_lifecycle(self, transport_factory):
        """Test basic Unix socket lifecycle."""
        pass
    
    @pytest.mark.asyncio
    async def test_permission_handling(self, transport_factory):
        """Test file permission handling."""
        pass
    
    @pytest.mark.asyncio
    async def test_error_conditions(self, transport_factory):
        """Test error scenarios."""
        pass

class TestTCPSocketTransport:
    """Test suite for TCP socket transport."""
    
    @pytest.mark.asyncio
    async def test_port_assignment(self, transport_factory):
        """Test port assignment logic."""
        pass

# ✅ Good: Use descriptive test names
@pytest.mark.asyncio
async def test_server_starts_successfully_with_unix_transport():
    pass

@pytest.mark.asyncio  
async def test_client_retries_connection_on_handshake_timeout():
    pass

# ❌ Avoid: Generic or unclear test names
def test_server():
    pass

def test_client_stuff():
    pass
```

### Fixture Best Practices

```python
# ✅ Good: Proper fixture cleanup
@pytest.fixture
async def managed_server(mock_protocol, mock_handler):
    """Server fixture with guaranteed cleanup."""
    server = plugin_server(protocol=mock_protocol, handler=mock_handler)
    
    server_task = None
    try:
        server_task = asyncio.create_task(server.serve())
        await server.wait_for_server_ready(timeout=5.0)
        yield server
    finally:
        await server.stop()
        if server_task:
            await asyncio.wait_for(server_task, timeout=5.0)

# ✅ Good: Scoped fixtures
@pytest.fixture(scope="session")
def test_certificates():
    """Generate certificates once per test session."""
    return generate_test_certificates()

@pytest.fixture(scope="function")
def transport_factory():
    """Create fresh transport factory for each test."""
    pass

# ❌ Avoid: Fixtures without cleanup
@pytest.fixture
async def leaky_server():
    server = plugin_server(protocol=protocol, handler=handler)
    await server.serve()  # Never cleaned up
    return server
```

### Assertion Best Practices

```python
# ✅ Good: Specific assertions with helpful messages
def test_transport_endpoint_format():
    transport = TCPSocketTransport(host="127.0.0.1", port=8080)
    endpoint = await transport.listen()
    
    assert endpoint == "127.0.0.1:8080", f"Expected specific endpoint format, got: {endpoint}"
    assert ":" in endpoint, "TCP endpoint should contain port separator"
    
    host, port = endpoint.split(":")
    assert host == "127.0.0.1", f"Unexpected host: {host}"
    assert int(port) == 8080, f"Unexpected port: {port}"

# ✅ Good: Test error conditions explicitly
def test_invalid_config_raises_specific_error():
    with pytest.raises(ConfigError) as exc_info:
        raise ConfigError("Invalid value", hint="Use valid option")
    
    error = exc_info.value
    assert "Invalid value" in error.message
    assert error.hint == "Use valid option"

# ❌ Avoid: Vague assertions
def test_something():
    result = do_something()
    assert result  # What should result be?
    assert len(result) > 0  # Why should it be non-empty?
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=pyvider --cov-report=html

# Run specific test categories
pytest tests/unit/           # Unit tests only
pytest tests/integration/    # Integration tests only
pytest -k "transport"        # Tests matching "transport"

# Run with verbose output
pytest -v

# Run tests in parallel (if pytest-xdist installed)
pytest -n auto

# Run with specific markers
pytest -m "asyncio"          # Only async tests
pytest -m "not slow"         # Skip slow tests
```

### Test Markers

```python
# Define custom markers in pytest.ini or pyproject.toml
# [tool.pytest.ini_options]
# markers = [
#     "slow: marks tests as slow (deselect with '-m \"not slow\"')",
#     "integration: marks tests as integration tests",
#     "unit: marks tests as unit tests"
# ]

@pytest.mark.slow
@pytest.mark.asyncio
async def test_large_scale_connections():
    """Test with many concurrent connections - takes time."""
    pass

@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_client_server_workflow():
    """Full integration test."""
    pass

@pytest.mark.unit
def test_config_validation():
    """Fast unit test."""
    pass
```

## Related Documentation

- [Configuration](../api/config/) - Configuration testing patterns
- [Exception Handling](../api/exceptions/) - Testing error conditions
- [Server API](../api/server/server.md) - Server testing specifics
- [Client API](../api/client/client.md) - Client testing specifics
- [Transport Layer](../api/transport/) - Transport testing details