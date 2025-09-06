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

### Transport Factory and Core Tests

```python
import pytest
import uuid
from pathlib import Path
from pyvider.rpcplugin.transport import UnixSocketTransport, TCPSocketTransport

@pytest.fixture
async def transport_factory(tmp_path: Path):
    """Factory for creating isolated transport instances with cleanup."""
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

    # Cleanup
    for transport in created_transports:
        try:
            await transport.close()
        except Exception:
            pass

@pytest.fixture
def unused_tcp_port():
    """Find unused TCP port."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

# Unix Socket Tests
@pytest.mark.asyncio
async def test_unix_socket_lifecycle(transport_factory):
    """Test Unix socket creation, connection, and cleanup."""
    transport = await transport_factory("unix")
    endpoint = await transport.listen()
    assert endpoint.endswith(".sock")
    
    # Test connection
    client = await transport_factory("unix")
    await client.connect(endpoint)
    assert client.endpoint == endpoint

@pytest.mark.asyncio
async def test_unix_socket_permissions(transport_factory):
    """Test Unix socket file permissions."""
    transport = await transport_factory("unix")
    await transport.listen()
    
    import os, stat
    stat_result = os.stat(transport.endpoint)
    mode = stat_result.st_mode
    assert stat.S_ISSOCK(mode)
    assert mode & stat.S_IRUSR and mode & stat.S_IWUSR  # Owner RW

# TCP Transport Tests
@pytest.mark.asyncio
async def test_tcp_transport_lifecycle(transport_factory, unused_tcp_port):
    """Test TCP transport creation and connection."""
    transport = await transport_factory("tcp", port=unused_tcp_port)
    endpoint = await transport.listen()
    assert endpoint == f"127.0.0.1:{unused_tcp_port}"
    
    client = await transport_factory("tcp")
    await client.connect(endpoint)
    assert client.endpoint == endpoint

@pytest.mark.asyncio
async def test_tcp_auto_port_assignment(transport_factory):
    """Test automatic port assignment."""
    transport = await transport_factory("tcp", port=0)
    endpoint = await transport.listen()
    
    host, port_str = endpoint.split(":")
    assert host == "127.0.0.1"
    assert int(port_str) > 0
```

## Server Testing

### Mock Components and Server Lifecycle

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

@pytest.fixture
def mock_protocol():
    return MockProtocol(service_name="TestService")

@pytest.fixture
def mock_handler():
    return MockHandler()

# Server Tests
from pyvider.rpcplugin.server import RPCPluginServer
from pyvider.rpcplugin.factories import plugin_server

@pytest.mark.asyncio
async def test_server_creation_and_config(mock_protocol, mock_handler, transport_factory):
    """Test server creation and configuration."""
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
async def test_server_factory_with_config(mock_protocol, mock_handler):
    """Test server creation via factory with config overrides."""
    server = plugin_server(
        protocol=mock_protocol,
        handler=mock_handler,
        transport="tcp",
        port=0,  # Auto-assign port
        config={
            "PLUGIN_LOG_LEVEL": "WARNING",
            "PLUGIN_HANDSHAKE_TIMEOUT": "5.0",
            "PLUGIN_RATE_LIMIT_ENABLED": True,
        }
    )
    
    assert server.protocol == mock_protocol
    assert server.config["PLUGIN_RATE_LIMIT_ENABLED"] == True

@pytest.mark.asyncio
async def test_server_lifecycle(mock_protocol, mock_handler, transport_factory):
    """Test server startup, readiness, and shutdown."""
    import asyncio
    
    transport = await transport_factory("unix")
    server = RPCPluginServer(mock_protocol, mock_handler, transport)
    
    # Start server
    server_task = asyncio.create_task(server.serve())
    
    try:
        await server.wait_for_server_ready(timeout=5.0)
        assert server._running
        assert transport.endpoint is not None
        
        # Test graceful shutdown
        await server.stop()
        await asyncio.wait_for(server_task, timeout=5.0)
        
    except Exception:
        server_task.cancel()
        try:
            await asyncio.wait_for(server_task, timeout=1.0)
        except asyncio.TimeoutError:
            pass
        raise
```

## Client Testing

### Mock Client and Integration Testing

```python
from unittest.mock import AsyncMock
from pyvider.rpcplugin.factories import plugin_client

@pytest.fixture
def mock_client():
    """Create mock client for testing."""
    client = plugin_client(
        command=["echo", "test"],
        config={"PLUGIN_LOG_LEVEL": "WARNING"}
    )
    
    # Mock async methods to avoid real process creation
    client.start = AsyncMock()
    client.shutdown_plugin = AsyncMock()
    client.close = AsyncMock()
    client.grpc_channel = AsyncMock()
    
    return client

@pytest.mark.asyncio
async def test_mock_client_lifecycle(mock_client):
    """Test client lifecycle with mocks."""
    await mock_client.start()
    assert mock_client.start.called
    assert mock_client.grpc_channel is not None
    
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
    
    assert client.config["env"]["PLUGIN_LOG_LEVEL"] == "DEBUG"
    assert client.config["env"]["TEST_VAR"] == "test_value"

@pytest.mark.asyncio
async def test_client_server_integration_pattern(mock_protocol, mock_handler):
    """Integration test pattern (components tested separately)."""
    # For full integration tests:
    # 1. Start real server with proper handshake
    # 2. Start client subprocess
    # 3. Perform gRPC calls
    # 4. Verify responses and clean shutdown
    
    server = plugin_server(
        protocol=mock_protocol,
        handler=mock_handler,
        transport="unix"
    )
    
    client = plugin_client(command=["echo", "mock_plugin"])
    
    assert server is not None
    assert client is not None
    # Complex integration tests require proper handshake implementation
```

## Exception Testing

### Exception Hierarchy and Error Simulation

```python
import pytest
from pyvider.rpcplugin.exception import *

def test_exception_hierarchy_and_attributes():
    """Test exception inheritance and attribute handling."""
    # Test hierarchy - all inherit from RPCPluginError
    config_error = ConfigError("test")
    transport_error = TransportError("Connection failed", 
                                   hint="Check network", 
                                   code="TRANSPORT_001")
    handshake_error = HandshakeError("test")
    protocol_error = ProtocolError("test")
    security_error = SecurityError("test")
    
    for error in [config_error, transport_error, handshake_error, 
                  protocol_error, security_error]:
        assert isinstance(error, RPCPluginError)
    
    # Test attributes
    assert transport_error.message == "Connection failed"
    assert transport_error.hint == "Check network"
    assert transport_error.code == "TRANSPORT_001"
    
    # Test string representation contains key information
    error_str = str(transport_error)
    assert "TransportError" in error_str
    assert "Connection failed" in error_str

def test_exception_chaining():
    """Test exception chaining with 'from' clause."""
    original_error = OSError("Network unreachable")
    
    try:
        raise TransportError("Failed to connect") from original_error
    except TransportError as e:
        assert e.__cause__ is original_error

@pytest.mark.asyncio
async def test_transport_error_conditions(transport_factory):
    """Test transport error simulation."""
    # Test connection to non-existent socket
    transport = await transport_factory("unix")
    
    with pytest.raises(TransportError) as exc_info:
        await transport.connect("/tmp/nonexistent.sock")
    
    assert "does not exist" in exc_info.value.message.lower()

@pytest.mark.asyncio
async def test_port_conflict_error(transport_factory):
    """Test TCP port conflict handling."""
    transport1 = await transport_factory("tcp", port=0)
    endpoint = await transport1.listen()
    port = int(endpoint.split(":")[1])
    
    transport2 = await transport_factory("tcp", port=port)
    
    with pytest.raises(TransportError):
        await transport2.listen()
```

## Performance Testing

### Load and Memory Testing

```python
import asyncio
import time
import gc
import os

@pytest.mark.asyncio
async def test_concurrent_connections(transport_factory):
    """Test multiple concurrent connections."""
    server_transport = await transport_factory("unix")
    endpoint = await server_transport.listen()
    
    # Create multiple client connections
    num_clients = 10
    client_tasks = []
    
    for i in range(num_clients):
        client_transport = await transport_factory("unix")
        task = asyncio.create_task(client_transport.connect(endpoint))
        client_tasks.append(task)
    
    start_time = time.time()
    await asyncio.gather(*client_tasks)
    duration = time.time() - start_time
    
    assert duration < 5.0  # All connections within 5 seconds
    print(f"Connected {num_clients} clients in {duration:.2f}s")

@pytest.mark.asyncio
async def test_server_startup_performance(mock_protocol, mock_handler, transport_factory):
    """Test server performance metrics."""
    server = plugin_server(protocol=mock_protocol, handler=mock_handler, transport="unix")
    
    start_time = time.time()
    server_task = asyncio.create_task(server.serve())
    await server.wait_for_server_ready(timeout=10.0)
    startup_time = time.time() - start_time
    
    try:
        assert startup_time < 2.0  # Start within 2 seconds
        
        # Test shutdown time
        shutdown_start = time.time()
        await server.stop()
        await asyncio.wait_for(server_task, timeout=5.0)
        shutdown_time = time.time() - shutdown_start
        
        assert shutdown_time < 1.0  # Shutdown within 1 second
        
    except Exception:
        await server.stop()
        server_task.cancel()
        raise

def test_memory_usage_pattern():
    """Test memory usage with resource cleanup."""
    try:
        import psutil
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
    except ImportError:
        pytest.skip("psutil not available for memory testing")
    
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
    
    memory_growth = final_memory - initial_memory
    assert memory_growth < 10.0  # Less than 10MB growth
```

## Security Testing

### Certificate and Authentication Testing

```python
from provide.foundation.crypto import Certificate
from unittest.mock import patch

@pytest.fixture
def test_certificates():
    """Generate test certificates for security testing."""
    ca_cert = Certificate.create_self_signed_ca(
        common_name="Test CA",
        organization_name="Test Org"
    )
    
    server_cert = Certificate.create_self_signed_server_cert(
        common_name="test-server",
        organization_name="Test Org",
        alt_names=["localhost", "127.0.0.1"]
    )
    
    client_cert = Certificate(generate_keypair=True, key_type="ecdsa")
    
    return {
        "ca": ca_cert,
        "server": server_cert,
        "client": client_cert
    }

def test_certificate_generation(test_certificates):
    """Test certificate generation and validation."""
    certs = test_certificates
    
    # Verify all certificates generated
    for cert_type in ["ca", "server", "client"]:
        assert certs[cert_type].cert is not None
        assert certs[cert_type].key is not None
    
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
    
    assert server.config["PLUGIN_AUTO_MTLS"] == False
    assert certs["server"].cert in server.config["PLUGIN_SERVER_CERT"]

def test_magic_cookie_validation():
    """Test magic cookie authentication."""
    with patch.dict(os.environ, {
        'PLUGIN_MAGIC_COOKIE_KEY': 'TEST_COOKIE',
        'PLUGIN_MAGIC_COOKIE_VALUE': 'valid-cookie-123',
        'TEST_COOKIE': 'valid-cookie-123'
    }):
        from pyvider.rpcplugin.config import rpcplugin_config
        
        assert rpcplugin_config.plugin_magic_cookie_key == 'TEST_COOKIE'
        assert rpcplugin_config.plugin_magic_cookie_value == 'valid-cookie-123'
```

## Best Practices

### Test Organization and Patterns

```python
# ✅ Good: Organize tests by component with descriptive names
class TestUnixSocketTransport:
    """Test suite for Unix socket transport."""
    
    @pytest.mark.asyncio
    async def test_basic_lifecycle(self, transport_factory):
        """Test Unix socket creation and cleanup."""
        pass
    
    @pytest.mark.asyncio
    async def test_permission_handling(self, transport_factory):
        """Test file permission validation."""
        pass

# ✅ Good: Descriptive test names
@pytest.mark.asyncio
async def test_server_starts_successfully_with_unix_transport():
    pass

# ❌ Avoid: Generic test names
def test_server():
    pass
```

### Fixture and Assertion Patterns

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

# ✅ Good: Specific assertions with context
def test_endpoint_format():
    transport = TCPSocketTransport(host="127.0.0.1", port=8080)
    endpoint = await transport.listen()
    
    assert endpoint == "127.0.0.1:8080", f"Expected format, got: {endpoint}"
    host, port = endpoint.split(":")
    assert host == "127.0.0.1" and int(port) == 8080

# ✅ Good: Test error conditions explicitly
def test_config_error_handling():
    with pytest.raises(ConfigError) as exc_info:
        raise ConfigError("Invalid value", hint="Use valid option")
    
    error = exc_info.value
    assert "Invalid value" in error.message
    assert error.hint == "Use valid option"
```

### Running Tests and Markers

```bash
# Basic test execution
pytest                       # Run all tests
pytest --cov=pyvider        # With coverage
pytest -v                   # Verbose output
pytest -k "transport"       # Filter by name
pytest -m "not slow"        # Skip slow tests

# Parallel execution (with pytest-xdist)
pytest -n auto
```

```python
# Test markers (define in pyproject.toml)
@pytest.mark.slow
@pytest.mark.asyncio
async def test_large_scale_connections():
    """Test with many concurrent connections."""
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