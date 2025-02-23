# PyVider Test Diagnostic Report and Action Plan

## Key Error Patterns

### 1. Handshake Error Pattern
```
HandshakeError: Failed to read handshake response. Server stderr: {error}
```
Root cause: Mock process not properly simulating handshake protocol

### 2. Transport Error Pattern
```
TransportError: Unsupported transport: {transport_type}
```
Root cause: Transport validation not handling all cases

### 3. Magic Cookie Error Pattern
```
Failed: DID NOT RAISE <class 'pyvider.rpcplugin.exception.HandshakeError'>
```
Root cause: Environment variable validation not working correctly

## Critical Test Dependencies

### 1. Environment Variables Required
```python
REQUIRED_ENV = {
    'PLUGIN_MAGIC_COOKIE_KEY': 'BASIC_PLUGIN',
    'PLUGIN_MAGIC_COOKIE': 'hello',
    'PLUGIN_PROTOCOL_VERSIONS': '6',
    'PLUGIN_TRANSPORTS': 'unix,tcp',
    'PLUGIN_AUTO_MTLS': 'true',
}
```

### 2. Socket Paths
```python
SOCKET_PATTERNS = [
    '/tmp/pyvider*.sock',
    '/tmp/plugin*.sock',
    '/var/folders/*/pyvider*.sock'
]
```

### 3. Mock Response Format
```python
VALID_HANDSHAKE_RESPONSE = {
    'basic': '1|6|tcp|127.0.0.1:12345|grpc|',
    'with_tls': '1|6|tcp|127.0.0.1:12345|grpc|{cert}',
    'unix': '1|6|unix|/tmp/plugin.sock|grpc|'
}
```

## Test Categories and Requirements

### 1. Security Tests
Required test vectors:
```python
TEST_VECTORS = {
    'valid_cert': {
        'common_name': 'localhost',
        'org': 'HashiCorp',
        'valid_days': 30,
        'key_type': 'ec',
        'curve': 'secp384r1'
    },
    'expired_cert': {
        'common_name': 'localhost',
        'org': 'HashiCorp',
        'valid_days': -1,
        'key_type': 'ec',
        'curve': 'secp384r1'
    }
}
```

### 2. Protocol Tests
Required protocol versions:
```python
PROTOCOL_VERSIONS = {
    'supported': [1, 2, 3, 4, 5, 6, 7],
    'unsupported': [0, 8, 9, 99],
    'current': 6
}
```

### 3. Transport Tests
Required transport tests:
```python
TRANSPORT_TESTS = {
    'tcp': {
        'valid_ports': [1024, 65535],
        'invalid_ports': [0, 1023, 65536],
        'timeout': 5.0
    },
    'unix': {
        'max_path_length': 104,
        'invalid_paths': ['/nonexistent', '/root/forbidden'],
        'timeout': 5.0
    }
}
```

## Test Fixtures Structure

### 1. Base Fixtures
Directory structure:
```
tests/
  ├── conftest.py          # Shared fixtures
  ├── fixtures/
  │   ├── security.py      # Security fixtures
  │   ├── transport.py     # Transport fixtures
  │   └── protocol.py      # Protocol fixtures
  └── utils/
      ├── cert_utils.py    # Certificate utilities
      └── mock_utils.py    # Mocking utilities
```

### 2. Mock Structure
```python
class MockServer:
    """Mock server structure required for tests"""
    def __init__(self):
        self.handshake_response = None
        self.certificate = None
        self.protocol_version = 6
        self.transport = 'tcp'

    async def start(self):
        pass

    async def stop(self):
        pass
```

## Error Context Requirements

### 1. Handshake Errors
Need to capture:
```python
ERROR_CONTEXT = {
    'handshake_state': str,
    'protocol_version': int,
    'transport_type': str,
    'server_stderr': str,
    'environment': dict
}
```

### 2. Transport Errors
Need to capture:
```python
TRANSPORT_ERROR_CONTEXT = {
    'endpoint': str,
    'timeout': float,
    'connection_state': str,
    'last_error': Exception
}
```

## Test Execution Environment

### 1. Required System State
```python
SYSTEM_REQUIREMENTS = {
    'temp_dir_writable': True,
    'tcp_ports_available': True,
    'certificate_generation': True,
    'async_support': True
}
```

### 2. Test Isolation Requirements
```python
ISOLATION_REQUIREMENTS = {
    'env_isolation': True,
    'file_system_isolation': True,
    'network_isolation': False,  # Needs local network
    'process_isolation': True
}
```

## Common Test Patterns

### 1. Connection Test Pattern
```python
async def test_connection_pattern(client, server):
    # 1. Setup environment
    # 2. Start server
    # 3. Initialize client
    # 4. Perform handshake
    # 5. Verify connection
    # 6. Cleanup resources
```

### 2. Error Test Pattern
```python
async def test_error_pattern():
    # 1. Setup invalid state
    # 2. Attempt operation
    # 3. Verify error
    # 4. Verify cleanup
```

## Additional Context Notes

1. Test timing is critical:
   - Handshake timeout: 5 seconds
   - Connection timeout: 3 seconds
   - Cleanup timeout: 1 second

2. Error propagation chain:
   ```
   HandshakeError
     ├─ TransportError
     ├─ ProtocolError
     └─ SecurityError
   ```

3. Resource cleanup order:
   1. Close connections
   2. Stop servers
   3. Remove socket files
   4. Clean environment
   5. Release ports

4. Test categorization tags:
   ```python
   @pytest.mark.handshake
   @pytest.mark.transport
   @pytest.mark.security
   @pytest.mark.slow
   @pytest.mark.integration
   ```

## Version Information
```
Python: 3.13.1
pytest: latest
grpc: latest
cryptography: latest
```

## Implementation Tips

1. Mock Process Properly:
```python
@pytest.fixture
def mock_process():
    process = AsyncMock()
    process.stdout.readline = AsyncMock(return_value="1|6|tcp|127.0.0.1:12345|grpc|")
    process.stderr = MagicMock()
    process.stderr.read = MagicMock(return_value="")
    return process
```

2. Handle Environment:
```python
@pytest.fixture(autouse=True)
async def env_setup():
    original_env = dict(os.environ)
    os.environ.update(REQUIRED_ENV)
    yield
    os.environ.clear()
    os.environ.update(original_env)
```

3. Clean Sockets:
```python
@pytest.fixture(autouse=True)
async def clean_sockets():
    for pattern in SOCKET_PATTERNS:
        for sock in glob.glob(pattern):
            try:
                os.unlink(sock)
            except OSError:
                pass
    yield
```

4. Certificate Handling:
```python
@pytest.fixture
def test_certs(tmp_path):
    key, cert = generate_test_certificate(TEST_VECTORS['valid_cert'])
    cert_path = tmp_path / "test.crt"
    key_path = tmp_path / "test.key"
    # Save and return paths
    return cert_path, key_path
```
