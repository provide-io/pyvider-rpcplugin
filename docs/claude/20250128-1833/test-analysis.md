# PyVider Test Analysis and Remediation Plan

## 1. Common Failure Patterns

### 1.1 Connection and Handshake Issues
- **Symptom**: Tests failing during initial connection/handshake phase
- **Root Causes**:
  - Race conditions in async setup
  - Improper cleanup of previous test resources
  - Certificate validation issues in mTLS setup
- **Remediation**:
  ```python
  @pytest.fixture(autouse=True)
  async def cleanup_sockets():
      # Before test cleanup
      for sock in glob.glob("/tmp/plugin*.sock"):
          try:
              os.unlink(sock)
          except OSError:
              pass
      
      yield
      
      # After test cleanup
      await asyncio.sleep(0.1)  # Allow time for socket cleanup
  ```

### 1.2 Resource Cleanup Issues
- **Symptom**: Tests failing intermittently due to resource conflicts
- **Root Causes**:
  - Socket files not being cleaned up
  - Zombie processes remaining
  - Port conflicts
- **Remediation**:
  ```python
  @pytest.fixture
  def unused_tcp_port():
      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
          s.bind(('127.0.0.1', 0))
          return s.getsockname()[1]
  ```

### 1.3 Timing-Related Failures
- **Symptom**: Tests failing due to race conditions
- **Root Causes**:
  - Insufficient wait times for async operations
  - Missing await statements
  - Resource cleanup race conditions
- **Remediation**:
  ```python
  async def wait_for_server_ready(endpoint: str, timeout: float = 5.0):
      start = time.time()
      while time.time() - start < timeout:
          try:
              async with aiohttp.ClientSession() as session:
                  async with session.get(f"http://{endpoint}/health") as resp:
                      if resp.status == 200:
                          return True
          except:
              await asyncio.sleep(0.1)
      return False
  ```

## 2. Test Suite Structural Issues

### 2.1 Test Dependencies
- Tests need proper isolation
- Fixture dependencies need review
- Environment variable handling needs improvement

### 2.2 Environment Setup
```python
@pytest.fixture(scope="session")
def test_env():
    # Save original environment
    old_env = {
        key: os.environ.get(key)
        for key in ['PLUGIN_MAGIC_COOKIE_KEY', 'PLUGIN_MAGIC_COOKIE',
                   'PLUGIN_PROTOCOL_VERSIONS', 'PLUGIN_TRANSPORTS']
    }
    
    # Set test environment
    os.environ.update({
        "PLUGIN_MAGIC_COOKIE_KEY": "BASIC_PLUGIN",
        "PLUGIN_MAGIC_COOKIE": "hello",
        "PLUGIN_PROTOCOL_VERSIONS": "6",
        "PLUGIN_TRANSPORTS": "unix,tcp",
    })
    
    yield
    
    # Restore original environment
    for key, value in old_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
```

## 3. Test Categories and Priority Fixes

### 3.1 Transport Tests
- Unix Socket Tests:
  - Need better socket cleanup
  - Add permission testing
  - Test path length limits

- TCP Tests:
  - Add port conflict handling
  - Test connection timeouts
  - Add error path testing

### 3.2 Security Tests
- Certificate Tests:
  - Add chain validation
  - Test expired certificates
  - Test malformed certificates

- mTLS Tests:
  - Test client verification
  - Test server verification
  - Test certificate rotation

### 3.3 Protocol Tests
- Handshake Tests:
  - Test version negotiation
  - Test transport negotiation
  - Test magic cookie validation

## 4. Implementation Plan

### Phase 1: Stabilize Base Tests
1. Fix socket cleanup
2. Add proper async fixtures
3. Implement timeout handling
4. Add environment isolation

### Phase 2: Add Missing Tests
1. Add security test suite
2. Add protocol test suite
3. Add integration tests
4. Add performance tests

### Phase 3: Improve Test Infrastructure
1. Add test parallelization
2. Add test categorization
3. Add test reporting
4. Add test monitoring

## 5. Test Fixtures Needed

### 5.1 Basic Fixtures
```python
@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="function")
async def client():
    client = RPCPluginClient(...)
    await client.start()
    yield client
    await client.stop()

@pytest.fixture(scope="function")
async def server():
    server = RPCPluginServer(...)
    yield server
    await server.stop()
```

### 5.2 Security Fixtures
```python
@pytest.fixture(scope="session")
def client_cert():
    # Generate test certificate
    key, cert = generate_test_certificate()
    return cert

@pytest.fixture(scope="session")
def server_cert():
    # Generate test certificate
    key, cert = generate_test_certificate()
    return cert
```

## 6. Common Test Patterns

### 6.1 Connection Tests
```python
@pytest.mark.asyncio
async def test_client_server_connection(client, server):
    # Start server
    await server.start()
    
    # Connect client
    await client.connect()
    
    # Verify connection
    assert client.is_connected()
    
    # Cleanup
    await client.disconnect()
    await server.stop()
```

### 6.2 Error Tests
```python
@pytest.mark.asyncio
async def test_connection_timeout(client):
    with pytest.raises(TimeoutError):
        await client.connect(timeout=0.1)
```

## 7. Next Steps

1. Implement base fixtures
2. Fix cleanup issues
3. Add missing tests
4. Improve error handling
5. Add documentation

