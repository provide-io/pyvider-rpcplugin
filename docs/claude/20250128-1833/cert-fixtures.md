# Certificate Fixtures Test Guide

## Available Certificate Sets

### ECDSA Certificates

1. **SECP256R1**
```python
SECP256R1_CERTS = {
    'client': {
        'cert': 'certs/ec-secp256r1-mtls-client.crt',
        'key': 'certs/ec-secp256r1-mtls-client.key'
    },
    'server': {
        'cert': 'certs/ec-secp256r1-mtls-server.crt',
        'key': 'certs/ec-secp256r1-mtls-server.key'
    }
}
```

2. **SECP384R1** (Recommended for Python gRPC Server)
```python
SECP384R1_CERTS = {
    'client': {
        'cert': 'certs/ec-secp384r1-mtls-client.crt',
        'key': 'certs/ec-secp384r1-mtls-client.key'
    },
    'server': {
        'cert': 'certs/ec-secp384r1-mtls-server.crt',
        'key': 'certs/ec-secp384r1-mtls-server.key'
    }
}
```

3. **SECP521R1** (Required for go-plugin Client)
```python
SECP521R1_CERTS = {
    'client': {
        'cert': 'certs/ec-secp521r1-mtls-client.crt',
        'key': 'certs/ec-secp521r1-mtls-client.key'
    },
    'server': {
        'cert': 'certs/ec-secp521r1-mtls-server.crt',
        'key': 'certs/ec-secp521r1-mtls-server.key'
    }
}
```

### RSA Certificates

1. **RSA-2048**
```python
RSA2048_CERTS = {
    'client': {
        'cert': 'certs/rsa-2048-mtls-client.crt',
        'key': 'certs/rsa-2048-mtls-client.key'
    },
    'server': {
        'cert': 'certs/rsa-2048-mtls-server.crt',
        'key': 'certs/rsa-2048-mtls-server.key'
    }
}
```

2. **RSA-4096**
```python
RSA4096_CERTS = {
    'client': {
        'cert': 'certs/rsa-4096-mtls-client.crt',
        'key': 'certs/rsa-4096-mtls-client.key'
    },
    'server': {
        'cert': 'certs/rsa-4096-mtls-server.crt',
        'key': 'certs/rsa-4096-mtls-server.key'
    }
}
```

## Test Fixture Implementation

```python
@pytest.fixture(scope="session")
def cert_paths():
    """Returns paths to all certificate sets"""
    base_path = Path(__file__).parent / "certs"
    return {
        'secp256r1': SECP256R1_CERTS,
        'secp384r1': SECP384R1_CERTS,
        'secp521r1': SECP521R1_CERTS,
        'rsa2048': RSA2048_CERTS,
        'rsa4096': RSA4096_CERTS
    }

@pytest.fixture(scope="session")
def load_cert_pair():
    """Helper to load certificate and key pairs"""
    def _load(cert_file: str, key_file: str) -> tuple[str, str]:
        with open(cert_file, 'r') as f:
            cert_pem = f.read()
        with open(key_file, 'r') as f:
            key_pem = f.read()
        return cert_pem, key_pem
    return _load
```

## Usage in Tests

### 1. Testing Python gRPC Server
```python
@pytest.mark.asyncio
async def test_grpc_server(cert_paths, load_cert_pair):
    # Use SECP384R1 for server
    server_cert, server_key = load_cert_pair(
        cert_paths['secp384r1']['server']['cert'],
        cert_paths['secp384r1']['server']['key']
    )
    
    # Configure server with these certificates
    server = RPCPluginServer(
        protocol=protocol,
        config={
            'server_cert_pem': server_cert,
            'server_key_pem': server_key
        }
    )
```

### 2. Testing go-plugin Client Compatibility
```python
@pytest.mark.asyncio
async def test_goplugin_client(cert_paths, load_cert_pair):
    # Use SECP521R1 for client to match go-plugin
    client_cert, client_key = load_cert_pair(
        cert_paths['secp521r1']['client']['cert'],
        cert_paths['secp521r1']['client']['key']
    )
    
    # Configure client with these certificates
    client = RPCPluginClient(
        command=['mock_server'],
        config={
            'client_cert_pem': client_cert,
            'client_key_pem': client_key
        }
    )
```

### 3. Testing Non-AutoMTLS Scenarios
```python
@pytest.mark.asyncio
async def test_manual_mtls(cert_paths, load_cert_pair):
    # Can use any certificate type when not using AutoMTLS
    server_cert, server_key = load_cert_pair(
        cert_paths['rsa2048']['server']['cert'],
        cert_paths['rsa2048']['server']['key']
    )
    client_cert, client_key = load_cert_pair(
        cert_paths['rsa2048']['client']['cert'],
        cert_paths['rsa2048']['client']['key']
    )
    
    # Test implementation
```

## Important Notes

1. Use SECP384R1 for Python gRPC servers
2. Use SECP521R1 for go-plugin client compatibility
3. RSA certificates can be used for non-AutoMTLS testing
4. Certificate fixtures should be used instead of generating new ones in most tests

## Test Categories

1. **AutoMTLS Tests**
   - Client must use SECP521R1
   - Server must use SECP384R1

2. **Manual mTLS Tests**
   - Can use any certificate type
   - Good for testing different algorithms

3. **Error Case Tests**
   - Use mixed certificate types
   - Test incompatible curves
   - Test invalid certificates

## Implementation Tips

1. Use the `load_cert_pair` fixture for consistent loading
2. Set appropriate certificate paths in environment variables
3. Test both AutoMTLS and manual mTLS scenarios
4. Verify certificate types in tests
