# Custom Protocols

Build domain-specific communication protocols for specialized plugin requirements when standard gRPC isn't optimal for your use case.

## When to Use Custom Protocols

Consider custom protocols for:
- **Ultra-low latency**: Financial trading, real-time gaming, IoT sensor data
- **Specialized formats**: Binary protocols, legacy system integration 
- **Domain optimization**: Custom compression, message framing, or serialization
- **Cross-language needs**: Protocols that work beyond gRPC ecosystems

## Protocol Architecture

### Protocol Interface

All custom protocols implement the base `RPCPluginProtocol`:

```python
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from provide.foundation import logger

class CustomProtocol(RPCPluginProtocol):
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version
        logger.info(f"🔧 Initializing {name} protocol v{version}")
    
    async def get_grpc_descriptors(self):
        """Return gRPC service descriptors for this protocol."""
        return self.service_descriptor, self.service_name
    
    async def add_to_server(self, server, handler):
        """Register protocol services with gRPC server."""
        self.service_implementation.add_to_server(server, handler)
```

### Protocol Registration

```python
from pyvider.rpcplugin import plugin_server

# Create custom protocol instance
my_protocol = CustomProtocol(
    name="trading-data",
    version="2.1.0"
)

# Register with server
server = plugin_server(
    protocol=my_protocol,
    handler=MyProtocolHandler()
)
```

## Common Custom Protocol Patterns

### 1. Binary Data Protocol

For high-performance binary data exchange:

```python
import struct
from dataclasses import dataclass

@dataclass
class BinaryMessage:
    message_type: int
    payload_size: int
    data: bytes
    
    def serialize(self) -> bytes:
        """Convert to binary format."""
        header = struct.pack('<BI', self.message_type, self.payload_size)
        return header + self.data
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'BinaryMessage':
        """Parse from binary format."""
        message_type, payload_size = struct.unpack('<BI', data[:5])
        payload = data[5:5+payload_size]
        return cls(message_type, payload_size, payload)

class BinaryProtocol(RPCPluginProtocol):
    async def process_binary_stream(self, stream):
        """Handle binary message stream."""
        async for raw_data in stream:
            message = BinaryMessage.deserialize(raw_data)
            yield await self.handle_message(message)
```

### 2. Streaming Data Protocol

For continuous data feeds:

```python
class StreamingProtocol(RPCPluginProtocol):
    async def start_data_stream(self, request, context):
        """Provide continuous data stream."""
        while context.is_active():
            # Generate or fetch data
            data = await self.get_next_data_batch()
            
            # Send to client
            yield StreamingResponse(
                timestamp=time.time_ns(),
                data=data,
                sequence=self.next_sequence()
            )
            
            await asyncio.sleep(0.001)  # 1ms intervals
```

### 3. Legacy System Integration

For connecting to existing systems:

```python
class LegacyProtocol(RPCPluginProtocol):
    def __init__(self, legacy_format: str):
        self.format = legacy_format
        super().__init__("legacy-bridge", "1.0")
    
    async def translate_request(self, grpc_request):
        """Convert gRPC request to legacy format."""
        if self.format == "xml":
            return self.to_xml(grpc_request)
        elif self.format == "fixed-width":
            return self.to_fixed_width(grpc_request)
    
    async def translate_response(self, legacy_response):
        """Convert legacy response to gRPC format."""
        return self.parse_legacy_response(legacy_response)
```

## Protocol Buffer Integration

### Custom Message Types

Define specialized message formats:

```protobuf
// trading_protocol.proto
syntax = "proto3";

package trading;

message MarketDataRequest {
  repeated string symbols = 1;
  int64 start_time = 2;
  int64 end_time = 3;
  DataFormat format = 4;
}

message MarketDataResponse {
  string symbol = 1;
  double price = 2;
  int64 volume = 3;
  int64 timestamp = 4;
  bytes custom_data = 5;  // Binary-encoded custom fields
}

enum DataFormat {
  STANDARD = 0;
  COMPRESSED = 1;
  BINARY = 2;
}
```

### Protocol Implementation

```python
import trading_pb2_grpc as trading_grpc
from trading_pb2 import MarketDataRequest, MarketDataResponse

class TradingProtocol(RPCPluginProtocol):
    async def get_grpc_descriptors(self):
        return (
            trading_grpc.DESCRIPTOR.services_by_name['MarketDataService'],
            "MarketDataService"
        )
    
    async def add_to_server(self, server, handler):
        trading_grpc.add_MarketDataServiceServicer_to_server(
            handler, server
        )
```

## Advanced Features

### Message Compression

```python
import zstandard as zstd

class CompressedProtocol(RPCPluginProtocol):
    def __init__(self):
        self.compressor = zstd.ZstdCompressor(level=3)
        self.decompressor = zstd.ZstdDecompressor()
        super().__init__("compressed", "1.0")
    
    def compress_message(self, data: bytes) -> bytes:
        return self.compressor.compress(data)
    
    def decompress_message(self, data: bytes) -> bytes:
        return self.decompressor.decompress(data)
```

### Custom Authentication

```python
class AuthenticatedProtocol(RPCPluginProtocol):
    def __init__(self, auth_provider):
        self.auth = auth_provider
        super().__init__("authenticated", "1.0")
    
    async def validate_request(self, context):
        """Validate incoming request authentication."""
        token = context.invocation_metadata().get('auth-token')
        if not await self.auth.validate_token(token):
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid token")
```

### Protocol Versioning

```python
class VersionedProtocol(RPCPluginProtocol):
    def __init__(self):
        self.supported_versions = ["1.0", "1.1", "2.0"]
        super().__init__("versioned", "2.0")
    
    async def negotiate_version(self, client_version: str) -> str:
        """Negotiate protocol version with client."""
        if client_version in self.supported_versions:
            return client_version
        
        # Find best compatible version
        compatible = self.find_compatible_version(client_version)
        logger.info(f"Negotiated version {compatible} for client {client_version}")
        return compatible
```

## Testing Custom Protocols

### Protocol Testing

```python
import pytest
from pyvider.rpcplugin.testing import ProtocolTestCase

class TestCustomProtocol(ProtocolTestCase):
    def setup_protocol(self):
        return CustomProtocol("test", "1.0")
    
    async def test_message_serialization(self):
        message = BinaryMessage(1, 100, b"test data")
        serialized = message.serialize()
        deserialized = BinaryMessage.deserialize(serialized)
        
        assert deserialized.message_type == 1
        assert deserialized.data == b"test data"
    
    async def test_protocol_integration(self):
        async with self.create_test_client() as client:
            response = await client.test_method(test_data="example")
            assert response.success
```

### Performance Testing

```python
import time
import asyncio

async def benchmark_protocol():
    """Benchmark custom protocol performance."""
    protocol = CustomProtocol("benchmark", "1.0")
    
    start_time = time.perf_counter()
    
    # Send 1000 messages
    for i in range(1000):
        await protocol.send_message(f"Message {i}")
    
    duration = time.perf_counter() - start_time
    messages_per_second = 1000 / duration
    
    logger.info(f"Protocol throughput: {messages_per_second:.0f} msg/sec")
```

## Deployment Considerations

### Protocol Discovery

```python
class ProtocolRegistry:
    def __init__(self):
        self.protocols = {}
    
    def register(self, protocol: RPCPluginProtocol):
        self.protocols[protocol.name] = protocol
        logger.info(f"Registered protocol: {protocol.name}")
    
    def get_protocol(self, name: str) -> RPCPluginProtocol:
        return self.protocols.get(name)

# Global registry
protocol_registry = ProtocolRegistry()
```

### Configuration

```python
# Environment-based protocol selection
import os
from pyvider.rpcplugin.config import rpcplugin_config

def create_protocol():
    protocol_type = os.getenv("PLUGIN_PROTOCOL_TYPE", "grpc")
    
    if protocol_type == "binary":
        return BinaryProtocol()
    elif protocol_type == "streaming":
        return StreamingProtocol()
    else:
        return plugin_protocol()  # Default gRPC
```

### Monitoring

```python
from provide.foundation import logger

class MonitoredProtocol(RPCPluginProtocol):
    def __init__(self, base_protocol):
        self.base = base_protocol
        self.message_count = 0
        self.error_count = 0
        super().__init__(f"monitored-{base_protocol.name}", base_protocol.version)
    
    async def send_message(self, message):
        try:
            result = await self.base.send_message(message)
            self.message_count += 1
            return result
        except Exception as e:
            self.error_count += 1
            logger.error(f"Protocol error: {e}")
            raise
```

## Best Practices

1. **Start Simple**: Begin with standard gRPC and only customize when needed
2. **Version Management**: Plan for protocol evolution and backwards compatibility
3. **Error Handling**: Implement robust error recovery and logging
4. **Performance Testing**: Benchmark custom protocols against gRPC baseline
5. **Documentation**: Document protocol specifications and wire formats
6. **Security**: Consider authentication, authorization, and data validation
7. **Monitoring**: Add metrics and observability to custom protocols

## Common Patterns

### Protocol Factory

```python
def create_protocol(protocol_type: str, config: dict) -> RPCPluginProtocol:
    """Factory function for protocol creation."""
    if protocol_type == "trading":
        return TradingProtocol(**config)
    elif protocol_type == "streaming":
        return StreamingProtocol(**config)
    elif protocol_type == "binary":
        return BinaryProtocol(**config)
    else:
        return plugin_protocol()  # Default
```

### Protocol Middleware

```python
class ProtocolMiddleware:
    def __init__(self, protocol: RPCPluginProtocol):
        self.protocol = protocol
    
    async def before_request(self, request):
        """Pre-process requests."""
        logger.debug(f"Processing request: {request}")
        return request
    
    async def after_response(self, response):
        """Post-process responses."""
        logger.debug(f"Sending response: {response}")
        return response
```

## Next Steps

- **[Performance Optimization](performance.md)** - Optimize protocol performance
- **[Testing Guide](../../development/testing.md)** - Test custom protocols
- **[Production Deployment](../../examples/production.md)** - Deploy protocols to production

For complex protocol requirements, consider consulting with the Foundation team for architecture guidance and optimization strategies.