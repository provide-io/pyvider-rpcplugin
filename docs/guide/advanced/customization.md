# Type System and Custom Protocols

Extend the framework with custom type safety patterns and specialized protocols for domain-specific requirements.

## Overview

The `pyvider.rpcplugin` framework provides comprehensive customization capabilities through modern Python typing features and pluggable protocol architecture. This enables type-safe, domain-optimized communication for specialized use cases.

**Type System Features:**
- Static type checking with mypy/pyre support
- Runtime-checkable protocols
- Type guards and generic types
- Modern Python 3.11+ typing syntax

**Custom Protocol Capabilities:**
- Binary data protocols for high performance
- Streaming protocols for continuous data
- Legacy system integration
- Domain-specific optimizations

## Type System

=== "Core Types"

    ```python
    from typing import TypeVar, Protocol, runtime_checkable

    # Generic type variables
    ServerT = TypeVar('ServerT')
    HandlerT = TypeVar('HandlerT')
    TransportT = TypeVar('TransportT')

    # Type aliases
    GrpcServerType = grpc.aio.Server
    GrpcChannelType = grpc.aio.Channel
    AddressType = tuple[str, int]

    # Modern union types (Python 3.11+)
    ConfigType = dict[str, any] | None
    EndpointType = str | tuple[str, int]
    ```

=== "Protocols"

    ```python
    @runtime_checkable
    class RPCPluginHandler(Protocol):
        """Base protocol for RPC handlers."""

        async def handle_request(self, request: any, context: any) -> any:
            """Handle an RPC request."""
            ...

    @runtime_checkable
    class RPCPluginTransport(Protocol):
        """Transport protocol for network communication."""

        endpoint: str | None

        async def listen(self) -> str:
            """Start listening and return endpoint."""
            ...

        async def connect(self, endpoint: str) -> None:
            """Connect to endpoint."""
            ...

        async def close(self) -> None:
            """Close transport."""
            ...
    ```

=== "Type Guards"

    ```python
    from typing import TypeGuard

    def is_valid_handler(obj: any) -> TypeGuard[RPCPluginHandler]:
        """Check if object implements handler protocol."""
        return (
            hasattr(obj, 'handle_request') and
            callable(getattr(obj, 'handle_request'))
        )

    def is_valid_transport(obj: any) -> TypeGuard[RPCPluginTransport]:
        """Check if object implements transport protocol."""
        return (
            hasattr(obj, 'endpoint') and
            hasattr(obj, 'listen') and
            hasattr(obj, 'connect') and
            hasattr(obj, 'close')
        )

    # Usage with type narrowing
    def setup_server(handler: any, transport: any) -> None:
        if not is_valid_handler(handler):
            raise TypeError("Invalid handler")
        if not is_valid_transport(transport):
            raise TypeError("Invalid transport")

        # Type checker knows types are correct here
        server = RPCPluginServer(handler=handler, transport=transport)
    ```

### Generic Classes

Build type-safe components with generics:

```python
from typing import Generic

class RPCPluginServer(Generic[ServerT, HandlerT, TransportT]):
    """
    Generic RPC server.

    Type parameters:
    - ServerT: The gRPC server type
    - HandlerT: The handler implementation type
    - TransportT: The transport implementation type
    """

    def __init__(
        self,
        protocol: RPCPluginProtocol[ServerT, HandlerT],
        handler: HandlerT,
        transport: TransportT | None = None
    ):
        self.protocol = protocol
        self.handler = handler
        self.transport = transport

# Usage with specific types
server: RPCPluginServer[grpc.aio.Server, MyHandler, MyTransport] = (
    RPCPluginServer(
        protocol=my_protocol,
        handler=MyHandler(),
        transport=MyTransport()
    )
)
```

### Attrs Integration

Type-safe data classes with validation:

```python
from attrs import define, field

@define
class RPCPluginClient:
    """Client with attrs type annotations."""

    command: list[str] = field()
    config: dict[str, any] | None = field(default=None)

    # Internal typed fields
    _process: ManagedProcess | None = field(init=False, default=None)
    _transport: TransportType | None = field(init=False, default=None)
    grpc_channel: grpc.aio.Channel | None = field(init=False, default=None)

    @command.validator
    def _validate_command(self, attribute, value):
        if not value or not all(isinstance(v, str) for v in value):
            raise TypeError("Command must be non-empty list of strings")
```

### Factory Functions with Overloads

```python
from typing import overload

@overload
def plugin_client(
    command: list[str],
    config: None = None
) -> RPCPluginClient: ...

@overload
def plugin_client(
    command: list[str],
    config: dict[str, any]
) -> RPCPluginClient: ...

def plugin_client(
    command: list[str],
    config: dict[str, any] | None = None
) -> RPCPluginClient:
    """Create client with proper typing."""
    return RPCPluginClient(command=command, config=config)
```

### Runtime Type Validation

```python
from typing import get_type_hints
import inspect

def validate_types(func):
    """Decorator for runtime type validation."""
    hints = get_type_hints(func)

    def wrapper(*args, **kwargs):
        bound = inspect.signature(func).bind(*args, **kwargs)
        for name, value in bound.arguments.items():
            if name in hints:
                expected_type = hints[name]
                if not isinstance(value, expected_type):
                    raise TypeError(
                        f"{name} must be {expected_type}, got {type(value)}"
                    )

        result = func(*args, **kwargs)

        if 'return' in hints:
            expected_return = hints['return']
            if not isinstance(result, expected_return):
                raise TypeError(
                    f"Return must be {expected_return}, got {type(result)}"
                )

        return result

    return wrapper

# Usage
@validate_types
def add_numbers(a: int, b: int) -> int:
    return a + b
```

## Custom Protocols

### When to Use

Consider custom protocols for:
- **Ultra-low latency**: Financial trading, real-time gaming, IoT
- **Specialized formats**: Binary protocols, legacy integration
- **Domain optimization**: Custom compression or serialization
- **Cross-language needs**: Beyond gRPC ecosystems

### Protocol Architecture

```python
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol
from provide.foundation.logger import get_logger

logger = get_logger(__name__)

class CustomProtocol(RPCPluginProtocol):
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version
        logger.info(f"🔧 Initializing {name} protocol v{version}")

    async def get_grpc_descriptors(self):
        """Return gRPC service descriptors."""
        return self.service_descriptor, self.service_name

    async def add_to_server(self, server, handler):
        """Register protocol services with server."""
        self.service_implementation.add_to_server(server, handler)
```

### Protocol Patterns

=== "Binary Data"

    ```python
    import struct
    from dataclasses import dataclass

    @dataclass
    class BinaryMessage:
        message_type: int
        payload_size: int
        data: bytes

        def serialize(self) -> bytes:
            header = struct.pack('<BI', self.message_type, self.payload_size)
            return header + self.data

        @classmethod
        def deserialize(cls, data: bytes) -> 'BinaryMessage':
            message_type, payload_size = struct.unpack('<BI', data[:5])
            payload = data[5:5+payload_size]
            return cls(message_type, payload_size, payload)

    class BinaryProtocol(RPCPluginProtocol):
        async def process_binary_stream(self, stream):
            async for raw_data in stream:
                message = BinaryMessage.deserialize(raw_data)
                yield await self.handle_message(message)
    ```

=== "Streaming Data"

    ```python
    class StreamingProtocol(RPCPluginProtocol):
        async def start_data_stream(self, request, context):
            """Provide continuous data stream."""
            while context.is_active():
                data = await self.get_next_data_batch()

                yield StreamingResponse(
                    timestamp=time.time_ns(),
                    data=data,
                    sequence=self.next_sequence()
                )

                await asyncio.sleep(0.001)  # 1ms intervals
    ```

=== "Legacy Integration"

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

### Protocol Buffer Definition

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
  bytes custom_data = 5;
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

        compatible = self.find_compatible_version(client_version)
        logger.info(f"Negotiated version {compatible} for client {client_version}")
        return compatible
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

## Testing

### Type Testing

```python
# Configure mypy for strict checking
# pyproject.toml
[tool.mypy]
strict = true
python_version = "3.11"
warn_unused_ignores = true

[[tool.mypy.overrides]]
module = "pyvider.rpcplugin.protocol.grpc_*_pb2*"
ignore_errors = true  # Ignore generated files
```

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

### Performance Benchmarking

```python
import time

async def benchmark_protocol():
    """Benchmark custom protocol performance."""
    protocol = CustomProtocol("benchmark", "1.0")

    start_time = time.perf_counter()

    for i in range(1000):
        await protocol.send_message(f"Message {i}")

    duration = time.perf_counter() - start_time
    messages_per_second = 1000 / duration

    logger.info(f"Protocol throughput: {messages_per_second:.0f} msg/sec")
```

## Deployment

### Protocol Registry

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

### Configuration-Based Selection

```python
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
from provide.foundation.logger import get_logger

logger = get_logger(__name__)

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

### Type System

1. **Use type hints everywhere** for IDE support and static analysis
2. **Define custom types** for domain-specific values (NewType)
3. **Use protocols for interfaces** instead of abstract base classes
4. **Leverage type guards** for runtime type narrowing
5. **Document type constraints** in docstrings

### Custom Protocols

1. **Start simple** - begin with gRPC, customize only when needed
2. **Version management** - plan for protocol evolution
3. **Error handling** - implement robust error recovery
4. **Performance testing** - benchmark against gRPC baseline
5. **Security** - consider authentication and validation
6. **Documentation** - document protocol specifications

## Advanced Patterns

### Conditional Types

```python
from typing import Literal, overload

@overload
def get_value(return_type: Literal["str"]) -> str: ...

@overload
def get_value(return_type: Literal["int"]) -> int: ...

def get_value(return_type: Literal["str", "int"]) -> str | int:
    if return_type == "str":
        return "hello"
    else:
        return 42
```

### Type-Safe Builder

```python
from typing import Self

class ServerBuilder:
    """Type-safe builder for server configuration."""

    def with_port(self, port: int) -> Self:
        self.port = port
        return self

    def with_handler(self, handler: HandlerT) -> Self:
        self.handler = handler
        return self

    def build(self) -> RPCPluginServer[any, HandlerT, any]:
        return RPCPluginServer(
            handler=self.handler,
            config={"port": self.port}
        )

# Method chaining with type preservation
server = (
    ServerBuilder()
    .with_port(8080)
    .with_handler(MyHandler())
    .build()
)
```

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

## Related Topics

- [API Reference](../../reference/index.md) - Complete API with type annotations
- [Architecture](../../development/architecture.md) - System design with types
- [Testing](../../development/testing.md) - Type testing strategies
- [Observability](observability.md) - Performance monitoring
