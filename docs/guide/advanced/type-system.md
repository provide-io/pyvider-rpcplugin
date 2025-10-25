# Type System

The `pyvider.rpcplugin` framework uses modern Python typing features extensively, providing type safety, better IDE support, and runtime validation. This guide covers the type system architecture, runtime-checkable protocols, type guards, and best practices.

## Overview

The type system provides:

- **Static Type Checking** - Full mypy and pyre support
- **Runtime Protocols** - Runtime-checkable interfaces
- **Type Guards** - Runtime type validation
- **Generic Types** - Flexible, reusable components
- **Type Aliases** - Simplified complex type signatures

## Core Type Definitions

### Type Variables

The framework defines type variables for generic components:

```python
from typing import TypeVar

# Server generic types
ServerT = TypeVar('ServerT')      # gRPC server type
HandlerT = TypeVar('HandlerT')    # Handler implementation type
TransportT = TypeVar('TransportT') # Transport implementation type

# Client generic types
ClientT = TypeVar('ClientT', bound='RPCPluginClient')

# Protocol generic types
T = TypeVar('T')  # Request type
U = TypeVar('U')  # Response type
```

### Type Aliases

Common type aliases simplify signatures:

```python
from typing import Any
import grpc.aio

# gRPC types
GrpcServerType = grpc.aio.Server
GrpcChannelType = grpc.aio.Channel
GrpcCredentialsType = grpc.ChannelCredentials | None

# Configuration types
RpcConfigType = dict[str, Any]

# Network types
EndpointType = str
AddressType = tuple[str, int]

# Handler types
HandlerCallableType = Callable[[Any, Any], Awaitable[Any]]
```

## Runtime-Checkable Protocols

The framework uses `Protocol` classes that can be checked at runtime:

### Handler Protocol

```python
from typing import Protocol, runtime_checkable

@runtime_checkable
class RPCPluginHandler(Protocol):
    """Base protocol for RPC handlers."""

    async def handle_request(self, request: Any, context: Any) -> Any:
        """Handle an RPC request."""
        ...

# Usage
def process_handler(handler: Any) -> None:
    """Process a handler with runtime checking."""
    if not isinstance(handler, RPCPluginHandler):
        raise TypeError("Handler must implement RPCPluginHandler protocol")

    # Now we know handler has handle_request method
    ...
```

### Transport Protocol

```python
@runtime_checkable
class RPCPluginTransport(Protocol):
    """Transport protocol for network communication."""

    endpoint: str | None

    async def listen(self) -> str:
        """Start listening and return endpoint."""
        ...

    async def connect(self, endpoint: str) -> None:
        """Connect to the specified endpoint."""
        ...

    async def close(self) -> None:
        """Close transport and cleanup."""
        ...

# Implementation
class TCPSocketTransport:
    """TCP transport implementation."""

    endpoint: str | None = None

    async def listen(self) -> str:
        # Implementation
        return f"{self.host}:{self.port}"

    async def connect(self, endpoint: str) -> None:
        # Implementation
        pass

    async def close(self) -> None:
        # Implementation
        pass

# Runtime check
transport = TCPSocketTransport()
assert isinstance(transport, RPCPluginTransport)  # True
```

### Protocol Protocol

```python
@runtime_checkable
class RPCPluginProtocol(Protocol):
    """Protocol for RPC service definitions."""

    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        """Return gRPC descriptors and service name."""
        ...

    async def add_to_server(self, server: Any, handler: Any) -> None:
        """Add protocol services to server."""
        ...

    async def get_method_type(self, method_name: str) -> str:
        """Get the RPC method type."""
        ...
```

## Type Guards

Type guards provide runtime type validation:

### Basic Type Guards

```python
from typing import TypeGuard, Any

def is_valid_handler(obj: Any) -> TypeGuard[RPCPluginHandler]:
    """Check if object implements handler protocol."""
    return (
        hasattr(obj, 'handle_request') and
        callable(getattr(obj, 'handle_request'))
    )

def is_valid_transport(obj: Any) -> TypeGuard[RPCPluginTransport]:
    """Check if object implements transport protocol."""
    return (
        hasattr(obj, 'endpoint') and
        hasattr(obj, 'listen') and
        hasattr(obj, 'connect') and
        hasattr(obj, 'close')
    )

# Usage
def setup_server(handler: Any, transport: Any) -> None:
    """Setup server with validated components."""
    if not is_valid_handler(handler):
        raise TypeError("Invalid handler")

    if not is_valid_transport(transport):
        raise TypeError("Invalid transport")

    # Now TypeScript knows the types are correct
    server = RPCPluginServer(handler=handler, transport=transport)
```

### Complex Type Guards

```python
def is_valid_connection(
    obj: Any
) -> TypeGuard[tuple[asyncio.StreamReader, asyncio.StreamWriter]]:
    """Check if object is a valid connection tuple."""
    return (
        isinstance(obj, tuple) and
        len(obj) == 2 and
        isinstance(obj[0], asyncio.StreamReader) and
        isinstance(obj[1], asyncio.StreamWriter)
    )

def is_valid_serializable(obj: Any) -> TypeGuard[SerializableT]:
    """Check if object can be serialized."""
    try:
        import json
        json.dumps(obj)
        return True
    except (TypeError, ValueError):
        return False
```

## Generic Classes

The framework uses generics for flexible, type-safe components:

### Generic Server

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
from myapp import MyHandler, MyTransport
import grpc.aio

server: RPCPluginServer[grpc.aio.Server, MyHandler, MyTransport] = (
    RPCPluginServer(
        protocol=my_protocol,
        handler=MyHandler(),
        transport=MyTransport()
    )
)
```

### Generic Protocol

```python
class RPCPluginProtocol(ABC, Generic[ServerT, HandlerT]):
    """
    Generic protocol base class.

    Type parameters:
    - ServerT: Server type this protocol works with
    - HandlerT: Handler type this protocol expects
    """

    @abstractmethod
    async def add_to_server(
        self,
        server: ServerT,
        handler: HandlerT
    ) -> None:
        """Add services to server with proper types."""
        ...

# Concrete implementation
class MyProtocol(RPCPluginProtocol[grpc.aio.Server, MyHandler]):
    async def add_to_server(
        self,
        server: grpc.aio.Server,
        handler: MyHandler
    ) -> None:
        # Type-safe implementation
        add_MyServiceServicer_to_server(handler, server)
```

## Attrs Integration

The framework uses `attrs` for data classes with type safety:

### Typed Attrs Classes

```python
from attrs import define, field
from typing import Any

@define
class RPCPluginClient:
    """Client with attrs type annotations."""

    command: list[str] = field()
    config: dict[str, Any] | None = field(default=None)

    # Internal typed fields
    _process: ManagedProcess | None = field(init=False, default=None)
    _transport: TransportType | None = field(init=False, default=None)
    grpc_channel: grpc.aio.Channel | None = field(init=False, default=None)

    # Validators can ensure type safety
    @command.validator
    def _validate_command(self, attribute, value):
        if not value or not all(isinstance(v, str) for v in value):
            raise TypeError("Command must be a non-empty list of strings")
```

### Factory Functions with Types

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
    config: dict[str, Any]
) -> RPCPluginClient: ...

def plugin_client(
    command: list[str],
    config: dict[str, Any] | None = None
) -> RPCPluginClient:
    """Create client with proper typing."""
    return RPCPluginClient(command=command, config=config)
```

## Modern Python Typing

The framework uses Python 3.11+ typing features:

### Union Types with |

```python
# Modern syntax (Python 3.11+)
def process(value: str | int | None) -> str | None:
    if value is None:
        return None
    return str(value)

# Instead of older Union syntax
from typing import Union, Optional
def process_old(value: Optional[Union[str, int]]) -> Optional[str]:
    ...
```

### Built-in Generic Types

```python
# Modern syntax - lowercase built-ins
def process_data(
    items: list[str],
    mapping: dict[str, int],
    unique: set[str]
) -> tuple[list[str], dict[str, int]]:
    ...

# Instead of typing module imports
from typing import List, Dict, Set, Tuple
def process_data_old(
    items: List[str],
    mapping: Dict[str, int],
    unique: Set[str]
) -> Tuple[List[str], Dict[str, int]]:
    ...
```

## Type Checking in Practice

### Static Type Checking

Configure mypy for strict checking:

```toml
# pyproject.toml
[tool.mypy]
strict = true
python_version = "3.11"
warn_unused_ignores = true
warn_unused_configs = true

[[tool.mypy.overrides]]
module = "pyvider.rpcplugin.protocol.grpc_*_pb2*"
ignore_errors = true  # Ignore generated files
```

Run type checking:

```bash
mypy src/pyvider/rpcplugin
pyre check
```

### Runtime Type Validation

```python
from typing import get_type_hints

def validate_types(func):
    """Decorator for runtime type validation."""
    hints = get_type_hints(func)

    def wrapper(*args, **kwargs):
        # Validate argument types
        bound = inspect.signature(func).bind(*args, **kwargs)
        for name, value in bound.arguments.items():
            if name in hints:
                expected_type = hints[name]
                if not isinstance(value, expected_type):
                    raise TypeError(
                        f"{name} must be {expected_type}, got {type(value)}"
                    )

        result = func(*args, **kwargs)

        # Validate return type
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

add_numbers(1, 2)    # OK
add_numbers("1", 2)  # TypeError: a must be <class 'int'>, got <class 'str'>
```

## Best Practices

### 1. Use Type Hints Everywhere

```python
# Good - fully typed
async def process_request(
    request: RequestType,
    context: grpc.aio.ServicerContext
) -> ResponseType:
    ...

# Bad - missing type hints
async def process_request(request, context):
    ...
```

### 2. Define Custom Types

```python
# Define domain-specific types
UserId = NewType('UserId', int)
SessionToken = NewType('SessionToken', str)
Timestamp = NewType('Timestamp', float)

async def get_user(
    user_id: UserId,
    token: SessionToken
) -> User:
    ...
```

### 3. Use Protocols for Interfaces

```python
@runtime_checkable
class Cacheable(Protocol):
    """Protocol for cacheable objects."""

    def cache_key(self) -> str: ...
    def ttl(self) -> int: ...

def add_to_cache(item: Cacheable) -> None:
    """Add any cacheable item."""
    key = item.cache_key()
    ttl = item.ttl()
    ...
```

### 4. Leverage Type Guards

```python
def process_value(value: str | int) -> str:
    """Process value with type narrowing."""
    if isinstance(value, str):
        # Type checker knows value is str here
        return value.upper()
    else:
        # Type checker knows value is int here
        return str(value * 2)
```

### 5. Document Type Constraints

```python
from typing import TypeVar, Callable

T = TypeVar('T', bound=BaseHandler)

def register_handler(
    handler_class: type[T]
) -> Callable[[T], T]:
    """
    Register a handler class.

    Type constraints:
    - T must be a subclass of BaseHandler
    - Returns a decorator that preserves the type
    """
    ...
```

## Advanced Patterns

### Conditional Types

```python
from typing import Literal, overload

@overload
def get_value(return_type: Literal["str"]) -> str: ...

@overload
def get_value(return_type: Literal["int"]) -> int: ...

def get_value(return_type: Literal["str", "int"]) -> str | int:
    """Return different types based on parameter."""
    if return_type == "str":
        return "hello"
    else:
        return 42
```

### Type-Safe Builder Pattern

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

    def build(self) -> RPCPluginServer[Any, HandlerT, Any]:
        return RPCPluginServer(
            handler=self.handler,
            config={"port": self.port}
        )

# Chain methods with type preservation
server = (
    ServerBuilder()
    .with_port(8080)
    .with_handler(MyHandler())
    .build()
)
```

## Related Topics

- [API Reference](../../reference/index.md) - Complete API with type annotations
- [Architecture](../../development/architecture.md) - System design with types
- [Testing](../../development/testing.md) - Type testing strategies
- [Configuration Reference](../config/configuration-reference.md) - Typed configuration