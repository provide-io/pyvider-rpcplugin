---
title: Pyvider Coding Example
scope: Code generation guidelines.
retrieval_tags: ["pyvider", "code", "example"]
---

#!/usr/bin/env python3  # Only include shebang for scripts with __main__
# pyvider/rpcplugin/example.py

"""
Module docstring explaining purpose and key concepts.
"""

import asyncio
import enum
import sys
from typing import (
    TypeVar, TypeGuard, Optional, Dict, Any, Self, 
    Literal, Protocol, Final, NotRequired, TypedDict
)

import attrs

from pyvider.rpcplugin.logger import logger
from pyvider.rpcplugin.exception import SecurityError


# Type definitions
class DataHandler(Protocol):
    """Protocol defining data handler interface."""
    async def handle(self, data: bytes) -> bool: ...


class ConfigDict(TypedDict):
    """Configuration type definition."""
    required_field: str
    optional_field: NotRequired[str]


# Constants
DEFAULT_CHUNK_SIZE: Final[int] = 8192
SUPPORTED_MODES: Final = frozenset({"strict", "lenient"})


class DataType(str, enum.Enum):
    """Type of data being processed."""
    BINARY = "binary"
    TEXT = "text"
    NONE = "none"

    def __str__(self) -> str:
        """String representation matches enum value."""
        return self.value


T = TypeVar('T', bound='ExampleData')


def is_valid_data(data: Any) -> TypeGuard[bytes]:
    """Type guard to validate data format."""
    return isinstance(data, bytes) and len(data) > 0


@attrs.define(frozen=True, slots=True)
class ProcessResult:
    """Immutable result container."""
    success: bool
    error: Optional[str] = None
    data_type: DataType = DataType.NONE

    def __str__(self) -> str:
        if self.success:
            return f"Success: {self.data_type}"
        return f"Failed: {self.error}"


@attrs.define(frozen=True, slots=True)
class ExampleData:
    """Immutable data container with strong typing."""
    content: bytes = attrs.field()
    data_type: DataType = attrs.field()
    _hash: int = attrs.field(init=False, repr=False)
    
    def __attrs_pre_init__(self) -> None:
        """Pre-initialization hook for attrs."""
        # Initialize values that need to exist before other initialization
        object.__setattr__(self, '_hash', 0)
    
    @content.validator
    def _validate_content(self, _: attrs.Attribute, value: bytes) -> None:
        if not is_valid_data(value):
            raise ValueError("Invalid content format")
        # Compute hash only once since we're immutable
        object.__setattr__(self, '_hash', hash(value))

    def __hash__(self) -> int:
        """Return precomputed hash."""
        return self._hash

    @classmethod
    def create_binary(cls, content: bytes) -> Self:
        """Create binary data instance."""
        return cls(content=content, data_type=DataType.BINARY)

    @classmethod
    def create_text(cls, content: str) -> Self:
        """Create text data instance."""
        return cls(content=content.encode(), data_type=DataType.TEXT)


@attrs.define(slots=True, kw_only=True, repr=True)
class ExampleClass:
    """Class demonstrating modern Python patterns."""
    name: str = attrs.field(repr=True)
    mode: Literal["strict", "lenient"] = attrs.field(default="strict")
    _internal: Dict[str, Any] = attrs.field(
        factory=dict, 
        init=False, 
        repr=False,
    )

    @name.validator
    def _validate_name(self, _: attrs.Attribute, value: str) -> None:
        if not value or not value.strip():
            raise ValueError("Name cannot be empty")

    def __attrs_post_init__(self) -> None:
        """Perform post-initialization setup."""
        try:
            self._setup_internals()
            logger.debug(f"✅ Initialized {self.__class__.__name__}: {self.name}")
        except Exception as e:
            logger.error(f"❌ Initialization failed: {e}")
            raise SecurityError(f"Failed to initialize {self.name}") from e

    def _setup_internals(self) -> None:
        """Set up internal state."""
        logger.debug("🔧 Setting up internal state")
        if not self.name:
            raise ValueError("Name cannot be empty")
        if self.mode not in SUPPORTED_MODES:
            raise ValueError(f"Unsupported mode: {self.mode}")
        self._internal["initialized"] = True

    def _handle_data_type(self, data: ExampleData) -> ProcessResult:
        """Handle different data types using pattern matching."""
        match data:
            case ExampleData(data_type=DataType.BINARY) as bin_data:
                logger.debug(f"🔢 Processing {len(bin_data.content)} bytes of binary data")
                return ProcessResult(success=True)
                
            case ExampleData(data_type=DataType.TEXT) as txt_data:
                logger.debug(f"📝 Processing {len(txt_data.content)} bytes of text data")
                return ProcessResult(success=True)
                
            case _:
                msg = f"Unsupported data type: {data.data_type}"
                logger.error(f"❌ {msg}")
                return ProcessResult(success=False, error=msg)

    def _handle_error(self, error: Exception) -> ProcessResult:
        """Handle different error types using pattern matching."""
        match error:
            case SecurityError():
                logger.error(f"🔐❌ Security error: {error}")
                return ProcessResult(success=False, error=str(error))
                
            case ValueError() | TypeError() as e:
                logger.error(f"📥❌ Validation error: {e}")
                return ProcessResult(success=False, error=str(e))
                
            case Exception() as e:
                logger.error(f"❌ Unexpected error: {e}")
                return ProcessResult(success=False, error=str(e))

    async def process_data(self, data: ExampleData) -> ProcessResult:
        """Process data with comprehensive error handling."""
        try:
            match (self._internal.get("initialized"), self.mode):
                case (True, "strict" | "lenient" as mode):
                    logger.debug(f"Processing in {mode} mode")
                case (False, _):
                    raise SecurityError("Not initialized")
                case _:
                    raise ValueError(f"Invalid state: {self.mode}")

            return self._handle_data_type(data)

        except Exception as e:
            return self._handle_error(e)

    @property
    def is_configured(self) -> bool:
        """Check if instance is properly configured."""
        return bool(self._internal.get("initialized"))


if __name__ == "__main__":
    async def main() -> None:
        example = ExampleClass(name="test", mode="strict")
        
        # Test different data types
        test_cases = [
            ExampleData.create_binary(b"binary data test"),
            ExampleData.create_text("text data test"),
        ]
        
        results = await asyncio.gather(
            *(example.process_data(data) for data in test_cases)
        )
        
        for i, result in enumerate(results, 1):
            match result:
                case ProcessResult(success=True):
                    print(f"✅ Test {i}: Processing succeeded")
                case ProcessResult(success=False, error=str(error)):
                    print(f"❌ Test {i}: Processing failed: {error}")
                case _:
                    print(f"❓ Test {i}: Unknown result")

        # Demonstrate error cases
        try:
            bad_example = ExampleClass(name="", mode="invalid")
        except Exception as e:
            print(f"🚫 Expected error: {e}")

    if sys.version_info >= (3, 11):
        asyncio.run(main())
    else:
        print("This script requires Python 3.11 or later")
