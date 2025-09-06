# Custom Protocols

Build domain-specific communication protocols for specialized plugin requirements. Learn protocol design patterns, binary formats, streaming support, and cross-language interoperability.

## Overview

Custom protocols enable optimization for specific use cases where standard gRPC may not be optimal. This includes ultra-low latency requirements, specialized data formats, legacy system integration, or domain-specific compression algorithms.

```python
from pyvider.rpcplugin.protocols import CustomProtocol, ProtocolBuilder
from pyvider.rpcplugin.serializers import BinarySerializer, CompressionCodec
import struct
import zstandard as zstd

async def custom_protocol_example():
    """Example of a custom high-frequency trading protocol."""
    
    # Define custom binary protocol for market data
    market_data_protocol = CustomProtocol(
        name="market-data-v3",
        version="3.1.0",
        
        # Ultra-low latency binary serialization
        serializer=BinarySerializer(
            byte_order='little',
            use_native_types=True,
            zero_copy=True
        ),
        
        # Domain-specific compression
        compression=CompressionCodec(
            algorithm="zstd",
            level=1,  # Fast compression
            dictionary=load_market_data_dictionary()
        ),
        
        # Custom message framing
        frame_format=FrameFormat(
            header_size=16,
            magic_bytes=b'MKDT',
            checksum_type='crc32c'
        )
    )
    
    # Server with custom protocol
    server = plugin_server(
        services=[MarketDataService()],
        protocol=market_data_protocol,
        port=8080
    )
    
    try:
        await server.start()
        print("🚀 Market data server with custom protocol started")
        
        # Client using same protocol
        async with plugin_client(
            host="127.0.0.1",
            port=8080,
            protocol=market_data_protocol
        ) as client:
            
            # Ultra-fast market data request
            start_time = time.perf_counter()
            
            quotes = await client.market_data.GetQuotes(
                symbols=["AAPL", "MSFT", "GOOGL"],
                fields=["bid", "ask", "last", "volume"]
            )
            
            latency = (time.perf_counter() - start_time) * 1000
            print(f"⚡ Market data retrieved in {latency:.2f}ms")
            
            for quote in quotes.data:
                print(f"   {quote.symbol}: ${quote.last:.2f}")
    
    finally:
        await server.stop()

# Usage
await custom_protocol_example()
```

## Protocol Design Patterns

### Binary Protocol Definition

```python
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum
import struct
import hashlib

class MessageType(Enum):
    """Message types for custom protocol."""
    HEARTBEAT = 0x01
    MARKET_DATA = 0x02
    ORDER_REQUEST = 0x03
    ORDER_RESPONSE = 0x04
    TRADE_EXECUTION = 0x05
    ERROR = 0xFF

@dataclass
class ProtocolHeader:
    """Binary protocol header structure."""
    
    magic: bytes = b'TRDP'  # Trading Protocol
    version: int = 1
    message_type: MessageType = MessageType.HEARTBEAT
    message_length: int = 0
    sequence_number: int = 0
    timestamp: int = 0  # Microseconds since epoch
    checksum: int = 0
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'ProtocolHeader':
        """Parse header from binary data."""
        
        if len(data) < 32:
            raise ValueError("Header too short")
        
        # Unpack binary header (little endian)
        unpacked = struct.unpack('<4sBBHIQI8x', data[:32])
        
        return cls(
            magic=unpacked[0],
            version=unpacked[1],
            message_type=MessageType(unpacked[2]),
            message_length=unpacked[3],
            sequence_number=unpacked[4],
            timestamp=unpacked[5],
            checksum=unpacked[6]
        )
    
    def to_bytes(self) -> bytes:
        """Serialize header to binary data."""
        
        return struct.pack(
            '<4sBBHIQI8x',  # 8 padding bytes for alignment
            self.magic,
            self.version,
            self.message_type.value,
            self.message_length,
            self.sequence_number,
            self.timestamp,
            self.checksum
        )
    
    def calculate_checksum(self, payload: bytes) -> int:
        """Calculate CRC32 checksum for header + payload."""
        
        header_data = struct.pack(
            '<4sBBHIQ',
            self.magic,
            self.version, 
            self.message_type.value,
            self.message_length,
            self.sequence_number,
            self.timestamp
        )
        
        return zlib.crc32(header_data + payload) & 0xffffffff

class BinaryProtocolCodec:
    """Codec for custom binary protocol."""
    
    def __init__(self):
        self.sequence_counter = 0
    
    def encode_message(self, message_type: MessageType, 
                      payload: bytes) -> bytes:
        """Encode message with protocol header."""
        
        timestamp = int(time.time() * 1000000)  # Microseconds
        self.sequence_counter += 1
        
        header = ProtocolHeader(
            message_type=message_type,
            message_length=len(payload),
            sequence_number=self.sequence_counter,
            timestamp=timestamp
        )
        
        # Calculate checksum
        header.checksum = header.calculate_checksum(payload)
        
        return header.to_bytes() + payload
    
    def decode_message(self, data: bytes) -> tuple[ProtocolHeader, bytes]:
        """Decode message from binary data."""
        
        if len(data) < 32:
            raise ValueError("Message too short")
        
        # Parse header
        header = ProtocolHeader.from_bytes(data[:32])
        
        # Validate magic bytes
        if header.magic != b'TRDP':
            raise ValueError("Invalid magic bytes")
        
        # Extract payload
        payload = data[32:32 + header.message_length]
        
        if len(payload) != header.message_length:
            raise ValueError("Payload length mismatch")
        
        # Verify checksum
        expected_checksum = header.calculate_checksum(payload)
        if header.checksum != expected_checksum:
            raise ValueError("Checksum verification failed")
        
        return header, payload

# Usage example
codec = BinaryProtocolCodec()

# Encode market data
market_data_payload = struct.pack('<fffffffffQ', 
    150.25,  # bid
    150.27,  # ask  
    150.26,  # last
    150.30,  # high
    149.80,  # low
    150.00,  # open
    150.25,  # close
    1500000, # volume
    1677648000000000  # timestamp
)

encoded = codec.encode_message(MessageType.MARKET_DATA, market_data_payload)
header, payload = codec.decode_message(encoded)

print(f"📦 Message: {header.message_type.name}, Length: {len(payload)} bytes")
```

### Schema Evolution and Versioning

```python
from typing import Dict, Type, Any
from abc import ABC, abstractmethod

class MessageSchema(ABC):
    """Base class for versioned message schemas."""
    
    version: int
    
    @abstractmethod
    def serialize(self, data: Dict[str, Any]) -> bytes:
        """Serialize data to bytes."""
        pass
    
    @abstractmethod
    def deserialize(self, data: bytes) -> Dict[str, Any]:
        """Deserialize bytes to data."""
        pass
    
    @abstractmethod
    def migrate_from(self, old_version: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """Migrate data from older schema version."""
        pass

class MarketDataSchemaV1(MessageSchema):
    """Version 1 market data schema."""
    
    version = 1
    
    def serialize(self, data: Dict[str, Any]) -> bytes:
        """Serialize v1 market data."""
        
        return struct.pack('<fff',
            data['bid'],
            data['ask'], 
            data['last']
        )
    
    def deserialize(self, data: bytes) -> Dict[str, Any]:
        """Deserialize v1 market data."""
        
        bid, ask, last = struct.unpack('<fff', data)
        
        return {
            'bid': bid,
            'ask': ask,
            'last': last,
            'volume': 0  # Default for missing field
        }
    
    def migrate_from(self, old_version: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """No migration needed for v1."""
        return data

class MarketDataSchemaV2(MessageSchema):
    """Version 2 market data schema with volume."""
    
    version = 2
    
    def serialize(self, data: Dict[str, Any]) -> bytes:
        """Serialize v2 market data."""
        
        return struct.pack('<fffQ',
            data['bid'],
            data['ask'],
            data['last'], 
            data['volume']
        )
    
    def deserialize(self, data: bytes) -> Dict[str, Any]:
        """Deserialize v2 market data."""
        
        bid, ask, last, volume = struct.unpack('<fffQ', data)
        
        return {
            'bid': bid,
            'ask': ask,
            'last': last,
            'volume': volume
        }
    
    def migrate_from(self, old_version: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """Migrate from older versions."""
        
        if old_version == 1:
            # Add default volume for v1 data
            if 'volume' not in data:
                data['volume'] = 0
        
        return data

class MarketDataSchemaV3(MessageSchema):
    """Version 3 market data schema with additional fields."""
    
    version = 3
    
    def serialize(self, data: Dict[str, Any]) -> bytes:
        """Serialize v3 market data."""
        
        # Variable length serialization for extensibility
        fields = []
        
        # Core fields
        fields.extend([
            ('bid', 'f', data['bid']),
            ('ask', 'f', data['ask']), 
            ('last', 'f', data['last']),
            ('volume', 'Q', data['volume'])
        ])
        
        # Optional fields
        if 'high' in data:
            fields.append(('high', 'f', data['high']))
        if 'low' in data:
            fields.append(('low', 'f', data['low']))
        if 'timestamp' in data:
            fields.append(('timestamp', 'Q', data['timestamp']))
        
        # Pack with field count and field descriptors
        result = struct.pack('<H', len(fields))
        
        for name, format_char, value in fields:
            name_bytes = name.encode('utf-8')
            result += struct.pack('<H', len(name_bytes))
            result += name_bytes
            result += struct.pack('<c', format_char.encode())
            result += struct.pack(f'<{format_char}', value)
        
        return result
    
    def deserialize(self, data: bytes) -> Dict[str, Any]:
        """Deserialize v3 market data."""
        
        offset = 0
        field_count = struct.unpack('<H', data[offset:offset+2])[0]
        offset += 2
        
        result = {}
        
        for _ in range(field_count):
            # Read field name
            name_length = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            
            name = data[offset:offset+name_length].decode('utf-8')
            offset += name_length
            
            # Read format character
            format_char = data[offset:offset+1].decode()
            offset += 1
            
            # Read value
            value_size = struct.calcsize(f'<{format_char}')
            value = struct.unpack(f'<{format_char}', data[offset:offset+value_size])[0]
            offset += value_size
            
            result[name] = value
        
        return result
    
    def migrate_from(self, old_version: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """Migrate from older versions."""
        
        if old_version == 1:
            if 'volume' not in data:
                data['volume'] = 0
        
        # v2 -> v3 migration (no changes needed)
        
        return data

class SchemaRegistry:
    """Registry for managing schema versions."""
    
    def __init__(self):
        self.schemas: Dict[int, MessageSchema] = {}
        self.latest_version = 0
    
    def register_schema(self, schema: MessageSchema):
        """Register schema version."""
        
        self.schemas[schema.version] = schema
        self.latest_version = max(self.latest_version, schema.version)
    
    def get_schema(self, version: int) -> MessageSchema:
        """Get schema by version."""
        
        if version not in self.schemas:
            raise ValueError(f"Unknown schema version: {version}")
        
        return self.schemas[version]
    
    def serialize(self, data: Dict[str, Any], version: int = None) -> bytes:
        """Serialize data using specified or latest version."""
        
        version = version or self.latest_version
        schema = self.get_schema(version)
        
        # Add version header
        payload = schema.serialize(data)
        return struct.pack('<H', version) + payload
    
    def deserialize(self, data: bytes) -> tuple[int, Dict[str, Any]]:
        """Deserialize data and return version and data."""
        
        if len(data) < 2:
            raise ValueError("Data too short")
        
        # Extract version
        version = struct.unpack('<H', data[:2])[0]
        payload = data[2:]
        
        # Deserialize with appropriate schema
        schema = self.get_schema(version)
        result = schema.deserialize(payload)
        
        return version, result
    
    def migrate_to_latest(self, version: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """Migrate data to latest schema version."""
        
        current_data = data
        
        # Apply migrations step by step
        for v in range(version + 1, self.latest_version + 1):
            schema = self.get_schema(v)
            current_data = schema.migrate_from(v - 1, current_data)
        
        return current_data

# Usage example
registry = SchemaRegistry()
registry.register_schema(MarketDataSchemaV1())
registry.register_schema(MarketDataSchemaV2())
registry.register_schema(MarketDataSchemaV3())

# Serialize with latest version
data = {
    'bid': 100.25,
    'ask': 100.27,
    'last': 100.26,
    'volume': 15000,
    'high': 100.50,
    'low': 99.80,
    'timestamp': int(time.time() * 1000000)
}

serialized = registry.serialize(data)
version, deserialized = registry.deserialize(serialized)

print(f"🔄 Schema version: {version}")
print(f"📊 Data: {deserialized}")

# Test migration from old version
old_data = {'bid': 95.50, 'ask': 95.52, 'last': 95.51}
migrated = registry.migrate_to_latest(1, old_data)
print(f"🔄 Migrated data: {migrated}")
```

## High-Performance Streaming Protocols

### Real-Time Data Streaming

```python
from typing import AsyncIterator, AsyncGenerator
import asyncio
from dataclasses import dataclass
import time

@dataclass
class StreamMessage:
    """Streaming message wrapper."""
    
    stream_id: str
    sequence: int
    timestamp: int
    data: bytes
    is_control: bool = False

class StreamingProtocol:
    """High-performance streaming protocol."""
    
    def __init__(self, buffer_size: int = 1024 * 1024):  # 1MB buffer
        self.buffer_size = buffer_size
        self.active_streams: Dict[str, 'StreamHandler'] = {}
        self.sequence_counters: Dict[str, int] = {}
    
    async def create_stream(self, stream_id: str, 
                          data_generator: AsyncGenerator[bytes, None]) -> 'StreamHandler':
        """Create new data stream."""
        
        handler = StreamHandler(stream_id, self, data_generator)
        self.active_streams[stream_id] = handler
        self.sequence_counters[stream_id] = 0
        
        return handler
    
    def get_next_sequence(self, stream_id: str) -> int:
        """Get next sequence number for stream."""
        
        self.sequence_counters[stream_id] += 1
        return self.sequence_counters[stream_id]
    
    async def close_stream(self, stream_id: str):
        """Close and cleanup stream."""
        
        if stream_id in self.active_streams:
            handler = self.active_streams[stream_id]
            await handler.close()
            del self.active_streams[stream_id]
            del self.sequence_counters[stream_id]

class StreamHandler:
    """Handles individual data stream."""
    
    def __init__(self, stream_id: str, protocol: StreamingProtocol,
                 data_generator: AsyncGenerator[bytes, None]):
        self.stream_id = stream_id
        self.protocol = protocol
        self.data_generator = data_generator
        
        # Buffering
        self.buffer = bytearray()
        self.buffer_lock = asyncio.Lock()
        
        # Flow control
        self.backpressure_threshold = protocol.buffer_size * 0.8
        self.is_paused = False
        
        # Statistics
        self.bytes_sent = 0
        self.messages_sent = 0
        self.start_time = time.time()
    
    async def stream_data(self) -> AsyncIterator[StreamMessage]:
        """Stream data with flow control."""
        
        try:
            async for data_chunk in self.data_generator:
                # Check for backpressure
                if len(self.buffer) > self.backpressure_threshold:
                    await self._handle_backpressure()
                
                # Create stream message
                message = StreamMessage(
                    stream_id=self.stream_id,
                    sequence=self.protocol.get_next_sequence(self.stream_id),
                    timestamp=int(time.time() * 1000000),  # Microseconds
                    data=data_chunk
                )
                
                # Buffer management
                async with self.buffer_lock:
                    self.buffer.extend(data_chunk)
                
                # Update statistics
                self.bytes_sent += len(data_chunk)
                self.messages_sent += 1
                
                yield message
        
        finally:
            # Send end-of-stream marker
            yield StreamMessage(
                stream_id=self.stream_id,
                sequence=self.protocol.get_next_sequence(self.stream_id),
                timestamp=int(time.time() * 1000000),
                data=b'',
                is_control=True
            )
    
    async def _handle_backpressure(self):
        """Handle backpressure by pausing stream."""
        
        if not self.is_paused:
            self.is_paused = True
            print(f"⚠️ Stream {self.stream_id} paused due to backpressure")
        
        # Wait for buffer to drain
        while len(self.buffer) > self.backpressure_threshold * 0.5:
            await asyncio.sleep(0.001)  # 1ms
        
        if self.is_paused:
            self.is_paused = False
            print(f"✅ Stream {self.stream_id} resumed")
    
    async def acknowledge_data(self, sequence: int):
        """Acknowledge received data (remove from buffer)."""
        
        # In a real implementation, this would remove acknowledged data
        # from the buffer to prevent memory buildup
        pass
    
    def get_stats(self) -> Dict[str, Any]:
        """Get streaming statistics."""
        
        duration = time.time() - self.start_time
        throughput = self.bytes_sent / duration if duration > 0 else 0
        
        return {
            'stream_id': self.stream_id,
            'bytes_sent': self.bytes_sent,
            'messages_sent': self.messages_sent,
            'throughput_bps': throughput,
            'buffer_size': len(self.buffer),
            'is_paused': self.is_paused,
            'duration_seconds': duration
        }
    
    async def close(self):
        """Close stream handler."""
        
        # Cleanup resources
        self.buffer.clear()
        print(f"🔒 Stream {self.stream_id} closed")

# Market data streaming example
class MarketDataStreamer:
    """Real-time market data streaming service."""
    
    def __init__(self):
        self.protocol = StreamingProtocol(buffer_size=2 * 1024 * 1024)  # 2MB
        self.subscriptions: Dict[str, List[str]] = {}  # client_id -> symbols
    
    async def subscribe_to_symbols(self, client_id: str, 
                                 symbols: List[str]) -> StreamHandler:
        """Subscribe client to real-time market data."""
        
        self.subscriptions[client_id] = symbols
        
        # Create data generator for subscribed symbols
        data_generator = self._create_market_data_generator(symbols)
        
        # Create stream
        stream = await self.protocol.create_stream(
            stream_id=f"market_data_{client_id}",
            data_generator=data_generator
        )
        
        return stream
    
    async def _create_market_data_generator(self, symbols: List[str]) -> AsyncGenerator[bytes, None]:
        """Generate real-time market data for symbols."""
        
        # Simulate real-time market data
        while True:
            for symbol in symbols:
                # Generate random market data
                price = 100.0 + random.uniform(-5.0, 5.0)
                volume = random.randint(100, 10000)
                
                # Pack as binary data
                data = struct.pack('<8sffQ',
                    symbol.encode('utf-8').ljust(8, b'\x00'),
                    price,  # bid
                    price + 0.01,  # ask
                    volume
                )
                
                yield data
            
            # Stream at 100Hz (10ms intervals)
            await asyncio.sleep(0.01)
    
    async def unsubscribe(self, client_id: str):
        """Unsubscribe client from market data."""
        
        stream_id = f"market_data_{client_id}"
        await self.protocol.close_stream(stream_id)
        
        if client_id in self.subscriptions:
            del self.subscriptions[client_id]

# Usage example
async def streaming_protocol_example():
    """Example of high-performance streaming protocol."""
    
    streamer = MarketDataStreamer()
    
    # Subscribe to market data
    symbols = ["AAPL", "MSFT", "GOOGL", "TSLA"]
    stream = await streamer.subscribe_to_symbols("client_001", symbols)
    
    print(f"📡 Streaming market data for: {symbols}")
    
    # Consume stream data
    message_count = 0
    start_time = time.time()
    
    try:
        async for message in stream.stream_data():
            if message.is_control:
                print("🏁 End of stream received")
                break
            
            # Parse market data
            symbol, bid, ask, volume = struct.unpack('<8sffQ', message.data)
            symbol = symbol.decode('utf-8').rstrip('\x00')
            
            message_count += 1
            
            if message_count % 1000 == 0:
                # Show periodic statistics
                stats = stream.get_stats()
                elapsed = time.time() - start_time
                rate = message_count / elapsed
                
                print(f"📊 Processed {message_count} messages")
                print(f"   Rate: {rate:.0f} msg/sec")
                print(f"   Throughput: {stats['throughput_bps'] / 1024 / 1024:.1f} MB/s")
                print(f"   Buffer: {stats['buffer_size'] / 1024:.1f} KB")
                print(f"   Latest: {symbol} ${bid:.2f}/${ask:.2f} vol={volume}")
            
            # Stop after processing some messages
            if message_count >= 10000:
                break
    
    finally:
        await streamer.unsubscribe("client_001")
        
        # Final statistics
        final_stats = stream.get_stats()
        print(f"\n🏁 Final Statistics:")
        print(f"   Messages: {final_stats['messages_sent']}")
        print(f"   Data: {final_stats['bytes_sent'] / 1024 / 1024:.1f} MB")
        print(f"   Avg throughput: {final_stats['throughput_bps'] / 1024 / 1024:.1f} MB/s")

# Usage
await streaming_protocol_example()
```

## Cross-Language Protocol Support

### Language-Agnostic Protocol Definition

```python
from typing import Dict, Any, List, Optional
import json
import yaml
from pathlib import Path

class ProtocolDefinition:
    """Language-agnostic protocol definition."""
    
    def __init__(self, definition: Dict[str, Any]):
        self.definition = definition
        self.name = definition['name']
        self.version = definition['version']
        self.messages = definition.get('messages', {})
        self.enums = definition.get('enums', {})
        self.services = definition.get('services', {})
    
    @classmethod
    def from_file(cls, file_path: str) -> 'ProtocolDefinition':
        """Load protocol definition from file."""
        
        path = Path(file_path)
        
        with open(path) as f:
            if path.suffix == '.json':
                definition = json.load(f)
            elif path.suffix in ['.yml', '.yaml']:
                definition = yaml.safe_load(f)
            else:
                raise ValueError(f"Unsupported file format: {path.suffix}")
        
        return cls(definition)
    
    def generate_python_code(self) -> str:
        """Generate Python code from protocol definition."""
        
        code = []
        code.append(f'"""Generated protocol code for {self.name} v{self.version}"""')
        code.append('')
        code.append('from typing import List, Dict, Any, Optional')
        code.append('from dataclasses import dataclass')
        code.append('from enum import Enum')
        code.append('import struct')
        code.append('')
        
        # Generate enums
        for enum_name, enum_def in self.enums.items():
            code.append(f'class {enum_name}(Enum):')
            code.append(f'    """{enum_def.get("description", f"{enum_name} enum")}"""')
            
            for value_name, value in enum_def['values'].items():
                code.append(f'    {value_name} = {value}')
            
            code.append('')
        
        # Generate message classes
        for message_name, message_def in self.messages.items():
            code.append('@dataclass')
            code.append(f'class {message_name}:')
            code.append(f'    """{message_def.get("description", f"{message_name} message")}"""')
            code.append('')
            
            # Generate fields
            for field_name, field_def in message_def.get('fields', {}).items():
                field_type = self._python_type_from_definition(field_def)
                default = field_def.get('default')
                
                if default is not None:
                    code.append(f'    {field_name}: {field_type} = {repr(default)}')
                else:
                    code.append(f'    {field_name}: {field_type}')
            
            code.append('')
            
            # Generate serialization methods
            code.extend(self._generate_serialization_methods(message_name, message_def))
            code.append('')
        
        return '\n'.join(code)
    
    def _python_type_from_definition(self, field_def: Dict[str, Any]) -> str:
        """Convert field definition to Python type."""
        
        type_name = field_def['type']
        
        type_mapping = {
            'int8': 'int',
            'int16': 'int',
            'int32': 'int',
            'int64': 'int',
            'uint8': 'int',
            'uint16': 'int',
            'uint32': 'int',
            'uint64': 'int',
            'float32': 'float',
            'float64': 'float',
            'bool': 'bool',
            'string': 'str',
            'bytes': 'bytes'
        }
        
        if type_name in type_mapping:
            base_type = type_mapping[type_name]
        elif type_name in self.messages:
            base_type = type_name
        elif type_name in self.enums:
            base_type = type_name
        else:
            base_type = 'Any'
        
        if field_def.get('repeated', False):
            return f'List[{base_type}]'
        elif field_def.get('optional', False):
            return f'Optional[{base_type}]'
        else:
            return base_type
    
    def _generate_serialization_methods(self, message_name: str, 
                                      message_def: Dict[str, Any]) -> List[str]:
        """Generate serialization methods for message."""
        
        code = []
        
        # Generate to_bytes method
        code.append('    def to_bytes(self) -> bytes:')
        code.append('        """Serialize message to bytes."""')
        code.append('')
        code.append('        data = bytearray()')
        
        for field_name, field_def in message_def.get('fields', {}).items():
            field_type = field_def['type']
            
            if field_type in ['int8', 'int16', 'int32', 'int64']:
                format_char = {'int8': 'b', 'int16': 'h', 'int32': 'i', 'int64': 'q'}[field_type]
                code.append(f'        data.extend(struct.pack("<{format_char}", self.{field_name}))')
            
            elif field_type in ['uint8', 'uint16', 'uint32', 'uint64']:
                format_char = {'uint8': 'B', 'uint16': 'H', 'uint32': 'I', 'uint64': 'Q'}[field_type]
                code.append(f'        data.extend(struct.pack("<{format_char}", self.{field_name}))')
            
            elif field_type == 'float32':
                code.append(f'        data.extend(struct.pack("<f", self.{field_name}))')
            
            elif field_type == 'float64':
                code.append(f'        data.extend(struct.pack("<d", self.{field_name}))')
            
            elif field_type == 'bool':
                code.append(f'        data.extend(struct.pack("<B", 1 if self.{field_name} else 0))')
            
            elif field_type == 'string':
                code.append(f'        field_bytes = self.{field_name}.encode("utf-8")')
                code.append(f'        data.extend(struct.pack("<H", len(field_bytes)))')
                code.append(f'        data.extend(field_bytes)')
            
            elif field_type == 'bytes':
                code.append(f'        data.extend(struct.pack("<I", len(self.{field_name})))')
                code.append(f'        data.extend(self.{field_name})')
        
        code.append('')
        code.append('        return bytes(data)')
        code.append('')
        
        # Generate from_bytes class method
        code.append('    @classmethod')
        code.append('    def from_bytes(cls, data: bytes) -> "{message_name}":'.format(message_name=message_name))
        code.append('        """Deserialize message from bytes."""')
        code.append('')
        code.append('        offset = 0')
        code.append('        kwargs = {}')
        code.append('')
        
        for field_name, field_def in message_def.get('fields', {}).items():
            field_type = field_def['type']
            
            if field_type in ['int8', 'int16', 'int32', 'int64']:
                format_char = {'int8': 'b', 'int16': 'h', 'int32': 'i', 'int64': 'q'}[field_type]
                size = struct.calcsize(format_char)
                code.append(f'        kwargs["{field_name}"] = struct.unpack("<{format_char}", data[offset:offset+{size}])[0]')
                code.append(f'        offset += {size}')
            
            elif field_type in ['uint8', 'uint16', 'uint32', 'uint64']:
                format_char = {'uint8': 'B', 'uint16': 'H', 'uint32': 'I', 'uint64': 'Q'}[field_type]
                size = struct.calcsize(format_char)
                code.append(f'        kwargs["{field_name}"] = struct.unpack("<{format_char}", data[offset:offset+{size}])[0]')
                code.append(f'        offset += {size}')
            
            elif field_type == 'string':
                code.append(f'        str_len = struct.unpack("<H", data[offset:offset+2])[0]')
                code.append(f'        offset += 2')
                code.append(f'        kwargs["{field_name}"] = data[offset:offset+str_len].decode("utf-8")')
                code.append(f'        offset += str_len')
        
        code.append('')
        code.append('        return cls(**kwargs)')
        
        return code
    
    def generate_javascript_code(self) -> str:
        """Generate JavaScript/TypeScript code."""
        
        code = []
        code.append(f'// Generated protocol code for {self.name} v{self.version}')
        code.append('')
        
        # Generate enums
        for enum_name, enum_def in self.enums.items():
            code.append(f'export enum {enum_name} {{')
            
            for value_name, value in enum_def['values'].items():
                code.append(f'  {value_name} = {value},')
            
            code.append('}')
            code.append('')
        
        # Generate interfaces
        for message_name, message_def in self.messages.items():
            code.append(f'export interface {message_name} {{')
            
            for field_name, field_def in message_def.get('fields', {}).items():
                ts_type = self._typescript_type_from_definition(field_def)
                optional = '?' if field_def.get('optional', False) else ''
                code.append(f'  {field_name}{optional}: {ts_type};')
            
            code.append('}')
            code.append('')
        
        return '\n'.join(code)
    
    def _typescript_type_from_definition(self, field_def: Dict[str, Any]) -> str:
        """Convert field definition to TypeScript type."""
        
        type_name = field_def['type']
        
        type_mapping = {
            'int8': 'number',
            'int16': 'number',
            'int32': 'number',
            'int64': 'number',
            'uint8': 'number',
            'uint16': 'number',
            'uint32': 'number',
            'uint64': 'number',
            'float32': 'number',
            'float64': 'number',
            'bool': 'boolean',
            'string': 'string',
            'bytes': 'Uint8Array'
        }
        
        if type_name in type_mapping:
            base_type = type_mapping[type_name]
        elif type_name in self.messages:
            base_type = type_name
        elif type_name in self.enums:
            base_type = type_name
        else:
            base_type = 'any'
        
        if field_def.get('repeated', False):
            return f'{base_type}[]'
        else:
            return base_type

# Protocol definition file (YAML format)
protocol_yaml = '''
name: "TradingProtocol"
version: "2.0"
description: "High-frequency trading protocol"

enums:
  OrderSide:
    description: "Order side enumeration"
    values:
      BUY: 1
      SELL: 2
  
  OrderType:
    description: "Order type enumeration"
    values:
      MARKET: 1
      LIMIT: 2
      STOP: 3

messages:
  MarketData:
    description: "Real-time market data message"
    fields:
      symbol:
        type: string
        description: "Trading symbol"
      bid:
        type: float64
        description: "Bid price"
      ask:
        type: float64
        description: "Ask price"
      last:
        type: float64
        description: "Last trade price"
      volume:
        type: uint64
        description: "Trading volume"
      timestamp:
        type: uint64
        description: "Timestamp in microseconds"
  
  OrderRequest:
    description: "Order placement request"
    fields:
      order_id:
        type: string
        description: "Unique order identifier"
      symbol:
        type: string
        description: "Trading symbol"
      side:
        type: OrderSide
        description: "Order side (buy/sell)"
      order_type:
        type: OrderType
        description: "Order type"
      quantity:
        type: uint64
        description: "Order quantity"
      price:
        type: float64
        description: "Order price (for limit orders)"
        optional: true
      timestamp:
        type: uint64
        description: "Order timestamp"

services:
  TradingService:
    description: "Trading service interface"
    methods:
      PlaceOrder:
        input: OrderRequest
        output: OrderResponse
      GetMarketData:
        input: MarketDataRequest
        output: MarketData
        streaming: true
'''

# Usage example
def generate_cross_language_protocol():
    """Generate protocol code for multiple languages."""
    
    # Save protocol definition
    with open('trading_protocol.yaml', 'w') as f:
        f.write(protocol_yaml)
    
    # Load and generate code
    protocol = ProtocolDefinition.from_file('trading_protocol.yaml')
    
    # Generate Python code
    python_code = protocol.generate_python_code()
    with open('trading_protocol.py', 'w') as f:
        f.write(python_code)
    
    # Generate JavaScript/TypeScript code
    js_code = protocol.generate_javascript_code()
    with open('trading_protocol.ts', 'w') as f:
        f.write(js_code)
    
    print("🔄 Generated protocol code:")
    print("  - trading_protocol.py (Python)")
    print("  - trading_protocol.ts (TypeScript)")
    
    # Show sample of generated Python code
    print(f"\n📝 Sample Python code (first 500 chars):")
    print(python_code[:500] + "..." if len(python_code) > 500 else python_code)

# Generate cross-language protocol
generate_cross_language_protocol()
```

## Advanced Compression and Encryption

### Domain-Specific Compression

```python
import zstandard as zstd
import lz4.frame
import brotli
from typing import Dict, Any, Optional, Callable
import pickle
import json
import msgpack

class CompressionRegistry:
    """Registry for compression algorithms."""
    
    def __init__(self):
        self.compressors: Dict[str, Callable] = {}
        self.decompressors: Dict[str, Callable] = {}
        self.dictionaries: Dict[str, bytes] = {}
        
        # Register built-in algorithms
        self._register_builtin_algorithms()
    
    def _register_builtin_algorithms(self):
        """Register built-in compression algorithms."""
        
        # Zstandard
        self.register_algorithm(
            name="zstd",
            compressor=lambda data, level=3, dict_data=None: zstd.compress(
                data, level=level, dict_data=dict_data
            ),
            decompressor=lambda data, dict_data=None: zstd.decompress(
                data, dict_data=dict_data
            )
        )
        
        # LZ4 (fastest)
        self.register_algorithm(
            name="lz4",
            compressor=lambda data, level=1, **kwargs: lz4.frame.compress(data),
            decompressor=lambda data, **kwargs: lz4.frame.decompress(data)
        )
        
        # Brotli (best compression)
        self.register_algorithm(
            name="brotli",
            compressor=lambda data, level=6, **kwargs: brotli.compress(data, quality=level),
            decompressor=lambda data, **kwargs: brotli.decompress(data)
        )
    
    def register_algorithm(self, name: str, compressor: Callable, decompressor: Callable):
        """Register compression algorithm."""
        
        self.compressors[name] = compressor
        self.decompressors[name] = decompressor
    
    def create_dictionary(self, name: str, sample_data: List[bytes], 
                         algorithm: str = "zstd") -> bytes:
        """Create compression dictionary from sample data."""
        
        if algorithm == "zstd":
            # Train Zstandard dictionary
            dict_data = zstd.train_dictionary(
                dict_size=32 * 1024,  # 32KB dictionary
                samples=sample_data
            )
            
            self.dictionaries[name] = dict_data.as_bytes()
            return dict_data.as_bytes()
        
        else:
            raise ValueError(f"Dictionary training not supported for {algorithm}")
    
    def compress(self, data: bytes, algorithm: str, 
                compression_level: int = None, 
                dictionary_name: str = None) -> bytes:
        """Compress data using specified algorithm."""
        
        if algorithm not in self.compressors:
            raise ValueError(f"Unknown compression algorithm: {algorithm}")
        
        kwargs = {}
        if compression_level is not None:
            kwargs['level'] = compression_level
        
        if dictionary_name and dictionary_name in self.dictionaries:
            kwargs['dict_data'] = self.dictionaries[dictionary_name]
        
        return self.compressors[algorithm](data, **kwargs)
    
    def decompress(self, data: bytes, algorithm: str,
                  dictionary_name: str = None) -> bytes:
        """Decompress data using specified algorithm."""
        
        if algorithm not in self.decompressors:
            raise ValueError(f"Unknown compression algorithm: {algorithm}")
        
        kwargs = {}
        if dictionary_name and dictionary_name in self.dictionaries:
            kwargs['dict_data'] = self.dictionaries[dictionary_name]
        
        return self.decompressors[algorithm](data, **kwargs)

class FinancialDataCompressor:
    """Specialized compressor for financial data."""
    
    def __init__(self, compression_registry: CompressionRegistry):
        self.registry = compression_registry
        self.trained_dictionaries = False
    
    async def train_on_market_data(self, sample_data: List[Dict[str, Any]]):
        """Train compression dictionaries on sample market data."""
        
        # Convert sample data to different serialization formats
        json_samples = [json.dumps(data).encode() for data in sample_data]
        msgpack_samples = [msgpack.packb(data) for data in sample_data]
        pickle_samples = [pickle.dumps(data) for data in sample_data]
        
        # Train dictionaries for each format
        self.registry.create_dictionary("market_data_json", json_samples)
        self.registry.create_dictionary("market_data_msgpack", msgpack_samples)
        self.registry.create_dictionary("market_data_pickle", pickle_samples)
        
        self.trained_dictionaries = True
        print("📚 Trained compression dictionaries on market data")
    
    def compress_market_data(self, data: Dict[str, Any], 
                           format: str = "msgpack",
                           algorithm: str = "zstd",
                           level: int = 3) -> bytes:
        """Compress market data with optimal settings."""
        
        # Serialize data
        if format == "json":
            serialized = json.dumps(data).encode()
            dict_name = "market_data_json" if self.trained_dictionaries else None
        
        elif format == "msgpack":
            serialized = msgpack.packb(data)
            dict_name = "market_data_msgpack" if self.trained_dictionaries else None
        
        elif format == "pickle":
            serialized = pickle.dumps(data)
            dict_name = "market_data_pickle" if self.trained_dictionaries else None
        
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        # Compress with dictionary if available
        compressed = self.registry.compress(
            serialized,
            algorithm=algorithm,
            compression_level=level,
            dictionary_name=dict_name
        )
        
        return compressed
    
    def decompress_market_data(self, data: bytes,
                             format: str = "msgpack",
                             algorithm: str = "zstd") -> Dict[str, Any]:
        """Decompress market data."""
        
        # Get dictionary name
        dict_name = None
        if self.trained_dictionaries:
            dict_name = f"market_data_{format}"
        
        # Decompress
        decompressed = self.registry.decompress(
            data,
            algorithm=algorithm,
            dictionary_name=dict_name
        )
        
        # Deserialize
        if format == "json":
            return json.loads(decompressed.decode())
        elif format == "msgpack":
            return msgpack.unpackb(decompressed, raw=False)
        elif format == "pickle":
            return pickle.loads(decompressed)
        else:
            raise ValueError(f"Unsupported format: {format}")

# Encryption integration
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class ProtocolEncryption:
    """Encryption support for custom protocols."""
    
    def __init__(self):
        self.symmetric_keys: Dict[str, bytes] = {}
        self.asymmetric_keys: Dict[str, Any] = {}
    
    def generate_symmetric_key(self, key_id: str) -> bytes:
        """Generate symmetric encryption key."""
        
        key = Fernet.generate_key()
        self.symmetric_keys[key_id] = key
        return key
    
    def generate_asymmetric_keypair(self, key_id: str) -> tuple[bytes, bytes]:
        """Generate asymmetric key pair."""
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        self.asymmetric_keys[key_id] = {
            'private': private_key,
            'public': public_key
        }
        
        return private_pem, public_pem
    
    def encrypt_data(self, data: bytes, key_id: str, 
                    method: str = "symmetric") -> bytes:
        """Encrypt data using specified key and method."""
        
        if method == "symmetric":
            if key_id not in self.symmetric_keys:
                raise ValueError(f"Symmetric key not found: {key_id}")
            
            fernet = Fernet(self.symmetric_keys[key_id])
            return fernet.encrypt(data)
        
        elif method == "asymmetric":
            if key_id not in self.asymmetric_keys:
                raise ValueError(f"Asymmetric key not found: {key_id}")
            
            public_key = self.asymmetric_keys[key_id]['public']
            
            # RSA can only encrypt small amounts of data
            # For larger data, use hybrid encryption
            if len(data) > 190:  # RSA-2048 limit minus padding
                # Generate temporary symmetric key
                temp_key = Fernet.generate_key()
                fernet = Fernet(temp_key)
                
                # Encrypt data with symmetric key
                encrypted_data = fernet.encrypt(data)
                
                # Encrypt symmetric key with RSA
                encrypted_key = public_key.encrypt(
                    temp_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Combine encrypted key and data
                return len(encrypted_key).to_bytes(4, 'big') + encrypted_key + encrypted_data
            
            else:
                return public_key.encrypt(
                    data,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
        
        else:
            raise ValueError(f"Unknown encryption method: {method}")

# Usage example
async def advanced_protocol_features_example():
    """Demonstrate advanced compression and encryption."""
    
    # Setup compression
    compression_registry = CompressionRegistry()
    financial_compressor = FinancialDataCompressor(compression_registry)
    
    # Sample market data for training
    sample_market_data = [
        {
            'symbol': 'AAPL',
            'bid': 150.25,
            'ask': 150.27,
            'last': 150.26,
            'volume': 1500000,
            'timestamp': 1677648000000
        },
        {
            'symbol': 'MSFT', 
            'bid': 280.15,
            'ask': 280.18,
            'last': 280.16,
            'volume': 980000,
            'timestamp': 1677648001000
        }
        # ... more sample data
    ] * 100  # Repeat for training
    
    # Train compression dictionaries
    await financial_compressor.train_on_market_data(sample_market_data)
    
    # Setup encryption
    encryption = ProtocolEncryption()
    symmetric_key = encryption.generate_symmetric_key("market_data_key")
    
    # Test data
    test_data = {
        'symbol': 'GOOGL',
        'bid': 2750.50,
        'ask': 2750.75,
        'last': 2750.60,
        'volume': 750000,
        'timestamp': int(time.time() * 1000)
    }
    
    print("🧪 Testing advanced protocol features:")
    print(f"Original data size: {len(str(test_data))} chars")
    
    # Test different compression formats and algorithms
    formats = ["json", "msgpack", "pickle"]
    algorithms = ["zstd", "lz4", "brotli"]
    
    results = {}
    
    for format in formats:
        for algorithm in algorithms:
            try:
                # Compress
                compressed = financial_compressor.compress_market_data(
                    test_data,
                    format=format,
                    algorithm=algorithm,
                    level=3
                )
                
                # Encrypt
                encrypted = encryption.encrypt_data(compressed, "market_data_key")
                
                # Decrypt
                decrypted = encryption.decrypt_data(encrypted, "market_data_key")
                
                # Decompress
                decompressed = financial_compressor.decompress_market_data(
                    decrypted,
                    format=format,
                    algorithm=algorithm
                )
                
                # Verify data integrity
                assert decompressed == test_data
                
                results[f"{format}_{algorithm}"] = {
                    'compressed_size': len(compressed),
                    'encrypted_size': len(encrypted),
                    'compression_ratio': len(str(test_data)) / len(compressed),
                    'total_ratio': len(str(test_data)) / len(encrypted)
                }
                
                print(f"✅ {format} + {algorithm}: {len(encrypted)} bytes "
                      f"(ratio: {results[f'{format}_{algorithm}']['total_ratio']:.2f})")
            
            except Exception as e:
                print(f"❌ {format} + {algorithm}: {e}")
    
    # Show best compression results
    best_result = min(results.items(), key=lambda x: x[1]['encrypted_size'])
    print(f"\n🏆 Best compression: {best_result[0]}")
    print(f"   Size: {best_result[1]['encrypted_size']} bytes")
    print(f"   Ratio: {best_result[1]['total_ratio']:.2f}:1")

# Usage
await advanced_protocol_features_example()
```

## Next Steps

- **[Performance Tuning](performance.md)** - Optimize protocols for maximum throughput and minimal latency
- **[Middleware](middleware.md)** - Add cross-cutting concerns to protocol processing
- **[Plugin Lifecycle](lifecycle.md)** - Manage protocol versioning and evolution
- **[Advanced Topics Overview](index.md)** - Explore other advanced plugin development topics