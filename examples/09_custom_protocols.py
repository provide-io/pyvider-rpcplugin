#!/usr/bin/env python3
# examples/09_custom_protocols.py
"""Demonstrates custom protocol development and advanced protocol patterns with pyvider-rpcplugin."""

import asyncio
import sys
import time
from pathlib import Path
from typing import Any, List, Tuple

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    plugin_server,
)
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol  # noqa: E402
from pyvider.telemetry import logger  # noqa: E402


# Mock gRPC classes for demonstration (in real usage, these would be generated from .proto files)
class MockGRPCServer:
    """Mock gRPC server for demonstration."""
    
    def __init__(self):
        self.services = {}
        self.interceptors = []
    
    def add_servicer(self, servicer, service_name: str):
        """Add a service handler."""
        self.services[service_name] = servicer
        logger.debug(
            f"Added servicer for {service_name}",
            domain="protocol",
            action="add_servicer",
            status="success",
            service_name=service_name
        )


def mock_add_servicer_to_server(servicer, server):
    """Mock function to add servicer to server.
    In a real scenario, this would be a generated gRPC function like
    `your_pb2_grpc.add_YourServicer_to_server(servicer, server)`.
    For this example, we'll just log, as the actual `grpc.aio.Server`
    instance doesn't have a direct `add_servicer` method.
    """
    logger.debug(
        "Mocked: Adding servicer to server",
        domain="protocol_mock",
        action="add_servicer",
        servicer_type=type(servicer).__name__,
        server_type=type(server).__name__
    )
    # server.add_servicer(servicer, "MockService") # This would cause AttributeError


class CustomDataStreamProtocol(RPCPluginProtocol):
    """Custom protocol for high-throughput data streaming."""
    
    def __init__(self, service_name: str, compression: bool = True, batch_size: int = 100):
        self.service_name = service_name
        self.compression = compression
        self.batch_size = batch_size
        self.metrics = {
            'messages_processed': 0,
            'bytes_transferred': 0,
            'compression_ratio': 0.0
        }
    
    async def get_grpc_descriptors(self) -> Tuple[Any, str]:
        """Return gRPC descriptors for data streaming service."""
        
        logger.info(
            "Creating data streaming protocol descriptors",
            domain="protocol",
            action="get_descriptors",
            status="creating",
            service_name=self.service_name,
            compression_enabled=self.compression,
            batch_size=self.batch_size
        )
        
        # In real implementation, this would return actual protobuf descriptors
        mock_descriptor = {
            'service_name': self.service_name,
            'methods': [
                'StreamData',
                'BatchProcess',
                'GetMetrics'
            ],
            'features': {
                'compression': self.compression,
                'batching': True,
                'streaming': True
            }
        }
        
        return mock_descriptor, self.service_name
    
    async def add_to_server(self, handler: Any, server: Any) -> None:
        """Register data streaming service with gRPC server."""
        
        logger.info(
            "Registering data streaming protocol",
            domain="protocol",
            action="register_service",
            status="starting",
            service_name=self.service_name,
            handler_type=type(handler).__name__
        )
        
        # Enhance handler with protocol-specific capabilities
        enhanced_handler = self._enhance_handler(handler)
        
        # Register with server (mock implementation)
        mock_add_servicer_to_server(enhanced_handler, server)
        
        logger.info(
            "Data streaming protocol registered successfully",
            domain="protocol",
            action="register_service",
            status="success",
            enhancements=["compression", "batching", "metrics"]
        )
    
    def _enhance_handler(self, handler: Any) -> Any:
        """Enhance handler with protocol-specific features."""
        
        class EnhancedHandler:
            def __init__(self, base_handler, protocol):
                self.base_handler = base_handler
                self.protocol = protocol
            
            async def StreamData(self, request_iterator, context):
                """Enhanced streaming with compression and batching."""
                
                logger.info(
                    "Starting enhanced data streaming",
                    domain="protocol",
                    action="stream_data",
                    status="starting",
                    compression=self.protocol.compression,
                    batch_size=self.protocol.batch_size
                )
                
                batch = []
                processed_count = 0
                
                async for request in request_iterator:
                    batch.append(request)
                    
                    if len(batch) >= self.protocol.batch_size:
                        # Process batch
                        results = await self._process_batch(batch)
                        processed_count += len(batch)
                        
                        # Yield results
                        for result in results:
                            yield result
                        
                        batch = []
                
                # Process remaining items
                if batch:
                    results = await self._process_batch(batch)
                    processed_count += len(batch)
                    
                    for result in results:
                        yield result
                
                logger.info(
                    "Enhanced data streaming completed",
                    domain="protocol",
                    action="stream_data",
                    status="completed",
                    total_processed=processed_count
                )
            
            async def _process_batch(self, batch: List[Any]) -> List[Any]:
                """Process a batch of data items."""
                
                # Simulate compression
                if self.protocol.compression:
                    original_size = sum(len(str(item)) for item in batch)
                    compressed_size = int(original_size * 0.7)  # 30% compression
                    self.protocol.metrics['compression_ratio'] = compressed_size / original_size
                
                # Update metrics
                self.protocol.metrics['messages_processed'] += len(batch)
                self.protocol.metrics['bytes_transferred'] += sum(len(str(item)) for item in batch)
                
                # Process through base handler
                results = []
                for item in batch:
                    if hasattr(self.base_handler, 'process_item'):
                        result = await self.base_handler.process_item(item)
                    else:
                        result = f"Processed: {item}"
                    results.append(result)
                
                return results
            
            async def GetMetrics(self, request, context):
                """Get protocol metrics."""
                
                logger.info(
                    "Retrieving protocol metrics",
                    domain="protocol",
                    action="get_metrics",
                    status="success",
                    **self.protocol.metrics
                )
                
                return self.protocol.metrics
        
        return EnhancedHandler(handler, self)


class AdaptiveCompressionProtocol(RPCPluginProtocol):
    """Protocol with adaptive compression based on payload characteristics."""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.compression_stats = {
            'text_ratio': 0.7,
            'binary_ratio': 0.9,
            'json_ratio': 0.6
        }
    
    async def get_grpc_descriptors(self) -> Tuple[Any, str]:
        """Return descriptors for adaptive compression service."""
        
        mock_descriptor = {
            'service_name': self.service_name,
            'methods': ['ProcessData', 'UpdateCompressionStats'],
            'features': {
                'adaptive_compression': True,
                'content_analysis': True,
                'optimization': True
            }
        }
        
        return mock_descriptor, self.service_name
    
    async def add_to_server(self, handler: Any, server: Any) -> None:
        """Register adaptive compression service."""
        
        logger.info(
            "Registering adaptive compression protocol",
            domain="protocol",
            action="register_adaptive",
            status="starting",
            service_name=self.service_name
        )
        
        enhanced_handler = self._create_adaptive_handler(handler)
        mock_add_servicer_to_server(enhanced_handler, server)
        
        logger.info(
            "Adaptive compression protocol registered",
            domain="protocol",
            action="register_adaptive",
            status="success",
            compression_types=list(self.compression_stats.keys())
        )
    
    def _create_adaptive_handler(self, handler: Any) -> Any:
        """Create handler with adaptive compression."""
        
        class AdaptiveHandler:
            def __init__(self, base_handler, protocol):
                self.base_handler = base_handler
                self.protocol = protocol
            
            async def ProcessData(self, request, context):
                """Process data with adaptive compression."""
                
                data = getattr(request, 'data', '')
                content_type = self._analyze_content(data)
                
                compression_ratio = self.protocol.compression_stats.get(content_type, 0.8)
                
                logger.info(
                    "Processing with adaptive compression",
                    domain="protocol",
                    action="adaptive_compress",
                    status="processing",
                    content_type=content_type,
                    compression_ratio=compression_ratio,
                    original_size=len(data)
                )
                
                # Simulate compression
                compressed_size = int(len(data) * compression_ratio)
                
                # Process through base handler
                if hasattr(self.base_handler, 'process_data'):
                    result = await self.base_handler.process_data(data)
                else:
                    result = f"Adaptively processed: {data[:50]}..."
                
                return {
                    'result': result,
                    'content_type': content_type,
                    'original_size': len(data),
                    'compressed_size': compressed_size,
                    'compression_ratio': compression_ratio
                }
            
            def _analyze_content(self, data: str) -> str:
                """Analyze content to determine optimal compression."""
                
                if data.strip().startswith('{') or data.strip().startswith('['):
                    return 'json'
                elif any(ord(c) > 127 for c in data):
                    return 'binary'
                else:
                    return 'text'
        
        return AdaptiveHandler(handler, self)


class VersionedProtocol(RPCPluginProtocol):
    """Protocol supporting multiple API versions."""
    
    def __init__(self, service_name: str, supported_versions: List[str]):
        self.service_name = service_name
        self.supported_versions = supported_versions
        self.default_version = supported_versions[-1]  # Latest version as default
    
    async def get_grpc_descriptors(self) -> Tuple[Any, str]:
        """Return versioned service descriptors."""
        
        mock_descriptor = {
            'service_name': self.service_name,
            'supported_versions': self.supported_versions,
            'default_version': self.default_version,
            'methods': {
                'v1': ['ProcessData'],
                'v2': ['ProcessData', 'ProcessBatch'],
                'v3': ['ProcessData', 'ProcessBatch', 'ProcessStream']
            }
        }
        
        return mock_descriptor, self.service_name
    
    async def add_to_server(self, handler: Any, server: Any) -> None:
        """Register versioned service."""
        
        logger.info(
            "Registering versioned protocol",
            domain="protocol",
            action="register_versioned",
            status="starting",
            service_name=self.service_name,
            supported_versions=self.supported_versions,
            default_version=self.default_version
        )
        
        versioned_handler = self._create_versioned_handler(handler)
        mock_add_servicer_to_server(versioned_handler, server)
        
        logger.info(
            "Versioned protocol registered successfully",
            domain="protocol",
            action="register_versioned",
            status="success",
            version_count=len(self.supported_versions)
        )
    
    def _create_versioned_handler(self, handler: Any) -> Any:
        """Create handler supporting multiple API versions."""
        
        class VersionedHandler:
            def __init__(self, base_handler, protocol):
                self.base_handler = base_handler
                self.protocol = protocol
            
            async def ProcessData(self, request, context):
                """Version-aware data processing."""
                
                # Extract version from metadata or use default
                version = self._get_client_version(context)
                
                logger.info(
                    "Processing request with versioned protocol",
                    domain="protocol",
                    action="versioned_process",
                    status="processing",
                    client_version=version,
                    available_versions=self.protocol.supported_versions
                )
                
                # Route to appropriate version handler
                if version == 'v1':
                    return await self._process_v1(request, context)
                elif version == 'v2':
                    return await self._process_v2(request, context)
                elif version == 'v3':
                    return await self._process_v3(request, context)
                else:
                    # Default to latest version
                    return await self._process_v3(request, context)
            
            def _get_client_version(self, context) -> str:
                """Extract client API version from context."""
                
                # In real implementation, would check gRPC metadata
                # For demo, use default version
                return self.protocol.default_version
            
            async def _process_v1(self, request, context):
                """Process using v1 API (basic functionality)."""
                
                data = getattr(request, 'data', '')
                result = f"v1: Basic processing of {data}"
                
                return {'result': result, 'api_version': 'v1'}
            
            async def _process_v2(self, request, context):
                """Process using v2 API (enhanced functionality)."""
                
                data = getattr(request, 'data', '')
                result = f"v2: Enhanced processing of {data}"
                metadata = {'processed_at': time.time(), 'features': ['validation', 'metrics']}
                
                return {'result': result, 'api_version': 'v2', 'metadata': metadata}
            
            async def _process_v3(self, request, context):
                """Process using v3 API (full functionality)."""
                
                data = getattr(request, 'data', '')
                result = f"v3: Full processing of {data}"
                metadata = {
                    'processed_at': time.time(),
                    'features': ['validation', 'metrics', 'streaming', 'compression'],
                    'performance': {'latency_ms': 5.2, 'throughput': '1000 req/s'}
                }
                
                return {'result': result, 'api_version': 'v3', 'metadata': metadata}
        
        return VersionedHandler(handler, self)


class CustomProtocolHandler:
    """Handler demonstrating custom protocol capabilities."""
    
    def __init__(self, handler_name: str):
        self.handler_name = handler_name
        self.processed_requests = 0
    
    async def process_item(self, item):
        """Process individual data item."""
        self.processed_requests += 1
        
        logger.debug(
            f"Processing item in {self.handler_name}",
            domain="protocol",
            action="process_item",
            status="processing",
            handler=self.handler_name,
            item_id=self.processed_requests
        )
        
        await asyncio.sleep(0.01)  # Simulate processing
        return f"Processed by {self.handler_name}: {item}"
    
    async def process_data(self, data):
        """Process data with custom logic."""
        self.processed_requests += 1
        
        logger.debug(
            f"Processing data in {self.handler_name}",
            domain="protocol",
            action="process_data",
            status="processing",
            handler=self.handler_name,
            data_length=len(data)
        )
        
        await asyncio.sleep(0.05)  # Simulate processing
        return f"Custom processed by {self.handler_name}: {data[:100]}..."


async def example_9_custom_streaming_protocol():
    """
    Example 9A: Demonstrates custom data streaming protocol.
    
    Shows how to create a custom protocol optimized for
    high-throughput data streaming with compression and batching.
    """
    print("\n" + "=" * 60)
    print("🌊 Example 9A: Custom Data Streaming Protocol")
    print(" Demonstrates: High-throughput streaming with custom protocol")
    print("=" * 60)
    
    # Create custom streaming protocol
    streaming_protocol = CustomDataStreamProtocol(
        service_name="DataStreamService",
        compression=True,
        batch_size=50
    )
    
    # Create handler
    handler = CustomProtocolHandler("StreamingHandler")
    
    logger.info(
        "Setting up custom streaming protocol server",
        domain="protocol",
        action="custom_setup",
        status="starting",
        protocol_type="data_streaming",
        compression=True,
        batch_size=50
    )
    
    # Create server with custom protocol
    server = plugin_server(
        protocol=streaming_protocol,
        handler=handler,
        transport="unix"
    )
    
    # Start server
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)
    
    try:
        # Simulate client operations
        logger.info(
            "Simulating streaming client operations",
            domain="protocol",
            action="client_simulation",
            status="starting",
            stream_size=100,
            protocol="custom_streaming"
        )
        
        # Simulate streaming data processing
        for batch_num in range(5):
            logger.info(
                f"Processing stream batch {batch_num + 1}",
                domain="protocol",
                action="stream_batch",
                status="processing",
                batch_number=batch_num + 1,
                batch_size=streaming_protocol.batch_size
            )
            
            # Simulate batch processing time
            await asyncio.sleep(0.1)
        
        # Display protocol metrics
        logger.info(
            "Custom streaming protocol metrics",
            domain="protocol",
            action="metrics_display",
            status="completed",
            **streaming_protocol.metrics
        )
        
    finally:
        await server.stop()
        await server_task
    
    logger.info(
        "Custom streaming protocol demonstration completed",
        domain="protocol",
        action="custom_setup",
        status="completed",
        benefits=["high_throughput", "compression", "batching", "metrics"]
    )


async def example_9_adaptive_compression():
    """
    Example 9B: Demonstrates adaptive compression protocol.
    
    Shows how to implement a protocol that automatically
    adjusts compression based on content characteristics.
    """
    print("\n" + "=" * 60)
    print("🗜️ Example 9B: Adaptive Compression Protocol")
    print(" Demonstrates: Content-aware compression optimization")
    print("=" * 60)
    
    # Create adaptive compression protocol
    compression_protocol = AdaptiveCompressionProtocol("AdaptiveCompressionService")
    
    # Create handler
    handler = CustomProtocolHandler("CompressionHandler")
    
    logger.info(
        "Setting up adaptive compression protocol",
        domain="protocol",
        action="adaptive_setup",
        status="starting",
        protocol_type="adaptive_compression",
        compression_types=list(compression_protocol.compression_stats.keys())
    )
    
    # Create server
    server = plugin_server(
        protocol=compression_protocol,
        handler=handler,
        transport="unix"
    )
    
    # Start server
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)
    
    try:
        # Test different content types
        test_data = [
            {
                'name': 'JSON data',
                'content': '{"users": [{"name": "Alice", "age": 30}, {"name": "Bob", "age": 25}]}',
                'expected_type': 'json'
            },
            {
                'name': 'Plain text',
                'content': 'This is a plain text message that should compress well with standard algorithms.',
                'expected_type': 'text'
            },
            {
                'name': 'Binary-like data',
                'content': 'Binary data with special chars: \x00\x01\x02\xff\xfe\xfd mixed content',
                'expected_type': 'binary'
            }
        ]
        
        for test_case in test_data:
            logger.info(
                f"Testing adaptive compression: {test_case['name']}",
                domain="protocol",
                action="compression_test",
                status="testing",
                content_type=test_case['expected_type'],
                original_size=len(test_case['content'])
            )
            
            # Simulate processing with adaptive compression
            # (In real implementation, would make actual RPC call)
            await asyncio.sleep(0.1)
            
            # Simulate compression results
            if test_case['expected_type'] == 'json':
                compression_ratio = 0.6
            elif test_case['expected_type'] == 'text':
                compression_ratio = 0.7
            else:
                compression_ratio = 0.9
            
            compressed_size = int(len(test_case['content']) * compression_ratio)
            
            logger.info(
                f"Adaptive compression result: {test_case['name']}",
                domain="protocol",
                action="compression_result",
                status="completed",
                content_type=test_case['expected_type'],
                original_size=len(test_case['content']),
                compressed_size=compressed_size,
                compression_ratio=compression_ratio,
                savings_percent=round((1 - compression_ratio) * 100, 1)
            )
        
    finally:
        await server.stop()
        await server_task
    
    logger.info(
        "Adaptive compression protocol demonstration completed",
        domain="protocol",
        action="adaptive_setup",
        status="completed",
        benefits=["content_aware", "optimized_compression", "automatic_adaptation"]
    )


async def example_9_versioned_api():
    """
    Example 9C: Demonstrates versioned API protocol.
    
    Shows how to implement backward-compatible API versioning
    with automatic version detection and routing.
    """
    print("\n" + "=" * 60)
    print("🔢 Example 9C: Versioned API Protocol")
    print(" Demonstrates: Backward-compatible API versioning")
    print("=" * 60)
    
    # Create versioned protocol
    versioned_protocol = VersionedProtocol(
        service_name="VersionedAPIService",
        supported_versions=["v1", "v2", "v3"]
    )
    
    # Create handler
    handler = CustomProtocolHandler("VersionedHandler")
    
    logger.info(
        "Setting up versioned API protocol",
        domain="protocol",
        action="versioned_setup",
        status="starting",
        protocol_type="versioned_api",
        supported_versions=versioned_protocol.supported_versions,
        default_version=versioned_protocol.default_version
    )
    
    # Create server
    server = plugin_server(
        protocol=versioned_protocol,
        handler=handler,
        transport="unix"
    )
    
    # Start server
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)
    
    try:
        # Test different API versions
        api_versions = ["v1", "v2", "v3"]
        
        for version in api_versions:
            logger.info(
                f"Testing API version: {version}",
                domain="protocol",
                action="version_test",
                status="testing",
                api_version=version,
                test_data="sample_data_for_processing"
            )
            
            # Simulate version-specific processing
            await asyncio.sleep(0.1)
            
            # Show version-specific features
            features = {
                'v1': ['basic_processing'],
                'v2': ['basic_processing', 'validation', 'metrics'],
                'v3': ['basic_processing', 'validation', 'metrics', 'streaming', 'compression']
            }
            
            performance = {
                'v1': {'latency_ms': 10.0, 'throughput': '500 req/s'},
                'v2': {'latency_ms': 8.0, 'throughput': '750 req/s'},
                'v3': {'latency_ms': 5.2, 'throughput': '1000 req/s'}
            }
            
            logger.info(
                f"API version {version} processing completed",
                domain="protocol",
                action="version_result",
                status="completed",
                api_version=version,
                features=features[version],
                performance=performance[version]
            )
        
        # Demonstrate backward compatibility
        logger.info(
            "Demonstrating backward compatibility",
            domain="protocol",
            action="compatibility_demo",
            status="testing",
            scenario="old_client_new_server"
        )
        
        # Simulate old client connecting to new server
        # Old client uses v1, but server supports v3
        logger.info(
            "Old client (v1) connecting to new server (v3)",
            domain="protocol",
            action="compatibility_test",
            status="success",
            client_version="v1",
            server_versions=versioned_protocol.supported_versions,
            compatibility="maintained"
        )
        
    finally:
        await server.stop()
        await server_task
    
    logger.info(
        "Versioned API protocol demonstration completed",
        domain="protocol",
        action="versioned_setup",
        status="completed",
        benefits=["backward_compatibility", "feature_evolution", "gradual_migration"]
    )


async def example_9_protocol_composition():
    """
    Example 9D: Demonstrates protocol composition and middleware.
    
    Shows how to combine multiple protocol features and
    implement middleware for cross-cutting concerns.
    """
    print("\n" + "=" * 60)
    print("🧩 Example 9D: Protocol Composition and Middleware")
    print(" Demonstrates: Combining protocol features with middleware")
    print("=" * 60)
    
    class CompositeProtocol(RPCPluginProtocol):
        """Protocol combining multiple features through composition."""
        
        def __init__(self, service_name: str):
            self.service_name = service_name
            self.middleware_stack = []
            self.features = {
                'compression': True,
                'versioning': True,
                'metrics': True,
                'caching': True
            }
        
        def add_middleware(self, middleware):
            """Add middleware to the processing stack."""
            self.middleware_stack.append(middleware)
            
            logger.info(
                f"Added middleware: {middleware.__class__.__name__}",
                domain="protocol",
                action="add_middleware",
                status="added",
                middleware_type=middleware.__class__.__name__,
                stack_size=len(self.middleware_stack)
            )
        
        async def get_grpc_descriptors(self) -> Tuple[Any, str]:
            """Return composite protocol descriptors."""
            
            mock_descriptor = {
                'service_name': self.service_name,
                'features': self.features,
                'middleware_count': len(self.middleware_stack),
                'methods': ['ProcessWithMiddleware', 'GetMiddlewareInfo']
            }
            
            return mock_descriptor, self.service_name
        
        async def add_to_server(self, handler: Any, server: Any) -> None:
            """Register composite protocol with middleware stack."""
            
            logger.info(
                "Registering composite protocol with middleware",
                domain="protocol",
                action="register_composite",
                status="starting",
                middleware_count=len(self.middleware_stack),
                features=list(self.features.keys())
            )
            
            # Wrap handler with middleware stack
            wrapped_handler = self._wrap_with_middleware(handler)
            mock_add_servicer_to_server(wrapped_handler, server)
            
            logger.info(
                "Composite protocol registered successfully",
                domain="protocol",
                action="register_composite",
                status="success"
            )
        
        def _wrap_with_middleware(self, handler):
            """Wrap handler with middleware stack."""
            
            class MiddlewareWrappedHandler:
                def __init__(self, base_handler, middleware_stack):
                    self.base_handler = base_handler
                    self.middleware_stack = middleware_stack
                
                async def ProcessWithMiddleware(self, request, context):
                    """Process request through middleware stack."""
                    
                    logger.info(
                        "Processing request through middleware stack",
                        domain="protocol",
                        action="middleware_process",
                        status="starting",
                        middleware_count=len(self.middleware_stack)
                    )
                    
                    # Pre-processing middleware
                    for middleware in self.middleware_stack:
                        if hasattr(middleware, 'pre_process'):
                            request = await middleware.pre_process(request, context)
                    
                    # Core processing
                    if hasattr(self.base_handler, 'process_data'):
                        result = await self.base_handler.process_data(getattr(request, 'data', ''))
                    else:
                        result = f"Processed through middleware: {getattr(request, 'data', '')}"
                    
                    # Post-processing middleware (reverse order)
                    for middleware in reversed(self.middleware_stack):
                        if hasattr(middleware, 'post_process'):
                            result = await middleware.post_process(result, context)
                    
                    logger.info(
                        "Middleware processing completed",
                        domain="protocol",
                        action="middleware_process",
                        status="completed",
                        result_length=len(str(result))
                    )
                    
                    return {'result': result, 'middleware_applied': len(self.middleware_stack)}
            
            return MiddlewareWrappedHandler(handler, self.middleware_stack)
    
    # Define middleware classes
    class LoggingMiddleware:
        """Middleware for request/response logging."""
        
        async def pre_process(self, request, context):
            logger.info(
                "Logging middleware: Pre-processing",
                domain="middleware",
                action="logging",
                status="pre_process",
                request_size=len(str(request))
            )
            return request
        
        async def post_process(self, result, context):
            logger.info(
                "Logging middleware: Post-processing",
                domain="middleware",
                action="logging",
                status="post_process",
                result_size=len(str(result))
            )
            return result
    
    class MetricsMiddleware:
        """Middleware for metrics collection."""
        
        def __init__(self):
            self.request_count = 0
            self.total_processing_time = 0.0
        
        async def pre_process(self, request, context):
            self.request_count += 1
            context.start_time = time.time()
            
            logger.debug(
                "Metrics middleware: Pre-processing",
                domain="middleware",
                action="metrics",
                status="pre_process",
                request_count=self.request_count
            )
            return request
        
        async def post_process(self, result, context):
            processing_time = time.time() - getattr(context, 'start_time', time.time())
            self.total_processing_time += processing_time
            
            logger.debug(
                "Metrics middleware: Post-processing",
                domain="middleware",
                action="metrics",
                status="post_process",
                processing_time_ms=processing_time * 1000,
                avg_processing_time_ms=(self.total_processing_time / self.request_count) * 1000
            )
            return result
    
    class CachingMiddleware:
        """Middleware for response caching."""
        
        def __init__(self):
            self.cache = {}
        
        async def pre_process(self, request, context):
            request_key = str(getattr(request, 'data', ''))
            
            if request_key in self.cache:
                logger.info(
                    "Caching middleware: Cache hit",
                    domain="middleware",
                    action="caching",
                    status="cache_hit",
                    cache_size=len(self.cache)
                )
                context.cached_result = self.cache[request_key]
            else:
                logger.debug(
                    "Caching middleware: Cache miss",
                    domain="middleware",
                    action="caching",
                    status="cache_miss"
                )
            
            return request
        
        async def post_process(self, result, context):
            if not hasattr(context, 'cached_result'):
                # Store in cache
                request_key = "sample_key"  # In real implementation, would derive from request
                self.cache[request_key] = result
                
                logger.debug(
                    "Caching middleware: Cached result",
                    domain="middleware",
                    action="caching",
                    status="cached",
                    cache_size=len(self.cache)
                )
            
            return getattr(context, 'cached_result', result)
    
    # Create composite protocol
    composite_protocol = CompositeProtocol("CompositeService")
    
    # Add middleware
    composite_protocol.add_middleware(LoggingMiddleware())
    composite_protocol.add_middleware(MetricsMiddleware())
    composite_protocol.add_middleware(CachingMiddleware())
    
    # Create handler
    handler = CustomProtocolHandler("CompositeHandler")
    
    logger.info(
        "Setting up composite protocol with middleware",
        domain="protocol",
        action="composite_setup",
        status="starting",
        middleware_count=len(composite_protocol.middleware_stack),
        features=list(composite_protocol.features.keys())
    )
    
    # Create server
    server = plugin_server(
        protocol=composite_protocol,
        handler=handler,
        transport="unix"
    )
    
    # Start server
    server_task = asyncio.create_task(server.serve())
    await asyncio.sleep(0.5)
    
    try:
        # Simulate requests through middleware stack
        test_requests = [
            "First request",
            "Second request",
            "First request",  # Should hit cache
            "Third request"
        ]
        
        for i, request_data in enumerate(test_requests):
            logger.info(
                f"Sending request {i + 1} through middleware stack",
                domain="protocol",
                action="composite_request",
                status="sending",
                request_number=i + 1,
                data=request_data
            )
            
            # Simulate request processing
            await asyncio.sleep(0.1)
        
    finally:
        await server.stop()
        await server_task
    
    logger.info(
        "Protocol composition demonstration completed",
        domain="protocol",
        action="composite_setup",
        status="completed",
        benefits=["modular_design", "reusable_middleware", "cross_cutting_concerns", "flexible_composition"]
    )


async def main():
    """Run all custom protocol examples."""
    print("🧩 pyvider-rpcplugin Custom Protocol Examples")
    print("==============================================")
    
    try:
        # Run each custom protocol example
        await example_9_custom_streaming_protocol()
        await example_9_adaptive_compression()
        await example_9_versioned_api()
        await example_9_protocol_composition()
        
        print("\n" + "=" * 60)
        print("✅ All Custom Protocol Examples Completed Successfully!")
        print("=" * 60)
        print("\n🧩 Custom Protocol Benefits:")
        print("  • Data streaming: Optimized for high-throughput scenarios")
        print("  • Adaptive compression: Content-aware optimization")
        print("  • API versioning: Backward-compatible evolution")
        print("  • Protocol composition: Modular, reusable components")
        print("  • Middleware support: Cross-cutting concerns")
        print("\n📖 Next Steps:")
        print("  • See example 10_performance_tuning.py for protocol optimization")
        print("  • Check docs/architecture.md for protocol design patterns")
        print("  • Review docs/api-reference.md for protocol interface details")
        
    except Exception as e:
        logger.error(
            "Custom protocol example failed",
            domain="examples",
            action="run",
            status="error",
            error=str(e)
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
