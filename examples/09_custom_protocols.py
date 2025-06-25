#!/usr/bin/env python3
# examples/09_custom_protocols.py
"""Custom protocol development and advanced patterns with pyvider-rpcplugin."""

import asyncio
import sys
import time
from collections.abc import AsyncGenerator as AbcAsyncGenerator
from pathlib import Path
from typing import Any, cast

import grpc  # For ServicerContext
from attrs import define, field

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from example_utils import configure_for_example, clear_plugin_env_vars # noqa: E402
from pyvider.rpcplugin import (  # noqa: E402
    plugin_server,
)
from pyvider.rpcplugin.protocol.base import RPCPluginProtocol  # noqa: E402
from pyvider.rpcplugin.server import RPCPluginServer  # noqa: E402 # For type hint
from pyvider.rpcplugin.types import (  # noqa: E402 # For type hint
    RPCPluginProtocol as TypesRPCPluginProtocol,
)
from pyvider.telemetry import logger  # noqa: E402


# Mock gRPC classes for demonstration
class MockGRPCServer:
    services: dict[str, Any] = {}
    interceptors: list[Any] = []

    def __init__(self) -> None:
        self.services = {}
        self.interceptors = []

    def add_servicer(self, servicer: Any, service_name: str) -> None:
        self.services[service_name] = servicer


def mock_add_servicer_to_server(servicer: Any, server: Any) -> None:
    logger.debug(f"Mocked: Adding {type(servicer).__name__} to {type(server).__name__}")


@define(frozen=True, slots=True)
class CustomReply:  # Generic reply for examples
    result: str = field()


class CustomDataStreamProtocol(RPCPluginProtocol):
    service_name: str
    compression: bool
    batch_size: int
    metrics: dict[str, Any]

    def __init__(
        self, service_name: str, compression: bool = True, batch_size: int = 100
    ) -> None:
        self.service_name = service_name
        self.compression = compression
        self.batch_size = batch_size
        self.metrics = {
            "messages_processed": 0,
            "bytes_transferred": 0,
            "compression_ratio": 0.0,
        }

    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        return ({"s": self.service_name}, self.service_name)

    def get_method_type(self, method_name: str) -> str:
        return "unary_unary"

    async def add_to_server(self, server: Any, handler: Any) -> None:
        mock_add_servicer_to_server(self._enhance_handler(handler), server)

    def _enhance_handler(self, handler: Any) -> Any:
        class EnhancedHandler:
            def __init__(
                self_eh: Any, base_h: Any, proto: CustomDataStreamProtocol
            ) -> None:
                self_eh.bh = base_h
                self_eh.p = proto

            async def StreamData(
                self_eh: Any,
                req_iter: AbcAsyncGenerator[Any],
                ctx: grpc.aio.ServicerContext,
            ) -> AbcAsyncGenerator[CustomReply]:
                yield CustomReply("stream_data")

            async def GetMetrics(
                self_eh: Any, req: Any, ctx: grpc.aio.ServicerContext
            ) -> dict[str, Any]:
                return self_eh.p.metrics

        return EnhancedHandler(handler, self)


class AdaptiveCompressionProtocol(RPCPluginProtocol):
    service_name: str
    compression_stats: dict[str, float]

    def __init__(self, service_name: str) -> None:
        self.service_name = service_name
        self.compression_stats = {"text": 0.7, "bin": 0.9, "json": 0.6}

    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        return ({}, self.service_name)

    def get_method_type(self, method_name: str) -> str:
        return "unary_unary"

    async def add_to_server(self, server: Any, handler: Any) -> None:
        mock_add_servicer_to_server(self._create_adaptive_handler(handler), server)

    def _create_adaptive_handler(self, handler: Any) -> Any:
        class AdaptiveHandler:
            def __init__(
                self_ah: Any, base_h: Any, proto: AdaptiveCompressionProtocol
            ) -> None:
                self_ah.bh = base_h
                self_ah.p = proto

            async def ProcessData(
                self_ah: Any, req: Any, ctx: grpc.aio.ServicerContext
            ) -> dict[str, Any]:
                return {"res": "adapt_ok"}

            def _analyze_content(self_ah: Any, data: str) -> str:
                return "text"

        return AdaptiveHandler(handler, self)


class VersionedProtocol(RPCPluginProtocol):
    service_name: str
    supported_versions: list[str]
    default_version: str

    def __init__(self, service_name: str, supported_versions: list[str]) -> None:
        self.service_name = service_name
        self.supported_versions = supported_versions
        self.default_version = supported_versions[-1] if supported_versions else "v1"

    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        return ({}, self.service_name)

    def get_method_type(self, method_name: str) -> str:
        return "unary_unary"

    async def add_to_server(self, server: Any, handler: Any) -> None:
        mock_add_servicer_to_server(self._create_versioned_handler(handler), server)

    def _create_versioned_handler(self, handler: Any) -> Any:
        class VersionedHandler:
            def __init__(self_vh: Any, base_h: Any, proto: VersionedProtocol) -> None:
                self_vh.bh = base_h
                self_vh.p = proto

            async def ProcessData(
                self_vh: Any, req: Any, ctx: grpc.aio.ServicerContext
            ) -> dict[str, Any]:
                return {"res": "version_ok"}

            def _get_client_version(self_vh: Any, ctx: grpc.aio.ServicerContext) -> str:
                return self_vh.p.default_version

        return VersionedHandler(handler, self)


class CustomProtocolHandler:
    handler_name: str
    processed_requests: int

    def __init__(self, handler_name: str) -> None:
        self.handler_name = handler_name
        self.processed_requests = 0

    async def process_item(self, item: Any) -> str:
        self.processed_requests += 1
        return f"Item: {item}"

    async def process_data(self, data: Any) -> str:
        self.processed_requests += 1
        return f"Data: {data}"


async def example_9_custom_streaming_protocol() -> None:
    clear_plugin_env_vars()
    configure_for_example(PLUGIN_MAGIC_COOKIE_VALUE="custom-streaming-cookie-09a")
    streaming_protocol = CustomDataStreamProtocol("DataStreamService")
    handler = CustomProtocolHandler("StreamingHandler")
    server: RPCPluginServer = plugin_server(
        protocol=cast(TypesRPCPluginProtocol, streaming_protocol),
        handler=handler,
        transport="unix", # Uses config from configure_for_example
    )
    server_task = asyncio.create_task(server.serve())
    await server.wait_for_server_ready(timeout=5.0)
    try:
        logger.info("Simulating streaming client ops for custom_streaming_protocol...")
        # Add a small delay to simulate work or client interaction
        await asyncio.sleep(0.1)
    finally:
        await server.stop()
        await server_task


async def example_9_adaptive_compression() -> None:
    clear_plugin_env_vars()
    configure_for_example(PLUGIN_MAGIC_COOKIE_VALUE="adaptive-compression-cookie-09b")
    compression_protocol = AdaptiveCompressionProtocol("AdaptiveService")
    handler = CustomProtocolHandler("CompressionHandler")
    server: RPCPluginServer = plugin_server(
        protocol=cast(TypesRPCPluginProtocol, compression_protocol),
        handler=handler,
        transport="unix",
    )
    server_task = asyncio.create_task(server.serve())
    await server.wait_for_server_ready(timeout=5.0)
    try:
        logger.info("Simulating adaptive client ops for adaptive_compression...")
        await asyncio.sleep(0.1)
    finally:
        await server.stop()
        await server_task


async def example_9_versioned_api() -> None:
    clear_plugin_env_vars()
    configure_for_example(PLUGIN_MAGIC_COOKIE_VALUE="versioned-api-cookie-09c")
    versioned_protocol = VersionedProtocol("VersionedService", ["v1", "v2"])
    handler = CustomProtocolHandler("VersionedHandler")
    server: RPCPluginServer = plugin_server(
        protocol=cast(TypesRPCPluginProtocol, versioned_protocol),
        handler=handler,
        transport="unix",
    )
    server_task = asyncio.create_task(server.serve())
    await server.wait_for_server_ready(timeout=5.0)
    try:
        logger.info("Simulating versioned client ops for versioned_api...")
        await asyncio.sleep(0.1)
    finally:
        await server.stop()
        await server_task


class CompositeProtocol(RPCPluginProtocol):
    service_name: str
    middleware_stack: list[Any]
    features: dict[str, bool]

    def __init__(self, service_name: str) -> None:
        self.service_name = service_name
        self.middleware_stack = []
        self.features = {"c": True}

    def add_middleware(self, middleware: Any) -> None:
        self.middleware_stack.append(middleware)

    async def get_grpc_descriptors(self) -> tuple[Any, str]:
        return ({}, self.service_name)

    def get_method_type(self, method_name: str) -> str:
        return "unary_unary"

    async def add_to_server(self, server: Any, handler: Any) -> None:
        mock_add_servicer_to_server(self._wrap_with_middleware(handler), server)

    def _wrap_with_middleware(self, handler: Any) -> Any:
        class MiddlewareWrappedHandler:
            def __init__(self_mwh: Any, base_h: Any, mw_s: list[Any]) -> None:
                self_mwh.bh = base_h
                self_mwh.mws = mw_s

            async def ProcessWithMiddleware(
                self_mwh: Any, req: Any, ctx: grpc.aio.ServicerContext
            ) -> dict[str, Any]:
                return {"res": "composite_ok"}

        return MiddlewareWrappedHandler(handler, self.middleware_stack)


class LoggingMiddleware:
    async def pre_process(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        return request

    async def post_process(self, result: Any, context: grpc.aio.ServicerContext) -> Any:
        return result


class MetricsMiddleware:
    rc: int
    tpt: float  # Shortened names

    def __init__(self) -> None:
        self.rc = 0
        self.tpt = 0.0

    async def pre_process(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        self.rc += 1
        context.st = time.time()
        return request  # Shortened

    async def post_process(self, result: Any, context: grpc.aio.ServicerContext) -> Any:
        return result


class CachingMiddleware:
    cache: dict[str, Any]

    def __init__(self) -> None:
        self.cache = {}

    async def pre_process(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        return request

    async def post_process(self, result: Any, context: grpc.aio.ServicerContext) -> Any:
        return result


async def example_9_protocol_composition() -> None:
    clear_plugin_env_vars()
    configure_for_example(PLUGIN_MAGIC_COOKIE_VALUE="protocol-composition-cookie-09d")
    composite_protocol = CompositeProtocol("CompositeService")
    composite_protocol.add_middleware(LoggingMiddleware())
    composite_protocol.add_middleware(MetricsMiddleware())
    handler = CustomProtocolHandler("CompositeHandler")
    server: RPCPluginServer = plugin_server(
        protocol=cast(TypesRPCPluginProtocol, composite_protocol),
        handler=handler,
        transport="unix",
    )
    server_task = asyncio.create_task(server.serve())
    await server.wait_for_server_ready(timeout=5.0)
    try:
        logger.info("Simulating composite client ops for protocol_composition...")
        await asyncio.sleep(0.1)
    finally:
        await server.stop()
        await server_task


async def main() -> None:
    print("🧩 pyvider-rpcplugin Custom Protocol Examples")
    try:
        await example_9_custom_streaming_protocol()
        await example_9_adaptive_compression()
        await example_9_versioned_api()
        await example_9_protocol_composition()
        print("✅ All Custom Protocol Examples Completed Successfully!")
    except Exception as e:
        logger.error("Custom protocol example failed", error=str(e))
        raise


if __name__ == "__main__":
    asyncio.run(main())
