#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 provide.io llc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#

"""Advanced RPC Plugin Example

Demonstrates:
- Rate limiting with token bucket
- OpenTelemetry integration for tracing
- Type-safe implementation with protocols
- mTLS security
- Health checks
- Comprehensive error handling
- Structured logging with Foundation

This example shows a production-ready plugin implementation
with all advanced features enabled."""

import asyncio
import os
from typing import Any, Protocol, runtime_checkable

from attrs import define, field
import grpc.aio
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from provide.foundation import logger
from provide.foundation.utils.rate_limiting import TokenBucketRateLimiter

from pyvider.rpcplugin import plugin_protocol, plugin_server
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin.telemetry import get_rpc_tracer
from pyvider.rpcplugin.types import RPCPluginHandler

# Configure environment for advanced features
os.environ.update(
    {
        # Enable rate limiting
        "PLUGIN_RATE_LIMIT_ENABLED": "true",
        "PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND": "100",
        "PLUGIN_RATE_LIMIT_BURST_CAPACITY": "200",
        # Enable health checks
        "PLUGIN_HEALTH_SERVICE_ENABLED": "true",
        # Configure logging
        "PLUGIN_LOG_LEVEL": "INFO",
        "PLUGIN_LOG_FORMAT": "json",
        # Security settings (for production, use real certificates)
        "PLUGIN_AUTO_MTLS": "false",  # Set to true with proper certs in production
        # gRPC configuration
        "PLUGIN_GRPC_MAX_CONCURRENT_STREAMS": "500",
        "PLUGIN_GRPC_KEEPALIVE_TIME": "30000",
    }
)


# Type-safe protocol definition
@runtime_checkable
class DataProcessor(Protocol):
    """Protocol for data processing services."""

    async def process(self, data: dict[str, Any]) -> dict[str, Any]:
        """Process data and return result."""
        ...

    async def validate(self, data: dict[str, Any]) -> bool:
        """Validate data before processing."""
        ...


@define
class AdvancedHandler:
    """
    Advanced handler with all features enabled.

    Attributes:
        name: Handler identifier
        tracer: OpenTelemetry tracer for distributed tracing
        rate_limiter: Custom rate limiter for specific operations
        metrics: Dictionary storing operational metrics
    """

    name: str = field(default="AdvancedHandler")
    tracer: trace.Tracer = field(factory=get_rpc_tracer)
    rate_limiter: TokenBucketRateLimiter = field(init=False)
    metrics: dict[str, int] = field(factory=dict)

    def __attrs_post_init__(self) -> None:
        """Initialize handler components."""
        # Custom rate limiter for expensive operations
        self.rate_limiter = TokenBucketRateLimiter(tokens_per_second=10, bucket_size=20)

        # Initialize metrics
        self.metrics = {
            "requests_processed": 0,
            "requests_failed": 0,
            "requests_rate_limited": 0,
        }

        logger.info(
            "Advanced handler initialized",
            handler_name=self.name,
            rate_limit_tps=10,
            features=["telemetry", "rate_limiting", "health_checks"],
        )

    async def process_request(
        self, request: dict[str, Any], context: grpc.aio.ServicerContext
    ) -> dict[str, Any]:
        """
        Process incoming request with full telemetry and rate limiting.

        Args:
            request: The request data
            context: gRPC context with metadata

        Returns:
            Processed response data

        Raises:
            grpc.RpcError: On processing errors
        """
        # Start trace span
        with self.tracer.start_as_current_span("process_request", kind=trace.SpanKind.SERVER) as span:
            # Add trace attributes
            span.set_attribute("handler.name", self.name)
            span.set_attribute("request.id", request.get("id", "unknown"))
            span.set_attribute("request.type", request.get("type", "unknown"))

            # Extract client metadata
            metadata = dict(context.invocation_metadata())
            client_id = metadata.get("client-id", "unknown")
            span.set_attribute("client.id", client_id)

            try:
                # Validate request
                if not await self._validate_request(request):
                    span.set_status(Status(StatusCode.ERROR, "Invalid request"))
                    await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Request validation failed")

                # Check rate limit for expensive operations
                if request.get("expensive", False) and not await self.rate_limiter.acquire():
                    self.metrics["requests_rate_limited"] += 1
                    span.set_status(Status(StatusCode.ERROR, "Rate limited"))

                    logger.warning(
                        "Rate limit exceeded for expensive operation",
                        client_id=client_id,
                        remaining_tokens=self.rate_limiter.available_tokens,
                    )

                    await context.abort(
                        grpc.StatusCode.RESOURCE_EXHAUSTED,
                        "Rate limit exceeded for expensive operations. Please retry with backoff.",
                    )

                # Process the request
                result = await self._do_processing(request, span)

                # Update metrics
                self.metrics["requests_processed"] += 1

                # Log success with trace correlation
                logger.info(
                    "Request processed successfully",
                    request_id=request.get("id"),
                    client_id=client_id,
                    trace_id=format(span.get_span_context().trace_id, "032x"),
                    processing_time_ms=result.get("processing_time_ms"),
                )

                span.set_status(Status(StatusCode.OK))
                return result

            except Exception as e:
                # Record exception in trace
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))

                # Update metrics
                self.metrics["requests_failed"] += 1

                # Log error with full context
                logger.error(
                    "Request processing failed",
                    error=str(e),
                    error_type=type(e).__name__,
                    request_id=request.get("id"),
                    client_id=client_id,
                    trace_id=format(span.get_span_context().trace_id, "032x"),
                    exc_info=True,
                )

                # Return appropriate gRPC error
                if isinstance(e, ValueError):
                    await context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(e))
                else:
                    await context.abort(grpc.StatusCode.INTERNAL, "Internal processing error")

    async def _validate_request(self, request: dict[str, Any]) -> bool:
        """
        Validate request data.

        Args:
            request: Request to validate

        Returns:
            True if valid, False otherwise
        """
        with self.tracer.start_as_current_span("validate_request") as span:
            span.set_attribute("request.keys", str(request.keys()))

            # Check required fields
            required_fields = ["id", "data"]
            for field in required_fields:
                if field not in request:
                    span.set_attribute("validation.error", f"Missing field: {field}")
                    return False

            # Validate data type
            if not isinstance(request["data"], (str, dict)):
                span.set_attribute("validation.error", "Invalid data type")
                return False

            span.set_attribute("validation.result", "valid")
            return True

    async def _do_processing(self, request: dict[str, Any], parent_span: trace.Span) -> dict[str, Any]:
        """
        Perform actual processing with nested tracing.

        Args:
            request: Request to process
            parent_span: Parent trace span

        Returns:
            Processing result
        """
        import time

        start_time = time.time()

        with self.tracer.start_as_current_span(
            "do_processing", context=trace.set_span_in_context(parent_span)
        ) as span:
            span.set_attribute("processing.type", request.get("type", "default"))

            # Simulate processing based on type
            processing_type = request.get("type", "default")

            if processing_type == "compute":
                # CPU-intensive operation
                await self._compute_operation(request["data"])

            elif processing_type == "io":
                # I/O operation
                await self._io_operation(request["data"])

            else:
                # Default processing
                await asyncio.sleep(0.1)

            processing_time_ms = (time.time() - start_time) * 1000
            span.set_attribute("processing.duration_ms", processing_time_ms)

            return {
                "id": request["id"],
                "status": "success",
                "processed_data": f"Processed: {request['data']}",
                "processing_time_ms": processing_time_ms,
                "handler": self.name,
                "metrics": dict(self.metrics),  # Include current metrics
            }

    async def _compute_operation(self, data: Any) -> None:
        """Simulate CPU-intensive operation."""
        with self.tracer.start_as_current_span("compute_operation") as span:
            span.set_attribute("operation.type", "compute")
            # Simulate computation
            await asyncio.sleep(0.2)

    async def _io_operation(self, data: Any) -> None:
        """Simulate I/O operation."""
        with self.tracer.start_as_current_span("io_operation") as span:
            span.set_attribute("operation.type", "io")
            # Simulate I/O
            await asyncio.sleep(0.15)

    async def health_check(self) -> dict[str, Any]:
        """
        Perform health check.

        Returns:
            Health status and metrics
        """
        return {
            "status": "healthy",
            "handler": self.name,
            "metrics": dict(self.metrics),
            "rate_limiter": {
                "available_tokens": self.rate_limiter.available_tokens,
                "bucket_size": self.rate_limiter.bucket_size,
            },
            "config": {
                "rate_limiting_enabled": rpcplugin_config.plugin_rate_limit_enabled,
                "health_checks_enabled": rpcplugin_config.plugin_health_service_enabled,
                "log_level": rpcplugin_config.plugin_log_level,
            },
        }


async def main() -> None:
    """Main entry point for the advanced plugin."""
    logger.info(
        "Starting advanced RPC plugin server",
        features={
            "rate_limiting": rpcplugin_config.plugin_rate_limit_enabled,
            "health_checks": rpcplugin_config.plugin_health_service_enabled,
            "telemetry": True,
            "type_safety": True,
        },
    )

    try:
        # Create protocol and handler
        protocol = plugin_protocol()
        handler = AdvancedHandler(name="ProductionHandler")

        # Verify handler implements protocol (type checking)
        if not isinstance(handler, RPCPluginHandler):
            logger.warning("Handler doesn't fully implement RPCPluginHandler protocol")

        # Create and start server
        server = plugin_server(protocol=protocol, handler=handler)

        logger.info(
            "Advanced plugin server ready",
            transport=rpcplugin_config.plugin_server_transports,
            rate_limit={
                "enabled": rpcplugin_config.plugin_rate_limit_enabled,
                "requests_per_second": rpcplugin_config.plugin_rate_limit_requests_per_second,
                "burst_capacity": rpcplugin_config.plugin_rate_limit_burst_capacity,
            },
        )

        # Start serving
        await server.serve()

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error("Server failed to start", error=str(e), error_type=type(e).__name__, exc_info=True)
        raise


if __name__ == "__main__":
    # Run the advanced plugin
    asyncio.run(main())

# 🔌📞🔚
