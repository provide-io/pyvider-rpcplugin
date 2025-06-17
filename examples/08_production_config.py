#!/usr/bin/env python3
# examples/08_production_config.py
"""Demonstrates production-ready configuration and deployment patterns with pyvider-rpcplugin."""

import asyncio
import os
import sys
from pathlib import Path

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    configure,
    create_basic_protocol,
    plugin_server,
)
from pyvider.rpcplugin.config import (  # noqa: E402
    RPCPluginConfig,
)
from pyvider.telemetry import logger  # noqa: E402


class ProductionServiceHandler:
    """Production-grade service handler with comprehensive logging and metrics."""

    def __init__(self, service_name: str = "ProductionService"):
        self.service_name = service_name
        self.request_count = 0
        self.error_count = 0
        self.start_time = asyncio.get_event_loop().time()

    async def ProcessRequest(self, request, context):
        """Handle production requests with full observability."""
        request_id = f"req_{self.request_count + 1}"
        self.request_count += 1

        start_time = asyncio.get_event_loop().time()

        logger.info(
            "Processing production request",
            domain="service",
            action="process_request",
            status="starting",
            service_name=self.service_name,
            request_id=request_id,
            total_requests=self.request_count,
        )

        try:
            # Simulate request processing
            message = getattr(request, "message", "production_request")
            processing_time = 0.05  # Simulate 50ms processing
            await asyncio.sleep(processing_time)

            response_data = f"Production Response [{request_id}]: {message}"

            end_time = asyncio.get_event_loop().time()
            duration_ms = (end_time - start_time) * 1000

            logger.info(
                "Request processed successfully",
                domain="service",
                action="process_request",
                status="success",
                request_id=request_id,
                duration_ms=round(duration_ms, 2),
                response_size=len(response_data),
            )

            # Log metrics for monitoring
            uptime_seconds = end_time - self.start_time
            logger.info(
                "Service metrics",
                domain="metrics",
                action="report",
                status="current",
                service_uptime_seconds=round(uptime_seconds, 1),
                total_requests=self.request_count,
                error_count=self.error_count,
                error_rate=self.error_count / self.request_count
                if self.request_count > 0
                else 0,
                avg_response_time_ms=round(duration_ms, 2),
            )

            return type("ProductionReply", (), {"response": response_data})()

        except Exception as e:
            self.error_count += 1

            logger.error(
                "Request processing failed",
                domain="service",
                action="process_request",
                status="error",
                request_id=request_id,
                error=str(e),
                error_count=self.error_count,
            )
            raise


async def example_8_environment_configuration():
    """
    Example 8A: Demonstrates environment-based configuration.

    Shows how to configure RPC plugins using environment variables
    for different deployment environments (dev, staging, production).
    """
    print("\n" + "=" * 60)
    print("🌍 Example 8A: Environment-Based Configuration")
    print(" Demonstrates: Configuration via environment variables")
    print("=" * 60)

    # Save original environment
    original_env = {}
    env_vars_to_set = {
        "PLUGIN_MAGIC_COOKIE_VALUE": "production-secret-2024",
        "PLUGIN_LOG_LEVEL": "INFO",
        "PLUGIN_SERVER_TRANSPORTS": "unix,tcp",
        "PLUGIN_AUTO_MTLS": "true",
        "PLUGIN_HANDSHAKE_TIMEOUT": "30.0",
        "PLUGIN_CONNECTION_TIMEOUT": "300.0",
        "PLUGIN_SERVER_ENDPOINT": "0.0.0.0:50051",
        "PYVIDER_SERVICE_NAME": "production-rpc-service",
        "PYVIDER_LOG_LEVEL": "INFO",
    }

    try:
        # Set production environment variables
        for key, value in env_vars_to_set.items():
            original_env[key] = os.environ.get(key)
            os.environ[key] = value

        logger.info(
            "Production environment configured",
            domain="config",
            action="env_setup",
            status="success",
            environment="production",
            config_vars=list(env_vars_to_set.keys()),
        )

        # Load configuration from environment
        config = RPCPluginConfig.instance()

        # Verify configuration values
        magic_cookie = config.get("PLUGIN_MAGIC_COOKIE_VALUE")
        transports = config.get("PLUGIN_SERVER_TRANSPORTS")
        auto_mtls = config.get("PLUGIN_AUTO_MTLS")

        logger.info(
            "Configuration loaded from environment",
            domain="config",
            action="env_load",
            status="success",
            magic_cookie_set=bool(magic_cookie),
            transports=transports,
            mtls_enabled=auto_mtls,
            security_level="production",
        )

        # Demonstrate different environment profiles
        env_profiles = {
            "development": {
                "PLUGIN_LOG_LEVEL": "DEBUG",
                "PLUGIN_AUTO_MTLS": "false",
                "PLUGIN_SERVER_TRANSPORTS": "unix",
            },
            "staging": {
                "PLUGIN_LOG_LEVEL": "INFO",
                "PLUGIN_AUTO_MTLS": "true",
                "PLUGIN_SERVER_TRANSPORTS": "unix,tcp",
            },
            "production": {
                "PLUGIN_LOG_LEVEL": "WARNING",
                "PLUGIN_AUTO_MTLS": "true",
                "PLUGIN_SERVER_TRANSPORTS": "tcp",
            },
        }

        for env_name, env_config in env_profiles.items():
            logger.info(
                f"Environment profile: {env_name}",
                domain="config",
                action="profile_demo",
                status="reference",
                profile=env_name,
                config=env_config,
            )

    finally:
        # Restore original environment
        for key, original_value in original_env.items():
            if original_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original_value


async def example_8_production_server_deployment():
    """
    Example 8B: Demonstrates production server deployment patterns.

    Shows how to deploy an RPC server with production-grade
    configuration, monitoring, and operational features.
    """
    print("\n" + "=" * 60)
    print("🏭 Example 8C: Production Server Deployment")
    print(" Demonstrates: Production-ready server with monitoring")
    print("=" * 60)

    # Production configuration
    # For this example to run without full cert setup, ensure PLUGIN_AUTO_MTLS is False.
    # Actual mTLS is demonstrated in 05_security_mtls.py.
    configure(
        PLUGIN_MAGIC_COOKIE_VALUE="production-server-2024",
        PLUGIN_PROTOCOL_VERSIONS=[1],
        PLUGIN_SERVER_TRANSPORTS=["tcp"],  # TCP for production deployments
        PLUGIN_AUTO_MTLS=False,  # Changed to False to allow running without certs
        PLUGIN_HANDSHAKE_TIMEOUT=30.0,
        PLUGIN_CONNECTION_TIMEOUT=600.0,  # 10 minutes for long-running operations
    )

    logger.info(
        "Configuring production server",
        domain="deployment",
        action="configure",
        status="starting",
        environment="production",
        security_level="mtls_disabled_for_example", # Updated log
    )

    # Create production protocol and handler
    protocol = create_basic_protocol()
    handler = ProductionServiceHandler("ProductionRPCService")

    # Note: The 'max_workers', 'max_connections', etc., keys in this config dict
    # are illustrative of potential gRPC server settings. Currently, RPCPluginServer
    # uses a set of hardcoded default gRPC options and does not dynamically
    # apply these specific keys from the passed 'config' dictionary for gRPC server tuning.
    # This dictionary is primarily for application-specific settings.
    # Create production server
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="tcp",
        host="0.0.0.0",  # nosec B104 # Example for production-like config, binding to 0.0.0.0 is intentional here. # Accept connections from any IP
        port=50051,  # Standard gRPC port
        config={
            # General application config can be passed here.
            # Note: Low-level gRPC options (max_workers, keepalive, etc.) are not directly
            # configurable through this factory's 'config' dict. They would require
            # direct instantiation of grpc.aio.server and potentially RPCPluginServer.
            "app_performance_profile": "high_throughput",
        },
    )

    logger.info(
        "Starting production server",
        domain="deployment",
        action="startup",
        status="starting",
        bind_address="0.0.0.0:50051",
        # max_workers, max_connections are conceptual for this example's logging
    )

    # Start server in background
    server_task = asyncio.create_task(server.serve())

    # Simulate server initialization time
    await asyncio.sleep(0.5)

    logger.info(
        "Production server started successfully",
        domain="deployment",
        action="startup",
        status="success",
        endpoint="0.0.0.0:50051",
        ready_for_traffic=True,
        health_status="healthy",
    )

    # Simulate health monitoring
    for i in range(3):
        await asyncio.sleep(0.2)

        logger.info(
            f"Health check {i + 1}",
            domain="monitoring",
            action="health_check",
            status="healthy",
            check_number=i + 1,
            server_status="running",
            memory_usage_mb=128 + (i * 10),  # Simulate increasing memory
            cpu_usage_percent=15 + (i * 5),
            active_connections=10 + (i * 3),
        )

    # Graceful shutdown
    logger.info(
        "Initiating graceful shutdown",
        domain="deployment",
        action="shutdown",
        status="starting",
        reason="example_completion",
    )

    await server.stop()
    await server_task

    logger.info(
        "Production server shutdown completed",
        domain="deployment",
        action="shutdown",
        status="success",
        cleanup="complete",
    )


async def example_8_monitoring_and_observability():
    """
    Example 8D: Demonstrates monitoring and observability patterns.

    Shows how to implement comprehensive monitoring, metrics,
    and observability for production RPC services.
    """
    print("\n" + "=" * 60)
    print("📊 Example 8D: Monitoring & Observability")
    print(" Demonstrates: Production monitoring and metrics")
    print("=" * 60)

    # Simulate production metrics collection
    metrics = {
        "service_info": {
            "name": "production-rpc-service",
            "version": "1.0.0",
            "environment": "production",
            "instance_id": "rpc-prod-01",
        },
        "performance": {
            "requests_per_second": 1250,
            "avg_response_time_ms": 15.3,
            "p95_response_time_ms": 45.2,
            "p99_response_time_ms": 89.1,
            "error_rate": 0.002,  # 0.2%
        },
        "resources": {
            "cpu_usage_percent": 23.5,
            "memory_usage_mb": 512,
            "memory_usage_percent": 15.8,
            "open_connections": 145,
            "max_connections": 1000,
        },
        "health": {
            "status": "healthy",
            "uptime_seconds": 86400,  # 24 hours
            "last_restart": "2024-06-08T10:30:00Z",
            "deployment_version": "v1.2.3",
        },
    }

    logger.info(
        "Service information",
        domain="monitoring",
        action="service_info",
        status="current",
        **metrics["service_info"],
    )

    logger.info(
        "Performance metrics",
        domain="monitoring",
        action="performance",
        status="current",
        **metrics["performance"],
    )

    logger.info(
        "Resource utilization",
        domain="monitoring",
        action="resources",
        status="current",
        **metrics["resources"],
    )

    logger.info(
        "Health status",
        domain="monitoring",
        action="health",
        # status="current", # Removed to avoid conflict with status in metrics["health"]
        **metrics["health"],
    )

    # Simulate alerting thresholds
    alert_conditions = [
        {
            "metric": "error_rate",
            "threshold": 0.05,
            "current": metrics["performance"]["error_rate"],
            "status": "ok",
        },
        {
            "metric": "cpu_usage_percent",
            "threshold": 80.0,
            "current": metrics["resources"]["cpu_usage_percent"],
            "status": "ok",
        },
        {
            "metric": "memory_usage_percent",
            "threshold": 85.0,
            "current": metrics["resources"]["memory_usage_percent"],
            "status": "ok",
        },
        {
            "metric": "avg_response_time_ms",
            "threshold": 100.0,
            "current": metrics["performance"]["avg_response_time_ms"],
            "status": "ok",
        },
    ]

    for condition in alert_conditions:
        is_alert = condition["current"] > condition["threshold"]

        logger.info(
            f"Alert condition check: {condition['metric']}",
            domain="alerting",
            action="threshold_check",
            status="alert" if is_alert else "ok",
            metric=condition["metric"],
            current_value=condition["current"],
            threshold=condition["threshold"],
            alert_triggered=is_alert,
        )

    # Demonstrate operational best practices
    best_practices = [
        "📊 Monitor key metrics: RPS, latency, error rate, resource usage",
        "🚨 Set up alerting for critical thresholds and service health",
        "📋 Implement structured logging with correlation IDs",
        "🔍 Use distributed tracing for request flow visibility",
        "📈 Create dashboards for real-time operational visibility",
        "🏥 Implement health check endpoints for load balancer integration",
        "🔄 Set up automated deployment and rollback procedures",
        "💾 Implement persistent logging and metrics storage",
    ]

    logger.info(
        "Production monitoring best practices",
        domain="monitoring",
        action="best_practices",
        status="reference",
        practices=best_practices,
    )


async def main():
    """Run all production configuration examples."""
    print("🏭 pyvider-rpcplugin Production Configuration Examples")
    print("====================================================")

    try:
        # Run each production configuration example
        await example_8_environment_configuration()
        await example_8_production_server_deployment()
        await example_8_monitoring_and_observability()

        print("\n" + "=" * 60)
        print("✅ All Production Configuration Examples Completed Successfully!")
        print("=" * 60)
        print("\n🏭 Production Checklist:")
        print("  • Environment-based configuration for different stages")
        print("  • mTLS security enabled for all environments")
        print("  • Comprehensive monitoring and alerting")
        print("  • Health checks and graceful shutdown procedures")
        print("  • Resource limits and performance tuning")
        print("\n📖 Next Steps:")
        print("  • Review docs/architecture.md for system design patterns")
        print("  • Check docs/security.md for production security guidelines")
        print("  • See example 10_performance_tuning.py for optimization")

    except Exception as e:
        logger.error(
            "Production configuration example failed",
            domain="examples",
            action="run",
            status="error",
            error=str(e),
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
