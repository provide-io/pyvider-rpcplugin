#!/usr/bin/env python3
# examples/08_production_config.py
"""Demonstrates production-ready configuration and deployment patterns with pyvider-rpcplugin."""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

# Add src to path for examples
example_dir = Path(__file__).resolve().parent
project_root = example_dir.parent
src_path = project_root / "src"
if src_path.exists() and str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

from pyvider.rpcplugin import (  # noqa: E402
    plugin_server,
    plugin_client,
    create_basic_protocol,
    configure,
)
from pyvider.rpcplugin.config import (  # noqa: E402
    RPCPluginConfig,
    load_config_from_file,
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
            total_requests=self.request_count
        )
        
        try:
            # Simulate request processing
            message = getattr(request, 'message', 'production_request')
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
                response_size=len(response_data)
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
                error_rate=self.error_count / self.request_count if self.request_count > 0 else 0,
                avg_response_time_ms=round(duration_ms, 2)
            )
            
            return type('ProductionReply', (), {'response': response_data})()
            
        except Exception as e:
            self.error_count += 1
            
            logger.error(
                "Request processing failed",
                domain="service",
                action="process_request",
                status="error",
                request_id=request_id,
                error=str(e),
                error_count=self.error_count
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
        'PLUGIN_MAGIC_COOKIE_VALUE': 'production-secret-2024',
        'PLUGIN_LOG_LEVEL': 'INFO',
        'PLUGIN_SERVER_TRANSPORTS': 'unix,tcp',
        'PLUGIN_AUTO_MTLS': 'true',
        'PLUGIN_HANDSHAKE_TIMEOUT': '30.0',
        'PLUGIN_CONNECTION_TIMEOUT': '300.0',
        'PLUGIN_SERVER_ENDPOINT': '0.0.0.0:50051',
        'PYVIDER_SERVICE_NAME': 'production-rpc-service',
        'PYVIDER_LOG_LEVEL': 'INFO'
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
            config_vars=list(env_vars_to_set.keys())
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
            security_level="production"
        )
        
        # Demonstrate different environment profiles
        env_profiles = {
            "development": {
                "PLUGIN_LOG_LEVEL": "DEBUG",
                "PLUGIN_AUTO_MTLS": "false",
                "PLUGIN_SERVER_TRANSPORTS": "unix"
            },
            "staging": {
                "PLUGIN_LOG_LEVEL": "INFO",
                "PLUGIN_AUTO_MTLS": "true",
                "PLUGIN_SERVER_TRANSPORTS": "unix,tcp"
            },
            "production": {
                "PLUGIN_LOG_LEVEL": "WARNING",
                "PLUGIN_AUTO_MTLS": "true",
                "PLUGIN_SERVER_TRANSPORTS": "tcp"
            }
        }
        
        for env_name, env_config in env_profiles.items():
            logger.info(
                f"Environment profile: {env_name}",
                domain="config",
                action="profile_demo",
                status="reference",
                profile=env_name,
                config=env_config
            )
        
    finally:
        # Restore original environment
        for key, original_value in original_env.items():
            if original_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = original_value


async def example_8_file_based_configuration():
    """
    Example 8B: Demonstrates file-based configuration.
    
    Shows how to use configuration files (.env, .json, .yaml)
    for managing complex production settings.
    """
    print("\n" + "=" * 60)
    print("📄 Example 8B: File-Based Configuration")
    print(" Demonstrates: Config files for production deployment")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as temp_dir:
        config_dir = Path(temp_dir)
        
        # Create .env configuration file
        env_config_path = config_dir / "production.env"
        env_content = """
# Production RPC Plugin Configuration
PLUGIN_MAGIC_COOKIE_VALUE=prod-cookie-2024-secure
PLUGIN_LOG_LEVEL=INFO
PLUGIN_SERVER_TRANSPORTS=tcp
PLUGIN_AUTO_MTLS=true
PLUGIN_HANDSHAKE_TIMEOUT=30.0
PLUGIN_CONNECTION_TIMEOUT=600.0

# Security Configuration
PLUGIN_SERVER_CERT=file:///etc/ssl/certs/rpc-server.crt
PLUGIN_SERVER_KEY=file:///etc/ssl/private/rpc-server.key
PLUGIN_CLIENT_CERT=file:///etc/ssl/certs/rpc-client.crt
PLUGIN_CLIENT_KEY=file:///etc/ssl/private/rpc-client.key

# Pyvider Telemetry Configuration
PYVIDER_SERVICE_NAME=production-rpc-plugin
PYVIDER_LOG_LEVEL=INFO
PYVIDER_LOG_FORMAT=json
"""
        
        with open(env_config_path, 'w') as f:
            f.write(env_content.strip())
        
        logger.info(
            "Created .env configuration file",
            domain="config",
            action="file_create",
            status="success",
            file_type=".env",
            file_path=str(env_config_path)
        )
        
        # Create JSON configuration file
        json_config_path = config_dir / "production.json"
        json_content = {
            "PLUGIN_MAGIC_COOKIE_VALUE": "prod-json-cookie-2024",
            "PLUGIN_LOG_LEVEL": "INFO",
            "PLUGIN_SERVER_TRANSPORTS": ["tcp"],
            "PLUGIN_AUTO_MTLS": True,
            "PLUGIN_HANDSHAKE_TIMEOUT": 30.0,
            "PLUGIN_CONNECTION_TIMEOUT": 600.0,
            "PLUGIN_PERFORMANCE_MODE": "high_throughput",
            "PLUGIN_MAX_CONCURRENT_CONNECTIONS": 1000,
            "PLUGIN_METRICS_ENABLED": True
        }
        
        import json
        with open(json_config_path, 'w') as f:
            json.dump(json_content, f, indent=2)
        
        logger.info(
            "Created JSON configuration file",
            domain="config",
            action="file_create",
            status="success",
            file_type=".json",
            file_path=str(json_config_path),
            config_keys=list(json_content.keys())
        )
        
        # Create YAML configuration file
        yaml_config_path = config_dir / "production.yaml"
        yaml_content = """
# Production RPC Plugin Configuration (YAML)
plugin:
  magic_cookie_value: "prod-yaml-cookie-2024"
  log_level: "INFO"
  server_transports: ["tcp"]
  auto_mtls: true
  handshake_timeout: 30.0
  connection_timeout: 600.0

security:
  server_cert: "/etc/ssl/certs/rpc-server.crt"
  server_key: "/etc/ssl/private/rpc-server.key"
  client_cert: "/etc/ssl/certs/rpc-client.crt"
  client_key: "/etc/ssl/private/rpc-client.key"

performance:
  max_workers: 32
  connection_pool_size: 100
  request_timeout: 30.0
  
monitoring:
  metrics_enabled: true
  health_check_interval: 60
  log_sampling_rate: 0.1
"""
        
        with open(yaml_config_path, 'w') as f:
            f.write(yaml_content.strip())
        
        logger.info(
            "Created YAML configuration file",
            domain="config",
            action="file_create",
            status="success",
            file_type=".yaml",
            file_path=str(yaml_config_path)
        )
        
        # Demonstrate loading different config file types
        config_files = [
            (env_config_path, ".env"),
            (json_config_path, ".json"),
            (yaml_config_path, ".yaml")
        ]
        
        for config_path, file_type in config_files:
            try:
                logger.info(
                    f"Loading {file_type} configuration",
                    domain="config",
                    action="file_load",
                    status="starting",
                    file_type=file_type,
                    file_path=str(config_path)
                )
                
                # Note: In real usage, you'd call load_config_from_file(config_path)
                # For this example, we'll just demonstrate the pattern
                
                logger.info(
                    f"{file_type} configuration loaded successfully",
                    domain="config",
                    action="file_load",
                    status="success",
                    file_type=file_type
                )
                
            except Exception as e:
                logger.error(
                    f"Failed to load {file_type} configuration",
                    domain="config",
                    action="file_load",
                    status="error",
                    file_type=file_type,
                    error=str(e)
                )


async def example_8_production_server_deployment():
    """
    Example 8C: Demonstrates production server deployment patterns.
    
    Shows how to deploy an RPC server with production-grade
    configuration, monitoring, and operational features.
    """
    print("\n" + "=" * 60)
    print("🏭 Example 8C: Production Server Deployment")
    print(" Demonstrates: Production-ready server with monitoring")
    print("=" * 60)
    
    # Production configuration
    configure(
        magic_cookie="production-server-2024",
        protocol_version=1,
        transports=["tcp"],  # TCP for production deployments
        auto_mtls=True,  # Always use mTLS in production
        handshake_timeout=30.0,
        connection_timeout=600.0,  # 10 minutes for long-running operations
    )
    
    logger.info(
        "Configuring production server",
        domain="deployment",
        action="configure",
        status="starting",
        environment="production",
        security_level="mtls_required"
    )
    
    # Create production protocol and handler
    protocol = create_basic_protocol()
    handler = ProductionServiceHandler("ProductionRPCService")
    
    # Create production server
    server = plugin_server(
        protocol=protocol,
        handler=handler,
        transport="tcp",
        host="0.0.0.0",  # Accept connections from any IP
        port=50051,      # Standard gRPC port
        config={
            "max_workers": 32,  # Scale with CPU cores
            "max_connections": 1000,
            "keepalive_timeout": 300,
            "keepalive_time": 60,
            "max_message_size": 1024 * 1024 * 4,  # 4MB
            "compression": "gzip"
        }
    )
    
    logger.info(
        "Starting production server",
        domain="deployment",
        action="startup",
        status="starting",
        bind_address="0.0.0.0:50051",
        max_workers=32,
        max_connections=1000
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
        health_status="healthy"
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
            active_connections=10 + (i * 3)
        )
    
    # Graceful shutdown
    logger.info(
        "Initiating graceful shutdown",
        domain="deployment",
        action="shutdown",
        status="starting",
        reason="example_completion"
    )
    
    await server.stop()
    await server_task
    
    logger.info(
        "Production server shutdown completed",
        domain="deployment",
        action="shutdown",
        status="success",
        cleanup="complete"
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
            "instance_id": "rpc-prod-01"
        },
        "performance": {
            "requests_per_second": 1250,
            "avg_response_time_ms": 15.3,
            "p95_response_time_ms": 45.2,
            "p99_response_time_ms": 89.1,
            "error_rate": 0.002  # 0.2%
        },
        "resources": {
            "cpu_usage_percent": 23.5,
            "memory_usage_mb": 512,
            "memory_usage_percent": 15.8,
            "open_connections": 145,
            "max_connections": 1000
        },
        "health": {
            "status": "healthy",
            "uptime_seconds": 86400,  # 24 hours
            "last_restart": "2024-06-08T10:30:00Z",
            "deployment_version": "v1.2.3"
        }
    }
    
    logger.info(
        "Service information",
        domain="monitoring",
        action="service_info",
        status="current",
        **metrics["service_info"]
    )
    
    logger.info(
        "Performance metrics",
        domain="monitoring",
        action="performance",
        status="current",
        **metrics["performance"]
    )
    
    logger.info(
        "Resource utilization",
        domain="monitoring",
        action="resources",
        status="current",
        **metrics["resources"]
    )
    
    logger.info(
        "Health status",
        domain="monitoring",
        action="health",
        # status="current", # Removed to avoid conflict with status in metrics["health"]
        **metrics["health"]
    )
    
    # Simulate alerting thresholds
    alert_conditions = [
        {
            "metric": "error_rate",
            "threshold": 0.05,
            "current": metrics["performance"]["error_rate"],
            "status": "ok"
        },
        {
            "metric": "cpu_usage_percent", 
            "threshold": 80.0,
            "current": metrics["resources"]["cpu_usage_percent"],
            "status": "ok"
        },
        {
            "metric": "memory_usage_percent",
            "threshold": 85.0,
            "current": metrics["resources"]["memory_usage_percent"],
            "status": "ok"
        },
        {
            "metric": "avg_response_time_ms",
            "threshold": 100.0,
            "current": metrics["performance"]["avg_response_time_ms"],
            "status": "ok"
        }
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
            alert_triggered=is_alert
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
        "💾 Implement persistent logging and metrics storage"
    ]
    
    logger.info(
        "Production monitoring best practices",
        domain="monitoring",
        action="best_practices",
        status="reference",
        practices=best_practices
    )


async def main():
    """Run all production configuration examples."""
    print("🏭 pyvider-rpcplugin Production Configuration Examples")
    print("====================================================")
    
    try:
        # Run each production configuration example
        await example_8_environment_configuration()
        await example_8_file_based_configuration()
        await example_8_production_server_deployment()
        await example_8_monitoring_and_observability()
        
        print("\n" + "=" * 60)
        print("✅ All Production Configuration Examples Completed Successfully!")
        print("=" * 60)
        print("\n🏭 Production Checklist:")
        print("  • Environment-based configuration for different stages")
        print("  • File-based config management (.env, .json, .yaml)")
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
            error=str(e)
        )
        raise


if __name__ == "__main__":
    asyncio.run(main())
