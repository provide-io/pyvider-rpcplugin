# Health Checks

Implement comprehensive health monitoring for plugin servers with gRPC health checks, custom health indicators, and integration with monitoring systems.

## gRPC Health Check Protocol

### Basic Health Service Implementation

```python
import asyncio
from enum import Enum
import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc
from grpc_health.v1.health_pb2 import HealthCheckResponse

class HealthStatus(Enum):
    SERVING = HealthCheckResponse.SERVING
    NOT_SERVING = HealthCheckResponse.NOT_SERVING
    SERVICE_UNKNOWN = HealthCheckResponse.SERVICE_UNKNOWN

class HealthCheckServicer(health_pb2_grpc.HealthServicer):
    """gRPC Health Check service implementation."""

    def __init__(self):
        self.service_status: dict[str, HealthStatus] = {}
        self.health_checkers: dict[str, callable] = {}

    def register_health_checker(self, service_name: str, checker: callable):
        """Register a health check function for a service."""
        self.health_checkers[service_name] = checker

    async def Check(self, request, context):
        """Handle health check request."""
        service = request.service

        try:
            if service in self.health_checkers:
                checker = self.health_checkers[service]
                is_healthy = await self._run_health_checker(checker)
                status = HealthStatus.SERVING if is_healthy else HealthStatus.NOT_SERVING
            else:
                status = self.service_status.get(service, HealthStatus.SERVICE_UNKNOWN)

            return health_pb2.HealthCheckResponse(status=status.value)

        except Exception as e:
            logging.error(f"Health check error for service {service}: {e}")
            return health_pb2.HealthCheckResponse(status=HealthStatus.NOT_SERVING.value)

    async def Watch(self, request, context):
        """Handle health check watch request (streaming)."""
        service = request.service
        last_status = None

        while not context.cancelled():
            try:
                if service in self.health_checkers:
                    checker = self.health_checkers[service]
                    is_healthy = await self._run_health_checker(checker)
                    current_status = HealthStatus.SERVING if is_healthy else HealthStatus.NOT_SERVING
                else:
                    current_status = self.service_status.get(service, HealthStatus.SERVICE_UNKNOWN)

                if current_status != last_status:
                    yield health_pb2.HealthCheckResponse(status=current_status.value)
                    last_status = current_status

                await asyncio.sleep(5.0)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"Health watch error for service {service}: {e}")
                yield health_pb2.HealthCheckResponse(status=HealthStatus.NOT_SERVING.value)
                await asyncio.sleep(5.0)

    async def _run_health_checker(self, checker: callable) -> bool:
        """Run health checker with timeout."""
        try:
            if asyncio.iscoroutinefunction(checker):
                result = await asyncio.wait_for(checker(), timeout=5.0)
            else:
                result = checker()
            return bool(result)
        except (asyncio.TimeoutError, Exception):
            return False

# Integration with plugin server
class HealthyPluginServer:
    def __init__(self, protocol, handler):
        self.protocol = protocol
        self.handler = handler
        self.health_service = HealthCheckServicer()

    def setup_health_checks(self):
        """Setup health checks for server components."""
        self.health_service.register_health_checker("database", self._check_database)
        self.health_service.register_health_checker("external_api", self._check_external_api)
        self.health_service.set_service_status("", HealthStatus.SERVING)

    async def _check_database(self) -> bool:
        """Check database connectivity."""
        # Replace with actual database ping
        return True

    async def _check_external_api(self) -> bool:
        """Check external API availability."""
        # Replace with actual API health check
        return True

    async def start(self):
        """Start server with health checks."""
        self.setup_health_checks()

        self.server = plugin_server(
            protocol=self.protocol,
            handler=self.handler,
            additional_services=[
                (health_pb2_grpc.add_HealthServicer_to_server, self.health_service)
            ]
        )

        await self.server.serve()
```

## Custom Health Indicators

### Advanced Health Monitoring

```python
import time
import psutil
from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class HealthMetric:
    """Individual health metric."""
    name: str
    value: any
    status: str = "healthy"  # healthy, warning, critical
    message: str = ""
    threshold: any = None
    last_updated: datetime = field(default_factory=datetime.now)

@dataclass
class HealthReport:
    """Complete health report."""
    overall_status: str = "healthy"
    timestamp: datetime = field(default_factory=datetime.now)
    metrics: dict[str, HealthMetric] = field(default_factory=dict)
    uptime_seconds: float = 0
    version: str = "1.0.0"

    def add_metric(self, metric: HealthMetric):
        """Add a health metric to the report."""
        self.metrics[metric.name] = metric

        if metric.status == "critical":
            self.overall_status = "critical"
        elif metric.status == "warning" and self.overall_status != "critical":
            self.overall_status = "warning"

class AdvancedHealthChecker:
    """Advanced health monitoring with custom indicators."""

    def __init__(self):
        self.start_time = time.time()
        self.request_stats = {"total_requests": 0, "failed_requests": 0, "avg_response_time": 0.0}
        self.resource_thresholds = {"cpu_percent": 80.0, "memory_percent": 85.0, "disk_usage_percent": 90.0}
        self.external_dependencies = {}

    def register_dependency(self, name: str, health_checker: callable):
        """Register external dependency health checker."""
        self.external_dependencies[name] = health_checker

    async def get_comprehensive_health_report(self) -> HealthReport:
        """Generate comprehensive health report."""
        report = HealthReport()
        report.uptime_seconds = time.time() - self.start_time

        await self._check_system_resources(report)
        await self._check_application_metrics(report)
        await self._check_external_dependencies(report)

        return report

    async def _check_system_resources(self, report: HealthReport):
        """Check system resource utilization."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_status = ("critical" if cpu_percent > self.resource_thresholds["cpu_percent"]
                         else "warning" if cpu_percent > self.resource_thresholds["cpu_percent"] * 0.8
                         else "healthy")

            report.add_metric(HealthMetric(
                name="cpu_usage", value=cpu_percent, status=cpu_status,
                message=f"CPU usage at {cpu_percent:.1f}%", threshold=self.resource_thresholds["cpu_percent"]
            ))

            # Memory usage
            memory = psutil.virtual_memory()
            memory_status = ("critical" if memory.percent > self.resource_thresholds["memory_percent"]
                           else "warning" if memory.percent > self.resource_thresholds["memory_percent"] * 0.8
                           else "healthy")

            report.add_metric(HealthMetric(
                name="memory_usage", value=memory.percent, status=memory_status,
                message=f"Memory usage at {memory.percent:.1f}%", threshold=self.resource_thresholds["memory_percent"]
            ))

        except Exception as e:
            report.add_metric(HealthMetric(
                name="system_resources", value="error", status="critical",
                message=f"Failed to check system resources: {e}"
            ))

    async def _check_application_metrics(self, report: HealthReport):
        """Check application-specific metrics."""
        try:
            total_requests = self.request_stats["total_requests"]
            failed_requests = self.request_stats["failed_requests"]

            if total_requests > 0:
                success_rate = ((total_requests - failed_requests) / total_requests) * 100
                success_status = ("critical" if success_rate < 95 else "warning" if success_rate < 98 else "healthy")

                report.add_metric(HealthMetric(
                    name="request_success_rate", value=success_rate, status=success_status,
                    message=f"Success rate: {success_rate:.1f}%", threshold=95.0
                ))

            avg_response_time = self.request_stats["avg_response_time"]
            response_time_status = ("critical" if avg_response_time > 5000
                                  else "warning" if avg_response_time > 2000 else "healthy")

            report.add_metric(HealthMetric(
                name="avg_response_time", value=avg_response_time, status=response_time_status,
                message=f"Average response time: {avg_response_time:.0f}ms", threshold=2000
            ))

        except Exception as e:
            report.add_metric(HealthMetric(
                name="application_metrics", value="error", status="critical",
                message=f"Failed to check application metrics: {e}"
            ))

    async def _check_external_dependencies(self, report: HealthReport):
        """Check external dependency health."""
        for name, checker in self.external_dependencies.items():
            try:
                is_healthy = await asyncio.wait_for(checker(), timeout=5.0)
                status = "healthy" if is_healthy else "critical"
                value = "available" if is_healthy else "unavailable"

                report.add_metric(HealthMetric(
                    name=f"dependency_{name}", value=value, status=status,
                    message=f"Dependency {name} is {value}"
                ))

            except asyncio.TimeoutError:
                report.add_metric(HealthMetric(
                    name=f"dependency_{name}", value="timeout", status="warning",
                    message=f"Dependency {name} check timed out"
                ))
            except Exception as e:
                report.add_metric(HealthMetric(
                    name=f"dependency_{name}", value="error", status="critical",
                    message=f"Dependency {name} check failed: {e}"
                ))

    def update_request_stats(self, response_time_ms: float, failed: bool = False):
        """Update request statistics."""
        self.request_stats["total_requests"] += 1
        if failed:
            self.request_stats["failed_requests"] += 1

        current_avg = self.request_stats["avg_response_time"]
        total = self.request_stats["total_requests"]
        self.request_stats["avg_response_time"] = ((current_avg * (total - 1)) + response_time_ms) / total

# Health Check Handler Integration
class HealthAwareHandler:
    def __init__(self):
        self.health_checker = AdvancedHealthChecker()
        self.health_checker.register_dependency("database", self._check_database)
        self.health_checker.register_dependency("external_api", self._check_external_api)

    async def _check_database(self) -> bool:
        """Check database connectivity."""
        # Implement actual database check
        return True

    async def _check_external_api(self) -> bool:
        """Check external API availability."""
        # Implement actual API check
        return True

    async def GetHealthReport(self, request, context):
        """Get detailed health report."""
        try:
            report = await self.health_checker.get_comprehensive_health_report()

            metrics = {
                name: {
                    "value": str(metric.value),
                    "status": metric.status,
                    "message": metric.message,
                    "threshold": str(metric.threshold) if metric.threshold else "",
                    "last_updated": metric.last_updated.isoformat()
                }
                for name, metric in report.metrics.items()
            }

            return HealthReportResponse(
                overall_status=report.overall_status,
                uptime_seconds=report.uptime_seconds,
                timestamp=report.timestamp.isoformat(),
                version=report.version,
                metrics=metrics
            )

        except Exception as e:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Health report generation failed: {e}")
            return HealthReportResponse(overall_status="critical")
```

## Monitoring Integration

### Foundation Configuration

Health checks integrate with Foundation logging and configuration using `PLUGIN_*` environment variables:

```python
import os
from pathlib import Path

class PluginHealthConfig:
    """Health check configuration using Foundation patterns."""

    def __init__(self):
        self.health_check_interval = float(os.getenv("PLUGIN_HEALTH_CHECK_INTERVAL", "30"))
        self.resource_cpu_threshold = float(os.getenv("PLUGIN_RESOURCE_CPU_THRESHOLD", "80"))
        self.resource_memory_threshold = float(os.getenv("PLUGIN_RESOURCE_MEMORY_THRESHOLD", "85"))
        self.health_file_path = os.getenv("PLUGIN_HEALTH_FILE_PATH", "/tmp/health")
        self.enable_prometheus = os.getenv("PLUGIN_ENABLE_PROMETHEUS", "false").lower() == "true"

class KubernetesHealthIntegration:
    """Kubernetes health check integration."""

    def __init__(self, health_checker: AdvancedHealthChecker, config: PluginHealthConfig):
        self.health_checker = health_checker
        self.config = config
        self.health_file_path = Path(config.health_file_path)

    async def start_health_file_updater(self):
        """Start background task to update health status file."""
        while True:
            try:
                report = await self.health_checker.get_comprehensive_health_report()

                health_data = {
                    "status": report.overall_status,
                    "timestamp": report.timestamp.isoformat(),
                    "uptime": report.uptime_seconds,
                    "healthy": report.overall_status in ["healthy", "warning"]
                }

                with open(self.health_file_path, 'w') as f:
                    json.dump(health_data, f)

                await asyncio.sleep(self.config.health_check_interval)

            except Exception as e:
                logging.error(f"Health file update failed: {e}")
                await asyncio.sleep(5)

# Kubernetes probe configuration
KUBERNETES_PROBES = {
    "liveness": """
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10""",

    "readiness": """
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5"""
}

class PrometheusHealthMetrics:
    """Simplified Prometheus metrics export."""

    def __init__(self):
        self.health_status_gauge = {}
        self.health_check_total = {}
        self.health_check_duration = {}

    def record_health_check(self, service: str, duration: float, status: str):
        """Record health check metrics."""
        self.health_status_gauge[service] = 1 if status == "healthy" else 0
        self.health_check_total[service] = self.health_check_total.get(service, 0) + 1

        if service not in self.health_check_duration:
            self.health_check_duration[service] = []
        self.health_check_duration[service].append(duration)

    def get_prometheus_metrics(self) -> str:
        """Generate Prometheus-formatted metrics."""
        metrics = []

        for service, status in self.health_status_gauge.items():
            metrics.append(f'health_status{{service="{service}"}} {status}')

        for service, count in self.health_check_total.items():
            metrics.append(f'health_checks_total{{service="{service}"}} {count}')

        for service, durations in self.health_check_duration.items():
            if durations:
                avg_duration = sum(durations) / len(durations)
                metrics.append(f'health_check_duration_seconds{{service="{service}"}} {avg_duration:.3f}')

        return "\n".join(metrics)
```

## Testing and Best Practices

### Health Check Testing

```python
import pytest
from unittest.mock import Mock, patch

class TestHealthChecks:
    @pytest.fixture
    def health_checker(self):
        return AdvancedHealthChecker()

    @pytest.mark.asyncio
    async def test_system_resource_check(self, health_checker):
        """Test system resource health checking."""
        with patch('psutil.cpu_percent', return_value=50.0), \
             patch('psutil.virtual_memory') as mock_memory:

            mock_memory.return_value = Mock(percent=60.0, used=1024*1024*1024)

            report = await health_checker.get_comprehensive_health_report()

            assert report.overall_status == "healthy"
            assert "cpu_usage" in report.metrics
            assert report.metrics["cpu_usage"].value == 50.0
            assert report.metrics["cpu_usage"].status == "healthy"

    @pytest.mark.asyncio
    async def test_dependency_health_check(self, health_checker):
        """Test external dependency health checking."""
        async def mock_healthy_dependency():
            return True

        async def mock_unhealthy_dependency():
            return False

        health_checker.register_dependency("healthy_service", mock_healthy_dependency)
        health_checker.register_dependency("unhealthy_service", mock_unhealthy_dependency)

        report = await health_checker.get_comprehensive_health_report()

        assert "dependency_healthy_service" in report.metrics
        assert report.metrics["dependency_healthy_service"].status == "healthy"
        assert report.metrics["dependency_unhealthy_service"].status == "critical"

    @pytest.mark.asyncio
    async def test_health_check_timeout(self, health_checker):
        """Test health check timeout handling."""
        async def slow_dependency():
            await asyncio.sleep(10)  # Longer than timeout
            return True

        health_checker.register_dependency("slow_service", slow_dependency)

        report = await health_checker.get_comprehensive_health_report()

        assert "dependency_slow_service" in report.metrics
        assert report.metrics["dependency_slow_service"].status == "warning"
```

### Production Configuration

```python
def create_production_health_setup(config: PluginHealthConfig):
    """Create production-focused health check setup."""

    health_checker = AdvancedHealthChecker()
    health_checker.resource_thresholds = {
        "cpu_percent": config.resource_cpu_threshold,
        "memory_percent": config.resource_memory_threshold,
        "disk_usage_percent": 85.0
    }

    # Register critical dependencies
    health_checker.register_dependency("primary_database", check_primary_db)
    health_checker.register_dependency("cache_service", check_cache)

    # Create gRPC health service
    health_service = HealthCheckServicer()
    health_service.register_health_checker("", lambda: True)
    health_service.register_health_checker("database", check_primary_db)

    # Setup monitoring integration
    prometheus_metrics = PrometheusHealthMetrics() if config.enable_prometheus else None
    k8s_integration = KubernetesHealthIntegration(health_checker, config)

    return {
        "health_checker": health_checker,
        "health_service": health_service,
        "prometheus_metrics": prometheus_metrics,
        "k8s_integration": k8s_integration
    }

async def check_primary_db():
    """Check primary database health."""
    # Implement actual database health check
    return True

async def check_cache():
    """Check cache service health."""
    # Implement actual cache health check
    return True
```

### Health Endpoints

Health checks provide multiple endpoints for different monitoring needs:

- `/health` - Overall service health (gRPC Check)
- `/ready` - Service readiness for traffic
- `/metrics` - Prometheus metrics export
- Health file at `PLUGIN_HEALTH_FILE_PATH` for Kubernetes exec probes

### Troubleshooting

Common health check issues:

1. **Timeout errors**: Reduce checker complexity or increase timeout values
1. **Resource threshold alerts**: Adjust thresholds via `PLUGIN_RESOURCE_*_THRESHOLD`
1. **Dependency failures**: Implement proper retry logic and circuit breakers
1. **File probe issues**: Ensure health file path is writable and monitored

### Integration with Foundation

Health checks integrate seamlessly with Foundation logging and configuration:

```python
# Use Foundation logging patterns
logger = logging.getLogger("plugin.health")

# Environment-based configuration
health_config = PluginHealthConfig()

# Structured health reports for monitoring systems
health_service = HealthCheckServicer()
```

## Next Steps

With comprehensive health checks implemented:

- **[Security](../security/index.md)** - Secure your health endpoints
- **[Configuration](../config/index.md)** - Configure health check parameters
- **[Production Deployment](../config/advanced.md)** - Deploy with monitoring integration
- **[Client Development](../client/index.md)** - Implement client-side health checking
