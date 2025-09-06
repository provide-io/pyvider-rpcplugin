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

### Comprehensive Health Monitoring

```python
import time
import psutil
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

@dataclass
class HealthMetric:
    """Individual health metric."""
    name: str
    value: Any
    threshold: Optional[Any] = None
    status: str = "healthy"  # healthy, warning, critical
    message: str = ""
    last_updated: datetime = field(default_factory=datetime.now)

@dataclass
class HealthReport:
    """Complete health report."""
    overall_status: str = "healthy"
    timestamp: datetime = field(default_factory=datetime.now)
    metrics: Dict[str, HealthMetric] = field(default_factory=dict)
    uptime_seconds: float = 0
    version: str = "1.0.0"
    
    def add_metric(self, metric: HealthMetric):
        """Add a health metric to the report."""
        self.metrics[metric.name] = metric
        
        # Update overall status based on worst metric
        if metric.status == "critical":
            self.overall_status = "critical"
        elif metric.status == "warning" and self.overall_status != "critical":
            self.overall_status = "warning"

class AdvancedHealthChecker:
    """Advanced health monitoring with custom indicators."""
    
    def __init__(self):
        self.start_time = time.time()
        self.request_stats = {
            "total_requests": 0,
            "failed_requests": 0,
            "avg_response_time": 0.0
        }
        self.resource_thresholds = {
            "cpu_percent": 80.0,
            "memory_percent": 85.0,
            "disk_usage_percent": 90.0
        }
        self.external_dependencies = {}
    
    def register_dependency(self, name: str, health_checker: callable):
        """Register external dependency health checker."""
        self.external_dependencies[name] = health_checker
    
    async def get_comprehensive_health_report(self) -> HealthReport:
        """Generate comprehensive health report."""
        report = HealthReport()
        report.uptime_seconds = time.time() - self.start_time
        
        # System resource metrics
        await self._check_system_resources(report)
        
        # Application metrics
        await self._check_application_metrics(report)
        
        # External dependencies
        await self._check_external_dependencies(report)
        
        # Custom business logic checks
        await self._check_business_logic(report)
        
        return report
    
    async def _check_system_resources(self, report: HealthReport):
        """Check system resource utilization."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_status = "healthy"
            if cpu_percent > self.resource_thresholds["cpu_percent"]:
                cpu_status = "critical"
            elif cpu_percent > self.resource_thresholds["cpu_percent"] * 0.8:
                cpu_status = "warning"
            
            report.add_metric(HealthMetric(
                name="cpu_usage",
                value=cpu_percent,
                threshold=self.resource_thresholds["cpu_percent"],
                status=cpu_status,
                message=f"CPU usage at {cpu_percent:.1f}%"
            ))
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_status = "healthy"
            if memory.percent > self.resource_thresholds["memory_percent"]:
                memory_status = "critical"
            elif memory.percent > self.resource_thresholds["memory_percent"] * 0.8:
                memory_status = "warning"
            
            report.add_metric(HealthMetric(
                name="memory_usage",
                value=memory.percent,
                threshold=self.resource_thresholds["memory_percent"],
                status=memory_status,
                message=f"Memory usage at {memory.percent:.1f}% ({memory.used // 1024 // 1024} MB used)"
            ))
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            disk_status = "healthy"
            if disk_percent > self.resource_thresholds["disk_usage_percent"]:
                disk_status = "critical"
            elif disk_percent > self.resource_thresholds["disk_usage_percent"] * 0.8:
                disk_status = "warning"
            
            report.add_metric(HealthMetric(
                name="disk_usage",
                value=disk_percent,
                threshold=self.resource_thresholds["disk_usage_percent"],
                status=disk_status,
                message=f"Disk usage at {disk_percent:.1f}%"
            ))
            
        except Exception as e:
            report.add_metric(HealthMetric(
                name="system_resources",
                value="error",
                status="critical",
                message=f"Failed to check system resources: {e}"
            ))
    
    async def _check_application_metrics(self, report: HealthReport):
        """Check application-specific metrics."""
        try:
            # Request success rate
            total_requests = self.request_stats["total_requests"]
            failed_requests = self.request_stats["failed_requests"]
            
            if total_requests > 0:
                success_rate = ((total_requests - failed_requests) / total_requests) * 100
                success_status = "healthy"
                
                if success_rate < 95:
                    success_status = "critical"
                elif success_rate < 98:
                    success_status = "warning"
                
                report.add_metric(HealthMetric(
                    name="request_success_rate",
                    value=success_rate,
                    threshold=95.0,
                    status=success_status,
                    message=f"Success rate: {success_rate:.1f}% ({total_requests} total requests)"
                ))
            
            # Average response time
            avg_response_time = self.request_stats["avg_response_time"]
            response_time_status = "healthy"
            
            if avg_response_time > 5000:  # 5 seconds
                response_time_status = "critical"
            elif avg_response_time > 2000:  # 2 seconds
                response_time_status = "warning"
            
            report.add_metric(HealthMetric(
                name="avg_response_time",
                value=avg_response_time,
                threshold=2000,
                status=response_time_status,
                message=f"Average response time: {avg_response_time:.0f}ms"
            ))
            
        except Exception as e:
            report.add_metric(HealthMetric(
                name="application_metrics",
                value="error",
                status="critical",
                message=f"Failed to check application metrics: {e}"
            ))
    
    async def _check_external_dependencies(self, report: HealthReport):
        """Check external dependency health."""
        for name, checker in self.external_dependencies.items():
            try:
                is_healthy = await asyncio.wait_for(
                    self._run_dependency_checker(checker),
                    timeout=5.0
                )
                
                status = "healthy" if is_healthy else "critical"
                message = f"Dependency {name} is {'available' if is_healthy else 'unavailable'}"
                
                report.add_metric(HealthMetric(
                    name=f"dependency_{name}",
                    value="available" if is_healthy else "unavailable",
                    status=status,
                    message=message
                ))
                
            except asyncio.TimeoutError:
                report.add_metric(HealthMetric(
                    name=f"dependency_{name}",
                    value="timeout",
                    status="warning",
                    message=f"Dependency {name} check timed out"
                ))
            except Exception as e:
                report.add_metric(HealthMetric(
                    name=f"dependency_{name}",
                    value="error",
                    status="critical",
                    message=f"Dependency {name} check failed: {e}"
                ))
    
    async def _run_dependency_checker(self, checker: callable) -> bool:
        """Run dependency health checker."""
        if asyncio.iscoroutinefunction(checker):
            return await checker()
        else:
            return checker()
    
    async def _check_business_logic(self, report: HealthReport):
        """Check business logic specific health indicators."""
        try:
            # Example: Check if critical business process is working
            business_process_healthy = await self._check_critical_business_process()
            
            report.add_metric(HealthMetric(
                name="business_process",
                value="operational" if business_process_healthy else "degraded",
                status="healthy" if business_process_healthy else "warning",
                message="Critical business process status"
            ))
            
            # Example: Check data consistency
            data_consistent = await self._check_data_consistency()
            
            report.add_metric(HealthMetric(
                name="data_consistency",
                value="consistent" if data_consistent else "inconsistent",
                status="healthy" if data_consistent else "critical",
                message="Data consistency check"
            ))
            
        except Exception as e:
            report.add_metric(HealthMetric(
                name="business_logic",
                value="error",
                status="critical",
                message=f"Business logic health check failed: {e}"
            ))
    
    async def _check_critical_business_process(self) -> bool:
        """Check if critical business process is operational."""
        # Implement your business logic health check
        await asyncio.sleep(0.01)  # Simulate check
        return True
    
    async def _check_data_consistency(self) -> bool:
        """Check data consistency."""
        # Implement your data consistency check
        await asyncio.sleep(0.01)  # Simulate check
        return True
    
    def update_request_stats(self, response_time_ms: float, failed: bool = False):
        """Update request statistics."""
        self.request_stats["total_requests"] += 1
        if failed:
            self.request_stats["failed_requests"] += 1
        
        # Update rolling average response time
        current_avg = self.request_stats["avg_response_time"]
        total = self.request_stats["total_requests"]
        self.request_stats["avg_response_time"] = ((current_avg * (total - 1)) + response_time_ms) / total

# Health Check Handler Integration
class HealthAwareHandler:
    def __init__(self):
        self.health_checker = AdvancedHealthChecker()
        
        # Register external dependencies
        self.health_checker.register_dependency("database", self.check_database)
        self.health_checker.register_dependency("redis", self.check_redis)
        self.health_checker.register_dependency("external_api", self.check_external_api)
    
    async def check_database(self) -> bool:
        """Check database connectivity."""
        # Implement actual database check
        await asyncio.sleep(0.01)
        return True
    
    async def check_redis(self) -> bool:
        """Check Redis connectivity."""
        # Implement actual Redis check
        await asyncio.sleep(0.01)
        return True
    
    async def check_external_api(self) -> bool:
        """Check external API availability."""
        # Implement actual API check
        await asyncio.sleep(0.01)
        return True
    
    async def SomeBusinessMethod(self, request, context):
        """Example business method with health tracking."""
        start_time = time.time()
        failed = False
        
        try:
            # Business logic here
            result = await self.process_request(request)
            return BusinessResponse(result=result)
            
        except Exception as e:
            failed = True
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return BusinessResponse()
        
        finally:
            # Update health statistics
            response_time_ms = (time.time() - start_time) * 1000
            self.health_checker.update_request_stats(response_time_ms, failed)
    
    async def GetHealthReport(self, request, context):
        """Get detailed health report."""
        try:
            report = await self.health_checker.get_comprehensive_health_report()
            
            # Convert to response format
            metrics = {}
            for name, metric in report.metrics.items():
                metrics[name] = {
                    "value": str(metric.value),
                    "status": metric.status,
                    "message": metric.message,
                    "threshold": str(metric.threshold) if metric.threshold else "",
                    "last_updated": metric.last_updated.isoformat()
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

## Health Check Integration

### Kubernetes Integration

```python
import json
from pathlib import Path

class KubernetesHealthIntegration:
    """Integration with Kubernetes health checks."""
    
    def __init__(self, health_checker: AdvancedHealthChecker, health_file_path: str = "/tmp/health"):
        self.health_checker = health_checker
        self.health_file_path = Path(health_file_path)
    
    async def start_health_file_updater(self):
        """Start background task to update health status file."""
        async def update_health_file():
            while True:
                try:
                    report = await self.health_checker.get_comprehensive_health_report()
                    
                    health_data = {
                        "status": report.overall_status,
                        "timestamp": report.timestamp.isoformat(),
                        "uptime": report.uptime_seconds,
                        "healthy": report.overall_status in ["healthy", "warning"]
                    }
                    
                    # Write health status to file for Kubernetes probes
                    with open(self.health_file_path, 'w') as f:
                        json.dump(health_data, f)
                    
                    await asyncio.sleep(10)  # Update every 10 seconds
                    
                except Exception as e:
                    logging.error(f"Health file update failed: {e}")
                    await asyncio.sleep(5)
        
        asyncio.create_task(update_health_file())
    
    def create_kubernetes_manifests(self) -> Dict[str, str]:
        """Generate Kubernetes health check manifests."""
        return {
            "livenessProbe": """
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
            """,
            
            "readinessProbe": """
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
            """,
            
            "exec_probe": f"""
livenessProbe:
  exec:
    command:
    - cat
    - {self.health_file_path}
  initialDelaySeconds: 30
  periodSeconds: 10
            """
        }
```

### Prometheus Metrics Integration

```python
from typing import Counter, Histogram, Gauge

class PrometheusHealthMetrics:
    """Export health metrics in Prometheus format."""
    
    def __init__(self):
        # Simulated Prometheus metrics (replace with actual prometheus_client)
        self.health_check_duration = {}  # Histogram
        self.health_status_gauge = {}    # Gauge  
        self.health_check_total = {}     # Counter
    
    def record_health_check(self, service: str, duration: float, status: str):
        """Record health check metrics."""
        # Record duration
        if service not in self.health_check_duration:
            self.health_check_duration[service] = []
        self.health_check_duration[service].append(duration)
        
        # Update status gauge (1 = healthy, 0 = unhealthy)
        self.health_status_gauge[service] = 1 if status == "healthy" else 0
        
        # Increment counter
        if service not in self.health_check_total:
            self.health_check_total[service] = 0
        self.health_check_total[service] += 1
    
    def get_prometheus_metrics(self) -> str:
        """Generate Prometheus-formatted metrics."""
        metrics = []
        
        # Health status gauges
        for service, status in self.health_status_gauge.items():
            metrics.append(f'health_status{{service="{service}"}} {status}')
        
        # Health check counters
        for service, count in self.health_check_total.items():
            metrics.append(f'health_checks_total{{service="{service}"}} {count}')
        
        # Health check duration histograms (simplified)
        for service, durations in self.health_check_duration.items():
            if durations:
                avg_duration = sum(durations) / len(durations)
                metrics.append(f'health_check_duration_seconds{{service="{service}"}} {avg_duration:.3f}')
        
        return "\n".join(metrics)

# Integration with health checker
class MonitoredHealthChecker(AdvancedHealthChecker):
    def __init__(self):
        super().__init__()
        self.prometheus_metrics = PrometheusHealthMetrics()
    
    async def check_service_health(self, service_name: str, checker: callable) -> bool:
        """Check service health with metrics recording."""
        start_time = time.time()
        
        try:
            is_healthy = await self._run_dependency_checker(checker)
            status = "healthy" if is_healthy else "unhealthy"
            
        except Exception:
            is_healthy = False
            status = "error"
        
        finally:
            duration = time.time() - start_time
            self.prometheus_metrics.record_health_check(service_name, duration, status)
        
        return is_healthy
```

## Testing Health Checks

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
             patch('psutil.virtual_memory') as mock_memory, \
             patch('psutil.disk_usage') as mock_disk:
            
            # Mock memory usage
            mock_memory.return_value = Mock(percent=60.0, used=1024*1024*1024)  # 1GB
            
            # Mock disk usage
            mock_disk.return_value = Mock(used=50*1024*1024*1024, total=100*1024*1024*1024)  # 50% used
            
            report = await health_checker.get_comprehensive_health_report()
            
            assert report.overall_status == "healthy"
            assert "cpu_usage" in report.metrics
            assert report.metrics["cpu_usage"].value == 50.0
            assert report.metrics["cpu_usage"].status == "healthy"
    
    @pytest.mark.asyncio
    async def test_dependency_health_check(self, health_checker):
        """Test external dependency health checking."""
        # Register mock dependency
        async def mock_healthy_dependency():
            return True
        
        async def mock_unhealthy_dependency():
            return False
        
        health_checker.register_dependency("healthy_service", mock_healthy_dependency)
        health_checker.register_dependency("unhealthy_service", mock_unhealthy_dependency)
        
        report = await health_checker.get_comprehensive_health_report()
        
        assert "dependency_healthy_service" in report.metrics
        assert report.metrics["dependency_healthy_service"].status == "healthy"
        
        assert "dependency_unhealthy_service" in report.metrics
        assert report.metrics["dependency_unhealthy_service"].status == "critical"
    
    @pytest.mark.asyncio
    async def test_grpc_health_service(self):
        """Test gRPC health service."""
        health_service = HealthCheckServicer()
        
        # Set service status
        health_service.set_service_status("test.Service", HealthStatus.SERVING)
        
        # Mock request
        request = Mock(service="test.Service")
        context = Mock()
        
        response = await health_service.Check(request, context)
        
        assert response.status == HealthStatus.SERVING.value
    
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
        assert "timeout" in report.metrics["dependency_slow_service"].message

# Usage
pytest.main([__file__])
```

## Health Check Best Practices

### Production Health Check Configuration

```python
def create_production_health_setup():
    """Create production-ready health check setup."""
    
    # Create health checker with appropriate thresholds
    health_checker = AdvancedHealthChecker()
    health_checker.resource_thresholds = {
        "cpu_percent": 85.0,    # Higher threshold for production
        "memory_percent": 90.0,  # Higher threshold for production
        "disk_usage_percent": 85.0
    }
    
    # Register critical dependencies
    health_checker.register_dependency("primary_database", check_primary_db)
    health_checker.register_dependency("cache_service", check_cache)
    health_checker.register_dependency("message_queue", check_message_queue)
    
    # Create gRPC health service
    health_service = HealthCheckServicer()
    health_service.register_health_checker("", lambda: True)  # Overall health
    health_service.register_health_checker("database", check_primary_db)
    
    # Setup monitoring integration
    prometheus_metrics = PrometheusHealthMetrics()
    k8s_integration = KubernetesHealthIntegration(health_checker)
    
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

async def check_message_queue():
    """Check message queue health."""
    # Implement actual message queue health check
    return True
```

## Next Steps

With comprehensive health checks implemented:

- **[Security](../security/)** - Secure your health endpoints
- **[Configuration](../config/)** - Configure health check parameters
- **[Production Deployment](../production/)** - Deploy with monitoring integration
- **[Client Development](../client/)** - Implement client-side health checking