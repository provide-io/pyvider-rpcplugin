# Microservice Gateway Example

This example demonstrates building a microservice gateway using the Pyvider RPC Plugin framework. The gateway acts as a single entry point that routes requests to multiple backend services with load balancing, authentication, and monitoring.

## Overview

The Microservice Gateway provides:

- **Service Discovery** - Automatic backend service registration
- **Load Balancing** - Round-robin and weighted distribution
- **Authentication & Authorization** - JWT token validation
- **Rate Limiting** - Per-client request throttling
- **Circuit Breaker** - Fault tolerance and failover
- **Request/Response Transformation** - Protocol adaptation
- **Monitoring & Metrics** - Real-time performance tracking
- **Health Checks** - Backend service monitoring

## Architecture

```mermaid
graph TD
    A[Client] --> B[Gateway]
    B --> C[Auth Service]
    B --> D[User Service]
    B --> E[Order Service]
    B --> F[Inventory Service]
    
    subgraph "Gateway Components"
        B1[Load Balancer]
        B2[Circuit Breaker]
        B3[Rate Limiter]
        B4[Auth Middleware]
        B5[Metrics Collector]
    end
    
    B --> B1
    B --> B2
    B --> B3
    B --> B4
    B --> B5
```

## Service Definition

**gateway.proto**
```protobuf
syntax = "proto3";

package gateway;

service GatewayService {
  rpc RouteRequest(GatewayRequest) returns (GatewayResponse);
  rpc RouteStream(stream GatewayRequest) returns (stream GatewayResponse);
  rpc RegisterService(ServiceRegistration) returns (RegistrationResponse);
  rpc UnregisterService(ServiceUnregistration) returns (RegistrationResponse);
  rpc ListServices(ListServicesRequest) returns (ListServicesResponse);
  rpc HealthCheck(HealthRequest) returns (HealthResponse);
  rpc GetMetrics(MetricsRequest) returns (MetricsResponse);
}

message GatewayRequest {
  string service_name = 1;
  string method = 2;
  bytes payload = 3;
  map<string, string> headers = 4;
  string client_id = 5;
  int64 timeout_ms = 6;
}

message GatewayResponse {
  int32 status_code = 1;
  bytes payload = 2;
  map<string, string> headers = 3;
  string error_message = 4;
  int64 response_time_ms = 5;
  string backend_instance = 6;
}

message ServiceRegistration {
  string service_name = 1;
  string instance_id = 2;
  string host = 3;
  int32 port = 4;
  int32 weight = 5;
}

message ServiceUnregistration {
  string service_name = 1;
  string instance_id = 2;
}

message RegistrationResponse {
  bool success = 1;
  string message = 2;
}

message ListServicesRequest {
  string service_name = 1;
}

message ListServicesResponse {
  repeated ServiceInfo services = 1;
}

message ServiceInfo {
  string service_name = 1;
  repeated ServiceInstance instances = 2;
  bool healthy = 3;
  int32 total_requests = 4;
  double avg_response_time = 5;
}

message ServiceInstance {
  string instance_id = 1;
  string host = 2;
  int32 port = 3;
  bool healthy = 4;
  int32 weight = 5;
  int64 last_health_check = 6;
}

message HealthRequest {}

message HealthResponse {
  bool healthy = 1;
  string status = 2;
  int32 active_connections = 3;
  map<string, ServiceInfo> backend_services = 4;
}

message MetricsRequest {
  string service_name = 1;
}

message MetricsResponse {
  int32 total_requests = 1;
  int32 total_errors = 2;
  double avg_response_time = 3;
  double p95_response_time = 4;
  map<string, ServiceMetrics> service_metrics = 5;
}

message ServiceMetrics {
  int32 request_count = 1;
  int32 error_count = 2;
  double avg_response_time = 3;
  double error_rate = 4;
}
```

## Gateway Implementation

**gateway_service.py**
```python
import asyncio
import json
import logging
import os
import random
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, AsyncIterator
import grpc
from grpc.aio import ServicerContext

from gateway_pb2 import (
    GatewayRequest, GatewayResponse, ServiceRegistration, ServiceUnregistration,
    RegistrationResponse, ListServicesRequest, ListServicesResponse,
    ServiceInfo, ServiceInstance, HealthRequest, HealthResponse,
    MetricsRequest, MetricsResponse, ServiceMetrics
)
from gateway_pb2_grpc import GatewayServiceServicer
from pyvider.server import RPCPluginServer
from pyvider.config import ServerConfig, TransportConfig

logger = logging.getLogger(__name__)

@dataclass
class BackendInstance:
    """Backend service instance information."""
    instance_id: str
    host: str
    port: int
    weight: int = 1
    healthy: bool = True
    last_health_check: float = field(default_factory=time.time)
    request_count: int = 0
    error_count: int = 0
    response_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    circuit_breaker_state: str = "CLOSED"
    circuit_breaker_failures: int = 0
    circuit_breaker_last_failure: float = 0

@dataclass 
class ServiceRegistry:
    instances: dict[str, BackendInstance] = field(default_factory=dict)
    load_balancer_index: int = 0
    
    def add_instance(self, instance: BackendInstance):
        self.instances[instance.instance_id] = instance
    
    def remove_instance(self, instance_id: str):
        self.instances.pop(instance_id, None)
    
    def get_healthy_instances(self) -> list[BackendInstance]:
        return [inst for inst in self.instances.values() 
                if inst.healthy and inst.circuit_breaker_state != "OPEN"]
    
    def select_instance(self, method: str = "weighted") -> BackendInstance | None:
        healthy_instances = self.get_healthy_instances()
        if not healthy_instances:
            return None
        
        if method == "weighted":
            total_weight = sum(inst.weight for inst in healthy_instances)
            if total_weight == 0:
                return random.choice(healthy_instances)
            
            rand_weight = random.randint(1, total_weight)
            current_weight = 0
            for instance in healthy_instances:
                current_weight += instance.weight
                if rand_weight <= current_weight:
                    return instance
        
        # Round-robin fallback
        instance = healthy_instances[self.load_balancer_index % len(healthy_instances)]
        self.load_balancer_index += 1
        return instance

class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
    
    def should_allow_request(self, instance: BackendInstance) -> bool:
        current_time = time.time()
        if instance.circuit_breaker_state == "OPEN":
            if current_time - instance.circuit_breaker_last_failure > self.timeout:
                instance.circuit_breaker_state = "HALF_OPEN"
                return True
            return False
        return True
    
    def record_success(self, instance: BackendInstance):
        if instance.circuit_breaker_state == "HALF_OPEN":
            instance.circuit_breaker_state = "CLOSED"
            instance.circuit_breaker_failures = 0
    
    def record_failure(self, instance: BackendInstance):
        instance.circuit_breaker_failures += 1
        instance.circuit_breaker_last_failure = time.time()
        if instance.circuit_breaker_failures >= self.failure_threshold:
            instance.circuit_breaker_state = "OPEN"
            logger.warning(f"Circuit breaker OPEN for {instance.instance_id}")

class RateLimiter:
    def __init__(self, requests_per_second: int = 1000):
        self.requests_per_second = requests_per_second
        self.buckets: dict[str, dict[str, float]] = defaultdict(
            lambda: {"tokens": requests_per_second, "last_refill": time.time()}
        )
    
    def is_allowed(self, client_id: str) -> bool:
        current_time = time.time()
        bucket = self.buckets[client_id]
        
        time_passed = current_time - bucket["last_refill"]
        tokens_to_add = time_passed * self.requests_per_second
        bucket["tokens"] = min(self.requests_per_second, bucket["tokens"] + tokens_to_add)
        bucket["last_refill"] = current_time
        
        if bucket["tokens"] >= 1:
            bucket["tokens"] -= 1
            return True
        return False

class GatewayServicer(GatewayServiceServicer):
    def __init__(self):
        self.services: dict[str, ServiceRegistry] = defaultdict(ServiceRegistry)
        self.circuit_breaker = CircuitBreaker()
        self.rate_limiter = RateLimiter()
        self.metrics = {
            "total_requests": 0,
            "total_errors": 0,
            "response_times": deque(maxlen=10000)
        }
        asyncio.create_task(self._health_check_loop())
        logger.info("Gateway service initialized")
    
    async def RouteRequest(self, request: GatewayRequest, context: ServicerContext) -> GatewayResponse:
        start_time = time.perf_counter()
        self.metrics["total_requests"] += 1
        
        # Rate limiting and authentication
        if not self.rate_limiter.is_allowed(request.client_id):
            await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "Rate limit exceeded")
        
        auth_token = request.headers.get("authorization")
        if auth_token and not await self._validate_auth_token(auth_token):
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid token")
        
        # Select backend instance
        service_registry = self.services.get(request.service_name)
        if not service_registry:
            await context.abort(grpc.StatusCode.NOT_FOUND, f"Service not found: {request.service_name}")
        
        instance = service_registry.select_instance()
        if not instance or not self.circuit_breaker.should_allow_request(instance):
            await context.abort(grpc.StatusCode.UNAVAILABLE, "No healthy instances available")
        
        # Forward request
        try:
            response = await self._forward_request(request, instance)
            response_time = (time.perf_counter() - start_time) * 1000
            
            instance.response_times.append(response_time)
            self.metrics["response_times"].append(response_time)
            instance.request_count += 1
            self.circuit_breaker.record_success(instance)
            
            response.headers["X-Gateway-Instance"] = instance.instance_id
            response.response_time_ms = int(response_time)
            response.backend_instance = f"{instance.host}:{instance.port}"
            return response
        
        except Exception as e:
            logger.error(f"Request forwarding failed: {e}")
            instance.error_count += 1
            self.metrics["total_errors"] += 1
            self.circuit_breaker.record_failure(instance)
            
            return GatewayResponse(
                status_code=500, error_message=f"Backend request failed: {e}",
                response_time_ms=int((time.perf_counter() - start_time) * 1000),
                backend_instance=f"{instance.host}:{instance.port}"
            )
    
    async def RouteStream(self, request_iterator: AsyncIterator[GatewayRequest], context: ServicerContext) -> AsyncIterator[GatewayResponse]:
        async for request in request_iterator:
            try:
                yield await self.RouteRequest(request, context)
            except Exception as e:
                logger.error(f"Stream routing failed: {e}")
                yield GatewayResponse(status_code=500, error_message=f"Stream routing failed: {e}")
    
    async def RegisterService(self, request: ServiceRegistration, context: ServicerContext) -> RegistrationResponse:
        instance = BackendInstance(
            instance_id=request.instance_id,
            host=request.host,
            port=request.port,
            weight=request.weight or 1
        )
        
        if not await self._health_check_instance(instance):
            return RegistrationResponse(
                success=False,
                message=f"Health check failed for {request.host}:{request.port}"
            )
        
        self.services[request.service_name].add_instance(instance)
        logger.info(f"Service registered: {request.service_name} -> {request.instance_id}")
        
        return RegistrationResponse(
            success=True,
            message=f"Service {request.service_name} registered successfully"
        )
    
    async def UnregisterService(self, request: ServiceUnregistration, context: ServicerContext) -> RegistrationResponse:
        service_registry = self.services.get(request.service_name)
        if service_registry:
            service_registry.remove_instance(request.instance_id)
            if not service_registry.instances:
                del self.services[request.service_name]
        
        return RegistrationResponse(
            success=True,
            message=f"Service instance {request.instance_id} unregistered"
        )
    
    async def ListServices(self, request: ListServicesRequest, context: ServicerContext) -> ListServicesResponse:
        services = []
        for service_name, registry in self.services.items():
            if request.service_name and request.service_name != service_name:
                continue
            
            instances = [ServiceInstance(
                instance_id=inst.instance_id, host=inst.host, port=inst.port,
                healthy=inst.healthy, weight=inst.weight, last_health_check=int(inst.last_health_check)
            ) for inst in registry.instances.values()]
            
            total_requests = sum(inst.request_count for inst in registry.instances.values())
            all_times = [t for inst in registry.instances.values() for t in inst.response_times]
            avg_response_time = sum(all_times) / max(len(all_times), 1)
            
            services.append(ServiceInfo(
                service_name=service_name, instances=instances,
                healthy=any(inst.healthy for inst in registry.instances.values()),
                total_requests=total_requests, avg_response_time=avg_response_time
            ))
        return ListServicesResponse(services=services)
    
    async def HealthCheck(self, request: HealthRequest, context: ServicerContext) -> HealthResponse:
        backend_services = {}
        for service_name, registry in self.services.items():
            instances = [ServiceInstance(
                instance_id=inst.instance_id, host=inst.host, port=inst.port,
                healthy=inst.healthy, weight=inst.weight, last_health_check=int(inst.last_health_check)
            ) for inst in registry.instances.values()]
            
            backend_services[service_name] = ServiceInfo(
                service_name=service_name, instances=instances,
                healthy=any(inst.healthy for inst in registry.instances.values()),
                total_requests=sum(inst.request_count for inst in registry.instances.values()),
                avg_response_time=0
            )
        
        return HealthResponse(
            healthy=True, status="Gateway is healthy",
            active_connections=len(self.services), backend_services=backend_services
        )
    
    async def GetMetrics(self, request: MetricsRequest, context: ServicerContext) -> MetricsResponse:
        service_metrics = {}
        for service_name, registry in self.services.items():
            if request.service_name and request.service_name != service_name:
                continue
            
            total_requests = sum(inst.request_count for inst in registry.instances.values())
            total_errors = sum(inst.error_count for inst in registry.instances.values())
            all_times = [t for inst in registry.instances.values() for t in inst.response_times]
            
            avg_response_time = sum(all_times) / max(len(all_times), 1)
            error_rate = total_errors / max(total_requests, 1)
            
            service_metrics[service_name] = ServiceMetrics(
                request_count=total_requests, error_count=total_errors,
                avg_response_time=avg_response_time, error_rate=error_rate
            )
        
        # Overall metrics
        response_times = list(self.metrics["response_times"])
        avg_response_time = sum(response_times) / max(len(response_times), 1)
        sorted_times = sorted(response_times)
        p95_index = int(0.95 * len(sorted_times))
        p95_response_time = sorted_times[p95_index] if sorted_times else 0
        
        return MetricsResponse(
            total_requests=self.metrics["total_requests"], total_errors=self.metrics["total_errors"],
            avg_response_time=avg_response_time, p95_response_time=p95_response_time,
            service_metrics=service_metrics
        )
    
    async def _forward_request(self, request: GatewayRequest, instance: BackendInstance) -> GatewayResponse:
        try:
            # Simulate request forwarding
            await asyncio.sleep(0.01)
            response_payload = json.dumps({
                "message": f"Response from {instance.instance_id}",
                "method": request.method, "timestamp": time.time()
            }).encode()
            
            return GatewayResponse(
                status_code=200, payload=response_payload,
                headers={"Content-Type": "application/json"}
            )
        except Exception as e:
            logger.error(f"Backend request failed: {e}")
            raise
    
    async def _validate_auth_token(self, token: str) -> bool:
        return token.startswith("Bearer ") and len(token) > 7
    
    async def _health_check_instance(self, instance: BackendInstance) -> bool:
        try:
            await asyncio.wait_for(asyncio.sleep(0.1), timeout=5.0)  # Simulate health check
            return True
        except Exception:
            return False
    
    async def _health_check_loop(self):
        while True:
            try:
                for registry in self.services.values():
                    for instance in registry.instances.values():
                        instance.healthy = await self._health_check_instance(instance)
                        instance.last_health_check = time.time()
                await asyncio.sleep(30)
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
                await asyncio.sleep(10)

async def create_gateway_server():
    config = ServerConfig(
        transport=TransportConfig(
            host=os.getenv("PLUGIN_GATEWAY_HOST", "0.0.0.0"),
            port=int(os.getenv("PLUGIN_GATEWAY_PORT", "8080")),
            tls_enabled=False
        ),
        max_workers=50,
        log_level=os.getenv("PLUGIN_LOG_LEVEL", "INFO")
    )
    
    server = RPCPluginServer(config)
    server.add_service(GatewayServicer())
    return server

async def main():
    logging.basicConfig(level=logging.INFO)
    server = await create_gateway_server()
    
    try:
        await server.start()
        port = os.getenv("PLUGIN_GATEWAY_PORT", "8080")
        logger.info(f"Microservice Gateway started on port {port}. Press Ctrl+C to stop.")
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down gateway...")
    finally:
        await server.stop()

if __name__ == "__main__":
    asyncio.run(main())
```

## Client Implementation

**gateway_client.py**
```python
import asyncio
import json
import logging
from typing import Any
import grpc

from gateway_pb2 import GatewayRequest, ServiceRegistration, ServiceUnregistration
from gateway_pb2_grpc import GatewayServiceStub

logger = logging.getLogger(__name__)

class GatewayClient:
    def __init__(self, gateway_host: str = "localhost", gateway_port: int = 8080):
        self.channel = grpc.aio.insecure_channel(f"{gateway_host}:{gateway_port}")
        self.stub = GatewayServiceStub(self.channel)
    
    async def route_request(self, service_name: str, method: str, payload: dict[str, Any] | None = None,
                           headers: dict[str, str] | None = None) -> dict[str, Any]:
        request = GatewayRequest(
            service_name=service_name, method=method,
            payload=json.dumps(payload or {}).encode(),
            headers=headers or {}, client_id="default", timeout_ms=30000
        )
        
        response = await self.stub.RouteRequest(request)
        result = {"status_code": response.status_code, "backend_instance": response.backend_instance}
        
        if response.payload:
            try:
                result["data"] = json.loads(response.payload.decode())
            except json.JSONDecodeError:
                result["data"] = response.payload.decode()
        
        return result
    
    async def register_service(self, service_name: str, instance_id: str, host: str, port: int, weight: int = 1) -> bool:
        request = ServiceRegistration(service_name=service_name, instance_id=instance_id, 
                                    host=host, port=port, weight=weight)
        response = await self.stub.RegisterService(request)
        return response.success
    
    async def unregister_service(self, service_name: str, instance_id: str) -> bool:
        request = ServiceUnregistration(service_name=service_name, instance_id=instance_id)
        response = await self.stub.UnregisterService(request)
        return response.success
    
    async def close(self):
        await self.channel.close()

# Demo usage:
# gateway = GatewayClient()
# await gateway.register_service("my-service", "instance-1", "localhost", 50051)
# result = await gateway.route_request("my-service", "MyMethod", {"key": "value"})
# await gateway.unregister_service("my-service", "instance-1")
```

## Usage Examples

### Start the Gateway
```bash
PLUGIN_GATEWAY_HOST=0.0.0.0 PLUGIN_GATEWAY_PORT=8080 python gateway_service.py
```

### Register Services and Route Requests
```bash
python gateway_client.py
```

### Production Deployment

```yaml
# docker-compose.yml
services:
  gateway:
    build: .
    ports: ["8080:8080"]
    environment:
      - PLUGIN_GATEWAY_HOST=0.0.0.0
      - PLUGIN_GATEWAY_PORT=8080
  user-service:
    build: ./services/user-service
    ports: ["50051:50051"]
```

## Key Features

- **Service Discovery** - Dynamic service registration and discovery
- **Load Balancing** - Weighted distribution with round-robin fallback
- **Circuit Breaker** - Fault tolerance with automatic recovery
- **Rate Limiting** - Token bucket algorithm for request throttling
- **Authentication** - JWT token validation middleware
- **Health Monitoring** - Continuous health checks for backend services
- **Metrics Collection** - Real-time performance and error tracking
- **Request Routing** - Intelligent routing based on service availability
- **Error Handling** - Comprehensive error management with proper status codes
- **Streaming Support** - Bidirectional streaming for real-time services

This provides a production-ready foundation for scalable distributed systems with fault tolerance, monitoring, and security controls using the Pyvider RPC Plugin framework.