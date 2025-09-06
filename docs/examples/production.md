# Production Deployment Example

This example demonstrates how to deploy Pyvider RPC Plugin services to production with Docker, Kubernetes, monitoring, and best practices for high availability and scalability.

## Overview

Production deployment includes:

- **Container Orchestration** - Docker and Kubernetes deployment
- **Load Balancing** - High availability and traffic distribution
- **Monitoring & Observability** - Prometheus, Grafana, and distributed tracing
- **Security** - mTLS, RBAC, and network policies
- **CI/CD Pipeline** - Automated build and deployment
- **Database Management** - PostgreSQL with replication
- **Caching Layer** - Redis for performance optimization

## Architecture

```mermaid
graph TB
    subgraph "External"
        LB[Load Balancer]
    end
    
    subgraph "Kubernetes Cluster"
        subgraph "Application Pods"
            API[API Service Pods x3]
            USER[User Service Pods x2]
            ORDER[Order Service Pods x2]
        end
        
        subgraph "Data Layer"
            POSTGRES[(PostgreSQL Cluster)]
            REDIS[(Redis)]
        end
        
        subgraph "Monitoring"
            PROM[Prometheus]
            GRAF[Grafana]
        end
    end
    
    LB --> API
    API --> USER
    API --> ORDER
    USER --> POSTGRES
    ORDER --> POSTGRES
    USER --> REDIS
    ORDER --> REDIS
```

## Docker Configuration

### Production Dockerfile

**Dockerfile**
```dockerfile
# Build stage
FROM python:3.11-slim AS builder
RUN apt-get update && apt-get install -y build-essential libpq-dev && rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim AS production
RUN groupadd -r appuser && useradd -r -g appuser appuser
RUN apt-get update && apt-get install -y libpq5 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
RUN chown -R appuser:appuser /app
COPY --chown=appuser:appuser src/ ./src/
COPY --chown=appuser:appuser config/ ./config/
COPY --chown=appuser:appuser scripts/ ./scripts/

USER appuser
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python scripts/healthcheck.py

CMD ["python", "-m", "src.main"]
LABEL maintainer="provide.io" version="1.0.0" description="Pyvider RPC Plugin Service"
```

### Core Dependencies

**requirements.txt**
```txt
# Core
pyvider-rpcplugin>=1.0.0
grpcio>=1.50.0
protobuf>=4.21.0

# Database & Caching
asyncpg>=0.28.0
sqlalchemy[asyncio]>=2.0.0
aioredis>=2.0.0

# Monitoring & Logging
prometheus-client>=0.18.0
opentelemetry-api>=1.20.0
opentelemetry-instrumentation-grpc>=0.41b0
structlog>=23.1.0

# Configuration & Security
pydantic-settings>=2.0.0
cryptography>=41.0.0
PyJWT>=2.8.0

# Performance
uvloop>=0.17.0
```

## Kubernetes Deployment

### Namespace and Configuration

**k8s/namespace.yaml**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: pyvider-services
  labels:
    name: pyvider-services
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pyvider-service-account
  namespace: pyvider-services
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: pyvider-config
  namespace: pyvider-services
data:
  config.yaml: |
    server:
      host: "0.0.0.0"
      port: 50051
      max_workers: 20
      tls_enabled: true
    database:
      host: "postgres-service"
      port: 5432
      database: "pyvider"
      pool_size: 20
    redis:
      host: "redis-service"
      port: 6379
      pool_size: 10
    monitoring:
      prometheus_port: 9090
      metrics_enabled: true
    logging:
      level: "INFO"
      format: "json"
---
apiVersion: v1
kind: Secret
metadata:
  name: pyvider-secrets
  namespace: pyvider-services
type: Opaque
data:
  database-username: cHl2aWRlcl91c2Vy
  database-password: c2VjdXJlX3Bhc3N3b3Jk
  jwt-secret: bXlfc3VwZXJfc2VjcmV0X2p3dF9rZXk=
  redis-password: cmVkaXNfcGFzc3dvcmQ=
---
apiVersion: v1
kind: Secret
metadata:
  name: pyvider-tls
  namespace: pyvider-services
type: kubernetes.io/tls
data:
  tls.crt: LS0tLS1CRUdJTi... # Your TLS certificate
  tls.key: LS0tLS1CRUdJTi... # Your TLS private key
```

### Application Deployment

**k8s/deployment.yaml**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pyvider-api-service
  namespace: pyvider-services
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 1
  selector:
    matchLabels:
      app: pyvider-api-service
  template:
    metadata:
      labels:
        app: pyvider-api-service
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
    spec:
      serviceAccountName: pyvider-service-account
      containers:
      - name: api-service
        image: your-registry/pyvider-api-service:1.0.0
        ports:
        - containerPort: 50051
          name: grpc
        - containerPort: 9090
          name: metrics
        env:
        - name: PLUGIN_DATABASE_URL
          value: "postgresql://$(DATABASE_USERNAME):$(DATABASE_PASSWORD)@postgres-service:5432/pyvider"
        - name: DATABASE_USERNAME
          valueFrom:
            secretKeyRef: {name: pyvider-secrets, key: database-username}
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef: {name: pyvider-secrets, key: database-password}
        - name: PLUGIN_REDIS_URL
          value: "redis://:$(REDIS_PASSWORD)@redis-service:6379/0"
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef: {name: pyvider-secrets, key: redis-password}
        - name: PLUGIN_JWT_SECRET
          valueFrom:
            secretKeyRef: {name: pyvider-secrets, key: jwt-secret}
        volumeMounts:
        - name: config-volume
          mountPath: /etc/config
        - name: tls-certs
          mountPath: /etc/certs
          readOnly: true
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          exec:
            command: [python, scripts/healthcheck.py]
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          exec:
            command: [python, scripts/healthcheck.py, --readiness]
          initialDelaySeconds: 5
          periodSeconds: 5
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          readOnlyRootFilesystem: true
          capabilities:
            drop: [ALL]
      volumes:
      - name: config-volume
        configMap:
          name: pyvider-config
      - name: tls-certs
        secret:
          secretName: pyvider-tls
---
apiVersion: v1
kind: Service
metadata:
  name: pyvider-api-service
  namespace: pyvider-services
spec:
  ports:
  - name: grpc
    port: 50051
  - name: metrics
    port: 9090
  selector:
    app: pyvider-api-service
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: pyvider-api-service-pdb
  namespace: pyvider-services
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: pyvider-api-service
```

### Auto-scaling

**k8s/hpa.yaml**
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: pyvider-api-service-hpa
  namespace: pyvider-services
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: pyvider-api-service
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 300
    scaleDown:
      stabilizationWindowSeconds: 300
```

## Database and Caching

### PostgreSQL High Availability

**k8s/postgres.yaml**
```yaml
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: postgres-cluster
  namespace: pyvider-services
spec:
  instances: 3
  postgresql:
    parameters:
      max_connections: "200"
      shared_buffers: "256MB"
      effective_cache_size: "1GB"
      work_mem: "4MB"
  storage:
    size: "100Gi"
    storageClass: "fast-ssd"
  monitoring:
    enabled: true
  bootstrap:
    initdb:
      database: "pyvider"
      owner: "pyvider_user"
      secret:
        name: "postgres-credentials"
  backup:
    retentionPolicy: "30d"
    barmanObjectStore:
      destinationPath: "s3://your-backup-bucket/postgres"
---
apiVersion: v1
kind: Service
metadata:
  name: postgres-service
  namespace: pyvider-services
spec:
  ports:
  - port: 5432
  selector:
    cnpg.io/cluster: postgres-cluster
    role: primary
```

### Redis Cache

**k8s/redis.yaml**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: pyvider-services
spec:
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        volumeMounts:
        - name: redis-config
          mountPath: /etc/redis
        - name: redis-data
          mountPath: /data
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "200m"
      volumes:
      - name: redis-config
        configMap:
          name: redis-config
      - name: redis-data
        persistentVolumeClaim:
          claimName: redis-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: redis-service
  namespace: pyvider-services
spec:
  ports:
  - port: 6379
  selector:
    app: redis
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: redis-config
  namespace: pyvider-services
data:
  redis.conf: |
    maxmemory 256mb
    maxmemory-policy allkeys-lru
    save 900 1
    requirepass ${REDIS_PASSWORD}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redis-pvc
  namespace: pyvider-services
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 10Gi
  storageClassName: fast-ssd
```

## Monitoring and Observability

### Prometheus Configuration

**monitoring/prometheus.yaml**
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: pyvider-services
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
    alerting:
      alertmanagers:
      - static_configs:
        - targets: ["alertmanager:9093"]
    scrape_configs:
    - job_name: 'pyvider-services'
      kubernetes_sd_configs:
      - role: pod
        namespaces:
          names: [pyvider-services]
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        target_label: __address__
        regex: (.+)
        replacement: ${1}:9090
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-alerts
  namespace: pyvider-services
data:
  alerts.yml: |
    groups:
    - name: pyvider-alerts
      rules:
      - alert: HighErrorRate
        expr: rate(pyvider_requests_total{status="error"}[5m]) / rate(pyvider_requests_total[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
      - alert: ServiceDown
        expr: up{job="pyvider-services"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service {{ $labels.kubernetes_pod_name }} is down"
      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(pyvider_request_duration_seconds_bucket[5m])) > 1.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High latency detected: {{ $value }}s"
```

### Key Monitoring Metrics

Essential metrics exposed by the service:

```python
# Application metrics exposed at /metrics
PLUGIN_REQUEST_COUNT = Counter('pyvider_requests_total', 'Total requests', ['method', 'status'])
PLUGIN_REQUEST_DURATION = Histogram('pyvider_request_duration_seconds', 'Request duration')
PLUGIN_DB_CONNECTIONS = Gauge('pyvider_database_connections_active', 'Active DB connections')
PLUGIN_CACHE_HITS = Counter('pyvider_cache_hits_total', 'Cache hits')
```

### Grafana Dashboard

Key dashboard panels for monitoring:

- **Request Rate**: `sum(rate(pyvider_requests_total[5m]))`
- **Error Rate**: `sum(rate(pyvider_requests_total{status="error"}[5m])) / sum(rate(pyvider_requests_total[5m]))`
- **95th Percentile Latency**: `histogram_quantile(0.95, rate(pyvider_request_duration_seconds_bucket[5m]))`
- **Database Connections**: `pyvider_database_connections_active`
- **Memory Usage**: `container_memory_usage_bytes{pod=~"pyvider-api-service.*"}`

## Health Check and Security

### Health Check Implementation

**scripts/healthcheck.py**
```python
#!/usr/bin/env python3
"""Health check script for production deployment."""

import asyncio
import argparse
import sys
import os
import grpc
import aioredis
import asyncpg

async def check_grpc_service(port: int = 50051) -> bool:
    """Check if gRPC service is responsive."""
    try:
        channel = grpc.aio.insecure_channel(f"localhost:{port}")
        await asyncio.wait_for(channel.channel_ready(), timeout=5.0)
        await channel.close()
        return True
    except Exception:
        return False

async def check_database(database_url: str) -> bool:
    """Check database connectivity."""
    try:
        conn = await asyncio.wait_for(asyncpg.connect(database_url), timeout=10.0)
        result = await conn.fetchval('SELECT 1')
        await conn.close()
        return result == 1
    except Exception:
        return False

async def check_redis(redis_url: str) -> bool:
    """Check Redis connectivity."""
    try:
        redis = aioredis.from_url(redis_url)
        result = await asyncio.wait_for(redis.ping(), timeout=5.0)
        await redis.close()
        return result
    except Exception:
        return False

async def main():
    """Main health check function."""
    parser = argparse.ArgumentParser(description='Health check script')
    parser.add_argument('--readiness', action='store_true')
    parser.add_argument('--grpc-port', type=int, default=50051)
    args = parser.parse_args()
    
    # Basic liveness check
    if not await check_grpc_service(port=args.grpc_port):
        sys.exit(1)
    
    # Readiness check includes dependencies
    if args.readiness:
        if database_url := os.getenv('PLUGIN_DATABASE_URL'):
            if not await check_database(database_url):
                sys.exit(1)
        
        if redis_url := os.getenv('PLUGIN_REDIS_URL'):
            if not await check_redis(redis_url):
                sys.exit(1)
    
    sys.exit(0)

if __name__ == "__main__":
    asyncio.run(main())
```

## CI/CD Pipeline

**-.github/workflows/production-deploy.yml**
```yaml
name: Production Deployment
on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    - run: pip install -e ".[dev,test]"
    - run: pytest tests/ -v --cov=src

  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'

  build:
    needs: [test, security-scan]
    runs-on: ubuntu-latest
    outputs:
      image-tag: ${{ steps.meta.outputs.tags }}
    steps:
    - uses: actions/checkout@v4
    - uses: docker/setup-buildx-action@v2
    - uses: docker/login-action@v2
      with:
        registry: ${{ secrets.REGISTRY_URL }}
        username: ${{ secrets.REGISTRY_USERNAME }}
        password: ${{ secrets.REGISTRY_PASSWORD }}
    - id: meta
      uses: docker/metadata-action@v4
      with:
        images: ${{ secrets.REGISTRY_URL }}/pyvider-api-service
        tags: |
          type=ref,event=branch
          type=ref,event=tag
    - uses: docker/build-push-action@v4
      with:
        context: .
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        cache-from: type=gha
        cache-to: type=gha,mode=max

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production
    steps:
    - uses: actions/checkout@v4
    - uses: azure/setup-kubectl@v3
    - run: echo "${{ secrets.KUBECONFIG }}" | base64 -d > ~/.kube/config
    - run: |
        kubectl set image deployment/pyvider-api-service \
          api-service=${{ needs.build.outputs.image-tag }} \
          -n pyvider-services
        kubectl rollout status deployment/pyvider-api-service \
          -n pyvider-services --timeout=300s
```

## Performance and Production Features

### Optimized Configuration

**config/production.yaml**
```yaml
server:
  host: "0.0.0.0"
  port: 50051
  max_workers: 50
  max_connections: 1000
  max_message_size: 4194304  # 4MB
  compression: gzip
  tls_enabled: true

database:
  pool_size: 20
  max_overflow: 10
  pool_timeout: 30
  pool_recycle: 3600
  connect_timeout: 10

redis:
  pool_size: 20
  max_connections: 50
  retry_on_timeout: true
  health_check_interval: 30

logging:
  level: "INFO"
  format: "json"
  enable_structured_logging: true

monitoring:
  prometheus_enabled: true
  prometheus_port: 9090
  tracing_enabled: true
  trace_sampling_rate: 0.1

# Feature flags for production
features:
  enable_caching: true
  enable_rate_limiting: true
  enable_circuit_breaker: true
  enable_request_validation: true
```

### Security and Operations

**Security essentials:**
- Non-root containers with read-only filesystems
- TLS encryption and secret management via Kubernetes
- Resource limits and security contexts
- Regular security scanning in CI/CD pipeline

**Common operations:**
```bash
# Service status and logs
kubectl get pods -n pyvider-services
kubectl logs -f deployment/pyvider-api-service -n pyvider-services

# Scaling and maintenance
kubectl scale deployment/pyvider-api-service --replicas=5 -n pyvider-services
kubectl exec -n pyvider-services postgres-cluster-1 -- pg_dump pyvider > backup.sql
kubectl port-forward svc/pyvider-api-service 9090:9090 -n pyvider-services
```

## Production Deployment Summary

This production-ready configuration provides:

1. **High Availability** - Multi-replica deployments with automatic failover
2. **Auto-scaling** - HPA based on CPU/memory metrics  
3. **Security** - TLS, RBAC, secrets management, and container hardening
4. **Monitoring** - Prometheus metrics, alerting, and distributed tracing
5. **Database HA** - PostgreSQL cluster with automated backups
6. **Performance** - Optimized connection pooling and caching
7. **CI/CD** - Automated testing, security scanning, and deployments
8. **Observability** - Structured logging, health checks, and dashboards

The configuration supports enterprise-scale deployments with proper resource management, security controls, and operational best practices. All services use the PLUGIN_* environment variable prefix for consistent configuration management.