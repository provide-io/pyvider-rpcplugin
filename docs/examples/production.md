# Production Deployment Example

This example demonstrates how to deploy Pyvider RPC Plugin services to production with Docker, Kubernetes, monitoring, and best practices for high availability and scalability.

## Overview

Production deployment includes:

- **Container Orchestration** - Docker and Kubernetes deployment
- **Service Mesh** - Istio integration for traffic management
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
        CDN[CDN]
    end
    
    subgraph "Kubernetes Cluster"
        subgraph "Ingress"
            NGINX[NGINX Ingress]
        end
        
        subgraph "Application Pods"
            API1[API Service Pod 1]
            API2[API Service Pod 2]
            API3[API Service Pod 3]
            
            USER1[User Service Pod 1]
            USER2[User Service Pod 2]
            
            ORDER1[Order Service Pod 1]
            ORDER2[Order Service Pod 2]
        end
        
        subgraph "Data Layer"
            POSTGRES[(PostgreSQL)]
            REDIS[(Redis)]
        end
        
        subgraph "Monitoring"
            PROM[Prometheus]
            GRAF[Grafana]
            JAEGER[Jaeger]
        end
    end
    
    CDN --> LB
    LB --> NGINX
    NGINX --> API1
    NGINX --> API2
    NGINX --> API3
    
    API1 --> USER1
    API1 --> ORDER1
    API2 --> USER2
    API2 --> ORDER2
    API3 --> USER1
    API3 --> ORDER1
    
    USER1 --> POSTGRES
    USER2 --> POSTGRES
    ORDER1 --> POSTGRES
    ORDER2 --> POSTGRES
    
    USER1 --> REDIS
    USER2 --> REDIS
    ORDER1 --> REDIS
    ORDER2 --> REDIS
```

## Docker Configuration

### Multi-stage Dockerfile

**Dockerfile**
```dockerfile
# Build stage
FROM python:3.11-slim AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Production stage
FROM python:3.11-slim AS production

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Create application directory
WORKDIR /app
RUN chown -R appuser:appuser /app

# Copy application code
COPY --chown=appuser:appuser src/ ./src/
COPY --chown=appuser:appuser config/ ./config/
COPY --chown=appuser:appuser scripts/ ./scripts/

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python scripts/healthcheck.py

# Default command
CMD ["python", "-m", "src.main"]

# Metadata
LABEL maintainer="provide.io"
LABEL version="1.0.0"
LABEL description="Pyvider RPC Plugin Service"
```

### Production Requirements

**requirements.txt**
```txt
# Core dependencies
pyvider-rpcplugin>=1.0.0
grpcio>=1.50.0
grpcio-tools>=1.50.0
protobuf>=4.21.0

# Database
asyncpg>=0.28.0
alembic>=1.12.0
sqlalchemy[asyncio]>=2.0.0

# Caching
aioredis>=2.0.0

# Monitoring
prometheus-client>=0.18.0
opentelemetry-api>=1.20.0
opentelemetry-sdk>=1.20.0
opentelemetry-instrumentation-grpc>=0.41b0
opentelemetry-exporter-jaeger>=1.20.0

# Logging
structlog>=23.1.0
python-json-logger>=2.0.0

# Configuration
pydantic>=2.4.0
pydantic-settings>=2.0.0

# Security
cryptography>=41.0.0
PyJWT>=2.8.0

# HTTP client
aiohttp>=3.8.0

# Production server
uvloop>=0.17.0  # For better async performance
```

## Kubernetes Deployment

### Namespace Configuration

**k8s/namespace.yaml**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: pyvider-services
  labels:
    name: pyvider-services
    istio-injection: enabled
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: pyvider-service-account
  namespace: pyvider-services
  labels:
    app: pyvider-services
```

### ConfigMap for Configuration

**k8s/configmap.yaml**
```yaml
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
      cert_file: "/etc/certs/tls.crt"
      key_file: "/etc/certs/tls.key"
    
    database:
      host: "postgres-service"
      port: 5432
      database: "pyvider"
      pool_size: 20
      max_overflow: 10
    
    redis:
      host: "redis-service"
      port: 6379
      db: 0
      pool_size: 10
    
    monitoring:
      prometheus_port: 9090
      jaeger_endpoint: "http://jaeger-collector:14268/api/traces"
      metrics_enabled: true
      tracing_enabled: true
    
    logging:
      level: "INFO"
      format: "json"
      enable_structured_logging: true
```

### Secret Management

**k8s/secrets.yaml**
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pyvider-secrets
  namespace: pyvider-services
type: Opaque
data:
  # Base64 encoded values
  database-username: cHl2aWRlcl91c2Vy  # pyvider_user
  database-password: c2VjdXJlX3Bhc3N3b3Jk  # secure_password
  jwt-secret: bXlfc3VwZXJfc2VjcmV0X2p3dF9rZXk=  # my_super_secret_jwt_key
  redis-password: cmVkaXNfcGFzc3dvcmQ=  # redis_password
---
apiVersion: v1
kind: Secret
metadata:
  name: pyvider-tls
  namespace: pyvider-services
type: kubernetes.io/tls
data:
  tls.crt: |
    # Base64 encoded TLS certificate
  tls.key: |
    # Base64 encoded TLS private key
```

### Service Deployment

**k8s/deployment.yaml**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pyvider-api-service
  namespace: pyvider-services
  labels:
    app: pyvider-api-service
    version: v1
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
      version: v1
  template:
    metadata:
      labels:
        app: pyvider-api-service
        version: v1
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9090"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: pyvider-service-account
      securityContext:
        fsGroup: 1000
      containers:
      - name: api-service
        image: your-registry/pyvider-api-service:1.0.0
        imagePullPolicy: IfNotPresent
        ports:
        - name: grpc
          containerPort: 50051
          protocol: TCP
        - name: metrics
          containerPort: 9090
          protocol: TCP
        env:
        - name: DATABASE_URL
          value: "postgresql://$(DATABASE_USERNAME):$(DATABASE_PASSWORD)@postgres-service:5432/pyvider"
        - name: DATABASE_USERNAME
          valueFrom:
            secretKeyRef:
              name: pyvider-secrets
              key: database-username
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: pyvider-secrets
              key: database-password
        - name: REDIS_URL
          value: "redis://:$(REDIS_PASSWORD)@redis-service:6379/0"
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: pyvider-secrets
              key: redis-password
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: pyvider-secrets
              key: jwt-secret
        - name: CONFIG_FILE
          value: "/etc/config/config.yaml"
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
            command:
            - python
            - scripts/healthcheck.py
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          exec:
            command:
            - python
            - scripts/healthcheck.py
            - --readiness
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          runAsGroup: 1000
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: config-volume
        configMap:
          name: pyvider-config
      - name: tls-certs
        secret:
          secretName: pyvider-tls
      restartPolicy: Always
      terminationGracePeriodSeconds: 30
---
apiVersion: v1
kind: Service
metadata:
  name: pyvider-api-service
  namespace: pyvider-services
  labels:
    app: pyvider-api-service
spec:
  type: ClusterIP
  ports:
  - name: grpc
    port: 50051
    targetPort: 50051
    protocol: TCP
  - name: metrics
    port: 9090
    targetPort: 9090
    protocol: TCP
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

### Horizontal Pod Autoscaler

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
      policies:
      - type: Percent
        value: 100
        periodSeconds: 15
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
```

## Database Setup

### PostgreSQL with High Availability

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
      maintenance_work_mem: "64MB"
      checkpoint_completion_target: "0.7"
      wal_buffers: "16MB"
      default_statistics_target: "100"
      random_page_cost: "1.1"
      effective_io_concurrency: "200"
      work_mem: "4MB"
      min_wal_size: "1GB"
      max_wal_size: "4GB"
  
  storage:
    size: "100Gi"
    storageClass: "fast-ssd"
  
  monitoring:
    enabled: true
    prometheusRule:
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
      s3Credentials:
        accessKeyId:
          name: "backup-credentials"
          key: "ACCESS_KEY_ID"
        secretAccessKey:
          name: "backup-credentials" 
          key: "SECRET_ACCESS_KEY"
      wal:
        retention: "7d"
      data:
        retention: "30d"
---
apiVersion: v1
kind: Service
metadata:
  name: postgres-service
  namespace: pyvider-services
spec:
  type: ClusterIP
  ports:
  - port: 5432
    targetPort: 5432
  selector:
    cnpg.io/cluster: postgres-cluster
    role: primary
```

### Redis Configuration

**k8s/redis.yaml**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: pyvider-services
spec:
  replicas: 1
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
        command: ["redis-server"]
        args: ["/etc/redis/redis.conf"]
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
  type: ClusterIP
  ports:
  - port: 6379
    targetPort: 6379
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
    save 300 10
    save 60 10000
    rdbcompression yes
    rdbchecksum yes
    requirepass ${REDIS_PASSWORD}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: redis-pvc
  namespace: pyvider-services
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: fast-ssd
```

## Monitoring Setup

### Prometheus Configuration

**monitoring/prometheus-config.yaml**
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
      evaluation_interval: 15s
    
    rule_files:
      - "/etc/prometheus/rules/*.yml"
    
    alerting:
      alertmanagers:
      - static_configs:
        - targets:
          - "alertmanager:9093"
    
    scrape_configs:
    - job_name: 'pyvider-services'
      kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
          - pyvider-services
      relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
      - action: labelmap
        regex: __meta_kubernetes_pod_label_(.+)
      - source_labels: [__meta_kubernetes_namespace]
        action: replace
        target_label: kubernetes_namespace
      - source_labels: [__meta_kubernetes_pod_name]
        action: replace
        target_label: kubernetes_pod_name
    
    - job_name: 'postgres'
      static_configs:
      - targets: ['postgres-service:5432']
      metrics_path: /metrics
      scrape_interval: 30s
    
    - job_name: 'redis'
      static_configs:
      - targets: ['redis-service:6379']
      metrics_path: /metrics
      scrape_interval: 30s
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-rules
  namespace: pyvider-services
data:
  pyvider-alerts.yml: |
    groups:
    - name: pyvider-service-alerts
      rules:
      - alert: HighErrorRate
        expr: rate(pyvider_requests_total{status="error"}[5m]) / rate(pyvider_requests_total[5m]) > 0.1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value | humanizePercentage }} for service {{ $labels.service_name }}"
      
      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(pyvider_request_duration_seconds_bucket[5m])) > 1.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High latency detected"
          description: "95th percentile latency is {{ $value }}s for service {{ $labels.service_name }}"
      
      - alert: ServiceDown
        expr: up{job="pyvider-services"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Service is down"
          description: "Service {{ $labels.kubernetes_pod_name }} is down"
      
      - alert: DatabaseConnectionFailed
        expr: pyvider_database_connections_failed_total > 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Database connection failures"
          description: "Database connection failures detected: {{ $value }}"
```

### Grafana Dashboards

**monitoring/grafana-dashboard.json**
```json
{
  "dashboard": {
    "id": null,
    "title": "Pyvider RPC Services",
    "tags": ["pyvider", "rpc", "microservices"],
    "timezone": "browser",
    "refresh": "30s",
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "panels": [
      {
        "title": "Request Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(rate(pyvider_requests_total[5m]))",
            "legendFormat": "Requests/sec"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "reqps"
          }
        }
      },
      {
        "title": "Error Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "sum(rate(pyvider_requests_total{status=\"error\"}[5m])) / sum(rate(pyvider_requests_total[5m]))",
            "legendFormat": "Error Rate"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "unit": "percentunit",
            "thresholds": {
              "steps": [
                {"color": "green", "value": 0},
                {"color": "yellow", "value": 0.05},
                {"color": "red", "value": 0.1}
              ]
            }
          }
        }
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.50, rate(pyvider_request_duration_seconds_bucket[5m]))",
            "legendFormat": "50th percentile"
          },
          {
            "expr": "histogram_quantile(0.95, rate(pyvider_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          },
          {
            "expr": "histogram_quantile(0.99, rate(pyvider_request_duration_seconds_bucket[5m]))",
            "legendFormat": "99th percentile"
          }
        ],
        "yAxes": [
          {
            "unit": "s",
            "min": 0
          }
        ]
      }
    ]
  }
}
```

## Health Check Implementation

**scripts/healthcheck.py**
```python
#!/usr/bin/env python3
"""Health check script for production deployment."""

import asyncio
import argparse
import sys
import time
from typing import Any
import grpc
import aioredis
import asyncpg

async def check_grpc_service(host: str = "localhost", port: int = 50051) -> bool:
    """Check if gRPC service is responsive."""
    try:
        channel = grpc.aio.insecure_channel(f"{host}:{port}")
        
        # Try to create connection with timeout
        await asyncio.wait_for(
            channel.channel_ready(),
            timeout=5.0
        )
        
        await channel.close()
        return True
    
    except Exception as e:
        print(f"gRPC health check failed: {e}")
        return False

async def check_database(database_url: str) -> bool:
    """Check database connectivity."""
    try:
        conn = await asyncio.wait_for(
            asyncpg.connect(database_url),
            timeout=10.0
        )
        
        # Simple query
        result = await conn.fetchval('SELECT 1')
        await conn.close()
        
        return result == 1
    
    except Exception as e:
        print(f"Database health check failed: {e}")
        return False

async def check_redis(redis_url: str) -> bool:
    """Check Redis connectivity."""
    try:
        redis = aioredis.from_url(redis_url)
        
        # Simple ping
        result = await asyncio.wait_for(
            redis.ping(),
            timeout=5.0
        )
        
        await redis.close()
        return result
    
    except Exception as e:
        print(f"Redis health check failed: {e}")
        return False

async def main():
    """Main health check function."""
    parser = argparse.ArgumentParser(description='Health check script')
    parser.add_argument('--readiness', action='store_true', 
                       help='Perform readiness check (more comprehensive)')
    parser.add_argument('--grpc-port', type=int, default=50051,
                       help='gRPC service port')
    
    args = parser.parse_args()
    
    # Basic liveness check
    grpc_healthy = await check_grpc_service(port=args.grpc_port)
    
    if not grpc_healthy:
        print("❌ gRPC service not healthy")
        sys.exit(1)
    
    print("✅ gRPC service healthy")
    
    # Readiness check includes dependencies
    if args.readiness:
        import os
        
        database_url = os.getenv('DATABASE_URL')
        if database_url:
            db_healthy = await check_database(database_url)
            if not db_healthy:
                print("❌ Database not ready")
                sys.exit(1)
            print("✅ Database ready")
        
        redis_url = os.getenv('REDIS_URL')
        if redis_url:
            redis_healthy = await check_redis(redis_url)
            if not redis_healthy:
                print("❌ Redis not ready")
                sys.exit(1)
            print("✅ Redis ready")
    
    print("✅ All health checks passed")
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
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        pip install -e ".[dev,test]"
    
    - name: Run tests
      run: |
        pytest tests/ -v --cov=src --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3

  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Run security scan
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

  build:
    needs: [test, security-scan]
    runs-on: ubuntu-latest
    outputs:
      image-tag: ${{ steps.meta.outputs.tags }}
      image-digest: ${{ steps.build.outputs.digest }}
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v2
    
    - name: Login to registry
      uses: docker/login-action@v2
      with:
        registry: ${{ secrets.REGISTRY_URL }}
        username: ${{ secrets.REGISTRY_USERNAME }}
        password: ${{ secrets.REGISTRY_PASSWORD }}
    
    - name: Extract metadata
      id: meta
      uses: docker/metadata-action@v4
      with:
        images: ${{ secrets.REGISTRY_URL }}/pyvider-api-service
        tags: |
          type=ref,event=branch
          type=ref,event=tag
          type=sha,prefix={{branch}}-
    
    - name: Build and push
      id: build
      uses: docker/build-push-action@v4
      with:
        context: .
        push: true
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        cache-from: type=gha
        cache-to: type=gha,mode=max
        platforms: linux/amd64,linux/arm64

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Configure kubectl
      uses: azure/setup-kubectl@v3
      with:
        version: 'latest'
    
    - name: Set up Kubeconfig
      run: |
        echo "${{ secrets.KUBECONFIG }}" | base64 -d > ~/.kube/config
    
    - name: Deploy to Kubernetes
      run: |
        # Update image in deployment
        kubectl set image deployment/pyvider-api-service \
          api-service=${{ needs.build.outputs.image-tag }} \
          -n pyvider-services
        
        # Wait for rollout to complete
        kubectl rollout status deployment/pyvider-api-service \
          -n pyvider-services --timeout=300s
    
    - name: Run smoke tests
      run: |
        # Wait for pods to be ready
        kubectl wait --for=condition=ready pod \
          -l app=pyvider-api-service \
          -n pyvider-services \
          --timeout=120s
        
        # Run smoke tests
        python scripts/smoke-tests.py
```

## Performance Optimization

### Application Configuration

**config/production.yaml**
```yaml
server:
  host: "0.0.0.0"
  port: 50051
  max_workers: 50
  max_connections: 1000
  keepalive_timeout: 300
  max_message_size: 4194304  # 4MB
  compression: gzip
  
  # TLS configuration
  tls_enabled: true
  cert_file: "/etc/certs/tls.crt"
  key_file: "/etc/certs/tls.key"
  
  # Performance tuning
  enable_http2: true
  tcp_nodelay: true
  tcp_keepalive: true
  tcp_keepalive_time: 60
  tcp_keepalive_interval: 10
  tcp_keepalive_probes: 3

database:
  pool_size: 20
  max_overflow: 10
  pool_timeout: 30
  pool_recycle: 3600
  pool_pre_ping: true
  
  # Connection tuning
  connect_timeout: 10
  command_timeout: 30
  server_settings:
    application_name: "pyvider-api-service"
    tcp_keepalives_idle: "600"
    tcp_keepalives_interval: "30"
    tcp_keepalives_count: "3"

redis:
  pool_size: 20
  max_connections: 50
  retry_on_timeout: true
  health_check_interval: 30
  
  # Performance settings
  socket_keepalive: true
  socket_keepalive_options:
    TCP_KEEPIDLE: 1
    TCP_KEEPINTVL: 3
    TCP_KEEPCNT: 5

logging:
  level: "INFO"
  format: "json"
  enable_structured_logging: true
  performance_logging: true
  
  # Log sampling for high-traffic endpoints
  sampling:
    enabled: true
    initial: 100
    thereafter: 100

monitoring:
  prometheus_enabled: true
  prometheus_port: 9090
  
  tracing_enabled: true
  jaeger_endpoint: "http://jaeger-collector:14268/api/traces"
  trace_sampling_rate: 0.1  # 10% sampling
  
  # Custom metrics
  collect_detailed_metrics: true
  metrics_collection_interval: 15

# Feature flags
features:
  enable_caching: true
  enable_rate_limiting: true
  enable_circuit_breaker: true
  enable_request_validation: true
```

## Key Production Features

1. **High Availability** - Multi-replica deployment with pod disruption budgets
2. **Auto Scaling** - HPA based on CPU/memory utilization
3. **Security** - mTLS, RBAC, network policies, and security contexts
4. **Monitoring** - Prometheus metrics, Grafana dashboards, and Jaeger tracing
5. **Database HA** - PostgreSQL cluster with automatic failover and backups
6. **Performance** - Connection pooling, caching, and optimized configurations
7. **CI/CD** - Automated testing, security scanning, and deployment
8. **Health Checks** - Comprehensive liveness and readiness probes
9. **Resource Management** - Proper resource requests/limits and quality of service
10. **Observability** - Structured logging, distributed tracing, and alerting

This production deployment configuration provides a robust, scalable, and secure foundation for running Pyvider RPC Plugin services at enterprise scale.