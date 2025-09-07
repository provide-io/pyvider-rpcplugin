# Database Plugin Example

Build a database plugin with PostgreSQL integration, connection pooling, and real-time features using Pyvider RPC Plugin and Foundation.

## Overview

This example demonstrates:
- **CRUD Operations** - Create, read, update, delete with safe parameterization
- **Connection Pooling** - Efficient database connection management
- **Streaming Results** - Handle large datasets efficiently
- **Real-time Subscriptions** - Database change notifications
- **Transaction Support** - ACID compliance with rollback

## Protocol Definition

**database.proto**
```protobuf
syntax = "proto3";

package database;

service DatabaseService {
  rpc ExecuteQuery(QueryRequest) returns (QueryResponse);
  rpc StreamQuery(QueryRequest) returns (stream QueryRow);
  rpc ExecuteTransaction(TransactionRequest) returns (TransactionResponse);
  rpc SubscribeToChanges(SubscriptionRequest) returns (stream ChangeEvent);
}

message QueryRequest {
  string sql = 1;
  repeated QueryParameter parameters = 2;
  int32 limit = 3;
  int32 offset = 4;
}

message QueryParameter {
  string name = 1;
  string value = 2;
  string type = 3;  // "string", "int", "float", "bool", "datetime"
}

message QueryResponse {
  repeated QueryRow rows = 1;
  int32 affected_rows = 2;
  string error = 3;
  bool success = 4;
}

message QueryRow {
  map<string, string> columns = 1;
}

message TransactionRequest {
  repeated QueryRequest queries = 1;
}

message TransactionResponse {
  repeated QueryResponse results = 1;
  bool success = 2;
  string error = 3;
}
```

## Plugin Implementation

### Database Handler

```python
import asyncio
import asyncpg
from typing import AsyncIterator
from contextlib import asynccontextmanager
from pyvider.rpcplugin import plugin_server, plugin_protocol
from provide.foundation import logger
from provide.foundation.config import field
import database_pb2_grpc as db_grpc
from database_pb2 import *

class DatabaseConfig:
    database_url: str = field(
        default="postgresql://user:pass@localhost/db",
        env_var="DATABASE_URL",
        description="PostgreSQL connection URL"
    )
    pool_min_size: int = field(default=5, env_var="DB_POOL_MIN_SIZE")
    pool_max_size: int = field(default=20, env_var="DB_POOL_MAX_SIZE")

class DatabaseHandler:
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.pool = None
        
    async def initialize(self):
        """Initialize database connection pool."""
        logger.info("🗄️ Initializing database connection pool")
        
        self.pool = await asyncpg.create_pool(
            self.config.database_url,
            min_size=self.config.pool_min_size,
            max_size=self.config.pool_max_size
        )
        
        # Test connection
        async with self.pool.acquire() as conn:
            version = await conn.fetchval("SELECT version()")
            logger.info(f"✅ Connected to: {version}")
    
    async def close(self):
        """Close database connections."""
        if self.pool:
            await self.pool.close()
            logger.info("🗄️ Database pool closed")
    
    @asynccontextmanager
    async def get_connection(self):
        """Get database connection from pool."""
        async with self.pool.acquire() as conn:
            yield conn

class DatabaseServicer(db_grpc.DatabaseServiceServicer):
    def __init__(self, handler: DatabaseHandler):
        self.handler = handler
    
    async def ExecuteQuery(self, request, context):
        """Execute SQL query with parameters."""
        try:
            async with self.handler.get_connection() as conn:
                # Build parameterized query
                sql, params = self._build_query(request.sql, request.parameters)
                
                # Execute query
                if sql.strip().upper().startswith(('SELECT', 'WITH')):
                    rows = await conn.fetch(sql, *params)
                    return self._build_query_response(rows)
                else:
                    result = await conn.execute(sql, *params)
                    affected_rows = int(result.split()[-1]) if result else 0
                    
                    return QueryResponse(
                        affected_rows=affected_rows,
                        success=True
                    )
                    
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return QueryResponse(success=False, error=str(e))
    
    async def StreamQuery(self, request, context):
        """Stream large result sets."""
        try:
            async with self.handler.get_connection() as conn:
                sql, params = self._build_query(request.sql, request.parameters)
                
                # Add LIMIT/OFFSET for pagination
                if request.limit > 0:
                    sql += f" LIMIT {request.limit}"
                if request.offset > 0:
                    sql += f" OFFSET {request.offset}"
                
                async with conn.transaction():
                    async for row in conn.cursor(sql, *params):
                        yield self._build_query_row(row)
                        
        except Exception as e:
            logger.error(f"Stream query failed: {e}")
            context.abort(grpc.StatusCode.INTERNAL, str(e))
    
    async def ExecuteTransaction(self, request, context):
        """Execute multiple queries in transaction."""
        results = []
        
        try:
            async with self.handler.get_connection() as conn:
                async with conn.transaction():
                    for query_req in request.queries:
                        sql, params = self._build_query(
                            query_req.sql, 
                            query_req.parameters
                        )
                        
                        if sql.strip().upper().startswith(('SELECT', 'WITH')):
                            rows = await conn.fetch(sql, *params)
                            result = self._build_query_response(rows)
                        else:
                            exec_result = await conn.execute(sql, *params)
                            affected = int(exec_result.split()[-1]) if exec_result else 0
                            result = QueryResponse(
                                affected_rows=affected,
                                success=True
                            )
                        
                        results.append(result)
            
            return TransactionResponse(results=results, success=True)
            
        except Exception as e:
            logger.error(f"Transaction failed: {e}")
            return TransactionResponse(
                results=results,
                success=False,
                error=str(e)
            )
    
    def _build_query(self, sql: str, parameters: list) -> tuple[str, list]:
        """Build parameterized query."""
        params = []
        param_map = {param.name: param.value for param in parameters}
        
        # Replace named parameters with positional
        param_index = 1
        for param in parameters:
            sql = sql.replace(f":{param.name}", f"${param_index}")
            
            # Convert parameter type
            if param.type == "int":
                params.append(int(param.value))
            elif param.type == "float":
                params.append(float(param.value))
            elif param.type == "bool":
                params.append(param.value.lower() == "true")
            else:
                params.append(param.value)
            
            param_index += 1
        
        return sql, params
    
    def _build_query_response(self, rows) -> QueryResponse:
        """Build response from database rows."""
        response_rows = []
        for row in rows:
            columns = {key: str(value) for key, value in dict(row).items()}
            response_rows.append(QueryRow(columns=columns))
        
        return QueryResponse(rows=response_rows, success=True)
    
    def _build_query_row(self, row) -> QueryRow:
        """Build single row response."""
        columns = {key: str(value) for key, value in dict(row).items()}
        return QueryRow(columns=columns)
```

### Protocol Implementation

```python
import database_pb2_grpc as db_grpc
from database_pb2 import DESCRIPTOR

class DatabaseProtocol:
    def __init__(self):
        self.name = "database"
        self.version = "1.0"
    
    async def get_grpc_descriptors(self):
        return DESCRIPTOR.services_by_name['DatabaseService'], "DatabaseService"
    
    async def add_to_server(self, server, handler):
        servicer = DatabaseServicer(handler)
        db_grpc.add_DatabaseServiceServicer_to_server(servicer, server)
```

### Server Setup

```python
async def main():
    """Database plugin server main function."""
    logger.info("🚀 Starting database plugin server")
    
    # Configuration
    config = DatabaseConfig()
    
    # Initialize database handler
    handler = DatabaseHandler(config)
    await handler.initialize()
    
    # Create protocol and server
    protocol = DatabaseProtocol()
    server = plugin_server(
        protocol=protocol,
        handler=handler
    )
    
    try:
        logger.info("📊 Database plugin ready for connections")
        await server.serve()
        
    except KeyboardInterrupt:
        logger.info("🛑 Shutting down database plugin")
    finally:
        await handler.close()

if __name__ == "__main__":
    asyncio.run(main())
```

## Client Usage

### Basic Operations

```python
import asyncio
from pyvider.rpcplugin import plugin_client
from provide.foundation import logger
from database_pb2 import QueryRequest, QueryParameter, TransactionRequest

async def database_client_example():
    """Example database client usage."""
    
    # Connect to database plugin
    async with plugin_client(
        command=["python", "database_plugin.py"]
    ) as client:
        
        # Execute simple query
        response = await client.database.ExecuteQuery(
            QueryRequest(
                sql="SELECT * FROM users WHERE age > :min_age",
                parameters=[
                    QueryParameter(name="min_age", value="18", type="int")
                ]
            )
        )
        
        if response.success:
            logger.info(f"Found {len(response.rows)} users")
            for row in response.rows:
                logger.info(f"User: {dict(row.columns)}")
        else:
            logger.error(f"Query failed: {response.error}")

async def streaming_example():
    """Stream large result set."""
    async with plugin_client() as client:
        
        request = QueryRequest(
            sql="SELECT * FROM large_table ORDER BY id",
            limit=1000  # Process in chunks
        )
        
        row_count = 0
        async for row in client.database.StreamQuery(request):
            row_count += 1
            if row_count % 100 == 0:
                logger.info(f"Processed {row_count} rows...")
        
        logger.info(f"✅ Streamed {row_count} total rows")

async def transaction_example():
    """Execute multiple queries in transaction."""
    async with plugin_client() as client:
        
        transaction = TransactionRequest(queries=[
            QueryRequest(
                sql="INSERT INTO users (name, email) VALUES (:name, :email)",
                parameters=[
                    QueryParameter(name="name", value="John Doe", type="string"),
                    QueryParameter(name="email", value="john@example.com", type="string")
                ]
            ),
            QueryRequest(
                sql="UPDATE accounts SET balance = balance - :amount WHERE user_id = :user_id",
                parameters=[
                    QueryParameter(name="amount", value="100.00", type="float"),
                    QueryParameter(name="user_id", value="1", type="int")
                ]
            )
        ])
        
        response = await client.database.ExecuteTransaction(transaction)
        
        if response.success:
            logger.info("✅ Transaction completed successfully")
            for i, result in enumerate(response.results):
                logger.info(f"Query {i+1}: {result.affected_rows} rows affected")
        else:
            logger.error(f"❌ Transaction failed: {response.error}")
```

### Advanced Features

```python
async def connection_pooling_example():
    """Demonstrate connection pooling benefits."""
    async with plugin_client() as client:
        
        # Execute multiple concurrent queries
        tasks = []
        for i in range(10):
            task = client.database.ExecuteQuery(
                QueryRequest(
                    sql="SELECT COUNT(*) FROM users WHERE status = :status",
                    parameters=[
                        QueryParameter(name="status", value="active", type="string")
                    ]
                )
            )
            tasks.append(task)
        
        # All queries use pooled connections efficiently
        results = await asyncio.gather(*tasks)
        logger.info(f"✅ Executed {len(results)} concurrent queries")

async def real_time_monitoring():
    """Monitor database changes in real-time."""
    # Note: This requires additional PostgreSQL NOTIFY/LISTEN setup
    async with plugin_client() as client:
        
        subscription = SubscriptionRequest(
            table_name="user_activity",
            operations=["INSERT", "UPDATE"]
        )
        
        logger.info("👀 Monitoring database changes...")
        async for change in client.database.SubscribeToChanges(subscription):
            logger.info(f"📢 Change detected: {change.operation} on {change.table_name}")
            logger.info(f"   Data: {dict(change.data)}")
```

## Production Configuration

### Environment Setup

```bash
# Database configuration
export DATABASE_URL="postgresql://app_user:secure_password@db.company.com:5432/production_db"
export DB_POOL_MIN_SIZE=10
export DB_POOL_MAX_SIZE=50

# Plugin configuration
export PLUGIN_LOG_LEVEL=INFO
export PLUGIN_AUTO_MTLS=true
export PLUGIN_HEALTH_SERVICE_ENABLED=true
export PLUGIN_RATE_LIMIT_ENABLED=true
export PLUGIN_RATE_LIMIT_REQUESTS_PER_SECOND=500.0
```

### Docker Deployment

```dockerfile
FROM python:3.11

# Install dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy plugin code
COPY database_plugin.py .
COPY database_pb2.py .
COPY database_pb2_grpc.py .

# Set up user
RUN useradd -m plugin
USER plugin

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import asyncio; from database_pb2 import HealthCheckRequest; \
                 from pyvider.rpcplugin import plugin_client; \
                 asyncio.run(plugin_client().database.HealthCheck(HealthCheckRequest()))"

EXPOSE 8080
CMD ["python", "database_plugin.py"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: database-plugin
spec:
  replicas: 3
  selector:
    matchLabels:
      app: database-plugin
  template:
    metadata:
      labels:
        app: database-plugin
    spec:
      containers:
      - name: database-plugin
        image: my-registry/database-plugin:latest
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: url
        - name: DB_POOL_MAX_SIZE
          value: "30"
        - name: PLUGIN_RATE_LIMIT_ENABLED
          value: "true"
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

## Testing

### Unit Tests

```python
import pytest
import asyncio
from unittest.mock import AsyncMock, patch

@pytest.fixture
async def database_handler():
    config = DatabaseConfig()
    config.database_url = "postgresql://test:test@localhost/test_db"
    
    handler = DatabaseHandler(config)
    await handler.initialize()
    
    yield handler
    
    await handler.close()

async def test_query_execution(database_handler):
    """Test basic query execution."""
    servicer = DatabaseServicer(database_handler)
    
    request = QueryRequest(
        sql="SELECT 1 as test_value",
        parameters=[]
    )
    
    response = await servicer.ExecuteQuery(request, None)
    
    assert response.success
    assert len(response.rows) == 1
    assert response.rows[0].columns["test_value"] == "1"

async def test_parameterized_query(database_handler):
    """Test parameterized queries."""
    servicer = DatabaseServicer(database_handler)
    
    request = QueryRequest(
        sql="SELECT :value as param_test",
        parameters=[
            QueryParameter(name="value", value="hello", type="string")
        ]
    )
    
    response = await servicer.ExecuteQuery(request, None)
    
    assert response.success
    assert response.rows[0].columns["param_test"] == "hello"
```

### Integration Tests

```python
async def test_full_plugin_integration():
    """Test complete plugin functionality."""
    async with plugin_client(
        command=["python", "database_plugin.py"],
        config={"DATABASE_URL": "postgresql://test:test@localhost/test_db"}
    ) as client:
        
        # Test connection
        response = await client.database.ExecuteQuery(
            QueryRequest(sql="SELECT 1")
        )
        assert response.success
        
        # Test transaction
        transaction = TransactionRequest(queries=[
            QueryRequest(sql="CREATE TEMPORARY TABLE test_table (id INT, name TEXT)"),
            QueryRequest(
                sql="INSERT INTO test_table VALUES (:id, :name)",
                parameters=[
                    QueryParameter(name="id", value="1", type="int"),
                    QueryParameter(name="name", value="test", type="string")
                ]
            )
        ])
        
        tx_response = await client.database.ExecuteTransaction(transaction)
        assert tx_response.success
```

## Best Practices

1. **Connection Pooling**: Always use connection pools for database access
2. **Parameterized Queries**: Prevent SQL injection with proper parameterization
3. **Transaction Management**: Use transactions for data consistency
4. **Error Handling**: Implement comprehensive error handling and logging
5. **Resource Management**: Properly close connections and handle timeouts
6. **Security**: Use environment variables for sensitive configuration
7. **Monitoring**: Implement health checks and performance monitoring

## Next Steps

- **[File Transfer Plugin](file-transfer.md)** - Handle file operations
- **[Production Deployment](production.md)** - Complete deployment guide
- **[Performance Optimization](../guide/advanced/performance.md)** - Optimize plugin performance

This example provides a solid foundation for database plugins. Adapt the schema and implementation to match your specific database requirements and use cases.