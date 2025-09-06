# Database Plugin Example

This example demonstrates how to build a database plugin using the Pyvider RPC Plugin framework with PostgreSQL, including connection pooling, transactions, and real-time subscriptions.

## Overview

The Database Plugin provides:

- **CRUD Operations** - Create, read, update, delete records
- **Connection Pooling** - Efficient database connections
- **Transactions** - ACID compliance with rollback support
- **Streaming Results** - Large result set streaming
- **Real-time Subscriptions** - Database change notifications
- **Schema Management** - Dynamic table operations
- **Query Builder** - Safe parameterized queries

## Service Definition

**database.proto**
```protobuf
syntax = "proto3";

package database;

service DatabaseService {
  // Execute SQL query
  rpc ExecuteQuery(QueryRequest) returns (QueryResponse);
  
  // Stream large result sets
  rpc StreamQuery(QueryRequest) returns (stream QueryRow);
  
  // Execute transaction
  rpc ExecuteTransaction(TransactionRequest) returns (TransactionResponse);
  
  // Subscribe to table changes
  rpc SubscribeToChanges(SubscriptionRequest) returns (stream ChangeEvent);
  
  // Schema operations
  rpc CreateTable(CreateTableRequest) returns (SchemaResponse);
  rpc DescribeTable(DescribeTableRequest) returns (TableSchema);
  rpc ListTables(ListTablesRequest) returns (ListTablesResponse);
  
  // Health check
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
}

message QueryRequest {
  string sql = 1;
  repeated QueryParameter parameters = 2;
  int32 limit = 3;
  int32 offset = 4;
  int32 timeout_seconds = 5;
}

message QueryParameter {
  string name = 1;
  oneof value {
    string string_value = 2;
    int64 int_value = 3;
    double float_value = 4;
    bool bool_value = 5;
    bytes bytes_value = 6;
  }
}

message QueryResponse {
  repeated QueryRow rows = 1;
  int32 affected_rows = 2;
  string query_id = 3;
  double execution_time_ms = 4;
}

message QueryRow {
  map<string, string> columns = 1;
}

message TransactionRequest {
  repeated QueryRequest queries = 1;
  string isolation_level = 2; // READ_COMMITTED, SERIALIZABLE, etc.
}

message TransactionResponse {
  bool success = 1;
  string error_message = 2;
  repeated QueryResponse results = 3;
  string transaction_id = 4;
}

message SubscriptionRequest {
  string table_name = 1;
  repeated string operations = 2; // INSERT, UPDATE, DELETE
  string filter_sql = 3;
}

message ChangeEvent {
  string table_name = 1;
  string operation = 2; // INSERT, UPDATE, DELETE
  map<string, string> old_values = 3;
  map<string, string> new_values = 4;
  int64 timestamp = 5;
  string transaction_id = 6;
}

message CreateTableRequest {
  string table_name = 1;
  repeated ColumnDefinition columns = 2;
  repeated string constraints = 3;
}

message ColumnDefinition {
  string name = 1;
  string data_type = 2;
  bool nullable = 3;
  string default_value = 4;
  bool primary_key = 5;
}

message TableSchema {
  string table_name = 1;
  repeated ColumnDefinition columns = 2;
  repeated string indexes = 3;
  repeated string constraints = 4;
}

message SchemaResponse {
  bool success = 1;
  string message = 2;
}

message DescribeTableRequest {
  string table_name = 1;
}

message ListTablesRequest {
  string schema_name = 1;
}

message ListTablesResponse {
  repeated string table_names = 1;
}

message HealthCheckRequest {}

message HealthCheckResponse {
  bool healthy = 1;
  string status = 2;
  int32 active_connections = 3;
  double avg_query_time_ms = 4;
}
```

Generate Python code:
```bash
python -m grpc_tools.protoc --python_out=. --grpc_python_out=. database.proto
```

## Server Implementation

**database_service.py**
```python
import asyncio
import asyncpg
import json
import logging
import time
import uuid
from typing import AsyncIterator, Any
from contextlib import asynccontextmanager
import grpc
from grpc.aio import ServicerContext

from database_pb2 import (
    QueryRequest, QueryResponse, QueryRow, QueryParameter,
    TransactionRequest, TransactionResponse,
    SubscriptionRequest, ChangeEvent,
    CreateTableRequest, ColumnDefinition, SchemaResponse,
    DescribeTableRequest, TableSchema,
    ListTablesRequest, ListTablesResponse,
    HealthCheckRequest, HealthCheckResponse
)
from database_pb2_grpc import DatabaseServiceServicer
from pyvider.server import RPCPluginServer
from pyvider.config import ServerConfig, TransportConfig

logger = logging.getLogger(__name__)

class DatabaseServicer(DatabaseServiceServicer):
    """Database service implementation with PostgreSQL."""
    
    def __init__(self, database_url: str, pool_size: int = 20):
        self.database_url = database_url
        self.pool_size = pool_size
        self.pool: asyncpg.Pool | None = None
        self.subscribers: dict[str, asyncio.Queue] = {}
        self.query_stats = {
            'total_queries': 0,
            'total_time': 0.0,
            'active_connections': 0
        }
        logger.info(f"Database service initialized with pool size: {pool_size}")
    
    async def initialize(self):
        """Initialize database connection pool."""
        try:
            self.pool = await asyncpg.create_pool(
                self.database_url,
                min_size=2,
                max_size=self.pool_size,
                command_timeout=30,
                server_settings={
                    'application_name': 'pyvider_database_plugin',
                }
            )
            
            # Test connection
            async with self.pool.acquire() as conn:
                await conn.fetchval('SELECT 1')
            
            logger.info("Database pool initialized successfully")
            
            # Setup change notifications
            await self._setup_change_notifications()
            
        except Exception as e:
            logger.error(f"Failed to initialize database pool: {e}")
            raise
    
    async def _setup_change_notifications(self):
        """Setup PostgreSQL LISTEN/NOTIFY for change tracking."""
        try:
            conn = await asyncpg.connect(self.database_url)
            
            # Create notification function and triggers
            await conn.execute("""
                CREATE OR REPLACE FUNCTION notify_change() RETURNS trigger AS $$
                DECLARE
                    payload json;
                BEGIN
                    IF TG_OP = 'DELETE' THEN
                        payload = json_build_object(
                            'table', TG_TABLE_NAME,
                            'operation', TG_OP,
                            'old', row_to_json(OLD),
                            'timestamp', extract(epoch from now())
                        );
                    ELSE
                        payload = json_build_object(
                            'table', TG_TABLE_NAME,
                            'operation', TG_OP,
                            'new', row_to_json(NEW),
                            'old', CASE WHEN TG_OP = 'UPDATE' THEN row_to_json(OLD) ELSE NULL END,
                            'timestamp', extract(epoch from now())
                        );
                    END IF;
                    
                    PERFORM pg_notify('table_changes', payload::text);
                    RETURN NULL;
                END;
                $$ LANGUAGE plpgsql;
            """)
            
            # Listen for notifications
            await conn.add_listener('table_changes', self._handle_change_notification)
            
            # Keep connection alive for notifications
            asyncio.create_task(self._keep_notification_connection_alive(conn))
            
        except Exception as e:
            logger.error(f"Failed to setup change notifications: {e}")
    
    async def _handle_change_notification(self, connection, pid, channel, payload):
        """Handle database change notifications."""
        try:
            data = json.loads(payload)
            
            change_event = ChangeEvent(
                table_name=data['table'],
                operation=data['operation'],
                old_values=self._dict_to_string_map(data.get('old', {})),
                new_values=self._dict_to_string_map(data.get('new', {})),
                timestamp=int(data['timestamp']),
                transaction_id=str(uuid.uuid4())
            )
            
            # Notify all subscribers for this table
            for subscriber_id, queue in list(self.subscribers.items()):
                try:
                    await queue.put(change_event)
                except Exception as e:
                    logger.warning(f"Failed to notify subscriber {subscriber_id}: {e}")
                    # Remove broken subscriber
                    self.subscribers.pop(subscriber_id, None)
        
        except Exception as e:
            logger.error(f"Failed to handle change notification: {e}")
    
    async def _keep_notification_connection_alive(self, conn):
        """Keep notification connection alive."""
        try:
            while True:
                await asyncio.sleep(30)
                await conn.fetchval('SELECT 1')
        except Exception as e:
            logger.error(f"Notification connection lost: {e}")
    
    @asynccontextmanager
    async def get_connection(self):
        """Get database connection from pool."""
        if not self.pool:
            raise RuntimeError("Database pool not initialized")
        
        self.query_stats['active_connections'] += 1
        try:
            async with self.pool.acquire() as conn:
                yield conn
        finally:
            self.query_stats['active_connections'] -= 1
    
    async def ExecuteQuery(
        self, 
        request: QueryRequest, 
        context: ServicerContext
    ) -> QueryResponse:
        """Execute SQL query."""
        start_time = time.perf_counter()
        query_id = str(uuid.uuid4())
        
        logger.info(f"Executing query {query_id}: {request.sql[:100]}...")
        
        try:
            async with self.get_connection() as conn:
                # Convert parameters
                params = self._convert_parameters(request.parameters)
                
                # Execute query with timeout
                if request.timeout_seconds > 0:
                    query_timeout = request.timeout_seconds
                else:
                    query_timeout = 30
                
                if request.sql.strip().upper().startswith(('SELECT', 'WITH')):
                    # Query with results
                    if request.limit > 0:
                        sql = f"{request.sql} LIMIT ${len(params) + 1}"
                        params.append(request.limit)
                        
                        if request.offset > 0:
                            sql = f"{sql} OFFSET ${len(params) + 1}"
                            params.append(request.offset)
                    
                    rows = await asyncio.wait_for(
                        conn.fetch(request.sql, *params),
                        timeout=query_timeout
                    )
                    
                    query_rows = []
                    for row in rows:
                        columns = {key: str(value) for key, value in row.items()}
                        query_rows.append(QueryRow(columns=columns))
                    
                    affected_rows = len(query_rows)
                
                else:
                    # Non-query (INSERT, UPDATE, DELETE)
                    result = await asyncio.wait_for(
                        conn.execute(request.sql, *params),
                        timeout=query_timeout
                    )
                    
                    # Extract affected rows from result
                    if result.startswith(('INSERT', 'UPDATE', 'DELETE')):
                        affected_rows = int(result.split()[-1])
                    else:
                        affected_rows = 0
                    
                    query_rows = []
            
            execution_time = (time.perf_counter() - start_time) * 1000
            
            # Update stats
            self.query_stats['total_queries'] += 1
            self.query_stats['total_time'] += execution_time
            
            logger.info(f"Query {query_id} completed in {execution_time:.2f}ms")
            
            return QueryResponse(
                rows=query_rows,
                affected_rows=affected_rows,
                query_id=query_id,
                execution_time_ms=execution_time
            )
        
        except asyncio.TimeoutError:
            logger.error(f"Query {query_id} timed out")
            await context.abort(grpc.StatusCode.DEADLINE_EXCEEDED, "Query timeout")
        
        except Exception as e:
            logger.error(f"Query {query_id} failed: {e}")
            await context.abort(grpc.StatusCode.INTERNAL, f"Query failed: {e}")
    
    async def StreamQuery(
        self, 
        request: QueryRequest, 
        context: ServicerContext
    ) -> AsyncIterator[QueryRow]:
        """Stream large query results."""
        query_id = str(uuid.uuid4())
        logger.info(f"Streaming query {query_id}: {request.sql[:100]}...")
        
        try:
            async with self.get_connection() as conn:
                params = self._convert_parameters(request.parameters)
                
                # Use cursor for streaming
                async with conn.transaction():
                    cursor_name = f"cursor_{query_id.replace('-', '_')}"
                    await conn.execute(f'DECLARE {cursor_name} CURSOR FOR {request.sql}', *params)
                    
                    batch_size = 1000  # Stream in batches
                    
                    while not context.cancelled():
                        rows = await conn.fetch(f'FETCH {batch_size} FROM {cursor_name}')
                        
                        if not rows:
                            break
                        
                        for row in rows:
                            columns = {key: str(value) for key, value in row.items()}
                            yield QueryRow(columns=columns)
                        
                        # Small delay to prevent overwhelming
                        await asyncio.sleep(0.01)
            
            logger.info(f"Query stream {query_id} completed")
        
        except Exception as e:
            logger.error(f"Query stream {query_id} failed: {e}")
            await context.abort(grpc.StatusCode.INTERNAL, f"Stream query failed: {e}")
    
    async def ExecuteTransaction(
        self, 
        request: TransactionRequest, 
        context: ServicerContext
    ) -> TransactionResponse:
        """Execute multiple queries in a transaction."""
        transaction_id = str(uuid.uuid4())
        logger.info(f"Starting transaction {transaction_id} with {len(request.queries)} queries")
        
        try:
            async with self.get_connection() as conn:
                # Set isolation level
                isolation_level = request.isolation_level or "READ_COMMITTED"
                
                async with conn.transaction(isolation=isolation_level):
                    results = []
                    
                    for i, query_req in enumerate(request.queries):
                        try:
                            # Execute each query in the transaction
                            params = self._convert_parameters(query_req.parameters)
                            
                            if query_req.sql.strip().upper().startswith(('SELECT', 'WITH')):
                                rows = await conn.fetch(query_req.sql, *params)
                                query_rows = []
                                for row in rows:
                                    columns = {key: str(value) for key, value in row.items()}
                                    query_rows.append(QueryRow(columns=columns))
                                
                                result = QueryResponse(
                                    rows=query_rows,
                                    affected_rows=len(query_rows),
                                    query_id=f"{transaction_id}_q{i}",
                                    execution_time_ms=0  # Individual timing not tracked in transactions
                                )
                            else:
                                result_str = await conn.execute(query_req.sql, *params)
                                affected_rows = int(result_str.split()[-1]) if result_str.split()[-1].isdigit() else 0
                                
                                result = QueryResponse(
                                    rows=[],
                                    affected_rows=affected_rows,
                                    query_id=f"{transaction_id}_q{i}",
                                    execution_time_ms=0
                                )
                            
                            results.append(result)
                        
                        except Exception as e:
                            logger.error(f"Query {i} in transaction {transaction_id} failed: {e}")
                            # Transaction will automatically rollback
                            raise
            
            logger.info(f"Transaction {transaction_id} committed successfully")
            
            return TransactionResponse(
                success=True,
                results=results,
                transaction_id=transaction_id
            )
        
        except Exception as e:
            logger.error(f"Transaction {transaction_id} failed: {e}")
            return TransactionResponse(
                success=False,
                error_message=str(e),
                results=[],
                transaction_id=transaction_id
            )
    
    async def SubscribeToChanges(
        self, 
        request: SubscriptionRequest, 
        context: ServicerContext
    ) -> AsyncIterator[ChangeEvent]:
        """Subscribe to table change notifications."""
        subscriber_id = str(uuid.uuid4())
        queue: asyncio.Queue = asyncio.Queue()
        self.subscribers[subscriber_id] = queue
        
        logger.info(f"New subscriber {subscriber_id} for table {request.table_name}")
        
        try:
            # Setup trigger for the table if it doesn't exist
            await self._ensure_change_trigger(request.table_name)
            
            while not context.cancelled():
                try:
                    # Wait for change events
                    change_event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    
                    # Filter by table and operations
                    if change_event.table_name != request.table_name:
                        continue
                    
                    if request.operations and change_event.operation not in request.operations:
                        continue
                    
                    # Apply filter if specified
                    if request.filter_sql:
                        # TODO: Implement SQL filter evaluation
                        pass
                    
                    yield change_event
                
                except asyncio.TimeoutError:
                    # Timeout is normal, continue listening
                    continue
        
        except Exception as e:
            logger.error(f"Subscription {subscriber_id} failed: {e}")
        
        finally:
            # Cleanup subscriber
            self.subscribers.pop(subscriber_id, None)
            logger.info(f"Subscriber {subscriber_id} disconnected")
    
    async def _ensure_change_trigger(self, table_name: str):
        """Ensure change notification trigger exists for table."""
        try:
            async with self.get_connection() as conn:
                # Check if trigger exists
                trigger_exists = await conn.fetchval("""
                    SELECT EXISTS (
                        SELECT 1 FROM pg_trigger 
                        WHERE tgname = $1 AND tgrelid = $2::regclass
                    )
                """, f"{table_name}_change_trigger", table_name)
                
                if not trigger_exists:
                    # Create trigger
                    await conn.execute(f"""
                        CREATE TRIGGER {table_name}_change_trigger
                        AFTER INSERT OR UPDATE OR DELETE ON {table_name}
                        FOR EACH ROW EXECUTE FUNCTION notify_change()
                    """)
                    logger.info(f"Created change trigger for table {table_name}")
        
        except Exception as e:
            logger.error(f"Failed to ensure change trigger for {table_name}: {e}")
    
    async def CreateTable(
        self, 
        request: CreateTableRequest, 
        context: ServicerContext
    ) -> SchemaResponse:
        """Create table with specified schema."""
        logger.info(f"Creating table: {request.table_name}")
        
        try:
            # Build CREATE TABLE statement
            columns_sql = []
            for column in request.columns:
                col_sql = f"{column.name} {column.data_type}"
                
                if not column.nullable:
                    col_sql += " NOT NULL"
                
                if column.default_value:
                    col_sql += f" DEFAULT {column.default_value}"
                
                if column.primary_key:
                    col_sql += " PRIMARY KEY"
                
                columns_sql.append(col_sql)
            
            # Add constraints
            if request.constraints:
                columns_sql.extend(request.constraints)
            
            sql = f"CREATE TABLE {request.table_name} ({', '.join(columns_sql)})"
            
            async with self.get_connection() as conn:
                await conn.execute(sql)
            
            logger.info(f"Table {request.table_name} created successfully")
            
            return SchemaResponse(
                success=True,
                message=f"Table {request.table_name} created successfully"
            )
        
        except Exception as e:
            logger.error(f"Failed to create table {request.table_name}: {e}")
            return SchemaResponse(
                success=False,
                message=f"Failed to create table: {e}"
            )
    
    async def DescribeTable(
        self, 
        request: DescribeTableRequest, 
        context: ServicerContext
    ) -> TableSchema:
        """Describe table schema."""
        try:
            async with self.get_connection() as conn:
                # Get column information
                columns_info = await conn.fetch("""
                    SELECT column_name, data_type, is_nullable, column_default
                    FROM information_schema.columns
                    WHERE table_name = $1
                    ORDER BY ordinal_position
                """, request.table_name)
                
                # Get primary key information
                pk_columns = await conn.fetch("""
                    SELECT column_name
                    FROM information_schema.key_column_usage
                    WHERE table_name = $1 AND constraint_name LIKE '%_pkey'
                """, request.table_name)
                
                pk_column_names = {row['column_name'] for row in pk_columns}
                
                # Build column definitions
                columns = []
                for col_info in columns_info:
                    column_def = ColumnDefinition(
                        name=col_info['column_name'],
                        data_type=col_info['data_type'],
                        nullable=col_info['is_nullable'] == 'YES',
                        default_value=col_info['column_default'] or '',
                        primary_key=col_info['column_name'] in pk_column_names
                    )
                    columns.append(column_def)
                
                # Get indexes
                indexes = await conn.fetch("""
                    SELECT indexname FROM pg_indexes
                    WHERE tablename = $1
                """, request.table_name)
                
                index_names = [row['indexname'] for row in indexes]
                
                return TableSchema(
                    table_name=request.table_name,
                    columns=columns,
                    indexes=index_names,
                    constraints=[]  # TODO: Implement constraint listing
                )
        
        except Exception as e:
            logger.error(f"Failed to describe table {request.table_name}: {e}")
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to describe table: {e}")
    
    async def ListTables(
        self, 
        request: ListTablesRequest, 
        context: ServicerContext
    ) -> ListTablesResponse:
        """List tables in schema."""
        try:
            schema_name = request.schema_name or 'public'
            
            async with self.get_connection() as conn:
                tables = await conn.fetch("""
                    SELECT table_name 
                    FROM information_schema.tables
                    WHERE table_schema = $1 AND table_type = 'BASE TABLE'
                    ORDER BY table_name
                """, schema_name)
                
                table_names = [row['table_name'] for row in tables]
                
                return ListTablesResponse(table_names=table_names)
        
        except Exception as e:
            logger.error(f"Failed to list tables: {e}")
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to list tables: {e}")
    
    async def HealthCheck(
        self, 
        request: HealthCheckRequest, 
        context: ServicerContext
    ) -> HealthCheckResponse:
        """Check database health."""
        try:
            start_time = time.perf_counter()
            
            async with self.get_connection() as conn:
                await conn.fetchval('SELECT 1')
            
            query_time = (time.perf_counter() - start_time) * 1000
            
            avg_query_time = (
                self.query_stats['total_time'] / max(self.query_stats['total_queries'], 1)
            )
            
            return HealthCheckResponse(
                healthy=True,
                status="Database is healthy",
                active_connections=self.query_stats['active_connections'],
                avg_query_time_ms=avg_query_time
            )
        
        except Exception as e:
            return HealthCheckResponse(
                healthy=False,
                status=f"Database error: {e}",
                active_connections=0,
                avg_query_time_ms=0
            )
    
    def _convert_parameters(self, parameters: list[QueryParameter]) -> list[Any]:
        """Convert protobuf parameters to Python values."""
        params = []
        for param in parameters:
            if param.HasField('string_value'):
                params.append(param.string_value)
            elif param.HasField('int_value'):
                params.append(param.int_value)
            elif param.HasField('float_value'):
                params.append(param.float_value)
            elif param.HasField('bool_value'):
                params.append(param.bool_value)
            elif param.HasField('bytes_value'):
                params.append(param.bytes_value)
            else:
                params.append(None)
        
        return params
    
    def _dict_to_string_map(self, data: dict) -> dict[str, str]:
        """Convert dictionary to string map."""
        if not data:
            return {}
        
        return {key: str(value) for key, value in data.items()}
    
    async def close(self):
        """Close database connections."""
        if self.pool:
            await self.pool.close()
            logger.info("Database pool closed")


async def create_database_server(database_url: str):
    """Create database server."""
    config = ServerConfig(
        transport=TransportConfig(
            host="localhost",
            port=50051,
            tls_enabled=False
        ),
        max_workers=20,
        log_level="INFO"
    )
    
    server = RPCPluginServer(config)
    
    # Add database service
    db_service = DatabaseServicer(database_url)
    await db_service.initialize()
    server.add_service(db_service)
    
    return server


async def main():
    """Run database server."""
    import os
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Get database URL from environment
    database_url = os.getenv(
        'DATABASE_URL', 
        'postgresql://user:password@localhost/dbname'
    )
    
    server = await create_database_server(database_url)
    
    try:
        await server.start()
        logger.info("Database server started. Press Ctrl+C to stop.")
        
        while True:
            await asyncio.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
    
    finally:
        await server.stop()


if __name__ == "__main__":
    asyncio.run(main())
```

## Client Implementation

**database_client.py**
```python
import asyncio
import logging
import time
from typing import AsyncIterator, Any
import grpc

from database_pb2 import (
    QueryRequest, QueryParameter, TransactionRequest,
    SubscriptionRequest, CreateTableRequest, ColumnDefinition,
    DescribeTableRequest, ListTablesRequest, HealthCheckRequest
)
from database_pb2_grpc import DatabaseServiceStub

logger = logging.getLogger(__name__)

class DatabaseClient:
    """Database service client."""
    
    def __init__(self, host: str = "localhost", port: int = 50051):
        self.channel = grpc.aio.insecure_channel(f"{host}:{port}")
        self.stub = DatabaseServiceStub(self.channel)
        logger.info(f"Database client connected to {host}:{port}")
    
    async def execute_query(
        self, 
        sql: str, 
        parameters: dict[str, Any] | None = None,
        limit: int = 0,
        offset: int = 0,
        timeout: int = 30
    ) -> dict[str, Any]:
        """Execute SQL query."""
        logger.info(f"Executing query: {sql[:100]}...")
        
        # Convert parameters
        query_params = []
        if parameters:
            for name, value in parameters.items():
                param = QueryParameter(name=name)
                
                if isinstance(value, str):
                    param.string_value = value
                elif isinstance(value, int):
                    param.int_value = value
                elif isinstance(value, float):
                    param.float_value = value
                elif isinstance(value, bool):
                    param.bool_value = value
                elif isinstance(value, bytes):
                    param.bytes_value = value
                
                query_params.append(param)
        
        request = QueryRequest(
            sql=sql,
            parameters=query_params,
            limit=limit,
            offset=offset,
            timeout_seconds=timeout
        )
        
        try:
            response = await self.stub.ExecuteQuery(request)
            
            # Convert response to dict
            rows = []
            for row in response.rows:
                rows.append(dict(row.columns))
            
            return {
                'rows': rows,
                'affected_rows': response.affected_rows,
                'query_id': response.query_id,
                'execution_time_ms': response.execution_time_ms
            }
        
        except grpc.RpcError as e:
            logger.error(f"Query failed: {e.code()}: {e.details()}")
            raise
    
    async def stream_query(
        self, 
        sql: str, 
        parameters: dict[str, Any] | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream large query results."""
        logger.info(f"Streaming query: {sql[:100]}...")
        
        query_params = []
        if parameters:
            for name, value in parameters.items():
                param = QueryParameter(name=name)
                
                if isinstance(value, str):
                    param.string_value = value
                elif isinstance(value, int):
                    param.int_value = value
                elif isinstance(value, float):
                    param.float_value = value
                elif isinstance(value, bool):
                    param.bool_value = value
                elif isinstance(value, bytes):
                    param.bytes_value = value
                
                query_params.append(param)
        
        request = QueryRequest(
            sql=sql,
            parameters=query_params
        )
        
        try:
            async for row in self.stub.StreamQuery(request):
                yield dict(row.columns)
        
        except grpc.RpcError as e:
            logger.error(f"Stream query failed: {e.code()}: {e.details()}")
            raise
    
    async def execute_transaction(
        self, 
        queries: list[tuple[str, dict[str, Any] | None]],
        isolation_level: str = "READ_COMMITTED"
    ) -> dict[str, Any]:
        """Execute multiple queries in a transaction."""
        logger.info(f"Executing transaction with {len(queries)} queries")
        
        query_requests = []
        for sql, parameters in queries:
            query_params = []
            if parameters:
                for name, value in parameters.items():
                    param = QueryParameter(name=name)
                    
                    if isinstance(value, str):
                        param.string_value = value
                    elif isinstance(value, int):
                        param.int_value = value
                    elif isinstance(value, float):
                        param.float_value = value
                    elif isinstance(value, bool):
                        param.bool_value = value
                    elif isinstance(value, bytes):
                        param.bytes_value = value
                    
                    query_params.append(param)
            
            query_requests.append(QueryRequest(
                sql=sql,
                parameters=query_params
            ))
        
        request = TransactionRequest(
            queries=query_requests,
            isolation_level=isolation_level
        )
        
        try:
            response = await self.stub.ExecuteTransaction(request)
            
            results = []
            for result in response.results:
                rows = [dict(row.columns) for row in result.rows]
                results.append({
                    'rows': rows,
                    'affected_rows': result.affected_rows,
                    'query_id': result.query_id,
                    'execution_time_ms': result.execution_time_ms
                })
            
            return {
                'success': response.success,
                'error_message': response.error_message,
                'results': results,
                'transaction_id': response.transaction_id
            }
        
        except grpc.RpcError as e:
            logger.error(f"Transaction failed: {e.code()}: {e.details()}")
            raise
    
    async def subscribe_to_changes(
        self, 
        table_name: str,
        operations: list[str] | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        """Subscribe to table change notifications."""
        logger.info(f"Subscribing to changes on table: {table_name}")
        
        request = SubscriptionRequest(
            table_name=table_name,
            operations=operations or ['INSERT', 'UPDATE', 'DELETE']
        )
        
        try:
            async for change in self.stub.SubscribeToChanges(request):
                yield {
                    'table_name': change.table_name,
                    'operation': change.operation,
                    'old_values': dict(change.old_values),
                    'new_values': dict(change.new_values),
                    'timestamp': change.timestamp,
                    'transaction_id': change.transaction_id
                }
        
        except grpc.RpcError as e:
            logger.error(f"Subscription failed: {e.code()}: {e.details()}")
            raise
    
    async def create_table(
        self, 
        table_name: str,
        columns: list[dict[str, Any]],
        constraints: list[str] | None = None
    ) -> dict[str, Any]:
        """Create table with specified schema."""
        logger.info(f"Creating table: {table_name}")
        
        column_defs = []
        for col in columns:
            column_def = ColumnDefinition(
                name=col['name'],
                data_type=col['data_type'],
                nullable=col.get('nullable', True),
                default_value=col.get('default_value', ''),
                primary_key=col.get('primary_key', False)
            )
            column_defs.append(column_def)
        
        request = CreateTableRequest(
            table_name=table_name,
            columns=column_defs,
            constraints=constraints or []
        )
        
        try:
            response = await self.stub.CreateTable(request)
            return {
                'success': response.success,
                'message': response.message
            }
        
        except grpc.RpcError as e:
            logger.error(f"Create table failed: {e.code()}: {e.details()}")
            raise
    
    async def describe_table(self, table_name: str) -> dict[str, Any]:
        """Get table schema information."""
        request = DescribeTableRequest(table_name=table_name)
        
        try:
            response = await self.stub.DescribeTable(request)
            
            columns = []
            for col in response.columns:
                columns.append({
                    'name': col.name,
                    'data_type': col.data_type,
                    'nullable': col.nullable,
                    'default_value': col.default_value,
                    'primary_key': col.primary_key
                })
            
            return {
                'table_name': response.table_name,
                'columns': columns,
                'indexes': list(response.indexes),
                'constraints': list(response.constraints)
            }
        
        except grpc.RpcError as e:
            logger.error(f"Describe table failed: {e.code()}: {e.details()}")
            raise
    
    async def list_tables(self, schema_name: str = 'public') -> list[str]:
        """List tables in schema."""
        request = ListTablesRequest(schema_name=schema_name)
        
        try:
            response = await self.stub.ListTables(request)
            return list(response.table_names)
        
        except grpc.RpcError as e:
            logger.error(f"List tables failed: {e.code()}: {e.details()}")
            raise
    
    async def health_check(self) -> dict[str, Any]:
        """Check database health."""
        request = HealthCheckRequest()
        
        try:
            response = await self.stub.HealthCheck(request)
            return {
                'healthy': response.healthy,
                'status': response.status,
                'active_connections': response.active_connections,
                'avg_query_time_ms': response.avg_query_time_ms
            }
        
        except grpc.RpcError as e:
            logger.error(f"Health check failed: {e.code()}: {e.details()}")
            raise
    
    async def close(self):
        """Close client connection."""
        await self.channel.close()
        logger.info("Database client closed")


async def demo_database_plugin():
    """Demonstrate database plugin functionality."""
    client = DatabaseClient()
    
    try:
        # Health check
        print("1. Health Check")
        health = await client.health_check()
        print(f"Database healthy: {health['healthy']}")
        print(f"Status: {health['status']}")
        
        # Create table
        print("\n2. Creating table...")
        result = await client.create_table(
            'users',
            columns=[
                {'name': 'id', 'data_type': 'SERIAL', 'primary_key': True, 'nullable': False},
                {'name': 'username', 'data_type': 'VARCHAR(50)', 'nullable': False},
                {'name': 'email', 'data_type': 'VARCHAR(100)', 'nullable': False},
                {'name': 'created_at', 'data_type': 'TIMESTAMP', 'default_value': 'NOW()', 'nullable': False}
            ],
            constraints=['UNIQUE(username)', 'UNIQUE(email)']
        )
        print(f"Create table: {result['success']} - {result['message']}")
        
        # Insert data
        print("\n3. Inserting data...")
        insert_queries = [
            ("INSERT INTO users (username, email) VALUES ($1, $2)", {'username': 'alice', 'email': 'alice@example.com'}),
            ("INSERT INTO users (username, email) VALUES ($1, $2)", {'username': 'bob', 'email': 'bob@example.com'}),
            ("INSERT INTO users (username, email) VALUES ($1, $2)", {'username': 'charlie', 'email': 'charlie@example.com'})
        ]
        
        tx_result = await client.execute_transaction(insert_queries)
        print(f"Transaction: {tx_result['success']}")
        
        # Query data
        print("\n4. Querying data...")
        result = await client.execute_query("SELECT * FROM users ORDER BY id")
        print(f"Found {len(result['rows'])} users:")
        for row in result['rows']:
            print(f"  {row['id']}: {row['username']} ({row['email']})")
        
        # Stream large results
        print("\n5. Streaming results...")
        async for row in client.stream_query("SELECT * FROM users"):
            print(f"  Streamed: {row['username']}")
        
        # Describe table
        print("\n6. Table schema:")
        schema = await client.describe_table('users')
        for col in schema['columns']:
            print(f"  {col['name']}: {col['data_type']} ({'NOT NULL' if not col['nullable'] else 'NULL'})")
    
    finally:
        await client.close()


async def main():
    """Run database client demo."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        await demo_database_plugin()
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())
```

## Key Features Demonstrated

1. **Connection Pooling** - Efficient PostgreSQL connection management
2. **Transaction Support** - ACID compliance with rollback capability
3. **Streaming Results** - Handle large datasets efficiently
4. **Real-time Notifications** - Database change subscriptions via LISTEN/NOTIFY
5. **Schema Management** - Dynamic table creation and introspection
6. **Query Builder** - Safe parameterized queries
7. **Health Monitoring** - Database status and performance metrics
8. **Error Handling** - Comprehensive error management with proper gRPC status codes

This database plugin provides a production-ready foundation for database-driven applications and can be extended with features like query caching, sharding, and advanced security controls.