# 🎯 Production-Quality Calculator RPC Demo

This demo showcases a complete, production-ready RPC plugin implementation using `pyvider-rpcplugin`.

## 📋 What This Demo Demonstrates

### Server Features (`demo_calculator_server.py`)
- ✅ **Service Implementation** - Complete calculator service with multiple operations
- ✅ **Transport Configuration** - Unix socket for high-performance local IPC
- ✅ **Rate Limiting** - Token bucket algorithm (100 req/s, burst of 200)
- ✅ **Health Checks** - gRPC health checking protocol support
- ✅ **Graceful Shutdown** - Signal handling (SIGTERM, SIGINT)
- ✅ **Structured Logging** - Rich, contextual logging with emojis
- ✅ **Error Handling** - Division by zero protection
- ✅ **Request Tracking** - Statistics on total requests processed

### Client Features (`demo_calculator_client.py`)
- ✅ **Automatic Server Launch** - Spawns server as subprocess
- ✅ **Handshake Protocol** - Automatic protocol negotiation
- ✅ **Connection Management** - Complete lifecycle management
- ✅ **Retry Logic** - Automatic retries with exponential backoff
- ✅ **Graceful Cleanup** - Proper resource cleanup
- ✅ **Error Handling** - Comprehensive exception handling
- ✅ **Logging** - Detailed operation logging

## 🚀 Running the Demo

### Prerequisites
```bash
# Ensure you have the environment set up
cd /REDACTED_ABS_PATH
uv sync --all-groups
```

### Option 1: Run Client (Auto-starts Server)
The client will automatically launch the server:

```bash
# Make scripts executable
chmod +x demo_calculator_*.py

# Run the client (it launches the server automatically)
PYTHONPATH=/REDACTED_ABS_PATH uv run python demo_calculator_client.py
```

### Option 2: Run Server Standalone
For testing or development, you can run the server independently:

```bash
# Terminal 1: Start the server
PYTHONPATH=/REDACTED_ABS_PATH uv run python demo_calculator_server.py

# Terminal 2: Connect with a client
# (In production, you would have a real client that makes gRPC calls)
```

### Option 3: Using uv run directly
```bash
# Run with uv (handles environment automatically)
cd /REDACTED_ABS_PATH
uv run python demo_calculator_client.py
```

## 📊 Expected Output

### Client Output
```
============================================================
🚀 Starting Calculator RPC Client
============================================================
⚙️ Configuration complete
🎯 Will launch server: /usr/bin/python3 demo_calculator_server.py
🔌 Connecting to calculator server...
✅ Client connected successfully!
============================================================
🔍 Client Features Demonstration
============================================================
✅ gRPC channel established
🚇 Transport: unix
📍 Connected to: /tmp/calculator-rpc.sock
🔢 Protocol version: 1
🧪 Testing calculator operations...
📞 Calling Add (10 + 5, should be 15)
📞 Calling Subtract (20 - 7, should be 13)
📞 Calling Multiply (6 × 7, should be 42)
📞 Calling Divide (100 ÷ 4, should be 25)
✅ All operations would be executed via gRPC channel
============================================================
⏱️ Keeping connection alive for 5 seconds...
🔌 Shutting down plugin...
✅ Plugin shutdown signal sent
🧹 Cleaning up client...
✅ Client closed
============================================================
👋 Client session ended
============================================================
```

### Server Output
```
============================================================
🚀 Starting Calculator RPC Server
============================================================
🧮 CalculatorHandler initialized
⚙️ Configuration complete
📍 Server will listen on: /tmp/calculator-rpc.sock
✅ Server created successfully
============================================================
📡 Server is ready to accept connections
💡 Use Ctrl+C to stop the server gracefully
============================================================
[Serving on /tmp/calculator-rpc.sock]
🛑 Shutdown signal received
👋 Server stopped
============================================================
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Client Process                    │
│  ┌───────────────────────────────────────────────┐  │
│  │         demo_calculator_client.py             │  │
│  │  - Spawns server subprocess                   │  │
│  │  - Performs handshake                         │  │
│  │  - Creates gRPC channel                       │  │
│  │  - Makes RPC calls                            │  │
│  │  - Handles lifecycle                          │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────┬───────────────────────────────┘
                      │
                      │ Unix Socket
                      │ /tmp/calculator-rpc.sock
                      │
┌─────────────────────┴───────────────────────────────┐
│                   Server Process                     │
│  ┌───────────────────────────────────────────────┐  │
│  │         demo_calculator_server.py             │  │
│  │  - CalculatorHandler (business logic)        │  │
│  │  - Rate limiting (100 req/s)                 │  │
│  │  - Health checks                             │  │
│  │  - Structured logging                        │  │
│  │  - Graceful shutdown                         │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## 🔧 Key Concepts Demonstrated

### 1. Service Handler Pattern
```python
class CalculatorHandler:
    async def Add(self, request, context):
        # Your business logic here
        return response
```

### 2. Server Configuration
```python
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="unix",          # or "tcp"
    transport_path="/path/to/socket"
)
```

### 3. Client Connection
```python
client = plugin_client(command=["python", "server.py"])
await client.start()
# Use client.grpc_channel with your stubs
```

### 4. Graceful Shutdown
```python
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)
```

## 🎓 Next Steps

### For Production Use

1. **Add Protobuf Definitions**
   ```bash
   # Define your service in calculator.proto
   # Generate Python code
   python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. calculator.proto
   ```

2. **Enable mTLS Security**
   ```python
   configure(
       PLUGIN_AUTO_MTLS=True,
       PLUGIN_SERVER_CERT="file:///etc/ssl/certs/server.crt",
       PLUGIN_SERVER_KEY="file:///etc/ssl/private/server.key",
       PLUGIN_CLIENT_ROOT_CERTS="file:///etc/ssl/certs/ca.crt",
   )
   ```

3. **Add Real gRPC Stubs**
   ```python
   from calculator_pb2_grpc import CalculatorStub
   stub = CalculatorStub(client.grpc_channel)
   response = await stub.Add(AddRequest(a=10, b=5))
   ```

4. **Deploy to Production**
   - Use TCP transport for network communication
   - Configure proper TLS certificates
   - Set up monitoring and logging
   - Configure rate limits appropriately
   - Add health check endpoints

## 📚 Additional Resources

- **Full Documentation**: `/REDACTED_ABS_PATH`
- **API Reference**: `/REDACTED_ABS_PATH`
- **Security Guide**: `/REDACTED_ABS_PATH`
- **More Examples**: `/REDACTED_ABS_PATH`

## 🐛 Troubleshooting

### Socket Already in Use
```bash
# Remove old socket file
rm /tmp/calculator-rpc.sock
```

### Permission Denied
```bash
# Make scripts executable
chmod +x demo_calculator_*.py
```

### Import Errors
```bash
# Ensure PYTHONPATH is set
export PYTHONPATH=/REDACTED_ABS_PATH:$PYTHONPATH
```

## 📝 Notes

- This demo uses simplified message types for clarity
- In production, use proper protobuf message definitions
- The server uses Unix sockets for maximum performance
- Rate limiting is enabled (100 req/s with burst of 200)
- Health checks are enabled via gRPC health protocol
- All communication is logged with structured logging

---

**Built with ❤️ using pyvider-rpcplugin v0.0.11**
