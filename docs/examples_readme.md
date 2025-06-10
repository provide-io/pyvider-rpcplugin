# 🔌 Pyvider RPC Plugin Examples

This directory contains a comprehensive collection of executable examples demonstrating the features and usage patterns of `pyvider-rpcplugin`. Each example is designed to be run independently and showcases specific aspects of the plugin framework.

## 🚀 Quick Start

To run any example:

1. **Navigate to the examples directory**:
   ```bash
   cd examples/
   ```

2. **Run the desired example**:
   ```bash
   python 01_echo_demo.py
   ```

Each script automatically configures the Python path to find the `pyvider` modules from the project's `src` directory.

## 📋 Example Files

### **Core Examples** (Numbered Series)

| File | Description | Complexity | Prerequisites |
|------|-------------|------------|---------------|
| **`01_echo_demo.py`** | 🔊 Basic echo service - **Featured in README** | Beginner | None |
| **`02_server_setup.py`** | 🚀 Server configuration patterns | Beginner | Basic Python async |
| **`03_client_connection.py`** | 🔗 Client implementation examples | Beginner | Understanding of 02 |
| **`04_transport_options.py`** | 🚚 Unix socket vs TCP configuration | Intermediate | Basic networking |
| **`05_security_mtls.py`** | 🔒 mTLS certificate setup | Advanced | PKI knowledge |
| **`06_error_handling.py`** | ⚠️ Robust error management patterns | Intermediate | Exception handling |
| **`07_async_patterns.py`** | ⚡ Advanced async best practices | Advanced | Asyncio proficiency |
| **`08_production_config.py`** | 🏭 Production deployment patterns | Advanced | Operations experience |

### **Complete Demos** (`demo/` directory)

#### **Echo Service** (`demo/echo_service/`)
A complete, production-ready echo service implementation.

```bash
# Start the server
python demo/echo_service/server.py --transport tcp --port 50051

# In another terminal, run the client
python demo/echo_service/client.py localhost:50051
```

**Files:**
- `echo.proto` - Protocol buffer service definition
- `server.py` - Complete server implementation with streaming support
- `client.py` - Full-featured client with unary and streaming operations

#### **Key-Value Service** (`demo/kvproto/`)
Advanced key-value store with persistence and atomic operations.

```bash
# Start the KV server
python demo/kvproto/server.py --storage-path /tmp/kv.db

# Run the client
python demo/kvproto/client.py
```

**Features:**
- Persistent storage
- Atomic operations
- Batch operations
- TTL support

## 🏃‍♂️ Running Examples

### **Prerequisites**
- Python 3.13+
- `pyvider-rpcplugin` installed or source available
- For `demo/` examples: `protoc` compiler (for generating .proto files)

### **Environment Setup**
```bash
# Install dependencies (if using as standalone)
pip install pyvider-rpcplugin

# Or if running from source
export PYTHONPATH="${PWD}/src:${PYTHONPATH}"
```

### **Running Individual Examples**
```bash
# Basic echo demo (great starting point)
python 01_echo_demo.py

# Server configuration examples
python 02_server_setup.py

# Client patterns
python 03_client_connection.py

# Transport comparison
python 04_transport_options.py
```

### **Running Complete Demos**

#### Echo Service Demo
```bash
# Terminal 1: Start server
cd examples/demo/echo_service/
python server.py

# Terminal 2: Run client
python client.py /path/to/server/socket
```

#### Key-Value Demo
```bash
# Terminal 1: Start KV server  
cd examples/demo/kvproto/
python server.py --transport tcp

# Terminal 2: Run KV client
python client.py
```

## 📚 Learning Path

### **For Beginners**
1. Start with `01_echo_demo.py` - Understand basic concepts
2. Explore `02_server_setup.py` - Learn server configuration
3. Try `03_client_connection.py` - Understand client patterns
4. Run the complete `demo/echo_service/` - See everything together

### **For Intermediate Users**
1. Study `04_transport_options.py` - Compare Unix vs TCP
2. Examine `06_error_handling.py` - Robust patterns
3. Experiment with `demo/kvproto/` - Complex service implementation

### **For Advanced Users**
1. Master `05_security_mtls.py` - Production security
2. Optimize with `07_async_patterns.py` - Performance patterns
3. Deploy using `08_production_config.py` - Production setup

## 🔧 Customizing Examples

All examples are designed to be easily customizable:

### **Modifying Transport**
```python
# Change from Unix socket to TCP
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="tcp",  # Changed from "unix"
    host="0.0.0.0",
    port=8080
)
```

### **Adding Security**
```python
# Enable mTLS
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="tcp",
    config={
        "security": {
            "mtls": True,
            "cert_file": "/path/to/server.crt",
            "key_file": "/path/to/server.key",
            "ca_file": "/path/to/ca.crt"
        }
    }
)
```

### **Custom Protocols**
See `demo/kvproto/kv.proto` for an example of defining custom protocol buffer services.

## 🐛 Troubleshooting

### **Common Issues**

**Import Errors:**
```bash
# Ensure source is in Python path
export PYTHONPATH="${PWD}/src:${PYTHONPATH}"
```

**Permission Errors (Unix sockets):**
```bash
# Ensure socket directory is writable
chmod 755 /tmp/pyvider-sockets/
```

**Connection Timeouts:**
```bash
# Increase client timeout
client = plugin_client(server_path, timeout=30.0)
```

### **Debugging**
Enable detailed logging:
```python
from pyvider.telemetry import configure_logging
configure_logging(level="DEBUG")
```

## 🤝 Contributing

Found an issue or want to add an example? 

1. Follow the existing naming convention (`##_description.py`)
2. Include comprehensive docstrings and error handling
3. Add the example to this README with appropriate complexity level
4. Test on both Unix and TCP transports where applicable

## 📖 Further Reading

- **Main Documentation**: See project README.md
- **API Reference**: Check `docs/api-reference.md`
- **Production Guide**: Review `docs/production-deployment.md`

---

**🎯 Start with `01_echo_demo.py` and work your way up!**
