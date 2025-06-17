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
   python 01_quick_start.py
   ```

Each script automatically configures the Python path to find the `pyvider` modules from the project's `src` directory.

## 📋 Example Files

### **Core Examples** (Numbered Series)

| File | Description | Complexity | Prerequisites |
|------|-------------|------------|---------------|
| **`01_quick_start.py`** | 🚀 Basic server/client setup - **Featured in README** | Beginner | None |
| **`02_server_setup.py`** | ⚙️ Server configuration patterns | Beginner | Basic Python async |
| **`03_client_connection.py`** | 🔗 Client implementation examples | Beginner | Understanding of 02 |
| **`04_transport_options.py`** | 🚚 Unix socket vs TCP configuration | Intermediate | Basic networking |
| **`05_security_mtls.py`** | 🔒 mTLS certificate setup | Advanced | PKI knowledge |
| **`06_async_patterns.py`** | ⚡ Advanced async best practices | Advanced | Asyncio proficiency |
| **`07_error_handling.py`** | ⚠️ Robust error management patterns | Intermediate | Exception handling |
| **`08_production_config.py`** | 🏭 Production deployment patterns | Advanced | Operations experience |
| **`09_custom_protocols.py`** | 🔧 Custom protocol definitions & middleware | Advanced | Framework understanding |
| **`10_performance_tuning.py`** | 📈 Performance benchmarking & optimization | Advanced | System knowledge |

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
# Basic quick start demo (great starting point)
python 01_quick_start.py

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
1. Start with `01_quick_start.py` - Understand basic concepts
2. Explore `02_server_setup.py` - Learn server configuration
3. Try `03_client_connection.py` - Understand client patterns
4. Run the complete `demo/echo_service/` - See everything together

### **For Intermediate Users**
1. Study `04_transport_options.py` - Compare Unix vs TCP
2. Study `06_async_patterns.py` for async best practices (Corrected order)
3. Review `07_error_handling.py` for robust applications (Corrected order)
4. Experiment with `demo/kvproto/` - Complex service implementation

### **For Advanced Users**
1. Master `05_security_mtls.py` - Production security
2. Deploy using `08_production_config.py` - Production setup
3. Analyze `09_custom_protocols.py` for protocol extensions
4. Optimize with `10_performance_tuning.py` for high-scale scenarios

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
# Note: For mTLS, global configuration via `configure()` or environment variables
# for PLUGIN_SERVER_CERT, PLUGIN_SERVER_KEY, and PLUGIN_CLIENT_ROOT_CERTS (for server to verify clients)
# or PLUGIN_CLIENT_CERT, PLUGIN_CLIENT_KEY, and PLUGIN_SERVER_ROOT_CERTS (for client to verify server)
# is generally preferred. See `05_security_mtls.py` for a detailed example.
# The following shows using `configure()` for a server requiring mTLS:
from pyvider.rpcplugin import configure # Add import

configure(
    PLUGIN_AUTO_MTLS=True,
    PLUGIN_SERVER_CERT="/path/to/server.crt",       # Example path for server's certificate
    PLUGIN_SERVER_KEY="/path/to/server.key",        # Example path for server's private key
    PLUGIN_CLIENT_ROOT_CERTS="/path/to/ca.crt"      # Example path to CA cert for server to verify clients
)
server = plugin_server(
    protocol=protocol,
    handler=handler,
    transport="tcp" # mTLS typically uses TCP
    # Client would need its own cert/key (PLUGIN_CLIENT_CERT, PLUGIN_CLIENT_KEY)
    # and the CA to verify this server (PLUGIN_SERVER_ROOT_CERTS).
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
Enable detailed logging via configuration:
```python
from pyvider.rpcplugin import configure
configure(PLUGIN_LOG_LEVEL="DEBUG")

# Alternatively, set the environment variable:
# export PLUGIN_LOG_LEVEL="DEBUG"
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
- **Configuration Guide**: Review `docs/configuration.md`
- **Security Guide**: Review `docs/security.md`

---

**🎯 Start with `01_quick_start.py` and work your way up!**
