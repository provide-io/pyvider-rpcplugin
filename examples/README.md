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
| **`05_security_mtls.py`** | 🔒 mTLS certificate setup & security patterns | Advanced | PKI knowledge |
| **`06_async_patterns.py`** | ⚡ Advanced async best practices | Advanced | Asyncio proficiency |
| **`07_error_handling.py`** | ⚠️ Robust error management patterns | Intermediate | Exception handling |
| **`08_production_config.py`** | 🏭 Production deployment patterns | Advanced | Operations experience |
| **`09_custom_protocols.py`** | 🔧 Custom protocol definitions & middleware | Advanced | Framework understanding |
| **`10_performance_tuning.py`** | 📈 Performance benchmarking & optimization | Advanced | System knowledge |

### **Complete Demos** (`demo/` directory)

#### **Echo Service** (`examples/demo/`)
A complete, production-ready echo service implementation.

```bash
# Start the server
python examples/demo/echo_server.py --transport tcp --port 50051

# In another terminal, run the client
python examples/demo/echo_client.py localhost:50051
```

**Files:**
- `examples/demo/echo.proto` - Protocol buffer service definition
- `examples/demo/echo_server.py` - Server implementation
- `examples/demo/echo_client.py` - Client implementation

#### **Key-Value Service** (`examples/kvproto/py_rpc/`)
Advanced key-value store with persistence and atomic operations.

```bash
# Start the KV server
python examples/kvproto/py_rpc/py_kv_server.py --transport tcp

# Run the client
python examples/kvproto/py_rpc/py_kv_client.py put mykey myvalue
python examples/kvproto/py_rpc/py_kv_client.py get mykey
```

**Features:**
- Persistent storage
- Atomic operations
- Batch operations
- Error handling

## 🏃‍♂️ Running Examples

### **Prerequisites**
- Python 3.13+
- `pyvider-rpcplugin` installed or source available
- For `demo/` examples: `protoc` compiler (for generating .proto files)

### **Environment Setup**

The examples are designed to be run from the root of the `pyvider-rpcplugin` repository.
Each example script (e.g., `01_quick_start.py`) typically includes:
```python
from example_utils import configure_for_example
configure_for_example()
```
This utility function automatically adjusts `sys.path` to ensure that the `pyvider.rpcplugin` library from the `src/` directory and `example_utils` itself are correctly imported.
Therefore, manually setting `PYTHONPATH` is usually not required if running examples from the project root (e.g., `python examples/01_quick_start.py`) or from within the `examples/` directory (e.g., `cd examples; python 01_quick_start.py`).

If you have `pyvider-rpcplugin` installed as a package (e.g., via `pip install pyvider-rpcplugin` or `uv add pyvider-rpcplugin`), the examples should also work by finding the installed package, provided the import paths are correctly resolved by your Python environment.

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

# Security and mTLS
python 05_security_mtls.py

# Advanced async patterns
python 06_async_patterns.py

# Error handling
python 07_error_handling.py

# Production configuration
python 08_production_config.py

# Custom protocols
python 09_custom_protocols.py

# Performance tuning
python 10_performance_tuning.py
```

### **Running Complete Demos**

#### Echo Service Demo
```bash
# Terminal 1: Start server
cd examples/demo/
python echo_server.py

# Terminal 2: Run client
python echo_client.py
```

#### Key-Value Demo
```bash
# Terminal 1: Start KV server  
cd examples/kvproto/py_rpc/
python py_kv_server.py --transport tcp

# Terminal 2: Run KV client
python py_kv_client.py put mykey myvalue
python py_kv_client.py get mykey
```

## 📚 Learning Path

### **For Beginners**
1. Start with `01_quick_start.py` - Understand basic concepts
2. Explore `02_server_setup.py` - Learn server configuration
3. Try `03_client_connection.py` - Understand client patterns
4. Run the complete `examples/demo/` (echo demo) - See everything together

### **For Intermediate Users**
1. Study `04_transport_options.py` - Compare Unix vs TCP
2. Review `07_error_handling.py` for robust applications
3. Study `06_async_patterns.py` for async best practices
4. Experiment with `examples/kvproto/py_rpc/` (KV demo) - Complex service implementation

### **For Advanced Users**
1. Master `05_security_mtls.py` - Production security
2. Deploy using `08_production_config.py` - Production setup
3. Analyze `09_custom_protocols.py` for protocol extensions
4. Optimize with `10_performance_tuning.py` - Performance patterns

## 🔧 Troubleshooting

### **Common Issues**

#### Import Errors
If you encounter import errors like `ModuleNotFoundError: No module named 'pyvider'` or `No module named 'example_utils'`:
- Ensure you are running the example script from the project's root directory (e.g., `python examples/01_quick_start.py`) or from within the `examples/` directory itself (e.g., `cd examples; python 01_quick_start.py`).
- The `example_utils.configure_for_example()` call at the beginning of each script is designed to set up `sys.path` correctly. Make sure this line is present and executed.
- If you've installed `pyvider-rpcplugin` as a package, ensure your Python environment can locate it.

#### Port Already in Use
```bash
# Examples automatically find available ports
# If issues persist, check for other services:
netstat -tulpn | grep :50051
```

#### Permission Errors (Unix Sockets)
```bash
# Ensure socket directory is writable
mkdir -p /tmp/pyvider_sockets
chmod 755 /tmp/pyvider_sockets
```

## 📖 Additional Resources

- **API Documentation**: See `docs/api-reference.md`
- **Architecture Guide**: See `docs/architecture.md`
- **Security Guide**: See `docs/security.md`
- **Production Deployment**: See `docs/production.md`

## 🤝 Contributing Examples

When adding new examples:

1. Use the numbered format for core examples (`11_new_feature.py`)
2. Include comprehensive docstrings and comments
3. Add appropriate emoji logging with `from pyvider.telemetry import logger`
4. Update this README with the new example
5. Ensure examples are self-contained and runnable
6. Follow the established patterns for path resolution

---

**Happy coding with pyvider-rpcplugin!** 🐍🚀
