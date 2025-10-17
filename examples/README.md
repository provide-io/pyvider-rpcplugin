# 🔌 Pyvider RPC Plugin Examples

This directory contains a comprehensive collection of executable examples demonstrating the features and usage patterns of `pyvider-rpcplugin`. Each example is designed to be run independently and showcases specific aspects of the plugin framework.

## 🚀 Quick Start

To run the quick start example:

1.  **Navigate to the project root directory** (if not already there).
2.  **Run the client script**:
    ```bash
    python examples/ch02_quick_start_client.py
    ```
    This script will launch the `ch02_dummy_server.py` plugin and demonstrate a basic connection.

Each example script automatically configures the Python path to find the `pyvider` modules from the project's `src` directory via `example_utils.py`.

## 📋 Example Files

The examples are now named with a `chXX_` prefix corresponding to the main documentation chapter they illustrate or relate to.

| File                                      | Description                                                                 | Relevant Chapter(s) |
| :---------------------------------------- | :-------------------------------------------------------------------------- | :------------------ |
| **`ch02_dummy_server.py`**                | Minimal plugin server used by other examples.                               | Ch02, Ch08, Ch09    |
| **`ch02_quick_start_client.py`**          | 🚀 Basic client launching `ch02_dummy_server.py`.                           | Ch02                |
| **`ch03_server_setup_concepts.py`**       | ⚙️ Server configuration patterns and concepts.                                | Ch03                |
| **`ch04_transport_options_demo.py`**      | 🚚 Demonstrates Unix socket vs TCP transport classes.                       | Ch04                |
| **`ch05_echo_server.py`**                 | 📢 Echo service: Server implementation.                                     | Ch05                |
| **`ch06_client_setup_concepts.py`**       | 🔗 Client implementation concepts and patterns.                             | Ch06                |
| **`ch07_echo_client.py`**                 | 💻 Echo service: Client launching `ch05_echo_server.py`.                    | Ch07                |
| **`ch08_direct_client_connection.py`**    | 🔌 Client connecting directly to an already running server.                 | Ch08                |
| **`ch09_security_mtls_example.py`**       | 🔒 mTLS certificate setup & security patterns.                              | Ch09                |
| **`ch10_async_patterns_demo.py`**         | ⚡ Advanced asyncio patterns relevant to RPC development.                    | Ch10                |
| **`ch11_error_handling_demo.py`**         | ⚠️ Robust error management patterns and exception handling.                  | Ch11                |
| **`ch12_production_config_discussion.py`**| 🏭 Discussion of production deployment patterns and configurations.         | Ch12                |
| **`ch13_custom_protocols_demo.py`**       | 🔧 Conceptual custom protocol definitions & middleware ideas.               | Ch13                |
| **`ch14_performance_tuning_concepts.py`** | 📈 Performance benchmarking & optimization concepts.                        | Ch14                |
| **`ch15_e2e_server.py`**                  | 🌐 End-to-end Greeter service: Server implementation.                       | Ch15                |
| **`ch15_e2e_client.py`**                  | 🌐 End-to-end Greeter service: Client launching `ch15_e2e_server.py`.       | Ch15                |

### **Service Examples Details**

#### **Echo Service** (using `ch05_echo_server.py` and `ch07_echo_client.py`)
A fundamental client-server example demonstrating basic RPC communication using a custom `Echo` service defined in `examples/proto/echo.proto`.

**Running the Echo Service:**
1.  **Run the client (which launches the server):**
    ```bash
    # From the project root directory:
    python examples/ch07_echo_client.py
    ```
    The client will launch `ch05_echo_server.py`, connect to it, send a message, and print the reply.

#### **End-to-End Greeter Service** (using `ch15_e2e_server.py` and `ch15_e2e_client.py`)
A client-server example demonstrating a true RPC call with a custom protobuf service defined in `examples/proto/e2e_greeting.proto`.

**Running the E2E Greeter Service:**
1.  **Run the client (which launches the server):**
    ```bash
    # From the project root directory:
    python examples/ch15_e2e_client.py
    ```
    The client will launch `ch15_e2e_server.py`, connect, make an RPC call, print the reply, and then both will shut down.

## 🏃‍♂️ Running Examples

### **Prerequisites**
- Python 3.11+ (3.13+ recommended)
- `pyvider-rpcplugin` installed or source available (i.e., run from the project root).
- `grpcio-tools` for compiling `.proto` files (though pre-generated files are provided for the examples).

### **Environment Setup**

The examples are designed to be run from the root of the `pyvider-rpcplugin` repository.
Each example script (e.g., `ch02_quick_start_client.py`) typically includes:
```python
# For scripts inside examples/ directory
import example_utils
example_utils.configure_for_example()
```
This utility function automatically adjusts `sys.path` to ensure that the `pyvider.rpcplugin` library from the `src/` directory and `example_utils` itself are correctly imported.
Therefore, manually setting `PYTHONPATH` is usually not required if running examples from the project root (e.g., `python examples/ch02_quick_start_client.py`).

### **Running Individual Examples**
(Run from the project root directory)
```bash
# Quick Start (Client launches ch02_dummy_server.py)
python examples/ch02_quick_start_client.py

# Echo Service (Client launches ch05_echo_server.py)
python examples/ch07_echo_client.py

# E2E Greeter Service (Client launches ch15_e2e_server.py)
python examples/ch15_e2e_client.py

# Other conceptual/demonstration scripts:
python examples/ch03_server_setup_concepts.py
python examples/ch04_transport_options_demo.py
python examples/ch06_client_setup_concepts.py
python examples/ch09_security_mtls_example.py # Launches ch02_dummy_server.py
python examples/ch10_async_patterns_demo.py
python examples/ch11_error_handling_demo.py
python examples/ch12_production_config_discussion.py
python examples/ch13_custom_protocols_demo.py
python examples/ch14_performance_tuning_concepts.py

# For ch08_direct_client_connection.py:
# 1. Start ch02_dummy_server.py in one terminal: python examples/ch02_dummy_server.py
#    (It will write its socket path to dummy_server_socket.txt)
# 2. In another terminal, run: python examples/ch08_direct_client_connection.py
```

## 📚 Learning Path

### **For Beginners**
1. Start with **Chapter 2: Getting Started** and run `ch02_quick_start_client.py`.
2. Explore server setup concepts with `ch03_server_setup_concepts.py` (Chapter 3).
3. Understand client setup with `ch06_client_setup_concepts.py` (Chapter 6).
4. Run the **Echo Service** (`ch07_echo_client.py` launching `ch05_echo_server.py`) to see a full client/server RPC interaction (Chapters 5 & 7).

### **For Intermediate Users**
1. Study transport options with `ch04_transport_options_demo.py` (Chapter 4).
2. Explore async patterns with `ch10_async_patterns_demo.py` (Chapter 10).
3. Review error handling with `ch11_error_handling_demo.py` (Chapter 11).
4. Run the **E2E Greeter Service** (`ch15_e2e_client.py` launching `ch15_e2e_server.py`) (Chapter 15).

### **For Advanced Users**
1. Master mTLS with `ch09_security_mtls_example.py` (Chapter 9).
2. Understand production configurations with `ch12_production_config_discussion.py` (Chapter 12).
3. Analyze custom protocol concepts with `ch13_custom_protocols_demo.py` (Chapter 13).
4. Review performance concepts with `ch14_performance_tuning_concepts.py` (Chapter 14).
5. Understand direct client connections (for testing/debugging) with `ch08_direct_client_connection.py` (Chapter 8).

## 🔧 Troubleshooting

### **Common Issues**

#### Import Errors
If you encounter import errors like `ModuleNotFoundError: No module named 'pyvider'` or `No module named 'example_utils'`:
- Ensure you are running the example script from the project's root directory (e.g., `python examples/ch02_quick_start_client.py`).
- The `example_utils.configure_for_example()` call at the beginning of most scripts is designed to set up `sys.path` correctly.

## 📖 Additional Resources

- **API Reference**: [API Documentation](../docs/api/index.md)
- **Core Architecture**: [Development Architecture Guide](../docs/development/architecture.md)
- **Security (mTLS)**: [mTLS Security Guide](../docs/guide/security/mtls.md)
- **Production Configuration & Deployment**: [Production Configuration Guide](../docs/guide/config/production.md)

## 🤝 Contributing Examples

When adding new examples:

1. Use the `chXX_descriptive_name.py` format, where `XX` is the primary chapter number it relates to.
2. Include comprehensive docstrings and comments.
3. Add appropriate emoji logging with `from provide.foundation import logger`.
4. Update this README with the new example.
5. Ensure examples are self-contained and runnable where possible, or provide clear instructions if they depend on other components.
6. Follow the established patterns for path resolution and `example_utils`.

---

**Happy coding with pyvider-rpcplugin!** 🐍🚀
