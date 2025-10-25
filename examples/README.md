# 🔌 Pyvider RPC Plugin Examples

This directory contains a comprehensive collection of executable examples demonstrating the features and usage patterns of `pyvider-rpcplugin`. Each example is designed to be run independently and showcases specific aspects of the plugin framework.

## 🚀 Quick Start

To run the quick start example:

1.  **Navigate to the project root directory** (if not already there).
2.  **Run the client script**:
    ```bash
    python examples/quick_start_client.py
    ```
    This script will launch the `dummy_server.py` plugin and demonstrate a basic connection.

Each example script automatically configures the Python path to find the `pyvider` modules from the project's `src` directory via `example_utils.py`.

## 📋 Example Files

### Getting Started Examples

| File                         | Description                                                    |
| :--------------------------- | :------------------------------------------------------------- |
| **`quick_start_client.py`**  | 🚀 Basic client launching `dummy_server.py`                    |
| **`dummy_server.py`**        | Minimal plugin server used by other examples                   |

### Core Concepts

| File                            | Description                                                 |
| :------------------------------ | :---------------------------------------------------------- |
| **`server_setup_concepts.py`**  | ⚙️ Server configuration patterns and concepts                |
| **`client_setup_concepts.py`**  | 🔗 Client implementation concepts and patterns              |
| **`transport_options_demo.py`** | 🚚 Demonstrates Unix socket vs TCP transport classes        |

### Complete Service Examples

| File                      | Description                                                    |
| :------------------------ | :------------------------------------------------------------- |
| **`echo_server.py`**      | 📢 Echo service: Server implementation                         |
| **`echo_client.py`**      | 💻 Echo service: Client launching `echo_server.py`             |
| **`e2e_greeter_server.py`** | 🌐 End-to-end Greeter service: Server implementation         |
| **`e2e_greeter_client.py`** | 🌐 End-to-end Greeter service: Client launching server       |

### Security Examples

| File                           | Description                                              |
| :----------------------------- | :------------------------------------------------------- |
| **`security_mtls_example.py`** | 🔒 mTLS certificate setup & security patterns            |

### Advanced Topics

| File                                  | Description                                                      |
| :------------------------------------ | :--------------------------------------------------------------- |
| **`async_patterns_demo.py`**          | ⚡ Advanced asyncio patterns relevant to RPC development          |
| **`error_handling_demo.py`**          | ⚠️ Robust error management patterns and exception handling        |
| **`custom_protocols_demo.py`**        | 🔧 Conceptual custom protocol definitions & middleware ideas     |
| **`performance_tuning_concepts.py`**  | 📈 Performance benchmarking & optimization concepts              |
| **`telemetry_demo.py`**               | 📊 Telemetry and observability integration                       |

### Production & Deployment

| File                                   | Description                                                   |
| :------------------------------------- | :------------------------------------------------------------ |
| **`production_config_discussion.py`**  | 🏭 Discussion of production deployment patterns               |
| **`direct_client_connection.py`**      | 🔌 Client connecting directly to an already running server    |

## 🎯 Featured Examples

### Echo Service

A fundamental client-server example demonstrating basic RPC communication using a custom `Echo` service defined in `examples/proto/echo.proto`.

**Running the Echo Service:**
```bash
# From the project root directory:
python examples/echo_client.py
```
The client will launch `echo_server.py`, connect to it, send a message, and print the reply.

### End-to-End Greeter Service

A client-server example demonstrating a true RPC call with a custom protobuf service defined in `examples/proto/e2e_greeting.proto`.

**Running the E2E Greeter Service:**
```bash
# From the project root directory:
python examples/e2e_greeter_client.py
```
The client will launch `e2e_greeter_server.py`, connect, make an RPC call, print the reply, and then both will shut down.

## 🏃‍♂️ Running Examples

### Prerequisites

- Python 3.11+ (3.13+ recommended)
- `pyvider-rpcplugin` installed or source available (i.e., run from the project root)
- `grpcio-tools` for compiling `.proto` files (though pre-generated files are provided)

### Environment Setup

The examples are designed to be run from the root of the `pyvider-rpcplugin` repository.
Each example script (e.g., `quick_start_client.py`) typically includes:
```python
# For scripts inside examples/ directory
import example_utils
example_utils.configure_for_example()
```
This utility function automatically adjusts `sys.path` to ensure that the `pyvider.rpcplugin` library from the `src/` directory and `example_utils` itself are correctly imported.

### Running Individual Examples

Run from the project root directory:

```bash
# Getting Started
python examples/quick_start_client.py    # Launches dummy_server.py
python examples/dummy_server.py          # Run standalone (for testing)

# Core Concepts
python examples/server_setup_concepts.py
python examples/client_setup_concepts.py
python examples/transport_options_demo.py

# Complete Services
python examples/echo_client.py           # Launches echo_server.py
python examples/e2e_greeter_client.py    # Launches e2e_greeter_server.py

# Security
python examples/security_mtls_example.py # Launches dummy_server.py with mTLS

# Advanced Topics
python examples/async_patterns_demo.py
python examples/error_handling_demo.py
python examples/custom_protocols_demo.py
python examples/performance_tuning_concepts.py
python examples/telemetry_demo.py

# Production & Deployment
python examples/production_config_discussion.py

# Direct Connection (requires manual server start)
# Terminal 1: python examples/dummy_server.py
# Terminal 2: python examples/direct_client_connection.py
```

## 📚 Learning Path

### For Beginners

1. Start with **Getting Started** - run `quick_start_client.py`
2. Explore server concepts with `server_setup_concepts.py`
3. Understand client concepts with `client_setup_concepts.py`
4. Run the **Echo Service** (`echo_client.py`) to see a full client/server RPC interaction

### For Intermediate Users

1. Study transport options with `transport_options_demo.py`
2. Explore async patterns with `async_patterns_demo.py`
3. Review error handling with `error_handling_demo.py`
4. Run the **E2E Greeter Service** (`e2e_greeter_client.py`)

### For Advanced Users

1. Master mTLS with `security_mtls_example.py`
2. Understand production configurations with `production_config_discussion.py`
3. Analyze custom protocol concepts with `custom_protocols_demo.py`
4. Review performance concepts with `performance_tuning_concepts.py`
5. Study observability with `telemetry_demo.py`
6. Understand direct client connections (for testing/debugging) with `direct_client_connection.py`

## 🔧 Troubleshooting

### Common Issues

#### Import Errors

If you encounter import errors like `ModuleNotFoundError: No module named 'pyvider'` or `No module named 'example_utils'`:
- Ensure you are running the example script from the project's root directory (e.g., `python examples/quick_start_client.py`)
- The `example_utils.configure_for_example()` call at the beginning of most scripts is designed to set up `sys.path` correctly

#### Connection Timeouts

If examples time out:
- Check that no other processes are using the same ports/socket paths
- Verify firewall settings aren't blocking local connections
- Check logs for specific error messages

## 📖 Additional Resources

- **API Reference**: [API Documentation](../docs/reference/index.md)
- **Core Architecture**: [Development Architecture Guide](../docs/development/architecture.md)
- **Security (mTLS)**: [mTLS Security Guide](../docs/guide/security/mtls.md)
- **Production Configuration & Deployment**: [Production Configuration Guide](../docs/guide/config/production.md)
- **Getting Started Documentation**: [Quick Start Guide](../docs/getting-started/quick-start.md)

## 🤝 Contributing Examples

When adding new examples:

1. Use descriptive names that clearly indicate the example's purpose
2. Include comprehensive docstrings and comments
3. Add appropriate logging with `from provide.foundation import logger`
4. Update this README with the new example in the appropriate category
5. Ensure examples are self-contained and runnable where possible, or provide clear instructions if they depend on other components
6. Follow the established patterns for path resolution and `example_utils`

---

**Happy coding with pyvider-rpcplugin!** 🐍🚀
