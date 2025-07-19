# Pyvider RPC Plugin Examples

This directory contains a collection of executable Python scripts demonstrating various features and usage patterns of the `pyvider-rpcplugin` library. Each script is designed to be run independently and showcases a specific aspect of building high-performance RPC plugins.

## 🚀 Running the Examples

To run an example script:
Note: Most examples are designed to work with mTLS enabled. It's generally recommended to have `export PLUGIN_AUTO_MTLS=True` in your environment for these examples to utilize automatic mTLS features. For detailed control over mTLS using specific certificates, refer to the notes for `05_security_mtls.py`.
Note: Most examples are designed to work with mTLS enabled. It's generally recommended to have `export PLUGIN_AUTO_MTLS=True` in your environment for these examples to utilize automatic mTLS features. For detailed control over mTLS using specific certificates, refer to the notes for `05_security_mtls.py`.
Note: Most examples are designed to work with mTLS enabled. It's generally recommended to have `export PLUGIN_AUTO_MTLS=True` in your environment for these examples to utilize automatic mTLS features. For detailed control over mTLS using specific certificates, refer to the notes for `05_security_mtls.py`.

1. **Navigate to this directory** in your terminal:
   ```bash
   cd examples/
   ```

2. **Execute the desired Python script**:
   ```bash
   python <example_file_name>.py
   ```
   For example, to run the quick start example:
   ```bash
   python 01_quick_start.py
   ```

Each script will print output to the console, typically including formatted log messages that demonstrate the feature being showcased. The scripts are self-contained and manipulate `sys.path` to ensure they can find the `pyvider.rpcplugin` module from the project's `src` directory.

## 📚 Example Files

Here's a complete list of the available examples and what they demonstrate:

### 🌟 **Beginner Examples**

- **`01_quick_start.py`** ⚡
  Shows the most basic server and client setup using default configuration. Perfect introduction to the RPC plugin framework with minimal code.

- **`02_server_setup.py`** 🛎️  
  Illustrates advanced server configuration options including transport selection, endpoint binding, and service registration patterns.

- **`03_client_connection.py`** 🙋
  Demonstrates robust client connection patterns with error handling, retry logic, and connection lifecycle management. (Note: Retry logic is demonstrated as an application-level pattern within this example.)

### 🚄 **Transport & Protocol Examples**

- **`04_transport_options.py`** 🔗
  Compares Unix domain socket vs TCP socket transports, showing when to use each and how to configure transport-specific options.

- **`05_security_mtls.py`** 🔒
  Comprehensive mTLS (mutual TLS) setup with certificate generation, validation, and secure client-server communication patterns.

  **Running with Specific Certificates (e.g., from `../example_certs_output/`):**
  To ensure this example uses specific, pre-generated certificates:
  1. Set `export PLUGIN_AUTO_MTLS=False` in your shell.
  2. Export the *content* of your certificate files to the corresponding environment variables:
     ```bash
     export PLUGIN_SERVER_CERT=$(cat ../example_certs_output/server.crt)
     export PLUGIN_SERVER_KEY=$(cat ../example_certs_output/server.key)
     export PLUGIN_SERVER_ROOT_CERTS=$(cat ../example_certs_output/ca.crt)
     export PLUGIN_CLIENT_CERT=$(cat ../example_certs_output/client.crt)
     export PLUGIN_CLIENT_KEY=$(cat ../example_certs_output/client.key)
     export PLUGIN_CLIENT_ROOT_CERTS=$(cat ../example_certs_output/ca.crt) # CA for client to verify server
     ```
  3. Then run `python 05_security_mtls.py`.
  This method is generally more reliable in environments where direct file path access from within scripts can be inconsistent. Alternatively, you can set `PLUGIN_SERVER_CERT`, `PLUGIN_CLIENT_CERT` (etc.) to the direct file paths if preferred and your environment supports it.

  **Running with Specific Certificates (e.g., from `../example_certs_output/`):**
  To ensure this example uses specific, pre-generated certificates:
  1. Set `export PLUGIN_AUTO_MTLS=False` in your shell.
  2. Export the *content* of your certificate files to the corresponding environment variables:
     ```bash
     export PLUGIN_SERVER_CERT=$(cat ../example_certs_output/server.crt)
     export PLUGIN_SERVER_KEY=$(cat ../example_certs_output/server.key)
     export PLUGIN_SERVER_ROOT_CERTS=$(cat ../example_certs_output/ca.crt)
     export PLUGIN_CLIENT_CERT=$(cat ../example_certs_output/client.crt)
     export PLUGIN_CLIENT_KEY=$(cat ../example_certs_output/client.key)
     export PLUGIN_CLIENT_ROOT_CERTS=$(cat ../example_certs_output/ca.crt) # CA for client to verify server
     ```
  3. Then run `python 05_security_mtls.py`.
  This method is generally more reliable in environments where direct file path access from within scripts can be inconsistent. Alternatively, you can set `PLUGIN_SERVER_CERT`, `PLUGIN_CLIENT_CERT` (etc.) to the direct file paths if preferred and your environment supports it.
  \
  **Running with Specific Certificates (e.g., from `../example_certs_output/`):**\
  To ensure this example uses specific, pre-generated certificates:\
  1. Set `export PLUGIN_AUTO_MTLS=False` in your shell.\
  2. Export the *content* of your certificate files to the corresponding environment variables:\
     ```bash\
     export PLUGIN_SERVER_CERT=$(cat ../example_certs_output/server.crt)\
     export PLUGIN_SERVER_KEY=$(cat ../example_certs_output/server.key)\
     export PLUGIN_SERVER_ROOT_CERTS=$(cat ../example_certs_output/ca.crt)\
     export PLUGIN_CLIENT_CERT=$(cat ../example_certs_output/client.crt)\
     export PLUGIN_CLIENT_KEY=$(cat ../example_certs_output/client.key)\
     export PLUGIN_CLIENT_ROOT_CERTS=$(cat ../example_certs_output/ca.crt) # CA for client to verify server\
     ```\
  3. Then run `python 05_security_mtls.py`.\
  This method is generally more reliable in environments where direct file path access from within scripts can be inconsistent. Alternatively, you can set `PLUGIN_SERVER_CERT`, `PLUGIN_CLIENT_CERT` (etc.) to the direct file paths if preferred and your environment supports it.

- **`06_async_patterns.py`** ⚙️
  Best practices for asynchronous RPC programming including concurrent request handling, async context managers, and graceful shutdown.

### 🏭 **Production Examples**

- **`07_error_handling.py`** 🚨
  Robust error handling strategies including custom exceptions, retry policies, circuit breakers, and failure recovery patterns. (Note: Retry policies and circuit breaker patterns are shown via example implementations within this script, not as built-in library classes.)

- **`08_production_config.py`** ⚙️
  Production-ready configuration management using environment variables, configuration files, and structured logging for monitoring.

- **`09_custom_protocols.py`** 🔧
  Advanced protocol customization including custom service definitions, middleware integration, and protocol extension patterns.

- **`10_performance_tuning.py`** 📈
  Performance optimization techniques including connection pooling, throughput tuning, latency optimization, and resource management. (Note: Connection pooling concepts are illustrated by managing multiple client instances; benchmark rigging is example-specific and uses direct gRPC channels for load simulation against the server.)

## 🏃‍♂️ Quick Reference

| Example | Focus Area | Complexity | Key Concepts |
|---------|------------|------------|-------------|
| `01_quick_start.py` | Basic Usage | ⭐ | Server, Client, Protocol |
| `02_server_setup.py` | Server Config | ⭐⭐ | Endpoints, Transports, Services |
| `03_client_connection.py` | Client Patterns | ⭐⭐ | Connections, Error Handling |
| `04_transport_options.py` | Transports | ⭐⭐ | Unix Sockets, TCP, Performance |
| `05_security_mtls.py` | Security | ⭐⭐⭐ | mTLS, Certificates, Encryption |
| `06_async_patterns.py` | Async Programming | ⭐⭐⭐ | Concurrency, Context Managers |
| `07_error_handling.py` | Reliability | ⭐⭐⭐ | Exceptions, Retries, Recovery |
| `08_production_config.py` | Production Setup | ⭐⭐⭐⭐ | Config Management, Monitoring |
| `09_custom_protocols.py` | Advanced Protocols | ⭐⭐⭐⭐ | Custom Services, Middleware |
| `10_performance_tuning.py` | Optimization | ⭐⭐⭐⭐⭐ | Benchmarking, Tuning, Scaling |

## 🎯 Learning Path

### **For Beginners** (New to RPC or pyvider-rpcplugin)
1. Start with `01_quick_start.py` to understand basic concepts
2. Move to `02_server_setup.py` for server configuration
3. Try `03_client_connection.py` for client-side patterns
4. Experiment with `04_transport_options.py` for transport choices

### **For Intermediate Users** (Familiar with RPC concepts)
1. Jump to `05_security_mtls.py` for production security
2. Study `06_async_patterns.py` for async best practices  
3. Review `07_error_handling.py` for robust applications
4. Examine `08_production_config.py` for deployment patterns

### **For Advanced Users** (Building production systems)
1. Analyze `09_custom_protocols.py` for protocol extensions
2. Optimize with `10_performance_tuning.py` for high-scale scenarios
3. Combine patterns from multiple examples for complex use cases

## 🛠️ Example Requirements

All examples use only the core `pyvider-rpcplugin` dependencies:

```python
# Core dependencies (automatically installed)
import asyncio                    # Built-in async support
from pyvider.rpcplugin import *  # Main RPC plugin framework
from pyvider.telemetry import *  # Logging and observability
```

Some advanced examples may demonstrate integration with:
- **Protocol Buffers** - For custom service definitions
- **Certificate generation** - For mTLS security examples
- **Performance monitoring** - For optimization examples

## 🧪 Testing Examples

Each example includes verification steps and expected outputs. You can run all examples as a test suite:

```bash
# Run all examples in sequence
for example in examples/[0-9]*.py; do
    echo "🧪 Testing $example"
    python "$example"
    echo "✅ Completed $example"
    echo ""
done
Note: The simple loop above runs all examples with the prevailing `PLUGIN_AUTO_MTLS` setting. For rigorous testing of `05_security_mtls.py` with specific certificates, ensure its dedicated environment (as described in its section above) is set up before execution.
Note: The simple loop above runs all examples with the prevailing `PLUGIN_AUTO_MTLS` setting. For rigorous testing of `05_security_mtls.py` with specific certificates, ensure its dedicated environment (as described in its section above) is set up before execution.
Note: The simple loop above runs all examples with the prevailing `PLUGIN_AUTO_MTLS` setting. For rigorous testing of `05_security_mtls.py` with specific certificates, ensure its dedicated environment (as described in its section above) is set up before execution.
```

Or test specific categories:

```bash
# Test basic examples only
python examples/01_quick_start.py
python examples/02_server_setup.py
python examples/03_client_connection.py

# Test security examples
python examples/05_security_mtls.py

# Test production examples  
python examples/08_production_config.py
python examples/09_custom_protocols.py # Added
python examples/10_performance_tuning.py
```

## 🔧 Customization

Feel free to modify and extend these examples for your specific use cases:

- **Change transport types** - Switch between Unix sockets and TCP
- **Modify security settings** - Adjust mTLS configuration for your environment
- **Add custom logging** - Integrate with your existing observability stack
- **Scale parameters** - Adjust concurrency and performance settings
- **Extend protocols** - Add your own service definitions and handlers

## 💡 Tips for Success

1. **Start Simple** - Begin with basic examples before moving to advanced patterns
2. **Read the Code** - Each example includes detailed comments explaining the concepts
3. **Experiment** - Modify examples to understand how changes affect behavior
4. **Check Logs** - Pay attention to the structured logging output for insights
5. **Measure Performance** - Use the benchmarking examples to understand system limits
6. **Configure mTLS Correctly:** For general examples, `PLUGIN_AUTO_MTLS=True` is often sufficient. For `05_security_mtls.py` or when needing specific certificates, ensure `PLUGIN_AUTO_MTLS=False` and provide the certificate paths or content as detailed in that example's description. Always prioritize mTLS in production.
7. **Understand Library Scope**: Some examples demonstrate advanced patterns (e.g., custom client-side retry logic, circuit breakers, specific pooling strategies for `plugin_client`) implemented within the example code itself. These illustrate how you can build robust applications on top of `pyvider.rpcplugin`, and may not represent built-in utility classes provided by the core library.

## 🆘 Getting Help

If you encounter issues with any examples:

1. **Check the logs** - Most issues are visible in the detailed log output
2. **Verify dependencies** - Ensure `pyvider-rpcplugin` is properly installed
3. **Review documentation** - See the main [README.md](../README.md) and [docs/](../docs/) 
4. **Open an issue** - Report bugs or request clarifications on GitHub

## 🚀 Next Steps

After exploring these examples:

1. **Build your own plugin** - Use the patterns as templates for your use case
2. **Read the API docs** - Review [docs/api-reference.md](../docs/api-reference.md) for complete details
3. **Study the architecture** - Understand the design in [docs/architecture.md](../docs/architecture.md)
4. **Optimize for production** - Follow guidelines in [docs/security.md](../docs/security.md) (which includes production checklists and operational security) and the Performance section in the main [README.md](../README.md#performance).

Happy coding with `pyvider.rpcplugin`! 🎉
