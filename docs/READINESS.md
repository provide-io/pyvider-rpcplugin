# pyvider.rpcplugin - Preview Release Checklist
Target Version: v0.1.0-preview.1
Python Requirement: 3.13+
Release Timeline: 2-3 weeks

## 🔥 CRITICAL - Must Complete Before Release

### 📚 Documentation (Priority 1)

#### README.md Creation
- [~] Partially Met - Project header with clear value proposition - Note: Header and tagline exist. Value proposition seems clear but cross-verify if it fully aligns with desired emphasis.
- [✓] Done - Tagline: "High-performance, type-safe RPC plugin framework for Python"
- [✓] Done - Key benefits: async-native, mTLS security, modern Python 3.13+ - Note: Covered in 'Why pyvider.rpcplugin?' section.
- [✓] Done - Badges: Python version, CI status, coverage, PyPI version
- [✓] Done - Quick Start section (5-minute setup) - Note: README Quick Start example updated to use `create_basic_protocol()` for a minimal, self-contained illustration. It's now more aligned with a 'few core lines' concept. The previous `GreeterHandler` example was more detailed and is better represented by `examples/01_quick_start.py`.
  ```python
  from pyvider.rpcplugin import plugin_server, plugin_protocol

  # Your first RPC plugin in 5 lines
  protocol = plugin_protocol("MyService", my_pb2, add_MyServiceServicer_to_server)
  server = plugin_server(protocol=protocol, handler=MyHandler())
  await server.serve()
  ```
- [✓] Done - Installation instructions
  - [✓] Done - `pip install pyvider-rpcplugin`
  - [✓] Done - Python 3.13+ requirement clearly stated
  - [~] Partially Met - Optional dependencies (dev, testing) - Note: README's 'Development Setup' section shows `uv sync --all-groups` for installing development/testing dependencies for contributors. This is appropriate. User-facing installation instructions correctly omit these. This item is considered addressed for README.md. Final check of `pyproject.toml` for correct definition of these groups (e.g., 'dev', 'test') is advisable as part of 'Packaging & Distribution' tasks.
- [✓] Done - Core concepts explanation - Note: Addressed via the new 'Core Concepts & Use Cases' section in README.md.
  - [✓] Done - What is a plugin architecture? - Note: Added explanation to new 'Core Concepts & Use Cases' section in README.md.
  - [✓] Done - When to use pyvider-rpcplugin? - Note: Expanded in the new 'Core Concepts & Use Cases' section in README.md with more explicit scenarios.
  - [✓] Done - How does it compare to alternatives? - Note: Added a high-level comparison to direct gRPC, go-plugin, and other Python RPC libs in the new 'Core Concepts & Use Cases' section in README.md.
- [✓] Done - Basic usage examples
  - [✓] Done - Server setup
  - [✓] Done - Client connection
  - [✓] Done - Protocol definition - Note: The main Quick Start now uses `create_basic_protocol()` avoiding this issue for the first example. For other examples using `plugin_protocol()` with generated modules (e.g., in 'Advanced Usage'), a comment has been added to README.md clarifying that these modules are typically generated from `.proto` files using `grpc_tools`.
- [✓] Done - Security highlights
  - [✓] Done - mTLS support
  - [✓] Done - Process isolation - Note: Added 'Process Isolation' with a brief explanation to the 'Security-Focused' subsection under 'Why pyvider.rpcplugin?' in README.md.
  - [✓] Done - Magic cookie authentication
- [✓] Done - Link to examples directory
- [✓] Done - Contributing section
- [✓] Done - License and acknowledgments

#### Examples Directory Creation
- [✓] Done - `examples/README.md` - Overview of all examples - Note: Exists and is comprehensive. Covers how to run, lists all examples (01-10) with descriptions, provides learning paths, testing instructions, etc.
- [✓] Done - `examples/01_quick_start.py` - Basic server/client - Note: File exists. Docstring `"""Demonstrates basic RPC plugin server and client setup with pyvider-rpcplugin."""` is descriptive. Shows basic server setup and a client that connects to a `./dummy_server.sh`, demonstrating client mechanics independently. Conceptual workflow also logged. Generally meets intent.
  ```python
  """Minimal working example - server and client in one file."""
  ```
- [✓] Done - `examples/02_server_setup.py` - Server configuration - Note: File exists. Docstring `"""Demonstrates advanced server configuration and setup patterns with pyvider-rpcplugin."""` is descriptive. Covers Unix, TCP, dual transport, and advanced configuration methods (programmatic, env var). Aligns well.
  ```python
  """Demonstrates server configuration options."""
  ```
- [✓] Done - `examples/03_client_connection.py` - Client usage - Note: RPCPluginClient now implements the async context manager protocol (`__aenter__`, `__aexit__`). Example `03_client_connection.py` (specifically `example_3_async_context_manager`) updated to use the actual `RPCPluginClient` with `async with` against `./dummy_server.sh`, demonstrating automatic lifecycle management. The example anticipates and logs the expected TransportError from dummy_server.sh.
  ```python
  """Shows client connection and RPC calls."""
  ```
- [✓] Done - `examples/04_transport_options.py` - Unix vs TCP - Note: Reviewed. Example logs simulated/illustrative benchmark results rather than performing live measurements, and client parts use `./dummy_server.sh`. This is acceptable for an example script demonstrating transport options and discussing performance. The key is accurate description of its behavior.
  ```python
  """Compares Unix socket and TCP transport performance."""
  ```
- [✓] Done - `examples/05_security_mtls.py` - mTLS setup - Note: Reviewed. Example uses self-signed certificates for CA, server, and client, and simulates the client connection to the mTLS server. These simplifications are acceptable for an example focused on mTLS configuration steps. Documentation should be clear about these aspects for users.
  ```python
  """Demonstrates mutual TLS certificate setup."""
  ```
- [✓] Done - Test all examples run independently - Note: All examples run successfully after installing the 'psutil' dependency for '10_performance_tuning.py'. The '01_quick_start.py' example correctly logs an expected TransportError with dummy_server.sh as per its design.
- [ ] Pending - Add example testing to CI pipeline - Note: To be verified/implemented. `examples/README.md` contains a shell loop to run examples.

#### API Documentation
- [✓] Done - `docs/api-reference.md` - Complete API documentation - Note: File renamed to `docs/api-reference.md`. Content appears comprehensive. A final detailed review for 100% completeness of all public APIs is still advisable during a dedicated docs pass.
  - [✓] Done - Factory functions: `plugin_server()`, `plugin_client()`, `plugin_protocol()` - Note: Well-documented with signatures, params, returns, and examples in `docs/api_reference_docs.md`. `create_basic_protocol()` also included.
  - [✓] Done - Core classes: `RPCPluginServer`, `RPCPluginClient`, `RPCPluginProtocol` - Note: Documented with constructors and methods in `docs/api_reference_docs.md`.
  - [✓] Done - Configuration: `configure()`, `RPCPluginConfig` - Note: Documented with signatures and params in `docs/api_reference_docs.md`. `load_config_from_file()` also included.
  - [✓] Done - Exceptions: Complete exception hierarchy - Note: Documented in `docs/api_reference_docs.md`, showing base `RPCPluginError` and derivatives.
  - [✓] Done - Transport classes: `UnixSocketTransport`, `TCPSocketTransport` - Note: Documented with constructors and key methods in `docs/api_reference_docs.md`.
- [✓] Done - Method signatures with type annotations - Note: Present throughout `docs/api_reference_docs.md`.
- [✓] Done - Parameter descriptions and examples - Note: Parameters are described, and examples are provided for many items in `docs/api_reference_docs.md`.
- [✓] Done - Return value specifications - Note: Return values are specified in `docs/api_reference_docs.md`.
- [✓] Done - Exception documentation - Note: Specific exceptions mentioned for some methods; general exception hierarchy also documented in `docs/api_reference_docs.md`.
- [✓] Done - Usage examples for each major function - Note: Numerous usage examples provided throughout `docs/api_reference_docs.md`.

### ⚙️ Configuration System Validation

#### Configuration File Support
- [✓] Done - Test JSON configuration loading - Note: Successfully tested loading and value verification. Values from JSON are correctly reflected in the config.
  ```json
  {
    "magic_cookie": "my-secret-cookie",
    "auto_mtls": true,
    "handshake_timeout": 30.0
  }
  ```
- [✓] Done - Test YAML configuration loading - Note: Successfully tested loading and value verification. Values from YAML are correctly reflected in the config.
  ```yaml
  magic_cookie: my-secret-cookie
  auto_mtls: true
  handshake_timeout: 30.0
  ```
- [✓] Done - Test .env file loading - Note: Successfully tested loading from a custom .env file (e.g., `test_config.env`) and value verification. PYVIDER_ prefixed vars are correctly mapped to their PLUGIN_ counterparts when loaded from a .env file.
  ```bash
  PYVIDER_MAGIC_COOKIE=my-secret-cookie
  PYVIDER_AUTO_MTLS=true
  PYVIDER_HANDSHAKE_TIMEOUT=30.0
  ```
- [✓] Done - Error handling for malformed config files - Note: Verified `ValueError` is raised for malformed JSON and YAML files during loading attempts, with clear error messages.
- [✓] Done - Default value fallbacks when config missing - Note: Verified that correct default values from the schema are applied when no config file is loaded and no overriding environment variables are set.
- [✓] Done - Configuration validation and type checking - Note: Verified type coercion (e.g., string "false" to bool False for env vars) and that `ValueError` is raised for invalid types (e.g., non-float for timeout) or values not in defined `valid_values` (e.g., invalid log level, invalid transport type) when loading from environment or through `configure()`. Unsupported protocol versions in `configure()` log a warning and set the value as intended.

#### Environment Variable Integration
- [~] Partially Met - Document all environment variable names (details in [docs/configuration.md](docs/configuration.md))
  - Full documentation for all environment variables, including their canonical `PLUGIN_` prefixed names, descriptions, types, defaults, and `.env` aliases (like `PYVIDER_` prefixed versions), is now available in the dedicated [Configuration Guide](docs/configuration.md).
  - Below are a few key examples:
    - **`PLUGIN_MAGIC_COOKIE_VALUE`** (`.env` Alias: `PYVIDER_MAGIC_COOKIE`):
      - Description: The expected magic cookie value for validation.
      - Default: `"rpcplugin-default-cookie"`
      - Type: `str`

    - **`PLUGIN_AUTO_MTLS`** (`.env` Alias: `PYVIDER_AUTO_MTLS`):
      - Description: Flag to enable automatic mTLS (true/false).
      - Default: `"true"`
      - Type: `bool`

    - **`PLUGIN_HANDSHAKE_TIMEOUT`** (`.env` Alias: `PYVIDER_HANDSHAKE_TIMEOUT`):
      - Description: Timeout in seconds for handshake operations.
      - Default: `10.0`
      - Type: `float`

    - **`PLUGIN_LOG_LEVEL`** (`.env` Alias: `PYVIDER_LOG_LEVEL`):
      - Description: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
      - Default: `"INFO"`
      - Type: `str`
      - Valid Values: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

    - **`PLUGIN_SERVER_TRANSPORTS`** (`.env` Alias: `PYVIDER_SERVER_TRANSPORTS`):
      - Description: List of transports supported by the server.
      - Default: `["unix", "tcp"]`
      - Type: `list_str`
      - Valid Values: `["unix"]`, `["tcp"]`, `["unix", "tcp"]`, `["tcp", "unix"]`

- [✓] Done - Test environment variable precedence - Note: Programmatic `configure()` calls correctly override values previously loaded from files (which set env vars). Direct environment variable overrides work when using canonical `PLUGIN_` names; file loading sets these env vars, so the last source setting the specific `PLUGIN_` env var before `get_config()` takes effect. `PYVIDER_` prefixed aliases are primarily effective through `.env` file loading.
- [✓] Done - Type conversion for env vars (string → bool, int, float) - Note: Successfully tested string to bool (e.g., "false" -> False, "true" -> True), string "int" to float (e.g., "22" -> 22.0), and comma-separated string to list-of-strings (e.g., "tcp,unix" -> ["tcp", "unix"]) for `PLUGIN_` prefixed environment variables.
- [✓] Done - Validation of environment variable values - Note: Successfully tested that `ValueError` is raised for invalid values for timeout (not a float), log level (not in enum), and transport types (invalid item in list) when set via `PLUGIN_` prefixed environment variables.

#### Configuration Documentation
- [ ] Pending - Complete configuration reference
  - [ ] Pending - All options with descriptions
  - [ ] Pending - Default values and acceptable ranges
  - [ ] Pending - Examples for common scenarios
- [ ] Pending - Configuration file examples
  - [ ] Pending - Development configuration
  - [ ] Pending - Production configuration
  - [ ] Pending - Security-focused configuration

## 📊 HIGH PRIORITY - Recommended for v0.1.0

### 🚀 Performance Testing & Documentation

#### Benchmark Suite Implementation
- [~] Partially Met - Request/response throughput tests - Note: Achieved approx. 1209 req/s with EchoService on Unix socket using `benchmarks/benchmark_throughput.py`. Target: 50,000+ req/s. Further optimization and TCP tests pending.
  ```python
  async def test_throughput_unix_socket():
      # Measure requests per second over Unix socket
      # Target: 50,000+ req/s
  ```
- [ ] Pending - Connection establishment timing - Note: Test script `benchmark_connection_speed.py` was developed but encountered timeouts during execution attempts. Further investigation required.
  ```python
  async def test_connection_speed():
      # Time from client.connect() to ready state
      # Target: <100ms for Unix, <200ms for TCP
  ```
- [ ] Pending - Concurrent connection tests - Note: Test script `benchmark_concurrency.py` (targeting 150 concurrent clients) was developed but repeatedly timed out during execution. This suggests potential resource limitations or contention issues needing further investigation.
  ```python
  async def test_concurrent_connections():
      # Test multiple clients connecting simultaneously
      # Target: 100+ concurrent connections
  ```
- [ ] Pending - Memory usage profiling - Note: Test script `benchmark_memory.py` was not implemented due to time constraints and issues encountered with other benchmark scripts.
  ```python
  async def test_memory_usage():
      # Profile memory usage under load
      # Target: <10MB base memory per connection
  ```

#### Performance Documentation
- [ ] Pending - Performance characteristics table
  | Metric     | Unix Socket | TCP Socket      |
  |------------|-------------|-----------------|
  | Throughput | 50K+ req/s  | Network limited |
  | Latency    | <1ms        | <5ms local      |
  | Memory     | 5MB base    | 8MB base        |
- [ ] Pending - Scaling recommendations
  - [ ] Pending - Connection limits per process
  - [ ] Pending - Resource usage guidelines
- [ ] Pending - Optimization tips
- [ ] Pending - Performance comparison with alternatives
  - [ ] Pending - vs. direct gRPC
  - [ ] Pending - vs. go-plugin (if measurable)
  - [ ] Pending - vs. other Python RPC frameworks

#### Performance Regression Testing
- [ ] Pending - Add performance tests to CI
- [ ] Pending - Performance threshold validation
- [ ] Pending - Automated performance reporting

### 🛠️ Error Experience Enhancement

#### Error Message Improvements
- [ ] Pending - Standardize error message format
  ```python
  # Before: "Connection failed"
  # After: "Failed to connect to plugin server at unix:///tmp/plugin.sock: Connection refused.
  #        Ensure the plugin server is running and accessible."
  ```
- [ ] Pending - Add context and debugging information
  - [ ] Pending - Include relevant configuration values
  - [ ] Pending - Suggest common solutions
  - [ ] Pending - Provide troubleshooting steps
- [ ] Pending - User-friendly error categories
  - [ ] Pending - Connection errors with network troubleshooting
  - [ ] Pending - Authentication errors with certificate help
  - [ ] Pending - Configuration errors with validation guidance

#### Error Recovery Mechanisms
- [ ] Pending - Automatic retry for transient failures
  - [ ] Pending - Connection timeouts with exponential backoff
  - [ ] Pending - Handshake failures with retry
- [ ] Pending - Transport negotiation fallbacks
- [ ] Pending - Graceful degradation options
  - [ ] Pending - Fallback from Unix to TCP transport
  - [ ] Pending - Reduced security mode warnings
  - [ ] Pending - Alternative connection methods

#### Error Documentation
- [ ] Pending - Common error scenarios and solutions
- [ ] Pending - Troubleshooting guide
- [ ] Pending - Debug mode and logging configuration

### 📦 Packaging & Distribution

#### pyproject.toml Finalization
- [ ] Pending - Verify all dependencies
  - [ ] Pending - Core dependencies with minimum versions
  - [ ] Pending - Optional dependencies properly marked
  - [ ] Pending - Development dependencies in separate group
- [ ] Pending - Set appropriate version constraints
  - [ ] Pending - Compatible Python versions (>=3.13)
  - [ ] Pending - Library version ranges that work
  - [ ] Pending - Avoid over-constraining
- [ ] Pending - Package metadata completion
  - [ ] Pending - Description, keywords, classifiers
  - [ ] Pending - Homepage, repository, documentation URLs
  - [ ] Pending - Author and maintainer information
  - [ ] Pending - License specification

#### PyPI Preparation
- [ ] Pending - Build wheel distribution
  ```bash
  uv run hatch build
  # Verify wheel contents
  ```
- [ ] Pending - Test package installation
  ```bash
  # Test in clean environment
  uv run pip install dist/pyvider_rpcplugin-*.whl
  python -c "import pyvider.rpcplugin; print('Success')"
  ```
- [ ] Pending - Verify import structure
  ```python
  from pyvider.rpcplugin import (
      plugin_server, plugin_client, plugin_protocol,
      RPCPluginServer, RPCPluginClient, RPCPluginProtocol,
      configure, RPCPluginConfig
  )
  ```
- [ ] Pending - Test PyPI upload process (TestPyPI first)

## ✅ Quality Gates

### Pre-Release Validation
- [ ] Pending - Functional Testing
  - [ ] Pending - All unit tests pass (pytest tests/)
  - [ ] Pending - All integration tests pass
  - [✓] Done - All examples run successfully - Note: Python version confirmed as 3.13.5. All examples (01-10) run successfully after installing 'psutil' for '10_performance_tuning.py'. The '01_quick_start.py' client component logs an expected TransportError due to `dummy_server.sh` not creating a real socket, then proceeds with simulated calls, which is acceptable for its purpose. No script crashed the execution loop.
  - [✓] Done - Configuration loading works in all formats - Note: JSON, YAML, and .env file loading tested successfully. Environment variables (using `PLUGIN_` prefixes) also load and convert types correctly. Validation for malformed files, incorrect types, and out-of-range values via environment variables behaves as expected, raising ValueErrors. Default fallbacks are correctly applied. Programmatic configuration via `configure()` also tested.
  - [ ] Pending - Error handling behaves as documented
- [ ] Pending - Performance Validation
  - [ ] Pending - Benchmark tests meet performance targets - Note: Throughput test partially completed (1209 req/s vs 50K+ target). Other benchmark tests (connection speed, concurrency) timed out and require further investigation.
  - [ ] Pending - Memory usage within acceptable limits - Note: Memory benchmark not yet executed.
  - [ ] Pending - No performance regressions detected - Note: Baseline performance data partially collected for throughput. Other benchmarks pending.
- [ ] Pending - Documentation Quality
  - [ ] Pending - README.md is complete and accurate
  - [ ] Pending - All examples are tested and working
  - [ ] Pending - API documentation matches implementation
  - [ ] Pending - Configuration documentation is complete
- [ ] Pending - Package Quality
  - [ ] Pending - Package builds without errors
  - [ ] Pending - Package installs in clean environment
  - [ ] Pending - All imports work correctly
  - [ ] Pending - Version metadata is correct

### Release Criteria
- [ ] Pending - All CRITICAL tasks completed
- [ ] Pending - All Quality Gates passed
- [ ] Pending - Documentation reviewed for accuracy
- [ ] Pending - Examples tested by independent reviewer
- [ ] Pending - Performance benchmarks documented

## 📅 Timeline & Milestones
- [ ] Pending - Week 1: Documentation Sprint
  - [ ] Pending - Day 1-2: README.md creation and examples
  - [ ] Pending - Day 3-4: API documentation
  - [ ] Pending - Day 5: Configuration system testing
- [ ] Pending - Week 2: Performance & Polish
  - [ ] Pending - Day 1-2: Performance benchmarking
  - [ ] Pending - Day 3-4: Error message improvements
  - [ ] Pending - Day 5: Package preparation
- [ ] Pending - Week 3: Final Validation
  - [ ] Pending - Day 1-2: End-to-end testing
  - [ ] Pending - Day 3: Independent review
  - [ ] Pending - Day 4: Final adjustments
  - [ ] Pending - Day 5: Release preparation
- [ ] Pending - Release Day
  - [ ] Pending - Final quality gate validation
  - [ ] Pending - Version tagging and changelog
  - [ ] Pending - PyPI upload
  - [ ] Pending - Release announcement

## 🎯 Success Metrics
- [ ] Pending - Release Goals
  - [ ] Pending - Documentation Completeness: README + examples + API docs
  - [ ] Pending - User Experience: 5-minute quick start working
  - [ ] Pending - Performance: Benchmarks documented and validated
  - [ ] Pending - Quality: Zero critical bugs, comprehensive error handling
  - [ ] Pending - Adoption Readiness: Easy installation and immediate value
- [ ] Pending - Post-Release Monitoring
  - [ ] Pending - Installation success rate (PyPI download metrics)
  - [ ] Pending - Documentation usage (which sections are most accessed)
  - [ ] Pending - Issue reports (common problems and user pain points)
  - [ ] Pending - Community feedback (GitHub issues, discussions)

This checklist will be updated as tasks are completed and new requirements are identified.
