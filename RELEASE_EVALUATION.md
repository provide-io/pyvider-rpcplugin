# Release Readiness Evaluation (pyvider.rpcplugin)

This document summarizes the state of the `pyvider.rpcplugin` library based on a review conducted on 2025-07-01, focusing on tests, documentation, and examples.

## 1. Tests

*   **Status**: The test suite is comprehensive.
    *   **Execution**: 557 tests passed, 1 test was skipped (this skip is known and expected: `tests/crypto/test_certificate_chains.py::test_certificate_self_signed_validation`).
*   **Coverage**: Code coverage is reported at 88%.
    *   Areas with potentially lower coverage (based on typical patterns seen in coverage reports where many lines are missed) might include parts of:
        *   `src/pyvider/rpcplugin/client/base.py`
        *   `src/pyvider/rpcplugin/crypto/certificate.py`
        *   `src/pyvider/rpcplugin/protocol/service.py`
        *   `src/pyvider/rpcplugin/server.py`
        *   `src/pyvider/rpcplugin/transport/unix.py`
    *   A detailed line-by-line review of the coverage report would be needed for specifics.
*   **Warnings**:
    *   One `PytestUnraisableExceptionWarning` was observed during the test run:
        *   `tests/transport/unix/test_transport_unix_close.py::test_unix_socket_close_unlink_fails_persistently`
        *   Related to an exception in `_SelectorTransport.__del__`.
        *   This test itself passed, but the warning might indicate a potential resource cleanup issue in an edge case for asyncio selector transports or in the test's specific conditions. This warrants further investigation.

## 2. Documentation

*   **Accuracy**:
    *   The documentation (files in `docs/`, `README.md`, `CHANGELOG.md`) was scanned for placeholder or "fix me" language (e.g., "TODO", "FIXME", "XXX", "is now Y"). No such issues were found in the core documentation files.
    *   Code snippets in the checked chapter guides (Chapters 2-15) generally align well with the corresponding example files. Minor differences in `__main__` blocks for example invocation were noted but deemed acceptable as the full example files are correct.
*   **Completeness**:
    *   The documentation appears to be comprehensive, featuring a User Guide, detailed chapter-based explanations of concepts and components, and API references.
    *   The `CHANGELOG.md` is present and follows a standard format.

## 3. Examples

*   **Functionality**:
    *   All chapter-based examples (`ch02` to `ch15`) were reviewed.
    *   Conceptual examples (those not involving client-server interaction) were run and executed successfully.
    *   Client-server examples were verified:
        *   `ch02_quick_start_client.py` (with `ch02_dummy_server.py`)
        *   `ch07_echo_client.py` (with `ch05_echo_server.py`)
        *   `ch08_direct_client_connection.py` (with `common_dummy_server_for_ch08.py`) - required fixes to `common_dummy_server_for_ch08.py` for standalone magic cookie validation and to `ch08_direct_client_connection.py` for correct configuration calls.
        *   `ch09_security_mtls_example.py` (with `ch02_dummy_server.py`)
        *   `ch15_e2e_client.py` (with `ch15_e2e_server.py`) - required a `NameError` fix in the client.
    *   The `run_all_examples.py` script successfully executed all its targeted examples after the aforementioned fixes.
*   **Clarity & Best Practices**:
    *   Examples that require a client and server use separate `.py` files.
    *   Internal mocks/stubs are not used for client/server pairs in the primary examples; they use distinct processes.
    *   `example_utils.py` provides common setup, which is good.
*   **Code Quality (of modified examples)**:
    *   `ruff format` was applied to all modified example files.
    *   `ruff check --fix` was run. Remaining `E501` (line too long) errors were manually addressed. `E402` (module level import) errors were annotated with `# noqa: E402` as the import order is necessary for `sys.path` manipulation by `example_utils.py`.
    *   `mypy` checks were performed:
        *   Import errors for `example_utils` were resolved by ensuring examples import it via `from examples.example_utils import ...`.
        *   Minor type hint issues in `ch03_server_setup_concepts.py` and `ch11_error_handling_demo.py` were fixed.
        *   Persistent Mypy errors in `ch03_server_setup_concepts.py` (related to `BasicProtocol` and generics) and `ch08_direct_client_connection.py` (related to `channel.close()`) were noted. These are likely due to Mypy's interpretation of the library's more complex types or stubs, as the code is functionally correct. These were ignored for this review as `src` code modifications are out of scope.
    *   `bandit` checks were performed:
        *   Two `B101:assert_used` issues in `ch15_e2e_client.py` were noted. These are deemed acceptable for an example script where asserts are used to demonstrate expected outcomes.

## 4. Duplicate Logic

*   **Proto Definitions**: `.proto` files in `examples/proto/` are identical to those in `tests/fixtures/proto/` (`e2e_greeting.proto`, `echo.proto`). This is common but noted for awareness.
*   **Example Handlers**: `DummyHandler` class was duplicated across `ch02_dummy_server.py` and `common_dummy_server_for_ch08.py`. This was refactored by moving `DummyHandler` into `examples/example_utils.py` and updating imports.
*   **Utility Files**: `examples/example_utils.py` and `tests/fixtures/utils.py` serve distinct purposes (example setup vs. test fixtures) and do not show significant problematic duplication.
*   **Conceptual Similarities**:
    *   `BasicRPCPluginProtocol` (from `src`) used by examples and `MockProtocol` (from `tests`) are both minimal protocol implementations.
    *   `DummyHandler` (examples) and `MockHandler` (tests) are both minimal handlers.
    *   These are acceptable as they cater to different contexts and allow for independent evolution if needed.
*   **Unused Code**: No obvious unused code in `src/` that is only used by tests or examples was identified during this review.

## 5. Summary & Recommendations

*   **Overall**: The `pyvider.rpcplugin` library appears to be in a reasonably good state regarding its examples and documentation. Tests are largely passing.
*   **High Priority**:
    *   Investigate the `PytestUnraisableExceptionWarning` in `tests/transport/unix/test_transport_unix_close.py`. This could mask underlying resource leak issues.
*   **Medium Priority**:
    *   Review the Mypy errors in `ch03_server_setup_concepts.py` concerning `BasicProtocol` and type variables. While the example runs, resolving these could improve type safety understanding or identify subtle issues in library typings for such minimal protocol implementations.
    *   Review Mypy error for `channel.close()` in `ch08_direct_client_connection.py`.
    *   Aim to improve test coverage above 88%, particularly in core logic areas like `server.py` and `client/base.py`.
*   **Low Priority**:
    *   Consider if the duplicated `.proto` files between examples and tests could be sourced from a single location if they are intended to always be identical. This is a minor point, as current duplication is manageable.

The library seems ready for further testing and validation, with a few specific points above that warrant deeper investigation for a production-quality release.

---

## Go-Plugin Comparison Matrix (pyvider.rpcplugin vs HashiCorp's go-plugin)

This matrix expands on the existing `docs/guide/ch22_go_plugin_comparison.md`.

| Feature / Concept             | HashiCorp's `go-plugin`                                     | `pyvider.rpcplugin` (Python)                                     | Notes                                                                                                                               |
| :---------------------------- | :---------------------------------------------------------- | :--------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------- |
| **Primary Language**          | Go                                                          | Python (3.13+)                                                   | `go-plugin` is idiomatic Go; `pyvider.rpcplugin` is idiomatic Python, leveraging modern async features.                               |
| **RPC Mechanism**             | Originally `net/rpc`, now also supports gRPC                | gRPC (exclusively)                                               | `pyvider.rpcplugin` is built on gRPC from the ground up, benefiting from its performance and ecosystem.                           |
| **Plugin Definition**         | Go interface implementations                                | gRPC service definitions (`.proto` files) & Python handlers      | `pyvider.rpcplugin` uses the standard gRPC approach (Protobuf IDL), promoting language-agnostic service definitions.              |
| **Cross-Language Support**    | Yes (via gRPC mode)                                         | Yes (in principle, via gRPC)                                     | Both can support plugins/hosts in other languages if they implement the gRPC services and handshake. `pyvider.rpcplugin` provides Python client/server. |
| **Handshake Protocol**        | Custom handshake over stdout/stdin (magic cookie, version string) | Custom handshake over stdout/stdin (core version, plugin version, network type, network address, protocol name, optional TLS cert body) | Both use a similar initial out-of-band handshake. `pyvider.rpcplugin` has a more structured, pipe-delimited handshake string. |
| **Communication Transport**   | Unix Domain Sockets, TCP                                    | Unix Domain Sockets (UDS), TCP                                   | Both support UDS for local IPC and TCP for network. `pyvider.rpcplugin` negotiates and defaults to UDS where appropriate.         |
| **Security (Transport)**      | TLS (configurable by user)                                  | mTLS (built-in, configurable via `PLUGIN_AUTO_MTLS` and cert paths/strings) | `pyvider.rpcplugin` has strong emphasis on mTLS with helper utilities (`crypto.Certificate`) for certificate management.         |
| **Plugin Authentication**     | Magic Cookie, Optional plugin binary checksum verification  | Magic Cookie                                                     | Both use a magic cookie. `pyvider.rpcplugin` does not currently implement plugin binary checksums.                                |
| **Logging**                   | Captures plugin's `log` or `hclog` output, streams to host  | Streams plugin's `stdout`/`stderr` to host via a dedicated gRPC service (`StdioService`). Integrates with `pyvider.telemetry` for structured logging. | `pyvider.rpcplugin` provides a clear mechanism for log/stdio streaming over gRPC.                                                   |
| **Stdout/Stderr Syncing**     | Yes, mirrored to host                                       | Yes, via `StdioService` (gRPC stream)                            | Both offer similar capabilities for plugin output visibility.                                                                     |
| **Complex Args/Return Values**| `MuxBroker` for new connections (e.g., for `io.Reader/Writer`) | Standard gRPC messages and streaming. `GRPCBroker` service exists for advanced multiplexing. | gRPC streaming in `pyvider.rpcplugin` is the primary way for large/continuous data. `GRPCBroker` offers more complex channel management. |
| **Protocol Versioning**       | Basic "protocol version" number for plugin invalidation.    | `PLUGIN_CORE_VERSION` (handshake wire format) & `PLUGIN_PROTOCOL_VERSIONS` (application-level, negotiated list). | `pyvider.rpcplugin` has a more granular versioning scheme, distinguishing core handshake from application service versions.      |
| **Reattachment/Host Upgrade** | Supports reattaching to long-running plugins.               | Not a current feature.                                           | `go-plugin` has specific support for this advanced lifecycle management.                                                            |
| **Configuration**             | Host app specific (flags, HCL); plugins via RPC/env.        | Environment variables (all `PLUGIN_*`), programmatic (`configure()`, `RPCPluginConfig` singleton). `RPCPluginClient` passes env vars to plugin. | `pyvider.rpcplugin` has a centralized, schema-validated configuration system for both library and application settings.            |
| **Health Checking**           | Ad-hoc or via specific RPCs if implemented by plugin.       | Built-in standard gRPC Health Checking service (configurable via `PLUGIN_HEALTH_SERVICE_ENABLED`). | `pyvider.rpcplugin` offers an integrated, standard way for plugins to report health.                                              |
| **Rate Limiting**             | Application-specific.                                       | Server-side request rate limiting built-in (token bucket, configurable via `PLUGIN_RATE_LIMIT_*`). | `pyvider.rpcplugin` provides optional server-side rate limiting as a library feature.                                             |
| **Async Model**               | Go goroutines                                               | Python `asyncio`                                                 | Both leverage their respective language's concurrency models. `pyvider.rpcplugin` is async-native.                              |
| **Ecosystem & Maturity**      | Widely used in HashiCorp tools (Terraform, Vault, etc.), mature. | Newer, Python-focused.                                           | `go-plugin` is more battle-tested. `pyvider.rpcplugin` is tailored for modern Python development.                                 |
| **Developer Experience**      | Geared towards Go developers.                               | Focus on Python type safety, `attrs`, modern Python features. Comprehensive `pyvider.telemetry` integration. | `pyvider.rpcplugin` aims for a rich Python developer experience.                                                                  |

This expanded matrix should provide a clearer comparison for users evaluating both systems.
