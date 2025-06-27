# Refactoring Candidates for Pyvider RPCPlugin

This document outlines potential areas for refactoring within the `pyvider.rpcplugin` codebase, focusing on duplicate or unused logic.

## 1. Unused Functions

The following functions appear to be unused across the main `src/`, `tests/`, and `examples/` directories.

*   **Function:** `main`
    *   **File:** `src/pyvider/rpcplugin/rate_limiter.py`
    *   **Description:** This function seems to be an example usage or test stub within the `rate_limiter.py` module itself. It's not called by any other part of the library, tests, or examples.
    *   **Recommendation:** Remove this function to clean up the module.

*   **Function:** `display_cert_details`
    *   **File:** `src/pyvider/rpcplugin/crypto/debug.py`
    *   **Description:** A debugging utility to print details of an X.509 certificate. It is not used in the main codebase, tests, or examples.
    *   **Recommendation:** Remove if it's a leftover developer utility and not intended for broader use or future debugging sessions.

*   **Function:** `display_key_details`
    *   **File:** `src/pyvider/rpcplugin/crypto/debug.py`
    *   **Description:** A debugging utility to print details of a private key. Similar to `display_cert_details`, it's not used elsewhere.
    *   **Recommendation:** Remove if it's a leftover developer utility.

## 2. Test-Only Functions / Potential Redundancy

The following function is currently only used within the test suite.

*   **Function:** `parse_and_validate_handshake`
    *   **File:** `src/pyvider/rpcplugin/handshake.py`
    *   **Used in:** `tests/handshake/test_handshake_process_io.py`
    *   **Description:** This function parses and validates a plugin handshake string. Its functionality is very similar to `parse_handshake_response` found in the same `handshake.py` file, which is used by `RPCPluginClient`.
    *   **Recommendation:**
        *   Evaluate if `parse_and_validate_handshake` provides any unique validation logic not present in `parse_handshake_response` that is critical for tests.
        *   If its logic is entirely redundant or can be covered by tests for `parse_handshake_response`, consider removing `parse_and_validate_handshake` and adapting tests to use `parse_handshake_response` directly or with test-specific helpers. This would reduce code duplication.
    *   **Potential Duplicate Code Snippets:**
        *   Both functions involve:
            *   Splitting the handshake string by `|`.
            *   Checking for the correct number of parts (6).
            *   Converting version parts to integers.
            *   Validating network type (`tcp` or `unix`).
            *   Validating the protocol part (e.g., `grpc`).
            *   Extracting and processing the server certificate string.

        **`parse_handshake_response` (used in client):**
        ```python
        # Snippet from parse_handshake_response
        parts = response.strip().split("|")
        if not is_valid_handshake_parts(parts):
            # ... error handling ...
            raise HandshakeError(...)
        try:
            core_version = int(parts[0])
            plugin_version = int(parts[1])
        except ValueError as e_ver:
            raise HandshakeError(...) from e_ver
        # ... further parsing and validation ...
        ```

        **`parse_and_validate_handshake` (test-only):**
        ```python
        # Snippet from parse_and_validate_handshake
        parts = handshake_line.strip().split("|")
        if len(parts) != 6:
            # ... error handling ...
            raise HandshakeError(...)
        try:
            core_version = int(parts[0])
            plugin_version = int(parts[1])
        except ValueError as e_ver:
            # ... error handling ...
            raise HandshakeError(...) from e_ver
        # ... further parsing and validation ...
        ```

## 3. Other Minor Observations (Not necessarily requiring immediate action)

*   **Client Retry Logic:** The `_connect_and_handshake_with_retry` method in `src/pyvider/rpcplugin/client/base.py` contains substantial retry logic. If similar retry patterns are needed elsewhere, consider refactoring it into a more generic, reusable utility.
*   **Configuration Getters:** The `RPCPluginConfig` class in `src/pyvider/rpcplugin/config.py` has numerous simple getter methods. This is a common pattern and generally acceptable, but worth noting if a different configuration access pattern is desired in the future.
*   **Certificate Creation Helpers:** In `src/pyvider/rpcplugin/crypto/certificate.py`, the class methods `create_ca`, `create_signed_certificate`, and `create_self_signed_server_cert` have some structural similarities. While they serve distinct purposes, there might be minor opportunities for consolidating common setup steps if desired.
*   **Transport `_handle_client` methods:** The `_handle_client` methods in `UnixSocketTransport` and `TCPSocketTransport` are for basic echo server functionality, likely for testing or initial transport development. They are not directly used by the main gRPC server logic but are part of the transport's standalone capability. They are distinct due to transport differences.
*   **Transport `_close_writer` methods:** Helper methods in `UnixSocketTransport` and `TCPSocketTransport` for closing stream writers. They are similar in purpose but adapted to specifics of each transport.

This analysis is based on the current state of the codebase. Further review and discussion would be beneficial before implementing any changes.
