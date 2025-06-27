# Refactoring TODO List

This checklist tracks the refactoring tasks identified in `docs/REFACTOR.md`.

## Tasks

- [x] **Remove `main` function from `rate_limiter.py`**
    - **File:** `src/pyvider/rpcplugin/rate_limiter.py`
    - **Action:** Delete the `main()` function.
    - **Action:** Delete the `if __name__ == "__main__":` block that calls `main()`.
    - **Reason:** Unused example/test code within the library module.
    - **Status:** Completed.

- [x] **Remove `parse_and_validate_handshake` function from `handshake.py`**
    - **File:** `src/pyvider/rpcplugin/handshake.py`
    - **Action:** Delete the `parse_and_validate_handshake()` function.
    - **Reason:** Unused function. Its functionality is covered by `parse_handshake_response()`, and it is not used by the library, examples, or tests.
    - **Status:** Completed.

## Minor Observations (For Future Consideration)

These items are noted in `docs/REFACTOR.md` but do not require immediate action as part of the current refactoring pass unless specified.

- [ ] **Evaluate refactoring client retry logic:**
    - **File:** `src/pyvider/rpcplugin/client/base.py` (method `_connect_and_handshake_with_retry`)
    - **Consideration:** Potentially refactor into a more generic, reusable utility if similar retry patterns are needed elsewhere.

- [ ] **Review configuration getters:**
    - **File:** `src/pyvider/rpcplugin/config.py` (class `RPCPluginConfig`)
    - **Consideration:** Numerous simple getter methods; evaluate if a different configuration access pattern is desired in the future.

- [ ] **Consolidate certificate creation helpers (minor):**
    - **File:** `src/pyvider/rpcplugin/crypto/certificate.py` (methods `create_ca`, `create_signed_certificate`, `create_self_signed_server_cert`)
    - **Consideration:** Minor opportunities for consolidating common setup steps if desired.
