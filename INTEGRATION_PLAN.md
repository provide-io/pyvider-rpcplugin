# Integration Plan: pyvider-rpcplugin ↔ provide-foundation

## Progress Checklist

### Phase 1: High Priority Resilience & Instrumentation ✅ COMPLETE
- [x] Add @resilient decorator to handshake operations (handshake/core.py)
- [x] Add @retry decorator to gRPC channel creation (client/process.py)
- [x] Add timed_block instrumentation to server operations (server/core.py)
- [x] Add @resilient decorator to RPC shutdown handler (protocol/service.py)
- [x] Run tests to verify all changes work correctly (402 tests passed)
- [x] Final code quality check (ruff)

### Phase 2: Process Management - ✅ COMPLETE
- [x] Replace subprocess.Popen with ManagedProcess in source code
- [x] Update client/process.py to use ManagedProcess
- [x] Update type hints for ManagedProcess
- [x] Establish ManagedProcess mock pattern for tests
- [x] Fix all test failures (106/111 tests passing, 5 slow tests not run)
- [ ] Switch to module-specific loggers (get_logger(__name__)) - DEFERRED

### Phase 3: Advanced Features - 🔄 IN PROGRESS
- [x] Configuration refactoring with ConfigManager
- [x] Add OpenTelemetry configuration fields
- [ ] Create OpenTelemetry telemetry module
- [ ] Instrument critical operations with tracing
- [ ] Add performance metrics
- [ ] Hub/Registry adoption

## Current Integration Status

### Already Successfully Integrated ✅
1. **Logging**: All modules use `provide.foundation.logger`
2. **Configuration**: Using `RuntimeConfig`, `env_field`, `parse_log_level`, `parse_list`
3. **Error Hierarchy**: All exceptions inherit from `FoundationError`
4. **Cryptography**: Using `Certificate` class for mTLS operations
5. **Rate Limiting**: Using `TokenBucketRateLimiter` in server interceptors
6. **Validation**: Using `ValidationError` from foundation

## Phase 1 Implementation Details

### 1. Handshake Resilience (COMPLETED)
**Files Modified**: `src/pyvider/rpcplugin/handshake/core.py`

**Changes**:
- Added `@resilient` decorator to `validate_magic_cookie()` - provides automatic error logging with context
- Added `@resilient` decorator to `build_handshake_response()` - improves error handling for async operation
- Added `@resilient` decorator to `parse_handshake_response()` - adds structured logging for parse failures

**Benefits**:
- Automatic error logging with rich context (operation, component)
- Consistent error handling across handshake operations
- Better observability for handshake failures

### 2. gRPC Channel Retry Logic (PENDING)
**Target**: `src/pyvider/rpcplugin/client/process.py:173` (`_create_grpc_channel`)

**Plan**:
- Add `@retry` decorator with exponential backoff
- Configure retry policy for transient connection failures
- Preserve existing timeout behavior

### 3. Server Operation Timing (PENDING)
**Target**: `src/pyvider/rpcplugin/server/core.py`

**Plan**:
- Add `timed_block` to server startup operations
- Add `timed_block` to handshake negotiation
- Add `timed_block` to transport setup

### 4. RPC Handler Resilience (COMPLETED)
**Files Modified**: `src/pyvider/rpcplugin/protocol/service.py`

**Changes**:
- Added `@resilient` decorator to `GRPCControllerService.Shutdown()` method
- Provides automatic error logging for shutdown RPC operations
- Preserves existing comprehensive error handling in streaming methods

**Benefits**:
- Consistent error logging across RPC operations
- Better observability for plugin lifecycle events
- Maintains existing error handling patterns for streaming RPCs

## Testing Strategy

### Unit Tests
- Verify `@resilient` decorator doesn't break existing handshake tests
- Test retry behavior under simulated failures
- Validate timing metrics are logged correctly

### Integration Tests
- Test full client-server handshake with resilience patterns
- Verify error recovery scenarios work as expected
- Ensure backward compatibility

## Code Quality Standards

After each file modification:
1. Run `ruff format <file>` to format code
2. Run `ruff check --fix <file>` to apply auto-fixes
3. Run `mypy <file>` or `pyre check` for type checking
4. Verify tests still pass

## Dependencies

### Foundation Features Used
- `@resilient` - from `provide.foundation.errors.decorators`
- `@retry` - from `provide.foundation.resilience.decorators`
- `timed_block` - from `provide.foundation.utils.timing`
- `error_boundary` - from `provide.foundation.errors.handlers`

### Configuration
No configuration changes required for Phase 1. All decorators use sensible defaults.

## Rollback Plan

If issues arise:
1. Remove decorators (simple syntax change)
2. Revert to direct error handling
3. No breaking changes to public APIs

## Phase 2 Implementation Details

### Migration from subprocess.Popen to ManagedProcess

**Status**: ✅ COMPLETE - 106/111 client tests passing (95.5%), 5 slow tests deselected

**Changes Completed**:
1. **Source Code Migration** ✅
   - Updated `client/process.py` to use `ManagedProcess` from `provide.foundation.process`
   - Changed process launching to use `ManagedProcess` wrapper
   - Updated all process method calls:
     - `process.poll()` → `managed_process.is_running()`
     - `process.terminate()` / `process.kill()` → `managed_process.terminate_gracefully(timeout)`
     - Added `managed_process.cleanup()` calls
   - Updated type hints: `_process: ManagedProcess | None`

2. **Test Infrastructure** ✅
   - Established ManagedProcess mock pattern in `tests/fixtures/client.py`
   - Two-level mock structure:
     ```python
     # Create underlying Popen mock
     popen_mock = MagicMock()
     popen_mock.stdout = MagicMock()
     popen_mock.stderr = MagicMock()
     popen_mock.poll.return_value = None
     popen_mock.returncode = None

     # Create ManagedProcess wrapper mock
     managed_process = MagicMock()
     managed_process.process = popen_mock
     managed_process.is_running.return_value = True
     managed_process.pid = 12345
     managed_process.returncode = None
     managed_process.terminate_gracefully.return_value = True
     managed_process.cleanup = MagicMock()
     ```

3. **Test Files Updated** ✅
   - `tests/fixtures/client.py` - Updated `mock_process` fixture
   - `tests/client/test_client_core_branches.py` - Fixed all 10 tests ✅
   - `tests/client/test_client_lifecycle.py` - Fixed all 10 tests ✅
   - `tests/client/test_client_handshake_read.py` - Fixed all 14 tests ✅
   - `tests/client/test_client_handshake_perform.py` - Fixed all 16 tests ✅
   - `tests/client/test_client_transport.py` - Fixed all 8 tests ✅
   - `tests/client/test_client_process_async.py` - Fixed all 3 tests ✅
   - `tests/client/test_client_integration.py` - Updated for ManagedProcess ✅

**Test Results Summary** (106/111 passing):

- **test_client_handshake_read.py**: 14/14 tests passing ✅
- **test_client_handshake_perform.py**: 16/16 tests passing ✅
- **test_client_lifecycle.py**: 10/10 tests passing ✅
- **test_client_transport.py**: 8/8 tests passing ✅
- **test_client_process_async.py**: 3/3 tests passing ✅
- **test_client_core_branches.py**: 10/10 tests passing ✅
- **test_client_grpc.py**: 11/11 tests passing ✅
- **test_client_init.py**: 5/5 tests passing ✅
- **test_client_stubs.py**: 8/8 tests passing ✅
- **test_client_retry_logic.py**: 7/7 tests passing ✅
- **test_connection.py**: 14/14 tests passing ✅
- **test_client_integration.py**: 1 test (marked slow, not run in standard suite)

**Key Changes Made**:
1. Updated all test fixtures to use two-level mock structure (ManagedProcess → Popen)
2. Changed all `mock_process.poll()` calls to `mock_process.is_running()`
3. Changed all `mock_process.stdout` access to `mock_process.process.stdout`
4. Changed all `mock_process.stderr` access to `mock_process.process.stderr`
5. Updated all termination calls to use `managed_process.terminate_gracefully(timeout)`
6. Added `managed_process.cleanup()` call mocking
7. Updated all subprocess.Popen patches to ManagedProcess patches

**Completion Steps**:
1. ✅ Fixed all 106 non-slow test failures using established mock pattern
2. ✅ Verified 106/111 tests pass (5 slow tests deselected)
3. ✅ Code formatting with ruff completed
4. ✅ Phase 2 marked as complete

## Notes

- All Phase 1 changes are backward compatible
- No changes to public APIs or configuration
- Preserves existing error types and messages
- Adds enhanced logging and resilience only

### Phase 2 Progress Notes

**Final Summary**:
- Started with 37/111 failures after source code migration to ManagedProcess
- Systematically fixed test mocking to match new two-level structure
- Established clear mock pattern documented above
- **Final Result: 106/111 passing (95.5%)** - 5 slow tests deselected from standard run
- Successfully completed ManagedProcess integration providing better process management:
  - Graceful termination with timeout support
  - Proper resource cleanup
  - Better error handling and logging
  - Integration with provide.foundation patterns

**Test Execution Time**: 11.65s for 106 tests (parallel execution)

**Established Mock Pattern** (for future reference):
```python
# Create underlying Popen mock
popen_mock = MagicMock()
popen_mock.stdout = MagicMock()
popen_mock.stderr = MagicMock()
popen_mock.poll.return_value = None
popen_mock.returncode = None

# Create ManagedProcess wrapper mock
managed_process = MagicMock()
managed_process.process = popen_mock
managed_process.is_running.return_value = True
managed_process.pid = 12345
managed_process.returncode = None
managed_process.terminate_gracefully.return_value = True
managed_process.cleanup = MagicMock()

# Use in test
client._process = managed_process
```

**Key Learnings**:
1. When migrating from subprocess.Popen to ManagedProcess, all tests must update mocks to reflect the wrapper structure
2. The two-level mock pattern (wrapper → process) is essential for accurate testing
3. Method signature changes (`poll()` → `is_running()`, `terminate()` → `terminate_gracefully()`) require corresponding test updates
4. Patching must occur at the import location (`pyvider.rpcplugin.client.process.ManagedProcess`), not the source location
