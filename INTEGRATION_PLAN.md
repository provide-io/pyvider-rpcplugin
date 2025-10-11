# Integration Plan: pyvider-rpcplugin ↔ provide-foundation

## Progress Checklist

### Phase 1: High Priority Resilience & Instrumentation
- [x] Add @resilient decorator to handshake operations (handshake/core.py)
- [x] Add @retry decorator to gRPC channel creation (client/process.py)
- [x] Add timed_block instrumentation to server operations (server/core.py)
- [x] Add @resilient decorator to RPC shutdown handler (protocol/service.py)
- [ ] Run tests to verify all changes work correctly
- [ ] Final code quality check (ruff + mypy)

### Phase 2: Process Management (Future)
- [ ] Replace subprocess.Popen with ManagedProcess
- [ ] Switch to module-specific loggers (get_logger(__name__))

### Phase 3: Advanced Features (Future)
- [ ] Configuration refactoring with ConfigManager
- [ ] OpenTelemetry integration
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

## Notes

- All Phase 1 changes are backward compatible
- No changes to public APIs or configuration
- Preserves existing error types and messages
- Adds enhanced logging and resilience only
