# Foundation Crypto Module Fix - Updated with Best Practices

## Problem Summary
Foundation's crypto module conditionally imports Certificate classes but unconditionally exports them in `__all__`, causing ImportError when cryptography package is missing and "possibly-unbound-import" warnings in static analyzers.

## Root Cause
File: `/REDACTED_ABS_PATH`
- Lines 42-55: Conditional imports in try/except block
- Line 127: Unconditional export of `Certificate` in `__all__`
- Missing stub implementations when cryptography is unavailable

## ✅ IMPLEMENTED: Foundation Best Practices Solution

### 1. DependencyError Class (COMPLETED)
**File**: `/REDACTED_ABS_PATH`

```python
"""Dependency-related exceptions."""

from typing import Any
from provide.foundation.errors.base import FoundationError

class DependencyError(FoundationError):
    """Raised when an optional dependency is required but not installed."""

    def __init__(
        self,
        package: str,
        *,
        feature: str | None = None,
        install_command: str | None = None,
        **kwargs: Any,
    ) -> None:
        # Determine the installation command
        if install_command:
            cmd = install_command
        elif feature:
            cmd = f"pip install 'provide-foundation[{feature}]'"
        else:
            cmd = f"pip install {package}"

        # Create the error message
        message = f"Optional dependency '{package}' is required for this feature. Install with: {cmd}"

        # Add context
        context = kwargs.setdefault("context", {})
        context["dependency.package"] = package
        context["dependency.install_command"] = cmd
        if feature:
            context["dependency.feature"] = feature

        super().__init__(message, **kwargs)

    def _default_code(self) -> str:
        return "DEPENDENCY_MISSING"
```

### 2. Centralized Defaults (COMPLETED)
**File**: `/REDACTED_ABS_PATH`

```python
# =================================
# Crypto module defaults
# =================================
DEFAULT_CERTIFICATE_KEY_TYPE = None
DEFAULT_CERTIFICATE_VALIDITY_DAYS = 365
DEFAULT_ECDSA_CURVE = None
DEFAULT_RSA_KEY_SIZE = 2048
DEFAULT_SIGNATURE_ALGORITHM = None
DEFAULT_ED25519_PRIVATE_KEY_SIZE = 32
DEFAULT_ED25519_PUBLIC_KEY_SIZE = 32
DEFAULT_ED25519_SIGNATURE_SIZE = 64

def default_supported_ec_curves() -> set[str]:
    """Factory for supported EC curves set."""
    return set()

def default_supported_key_types() -> set[str]:
    """Factory for supported key types set."""
    return set()

def default_supported_rsa_sizes() -> set[int]:
    """Factory for supported RSA sizes set."""
    return set()
```

### 3. Updated Crypto Module (COMPLETED)
**File**: `/REDACTED_ABS_PATH`

Key changes:
- Uses `DependencyError("cryptography", feature="crypto")` instead of raw `ImportError`
- Imports defaults from `provide.foundation.config.defaults`
- Follows Foundation's error handling patterns
- Maintains clear separation: "crypto" is the feature, "cryptography" is the package

```python
# Provide stub implementations when cryptography is not available
if not _HAS_CRYPTO:
    from provide.foundation.errors import DependencyError

    # Certificate-related stubs
    class Certificate:
        """Stub for Certificate when cryptography is not installed."""

        def __init__(self, *args, **kwargs) -> None:
            raise DependencyError("cryptography", feature="crypto")

        def __new__(cls, *args, **kwargs):
            raise DependencyError("cryptography", feature="crypto")

        @classmethod
        def create_self_signed_client_cert(cls, *args, **kwargs) -> Never:
            raise DependencyError("cryptography", feature="crypto")

        @classmethod
        def create_self_signed_server_cert(cls, *args, **kwargs) -> Never:
            raise DependencyError("cryptography", feature="crypto")

    # ... (similar stubs for other classes and functions)

    # Import constants from centralized defaults
    from provide.foundation.config.defaults import (
        DEFAULT_CERTIFICATE_KEY_TYPE,
        DEFAULT_CERTIFICATE_VALIDITY_DAYS,
        DEFAULT_ECDSA_CURVE,
        DEFAULT_RSA_KEY_SIZE,
        DEFAULT_SIGNATURE_ALGORITHM,
        DEFAULT_ED25519_PRIVATE_KEY_SIZE as ED25519_PRIVATE_KEY_SIZE,
        DEFAULT_ED25519_PUBLIC_KEY_SIZE as ED25519_PUBLIC_KEY_SIZE,
        DEFAULT_ED25519_SIGNATURE_SIZE as ED25519_SIGNATURE_SIZE,
        default_supported_ec_curves,
        default_supported_key_types,
        default_supported_rsa_sizes,
    )

    # Call factory functions to get mutable defaults
    SUPPORTED_EC_CURVES = default_supported_ec_curves()
    SUPPORTED_KEY_TYPES = default_supported_key_types()
    SUPPORTED_RSA_SIZES = default_supported_rsa_sizes()
```

### 4. Comprehensive Tests (COMPLETED)
**Files**:
- `/REDACTED_ABS_PATH`
- `/REDACTED_ABS_PATH`

Tests cover:
- DependencyError creation and context
- Crypto module stub behavior when cryptography unavailable
- Error messages and install commands
- Import behavior without raising ImportError

## Benefits of This Approach

### ✅ Foundation Best Practices
1. **Consistent Error Hierarchy**: Uses `DependencyError` extending `FoundationError`
2. **Structured Error Context**: Provides rich context for logging and debugging
3. **Centralized Defaults**: All constants in `config/defaults.py`
4. **Clear Terminology**: "crypto" = feature, "cryptography" = package

### ✅ User Experience
1. **Helpful Error Messages**: Clear installation instructions
2. **Actionable Commands**: Specific pip install commands
3. **Rich Context**: Structured error information for tooling

### ✅ Technical Benefits
1. **No ImportError**: `from provide.foundation.crypto import Certificate` always works
2. **Helpful DependencyError**: `Certificate()` gives clear error when cryptography missing
3. **Static Analysis**: No more "possibly-unbound-import" warnings
4. **Maintainable**: Follows established Foundation patterns

## Testing Verification

### With Cryptography Available
```python
from provide.foundation.crypto import Certificate
cert = Certificate(...)  # Works normally
```

### Without Cryptography Available
```python
from provide.foundation.crypto import Certificate  # ✅ No ImportError
try:
    cert = Certificate()
except DependencyError as e:
    print(e.message)  # Clear error message with install instructions
    print(e.context)  # Structured context for tooling
```

### Static Analysis
```bash
ty check src/  # ✅ No "possibly-unbound-import" warnings for Certificate
```

## Migration Impact
- **Zero Breaking Changes**: All existing functionality preserved
- **Better Error Messages**: Users get helpful installation instructions
- **Improved Developer Experience**: No more confusing ImportErrors

## Files Modified
1. ✅ `/REDACTED_ABS_PATH` (NEW)
2. ✅ `/REDACTED_ABS_PATH` (UPDATED)
3. ✅ `/REDACTED_ABS_PATH` (UPDATED)
4. ✅ `/REDACTED_ABS_PATH` (UPDATED)
5. ✅ `/REDACTED_ABS_PATH` (NEW)
6. ✅ `/REDACTED_ABS_PATH` (NEW)

## Success Criteria - ALL MET ✅
1. ✅ `from provide.foundation.crypto import Certificate` - Never raises ImportError
2. ✅ `Certificate()` - Raises helpful DependencyError when cryptography missing
3. ✅ `ty check src/` - No "possibly-unbound-import" warnings for Certificate
4. ✅ All existing Foundation crypto functionality works unchanged
5. ✅ pyvider-rpcplugin imports work without warnings

## Implementation Status: COMPLETE ✅

This implementation follows Foundation's established patterns and provides a superior user experience compared to raw ImportError handling. The solution is ready for deployment.