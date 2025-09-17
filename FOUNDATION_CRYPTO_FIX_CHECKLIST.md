# Foundation Crypto Module Fix - Detailed Checklist

## Problem Summary
Foundation's crypto module conditionally imports Certificate classes but unconditionally exports them in `__all__`, causing ImportError when cryptography package is missing and "possibly-unbound-import" warnings in static analyzers.

## Root Cause
File: `/REDACTED_ABS_PATH`
- Lines 42-55: Conditional imports in try/except block
- Line 127: Unconditional export of `Certificate` in `__all__`
- Missing stub implementations when cryptography is unavailable

## Complete Fix Checklist

### 1. Pre-Implementation Analysis

#### 1.1 Verify Current Foundation Structure
- [ ] **File exists**: `/REDACTED_ABS_PATH`
- [ ] **Backup file**: `cp __init__.py __init__.py.backup`
- [ ] **Check current imports** (lines 42-55):
  ```python
  try:
      from provide.foundation.crypto.certificates import (
          Certificate,
          CertificateBase,
          CertificateConfig,
          CertificateError,
          CurveType,
          KeyType,
          create_ca,
          create_self_signed,
      )
      _HAS_CRYPTO = True
  except ImportError:
      _HAS_CRYPTO = False
  ```

#### 1.2 Identify All Crypto-Dependent Symbols
**Certificate Classes (lines 42-51):**
- [ ] `Certificate`
- [ ] `CertificateBase`
- [ ] `CertificateConfig`
- [ ] `CertificateError`
- [ ] `CurveType` (enum)
- [ ] `KeyType` (enum)
- [ ] `create_ca` (function)
- [ ] `create_self_signed` (function)

**Key Generation Functions (lines 88-94):**
- [ ] `generate_ec_keypair`
- [ ] `generate_key_pair`
- [ ] `generate_keypair`
- [ ] `generate_rsa_keypair`
- [ ] `generate_tls_keypair`

**Signature Functions (lines 95-100):**
- [ ] `generate_ed25519_keypair`
- [ ] `generate_signing_keypair`
- [ ] `sign_data`
- [ ] `verify_signature`

**Constants (lines 73-87):**
- [ ] `DEFAULT_CERTIFICATE_KEY_TYPE`
- [ ] `DEFAULT_CERTIFICATE_VALIDITY_DAYS`
- [ ] `DEFAULT_ECDSA_CURVE`
- [ ] `DEFAULT_RSA_KEY_SIZE`
- [ ] `DEFAULT_SIGNATURE_ALGORITHM`
- [ ] `ED25519_PRIVATE_KEY_SIZE`
- [ ] `ED25519_PUBLIC_KEY_SIZE`
- [ ] `ED25519_SIGNATURE_SIZE`
- [ ] `SUPPORTED_EC_CURVES`
- [ ] `SUPPORTED_KEY_TYPES`
- [ ] `SUPPORTED_RSA_SIZES`
- [ ] `get_default_hash_algorithm` (function)
- [ ] `get_default_signature_algorithm` (function)

#### 1.3 Check __all__ Exports (lines 108-165)
- [ ] **Verify `Certificate` in `__all__`** (line 127)
- [ ] **Verify other crypto symbols in `__all__`**:
  - Line 129: `CertificateBase`
  - Line 130: `CertificateConfig`
  - Line 131: `CertificateError`
  - Line 132: `CurveType`
  - Line 133: `KeyType`
  - Line 137: `create_ca`
  - Line 138: `create_self_signed`
  - And others...

### 2. Implementation Steps

#### 2.1 Create Error Message Constant
**Location**: After line 105, before the `__all__` definition
**Code to add**:
```python
# Provide stub implementations when cryptography is not available
if not _HAS_CRYPTO:
    # Define error message
    _CRYPTO_ERROR_MSG = (
        "This feature requires the 'cryptography' package. "
        "Install it with: pip install 'provide-foundation[crypto]' or pip install cryptography"
    )
```

#### 2.2 Create Certificate Class Stubs
**Location**: Continue after step 2.1
**Code to add**:
```python
    # Certificate-related stubs
    class Certificate:
        """Stub for Certificate when cryptography is not installed."""
        def __init__(self, *args, **kwargs):
            raise ImportError(_CRYPTO_ERROR_MSG)

        def __new__(cls, *args, **kwargs):
            raise ImportError(_CRYPTO_ERROR_MSG)

        @classmethod
        def create_self_signed_client_cert(cls, *args, **kwargs):
            raise ImportError(_CRYPTO_ERROR_MSG)

        @classmethod
        def create_self_signed_server_cert(cls, *args, **kwargs):
            raise ImportError(_CRYPTO_ERROR_MSG)

    class CertificateBase:
        """Stub for CertificateBase when cryptography is not installed."""
        def __init__(self, *args, **kwargs):
            raise ImportError(_CRYPTO_ERROR_MSG)

    class CertificateConfig:
        """Stub for CertificateConfig when cryptography is not installed."""
        def __init__(self, *args, **kwargs):
            raise ImportError(_CRYPTO_ERROR_MSG)

    class CertificateError(Exception):
        """Stub for CertificateError when cryptography is not installed."""
        pass  # Keep as regular exception for compatibility
```

#### 2.3 Create Enum Stubs
**Location**: Continue after step 2.2
**Code to add**:
```python
    # Enum stubs
    class CurveType:
        """Stub for CurveType when cryptography is not installed."""
        def __init__(self, *args, **kwargs):
            raise ImportError(_CRYPTO_ERROR_MSG)

    class KeyType:
        """Stub for KeyType when cryptography is not installed."""
        def __init__(self, *args, **kwargs):
            raise ImportError(_CRYPTO_ERROR_MSG)
```

#### 2.4 Create Certificate Function Stubs
**Location**: Continue after step 2.3
**Code to add**:
```python
    # Certificate function stubs
    def create_ca(*args, **kwargs):
        """Stub for create_ca when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)

    def create_self_signed(*args, **kwargs):
        """Stub for create_self_signed when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)
```

#### 2.5 Create Key Generation Function Stubs
**Location**: Continue after step 2.4
**Code to add**:
```python
    # Key generation function stubs
    def generate_ec_keypair(*args, **kwargs):
        """Stub for generate_ec_keypair when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)

    def generate_ed25519_keypair(*args, **kwargs):
        """Stub for generate_ed25519_keypair when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)

    def generate_key_pair(*args, **kwargs):
        """Stub for generate_key_pair when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)

    def generate_keypair(*args, **kwargs):
        """Stub for generate_keypair when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)

    def generate_rsa_keypair(*args, **kwargs):
        """Stub for generate_rsa_keypair when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)

    def generate_signing_keypair(*args, **kwargs):
        """Stub for generate_signing_keypair when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)

    def generate_tls_keypair(*args, **kwargs):
        """Stub for generate_tls_keypair when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)
```

#### 2.6 Create Signature Function Stubs
**Location**: Continue after step 2.5
**Code to add**:
```python
    # Signature function stubs
    def sign_data(*args, **kwargs):
        """Stub for sign_data when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)

    def verify_signature(*args, **kwargs):
        """Stub for verify_signature when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)
```

#### 2.7 Create Constant Stubs
**Location**: Continue after step 2.6
**Code to add**:
```python
    # Constant stubs (set to sensible defaults or None)
    DEFAULT_CERTIFICATE_KEY_TYPE = None
    DEFAULT_CERTIFICATE_VALIDITY_DAYS = 365
    DEFAULT_ECDSA_CURVE = None
    DEFAULT_RSA_KEY_SIZE = 2048
    DEFAULT_SIGNATURE_ALGORITHM = None
    ED25519_PRIVATE_KEY_SIZE = 32
    ED25519_PUBLIC_KEY_SIZE = 32
    ED25519_SIGNATURE_SIZE = 64
    SUPPORTED_EC_CURVES = []
    SUPPORTED_KEY_TYPES = []
    SUPPORTED_RSA_SIZES = []

    def get_default_hash_algorithm():
        """Stub for get_default_hash_algorithm when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)

    def get_default_signature_algorithm():
        """Stub for get_default_signature_algorithm when cryptography is not installed."""
        raise ImportError(_CRYPTO_ERROR_MSG)
```

### 3. Testing and Validation

#### 3.1 Test Without Cryptography Package
- [ ] **Create test environment**: `python -m venv test_env_no_crypto`
- [ ] **Activate environment**: `source test_env_no_crypto/bin/activate`
- [ ] **Install Foundation without crypto**: `pip install /path/to/foundation`
- [ ] **Test import succeeds**:
  ```python
  from provide.foundation.crypto import Certificate  # Should not raise ImportError
  ```
- [ ] **Test usage fails with helpful error**:
  ```python
  try:
      cert = Certificate()
  except ImportError as e:
      print(f"Expected error: {e}")  # Should show helpful message
  ```

#### 3.2 Test With Cryptography Package
- [ ] **Create test environment**: `python -m venv test_env_with_crypto`
- [ ] **Install cryptography**: `pip install cryptography`
- [ ] **Install Foundation**: `pip install /path/to/foundation`
- [ ] **Test normal operation**:
  ```python
  from provide.foundation.crypto import Certificate
  # Should work normally
  ```

#### 3.3 Test Static Analysis
- [ ] **Run ty check**: `ty check src/` on pyvider-rpcplugin
- [ ] **Verify no more "possibly-unbound-import" warnings** for Certificate
- [ ] **Run mypy**: `mypy src/`
- [ ] **Verify type checking passes**

#### 3.4 Test Integration
- [ ] **Test in pyvider-rpcplugin**:
  ```python
  from pyvider.rpcplugin.client.handshake import ClientHandshakeMixin
  # Should import without warnings
  ```

### 4. Documentation Updates

#### 4.1 Update Foundation Documentation
- [ ] **File**: Update Foundation's crypto module docstring
- [ ] **Add note** about cryptography dependency
- [ ] **Document error behavior** when cryptography is missing

#### 4.2 Update Foundation CHANGELOG
- [ ] **Add entry**: "Fixed: Certificate classes now provide helpful error messages when cryptography package is missing"
- [ ] **Note**: "Breaking change: None - all existing functionality preserved"

### 5. Final Verification Checklist

#### 5.1 Code Quality Checks
- [ ] **Run Foundation tests**: `pytest tests/crypto/`
- [ ] **All tests pass**: Verify no regressions
- [ ] **Linting**: `ruff check src/provide/foundation/crypto/`
- [ ] **Type checking**: `mypy src/provide/foundation/crypto/`

#### 5.2 Downstream Testing
- [ ] **Test pyvider-rpcplugin**: All imports work
- [ ] **Test other Foundation users**: Check any other packages using crypto
- [ ] **Verify ty warnings gone**: Run `ty check` on downstream packages

#### 5.3 Deployment Checklist
- [ ] **Version bump**: Update Foundation version
- [ ] **Release notes**: Document the fix
- [ ] **Publish**: Push to package registry
- [ ] **Update dependents**: Update pyvider-rpcplugin Foundation version

## Files Affected

### Primary File
- **File**: `/REDACTED_ABS_PATH`
- **Lines modified**: Insert after line 105 (before `__all__` definition)
- **Estimated additions**: ~80-100 lines of stub code

### Backup Files to Create
- [ ] `__init__.py.backup` - Original file backup
- [ ] `__init__.py.new` - New version for comparison

## Success Criteria

### ✅ When Complete, These Should All Pass:
1. `from provide.foundation.crypto import Certificate` - Never raises ImportError
2. `Certificate()` - Raises helpful ImportError when cryptography missing
3. `ty check src/` - No "possibly-unbound-import" warnings for Certificate
4. All existing Foundation crypto functionality works unchanged
5. pyvider-rpcplugin imports work without warnings

## Rollback Plan

### If Issues Arise:
1. **Restore backup**: `cp __init__.py.backup __init__.py`
2. **Test restoration**: Verify original behavior restored
3. **Investigate issue**: Check error logs and test failures
4. **Iterate fix**: Adjust stub implementation and retry

## Time Estimates

- **Analysis**: 30 minutes
- **Implementation**: 2 hours
- **Testing**: 1 hour
- **Documentation**: 30 minutes
- **Total**: ~4 hours

## Dependencies

- Access to Foundation repository
- Python virtual environments for testing
- pytest for testing
- ty/mypy for static analysis verification

---

**Note**: This checklist assumes the fix will be implemented in provide-foundation. Once completed, pyvider-rpcplugin will automatically benefit from the fix without any changes needed.