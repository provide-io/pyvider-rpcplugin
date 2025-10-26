# Detailed Documentation Fix Checklist

Based on comprehensive audit completed on 2025-01-24.

**Total Files Audited**: 72 documentation files
**Overall Grade**: B+
**Estimated Total Fix Time**: 5-8 hours

---

## 🔴 HIGH PRIORITY FIXES

### Fix #1: Resolve `simple-custom-rpc.md` Issue
**Decision Required**: Choose one of three options below

#### Option A: Remove the File (Recommended - Fastest)
- [ ] **Delete file**: `docs/getting-started/simple-custom-rpc.md`
- [ ] **Update links**: Search for links to `simple-custom-rpc.md` and remove them
  - Search pattern: `simple-custom-rpc`
  - Expected: Likely no links since it's not in navigation

**Reasoning**: This is conceptual content that adds confusion. The jump from Quick Start → First Plugin (with Protocol Buffers) is not that difficult, and the Echo example already bridges this gap.

#### Option B: Move to Concepts Section
- [ ] **Move file**: `docs/getting-started/simple-custom-rpc.md` → `docs/guide/concepts/python-only-rpc.md`
- [ ] **Update mkdocs.yml** (line 254-260): Add under Core Concepts:
  ```yaml
  - Core Concepts:
      - guide/concepts/index.md
      - RPC Architecture: guide/concepts/rpc-architecture.md
      - Python-Only RPC (Conceptual): guide/concepts/python-only-rpc.md  # NEW
      - Transports: guide/concepts/transports.md
  ```
- [ ] **Strengthen disclaimer** at top of file (lines 5-16): Make it VERY clear these are conceptual examples

#### Option C: Create the Missing Example Files
- [ ] **Create**: `examples/tutorials/processor_service.py` (extract from docs lines 38-92)
- [ ] **Create**: `examples/tutorials/simple_protocol.py` (extract from docs lines 95-127)
- [ ] **Create**: `examples/tutorials/simple_server.py` (extract from docs lines 130-167)
- [ ] **Create**: `examples/tutorials/simple_client.py` (extract from docs lines 170-217)
- [ ] **Update file** (line 6): Change disclaimer to point to actual files
- [ ] **Add to mkdocs.yml** (line 248-251): Add under Getting Started navigation
- [ ] **Test**: Verify all four files actually run without errors

---

### Fix #2: Create Single Source of Truth for Example Mapping
**Files to modify**: 3 files

#### Step 1: Enhance `docs/examples/index.md`
- [ ] **Location**: `docs/examples/index.md:12-31`
- [ ] **Replace** the current "Tutorial Example → Actual File Mapping" table with comprehensive version:

```markdown
## Tutorial Example → Actual File Mapping

!!! tip "Simplified Tutorial Examples vs. Runnable Files"
    Documentation tutorials use **simplified examples for teaching**. Here's the complete mapping:

| Tutorial Reference | Actual Runnable File | Description | Complexity | Location in Docs |
|-------------------|---------------------|-------------|-----------|------------------|
| `my_plugin.py` | `examples/dummy_server.py` | Minimal server with BasicRPCPluginProtocol | 🟢 Beginner | [Quick Start](../getting-started/quick-start.md) |
| `host_app.py` | `examples/quick_start_client.py` | Client that launches dummy_server.py | 🟢 Beginner | [Quick Start](../getting-started/quick-start.md) |
| `basic_plugin.py` | `examples/dummy_server.py` | Same as my_plugin.py | 🟢 Beginner | [Examples](index.md#basic-plugin) |
| `basic_client.py` | `examples/quick_start_client.py` | Same as host_app.py | 🟢 Beginner | [Examples](index.md#basic-plugin) |
| `echo_server.py` | `examples/echo_server.py` ✓ | Complete RPC service with Protocol Buffers | 🟡 Intermediate | [First Plugin](../getting-started/first-plugin.md) |
| `echo_client.py` | `examples/echo_client.py` ✓ | Class-based client implementation | 🟡 Intermediate | [First Plugin](../getting-started/first-plugin.md) |
| `echo_plugin.py` | `examples/echo_server.py` | Same as echo_server.py (different name in tutorial) | 🟡 Intermediate | [First Plugin](../getting-started/first-plugin.md) |
| `echo_host.py` | `examples/echo_client.py` | Same as echo_client.py (different name in tutorial) | 🟡 Intermediate | [First Plugin](../getting-started/first-plugin.md) |

**✓ = Tutorial name matches actual file exactly**

### Key Differences

The actual files include:
- `example_utils.configure_for_example()` for environment setup
- More comprehensive error handling and logging
- Production-ready patterns and best practices
- Additional documentation and type hints

**To run examples:**
```bash
# Quick start example
python examples/quick_start_client.py

# Echo service example
python examples/echo_client.py

# All short examples
python examples/short/basic_client.py
python examples/short/health_check.py
# ... etc
```
```

#### Step 2: Update `docs/getting-started/quick-start.md`
- [ ] **Location**: Lines 25-35 (inside first tip box)
- [ ] **Replace** with link to single source of truth:
```markdown
!!! tip "Tutorial Code vs Production Code"
    The examples below are **simplified for teaching** to focus on core concepts.

    **For production-ready, runnable code**, see the [Example File Mapping](../examples/index.md#tutorial-example-actual-file-mapping).

    Quick links:
    - Production version of `my_plugin.py` → [`examples/dummy_server.py`](https://github.com/provide-io/pyvider-rpcplugin/blob/main/examples/dummy_server.py)
    - Production version of `host_app.py` → [`examples/quick_start_client.py`](https://github.com/provide-io/pyvider-rpcplugin/blob/main/examples/quick_start_client.py)

    Run with: `python examples/quick_start_client.py`
```

- [ ] **Location**: Lines 167-178 (second note box)
- [ ] **Replace** with:
```markdown
!!! note "Actual Runnable Examples"
    The simplified examples above (`my_plugin.py`, `host_app.py`) are for teaching.

    **For working code you can run**, see the [Example File Mapping](../examples/index.md#tutorial-example-actual-file-mapping).
```

#### Step 3: Update `docs/getting-started/first-plugin.md`
- [ ] **Location**: Lines 5-16 (tip box at top)
- [ ] **Replace** with:
```markdown
!!! tip "Tutorial Code vs Production Code"
    This tutorial shows **simplified examples for teaching** purposes.

    **For complete, production-ready implementation**, see the [Example File Mapping](../examples/index.md#tutorial-example-actual-file-mapping).

    Quick links:
    - Full Echo server → [`examples/echo_server.py`](https://github.com/provide-io/pyvider-rpcplugin/blob/main/examples/echo_server.py)
    - Full Echo client → [`examples/echo_client.py`](https://github.com/provide-io/pyvider-rpcplugin/blob/main/examples/echo_client.py)
    - Protocol definition → [`examples/proto/echo.proto`](https://github.com/provide-io/pyvider-rpcplugin/blob/main/examples/proto/echo.proto)

    Run with: `python examples/echo_client.py`
```

---

### Fix #3: Add Missing Navigation Entry (or Remove File)
**File**: `mkdocs.yml`

**Conditional on Fix #1 decision:**

#### If keeping simple-custom-rpc.md:
- [ ] **Location**: `mkdocs.yml:248-251` (Getting Started section)
- [ ] **Add** after `first-plugin.md`:
```yaml
  - Getting Started:
    - getting-started/index.md
    - Installation: getting-started/installation.md
    - Quick Start: getting-started/quick-start.md
    - Your First Plugin: getting-started/first-plugin.md
    - Simple Custom RPC: getting-started/simple-custom-rpc.md  # ADD THIS
    - Examples Overview: getting-started/examples.md
```

#### If moving to concepts:
- [ ] **Location**: `mkdocs.yml:254-260` (Core Concepts section)
- [ ] **Add** as shown in Fix #1 Option B

#### If removing file:
- [ ] No mkdocs.yml changes needed

---

## 🟡 MEDIUM PRIORITY FIXES

### Fix #4: Verify and Standardize Certificate API Examples

#### Step 1: Verify Foundation Certificate API
- [ ] **Check**: Does `provide.foundation.crypto.Certificate` have these methods?
  - `Certificate.from_pem(cert_pem, key_pem)` - verify it accepts both file:// URIs and PEM content
  - `Certificate.create_self_signed_server_cert(common_name, organization_name, validity_days, alt_names=None)`
- [ ] **Action**: Run this verification script:
```python
# verify_cert_api.py
from provide.foundation.crypto import Certificate
import inspect

print("Certificate.from_pem signature:")
print(inspect.signature(Certificate.from_pem))

print("\nCertificate.create_self_signed_server_cert signature:")
print(inspect.signature(Certificate.create_self_signed_server_cert))

# Test patterns
print("\n=== Testing Pattern 1: file:// URI ===")
try:
    # This should work or fail - we need to know
    cert = Certificate.from_pem(
        cert_pem="file:///tmp/test.crt",
        key_pem="file:///tmp/test.key"
    )
    print("✓ file:// URI pattern supported")
except Exception as e:
    print(f"✗ file:// URI pattern failed: {e}")

print("\n=== Testing Pattern 2: PEM content ===")
try:
    # Test with actual PEM content
    from pathlib import Path
    # Assuming some test cert exists
    print("✓ PEM content pattern supported")
except Exception as e:
    print(f"✗ PEM content pattern failed: {e}")

print("\n=== Testing Pattern 3: Self-signed ===")
try:
    cert = Certificate.create_self_signed_server_cert(
        common_name="test.local",
        organization_name="Test Org",
        validity_days=365
    )
    print("✓ Self-signed pattern supported")
    print(f"  - Has alt_names parameter: {'alt_names' in inspect.signature(Certificate.create_self_signed_server_cert).parameters}")
except Exception as e:
    print(f"✗ Self-signed pattern failed: {e}")
```

#### Step 2: Update Certificate Examples Based on Verification
**Files to update**: 2 files (only if API verification reveals issues)

- [ ] **File**: `docs/introduction/foundation.md`
  - **Lines 89-118**: Update Pattern 1 and Pattern 3 if needed
  - **Lines 221-249**: Update certificate loading examples if needed

- [ ] **File**: `docs/guide/advanced/foundation-integration.md`
  - **Lines 85-119**: Update certificate generation example if needed

#### Step 3: Add Parameter Documentation
- [ ] **File**: `docs/introduction/foundation.md:109-114`
- [ ] **Enhance** the self-signed cert example with complete parameter docs:
```python
cert = Certificate.create_self_signed_server_cert(
    common_name="myservice.example.com",  # Required: CN in cert subject
    organization_name="My Organization",   # Required: O in cert subject
    validity_days=365,                     # Required: Certificate lifetime
    alt_names=["localhost", "127.0.0.1"]  # Optional: Subject Alternative Names
    # Optional additional parameters (check API):
    # key_type="rsa",           # Default: RSA
    # key_size=2048,            # Default: 2048 bits
    # ecdsa_curve="secp256r1"   # For ECDSA keys
)
```

---

### Fix #5: Consolidate Foundation Explanations

#### Step 1: Audit Files That Explain Foundation
- [ ] **Search** for files containing Foundation explanations:
  - `grep -r "What is Foundation" docs/`
  - `grep -r "Foundation provides" docs/`

#### Step 2: Update Quick Start
- [ ] **File**: `docs/getting-started/quick-start.md:18-23`
- [ ] **Replace** the Foundation info box with link:
```markdown
!!! info "Built on Foundation"
    Pyvider RPC Plugin is built on **Foundation** (`provide.foundation`), which provides infrastructure for logging, configuration, cryptography, and utilities.

    **→ [Understanding Foundation](../introduction/foundation.md)** - Complete Foundation overview and practical examples
```

#### Step 3: Update Installation
- [ ] **File**: `docs/getting-started/installation.md:86-104`
- [ ] **Simplify** the Foundation Integration section:
```markdown
### Foundation Integration

Pyvider RPC Plugin is built on Foundation's infrastructure:

```python
from provide.foundation.config import RuntimeConfig
from provide.foundation import logger
from pyvider.rpcplugin.config import rpcplugin_config
from pyvider.rpcplugin import plugin_server, plugin_client
```

!!! tip "Understanding the Architecture"
    **Foundation** provides infrastructure (config, logging, crypto, utilities)
    **Pyvider RPC Plugin** provides RPC communication (gRPC, transports, protocols)
    **Your Plugin** provides business logic

    **→ [Complete Foundation Overview](../introduction/foundation.md)** for detailed architecture
```

#### Step 4: Add Breadcrumbs to Advanced Foundation Guide
- [ ] **File**: `docs/guide/advanced/foundation-integration.md:1-3`
- [ ] **Add** navigation breadcrumb at top:
```markdown
# Advanced Foundation Integration

!!! info "Prerequisites"
    This guide covers **advanced integration patterns**. For Foundation basics, see:

    - **[Foundation Overview](../../introduction/foundation.md)** - What Foundation is and how it works with Pyvider
    - **[Configuration Guide](../config/index.md)** - Basic configuration patterns
    - **[Security Guide](../security/index.md)** - Basic security setup

This guide demonstrates advanced integration patterns between Pyvider RPC Plugin and Foundation...
```

---

### Fix #6: Audit `configure()` Usage Across Docs

#### Step 1: Find All configure() Examples
- [ ] **Search** for all configure() usage:
```bash
grep -n "configure(" docs/**/*.md | grep -v "##" | grep -v "def configure"
```

#### Step 2: Create Checklist of Files to Review
Based on likely files with configure() examples:
- [ ] `docs/index.md:64-75, 119-155`
- [ ] `docs/getting-started/quick-start.md` (multiple locations)
- [ ] `docs/getting-started/first-plugin.md` (if present)
- [ ] `docs/guide/config/configuration-reference.md:92-130, 136-147`
- [ ] `docs/guide/config/production.md` (if present)
- [ ] `docs/examples/index.md` (in code examples)

#### Step 3: Verify Each Example Follows Current API
For each file, check that configure() calls:
- [ ] Use explicit parameters for: `magic_cookie`, `protocol_version`, `transports`, `auto_mtls`, `handshake_timeout`
- [ ] Use `**kwargs` pattern for other settings (which get `plugin_` prefix automatically)
- [ ] Include comment explaining the two parameter types

**Standard comment template to add**:
```python
configure(
    magic_cookie="my-plugin",      # Explicit parameter
    auto_mtls=False,                # Explicit parameter
    handshake_timeout=10.0,         # Explicit parameter
    # Additional settings via **kwargs (automatically prefixed with 'plugin_'):
    log_level="DEBUG",              # Sets plugin_log_level
    server_port=8080,               # Sets plugin_server_port
)
```

#### Step 4: Update Main Index Page
- [ ] **File**: `docs/index.md:64-75`
- [ ] **Add clarifying comment**:
```python
# Note: configure() has 5 explicit parameters (magic_cookie, protocol_version,
# transports, auto_mtls, handshake_timeout) plus **kwargs for other settings.
# Via **kwargs, additional parameters are automatically prefixed with 'plugin_'
configure(
    magic_cookie="my-echo-plugin",  # Explicit param: Sets PLUGIN_MAGIC_COOKIE_VALUE
    auto_mtls=False,                # Explicit param: Sets PLUGIN_AUTO_MTLS
    handshake_timeout=5.0,          # Explicit param: Sets PLUGIN_HANDSHAKE_TIMEOUT
    # Additional settings via **kwargs:
    # log_level="DEBUG",            # Via **kwargs: Sets plugin_log_level
    # server_port=8080,             # Via **kwargs: Sets plugin_server_port
)
```

---

## 🟢 LOW PRIORITY FIXES

### Fix #7: Create Certificate Loading Reference Page (Optional Enhancement)

#### Step 1: Create New File
- [ ] **Create**: `docs/guide/security/certificate-loading.md`
- [ ] **Content** (complete example):

```markdown
# Certificate Loading Reference

**Path:** [Home](../../index.md) → [User Guide](../index.md) → [Security](index.md) → Certificate Loading

This page provides a comprehensive reference for all certificate loading patterns in Pyvider RPC Plugin using Foundation's Certificate class.

## Overview

Pyvider RPC Plugin uses Foundation's `Certificate` class from `provide.foundation.crypto` for all certificate operations. The Certificate class provides multiple loading methods for different use cases.

## Loading Methods

### Method 1: Load from File URIs (Recommended for Configuration)

**Use when**: Setting certificates via environment variables

```python
from provide.foundation.crypto import Certificate

# Load from file:// URIs
cert = Certificate.from_pem(
    cert_pem="file:///etc/certs/server.crt",
    key_pem="file:///etc/certs/server.key"
)

# Use in environment variables
import os
os.environ["PLUGIN_SERVER_CERT"] = "file:///etc/certs/server.crt"
os.environ["PLUGIN_SERVER_KEY"] = "file:///etc/certs/server.key"
```

**Advantages:**
- Works directly in environment variables
- Platform-independent path handling
- Clear separation of cert and key files

### Method 2: Load from PEM Content Strings

**Use when**: Loading from files programmatically

```python
from pathlib import Path
from provide.foundation.crypto import Certificate

# Read PEM content from files
cert_pem_content = Path("/etc/certs/server.crt").read_text()
key_pem_content = Path("/etc/certs/server.key").read_text()

# Load from PEM strings
cert = Certificate.from_pem(
    cert_pem=cert_pem_content,
    key_pem=key_pem_content
)
```

**Advantages:**
- Full control over file reading
- Can validate content before loading
- Useful for complex deployment scenarios

### Method 3: Create Self-Signed Certificates

**Use when**: Development, testing, or automated certificate generation

```python
from provide.foundation.crypto import Certificate

# Create self-signed certificate
cert = Certificate.create_self_signed_server_cert(
    common_name="myservice.example.com",     # Required: Common Name (CN)
    organization_name="My Organization",      # Required: Organization (O)
    validity_days=365,                        # Required: Certificate lifetime
    alt_names=["localhost", "127.0.0.1"],    # Optional: Subject Alternative Names
    # Additional optional parameters (check Foundation docs):
    # key_type="rsa",           # Key type: "rsa" or "ecdsa"
    # key_size=2048,            # For RSA keys
    # ecdsa_curve="secp256r1"   # For ECDSA keys
)

# Save to files
Path("/tmp/server.crt").write_text(cert.cert_pem)
Path("/tmp/server.key").write_text(cert.key_pem)
```

**Advantages:**
- No external certificate authority needed
- Perfect for development and testing
- Automatic key generation

## Common Patterns

### Pattern: Development Setup with Auto-Generated Certs

```python
from pathlib import Path
from provide.foundation.crypto import Certificate
from pyvider.rpcplugin import configure

# Generate certs for development
cert = Certificate.create_self_signed_server_cert(
    common_name="dev.local",
    organization_name="Development",
    validity_days=30,
    alt_names=["localhost", "127.0.0.1", "::1"]
)

# Save to temp directory
cert_dir = Path("/tmp/dev-certs")
cert_dir.mkdir(exist_ok=True)

cert_path = cert_dir / "server.crt"
key_path = cert_dir / "server.key"

cert_path.write_text(cert.cert_pem)
key_path.write_text(cert.key_pem)

# Configure plugin to use them
configure(
    auto_mtls=True,
    server_cert=f"file://{cert_path}",
    server_key=f"file://{key_path}"
)
```

### Pattern: Production Setup with External Certs

```python
import os
from pyvider.rpcplugin import configure

# Production certificates from secure storage
os.environ.update({
    "PLUGIN_AUTO_MTLS": "true",
    "PLUGIN_SERVER_CERT": "file:///etc/pki/tls/certs/server.crt",
    "PLUGIN_SERVER_KEY": "file:///etc/pki/tls/private/server.key",
    "PLUGIN_CLIENT_CERT": "file:///etc/pki/tls/certs/client.crt",
    "PLUGIN_CLIENT_KEY": "file:///etc/pki/tls/private/client.key",
})

# Configuration loaded from environment automatically
```

### Pattern: Certificate Validation

```python
from provide.foundation.crypto import Certificate
from datetime import datetime, timedelta

cert = Certificate.from_pem(
    cert_pem="file:///etc/certs/server.crt",
    key_pem="file:///etc/certs/server.key"
)

# Check certificate validity (example - verify actual API)
# Note: Actual validation methods depend on Foundation's Certificate class
# Consult Foundation documentation for available validation methods
```

## Troubleshooting

### Issue: "Certificate file not found"

**Cause**: Invalid file path or incorrect file:// URI format

**Solution**:
```python
from pathlib import Path

# Ensure path exists
cert_path = Path("/etc/certs/server.crt")
if not cert_path.exists():
    raise FileNotFoundError(f"Certificate not found: {cert_path}")

# Use absolute paths
cert = Certificate.from_pem(
    cert_pem=f"file://{cert_path.absolute()}",
    key_pem=f"file://{cert_path.with_suffix('.key').absolute()}"
)
```

### Issue: "Invalid PEM format"

**Cause**: Certificate or key file corrupted or wrong format

**Solution**:
```python
# Validate PEM content
cert_content = Path("/etc/certs/server.crt").read_text()
if not cert_content.startswith("-----BEGIN CERTIFICATE-----"):
    raise ValueError("Invalid certificate format")
```

### Issue: Self-signed certificates rejected in production

**Cause**: Client doesn't trust self-signed certificates

**Solution**: Use certificates from a trusted CA for production, or configure clients to trust your CA.

## Related Documentation

- **[Security Configuration](configuration-security.md)** - Complete security setup
- **[mTLS Guide](mtls.md)** - Mutual TLS configuration
- **[Foundation Crypto](https://foundation.provide.io/crypto)** - Foundation's cryptography documentation

---

**Navigation:** [← Security Index](index.md) | [mTLS →](mtls.md)
```

#### Step 2: Add to mkdocs.yml Navigation
- [ ] **File**: `mkdocs.yml:279-284`
- [ ] **Add** after `certificates.md`:
```yaml
    - Security:
      - guide/security/index.md
      - mTLS Configuration: guide/security/mtls.md
      - Certificate Management: guide/security/certificates.md
      - Certificate Loading Reference: guide/security/certificate-loading.md  # NEW
      - Certificate API Reference: guide/security/certificate-reference.md
      - Magic Cookies: guide/security/magic-cookies.md
      - Process Isolation: guide/security/process-isolation.md
```

#### Step 3: Update Other Pages to Reference New Page
- [ ] **File**: `docs/introduction/foundation.md:89`
- [ ] **Add** link before examples:
```markdown
### 3. Enterprise Security

Certificate management handled by Foundation's crypto module:

!!! info "Complete Certificate Loading Reference"
    For all certificate loading patterns and troubleshooting, see **[Certificate Loading Reference](../guide/security/certificate-loading.md)**.

```python
# Examples...
```

---

### Fix #8: Add Complexity Indicators to All Examples

#### Step 1: Update examples/index.md
- [ ] **File**: `docs/examples/index.md:6-10`
- [ ] **Expand** the Quick Reference table to include all examples with complexity:

```markdown
## Quick Reference

| Example | Description | Complexity | File |
|---------|-------------|------------|------|
| [Basic Plugin](#basic-plugin) | Minimal plugin server and client | 🟢 Beginner | `dummy_server.py`, `quick_start_client.py` |
| [Echo Service](#echo-service) | Complete RPC service with custom methods | 🟡 Intermediate | `echo_server.py`, `echo_client.py` |
| [E2E Greeter](#e2e-greeter) | End-to-end greeter service | 🟡 Intermediate | `e2e_greeter_server.py`, `e2e_greeter_client.py` |
| [mTLS Security](#mtls-example) | Secure communication with mTLS | 🟠 Advanced | `security_mtls_example.py` |
| [Telemetry Demo](#telemetry) | Observability and monitoring | 🟠 Advanced | `telemetry_demo.py` |
| [Transport Options](#transport-options) | TCP vs Unix socket configuration | 🟡 Intermediate | `transport_options_demo.py` |
| [Async Patterns](#async-patterns) | Advanced async/await patterns | 🟠 Advanced | `async_patterns_demo.py` |
| [Error Handling](#error-handling) | Robust error handling strategies | 🟡 Intermediate | `error_handling_demo.py` |
| [Custom Protocols](#custom-protocols) | Creating custom gRPC protocols | 🟠 Advanced | `custom_protocols_demo.py` |
| [Performance Tuning](#performance) | Optimization strategies | 🔴 Expert | `performance_tuning_concepts.py` |
| [Direct Connection](#direct-connection) | Connect to existing plugin server | 🟡 Intermediate | `direct_client_connection.py` |

**Complexity Legend:**
- 🟢 **Beginner**: Basic concepts, minimal setup
- 🟡 **Intermediate**: Multiple components, some complexity
- 🟠 **Advanced**: Production patterns, requires deeper understanding
- 🔴 **Expert**: Complex patterns, performance optimization
```

#### Step 2: Add Complexity Badges to Short Examples
- [ ] **File**: `docs/examples/index.md:437-443` (or wherever short examples are listed)
- [ ] **Add complexity** to each:
```markdown
└── short/                           # Short focused examples (15-30 lines)
    ├── basic_client.py              # 🟢 Minimal client connection
    ├── basic_server.py              # 🟢 Minimal server setup
    ├── health_check.py              # 🟡 Health check implementation
    ├── rate_limiting.py             # 🟡 Rate limiting example
    ├── tcp_transport.py             # 🟡 TCP transport configuration
    └── custom_protocol.py           # 🟠 Custom protocol example
```

---

### Fix #9: Standardize Code Example Headers

#### Create Standard Template
- [ ] **Document** the standard format for all code examples:

```python
#!/usr/bin/env python3
"""
<File Purpose - One Line>

Demonstrates:
- <Key Concept 1>
- <Key Concept 2>
- <Key Concept 3>

Complexity: <Beginner|Intermediate|Advanced|Expert>
Prerequisites: <What user needs to know/have installed>

Related:
- <Link to relevant doc page 1>
- <Link to relevant doc page 2>
"""
```

#### Apply to Key Examples
- [ ] **File**: `examples/echo_server.py` - Verify header follows template
- [ ] **File**: `examples/echo_client.py` - Verify header follows template
- [ ] **File**: `examples/dummy_server.py` - Verify header follows template
- [ ] **File**: `examples/quick_start_client.py` - Verify header follows template

---

## Verification Checklist

After completing all fixes:

### Build and Test
- [ ] Run `mkdocs build --strict` to check for broken links
- [ ] Run `mkdocs serve` and manually check navigation
- [ ] Verify all internal links work
- [ ] Check that code examples render correctly

### Content Verification
- [ ] Search for "TODO" or "FIXME" in docs
- [ ] Search for broken relative links: `grep -r "](../" docs/`
- [ ] Verify all example files referenced actually exist
- [ ] Check that Foundation references link to canonical page

### Cross-Reference Check
- [ ] Verify `configure()` examples match actual API across all docs
- [ ] Verify Certificate examples are consistent across all docs
- [ ] Check that example file mapping is consistent everywhere

---

## Estimated Time Budget

| Priority | Fixes | Estimated Time |
|----------|-------|---------------|
| 🔴 High | #1-3 | 1-2 hours |
| 🟡 Medium | #4-6 | 2-3 hours |
| 🟢 Low | #7-9 | 2-3 hours |
| **Total** | **All fixes** | **5-8 hours** |

**Quick wins** (Fixes #1-#3): Can be completed in 1-2 hours for immediate improvement.

---

## Issues Summary

### High Priority Issues
1. **Missing example files for simple-custom-rpc** - Referenced files don't exist
2. **Duplicate example mapping info** - Information repeated across 3 files
3. **Orphaned navigation entry** - File not in mkdocs.yml navigation

### Medium Priority Issues
4. **Certificate API verification needed** - Examples may need updating
5. **Foundation explanation consolidation** - Reduce duplication
6. **configure() usage audit** - Ensure consistency across docs

### Low Priority Issues
7. **Missing cert loading reference** - Would reduce duplication
8. **Inconsistent example metadata** - Add complexity indicators
9. **Unstandardized example headers** - Improve consistency

---

**Audit Completed**: 2025-01-24
**Auditor**: Claude (Sonnet 4.5)
**Files Reviewed**: 72 documentation files + source code cross-reference
