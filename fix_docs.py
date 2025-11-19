#!/usr/bin/env python3
"""Fix documentation issues found in comprehensive review."""
import re
from pathlib import Path

def fix_certificate_from_pem_in_file(file_path: Path) -> bool:
    """Fix Certificate.from_pem() usage with file:// URIs."""
    content = file_path.read_text()
    original = content

    # Pattern 1: cert_pem=f"file://{cert_path}", key_pem=f"file://{key_path}"
    pattern1 = r'cert = Certificate\.from_pem\(\s*cert_pem=f"file://\{([^}]+)\}",\s*key_pem=f"file://\{([^}]+)\}"\s*\)'
    replacement1 = r'''# Read PEM content from files
        cert_pem_content = Path(\1).read_text()
        key_pem_content = Path(\2).read_text()
        cert = Certificate.from_pem(
            cert_pem=cert_pem_content,
            key_pem=key_pem_content
        )'''
    content = re.sub(pattern1, replacement1, content)

    # Pattern 2: cert_pem="file://filename.pem", key_pem="file://filename.key"
    pattern2 = r'Certificate\.from_pem\(\s*cert_pem="file://([^"]+)",\s*key_pem="file://([^"]+)"\s*\)'
    def replace_pattern2(match):
        cert_file = match.group(1)
        key_file = match.group(2)
        return f'''# Read PEM content from files
cert_pem_content = Path("{cert_file}").read_text()
key_pem_content = Path("{key_file}").read_text()
Certificate.from_pem(
    cert_pem=cert_pem_content,
    key_pem=key_pem_content
)'''
    content = re.sub(pattern2, replace_pattern2, content)

    # Pattern 3: Single file:// in from_pem (like CA certs)
    pattern3 = r'Certificate\.from_pem\(\s*cert_pem="file://([^"]+)"\s*\)'
    def replace_pattern3(match):
        cert_file = match.group(1)
        return f'''# Read PEM content from file
cert_pem_content = Path("{cert_file}").read_text()
Certificate.from_pem(cert_pem=cert_pem_content)'''
    content = re.sub(pattern3, replace_pattern3, content)

    if content != original:
        file_path.write_text(content)
        return True
    return False

def remove_nonexistent_params_from_factories(file_path: Path) -> bool:
    """Remove non-existent parameters from plugin_server/plugin_client examples."""
    content = file_path.read_text()
    original = content

    # Remove these non-existent params from plugin_server
    bad_server_params = [
        'auto_mtls=',
        'tls_certificate=',
        'tls_ca_certificate=',
        'require_client_certificate=',
        'services=',
        'allowed_client_cns=',
        'cipher_suites=',
        'min_tls_version=',
        'bind_address=',
        'trust_forwarded_headers=',
        'allowed_forwarded_ips=',
    ]

    # Remove these non-existent params from plugin_client
    bad_client_params = [
        'auto_mtls=',
        'tls_client_certificate=',
        'tls_ca_certificate=',
        'verify_server_certificate=',
    ]

    # Note: We need to be careful not to remove valid uses of these in text/comments
    # This is a simplified approach - may need manual review after

    if content != original:
        file_path.write_text(content)
        return True
    return False

def add_disclaimer_to_nonexistent_modules(file_path: Path) -> bool:
    """Add disclaimers to files that reference non-existent modules."""
    content = file_path.read_text()
    original = content

    # Check if file mentions MagicCookie or ProcessIsolator without disclaimer
    if 'pyvider.rpcplugin.security.MagicCookie' in content:
        if '!!! warning "Conceptual API"' not in content:
            # Add warning at top of code block
            content = content.replace(
                'from pyvider.rpcplugin.security import MagicCookie',
                '# NOTE: pyvider.rpcplugin.security.MagicCookie does not currently exist\n# This is a conceptual example showing potential future API\n# from pyvider.rpcplugin.security import MagicCookie'
            )

    if 'pyvider.rpcplugin.isolation' in content:
        if '!!! warning "Conceptual API"' not in content:
            content = content.replace(
                'from pyvider.rpcplugin.isolation import ProcessIsolator',
                '# NOTE: pyvider.rpcplugin.isolation does not currently exist\n# This is a conceptual example showing potential future API\n# from pyvider.rpcplugin.isolation import ProcessIsolator'
            )

    if content != original:
        file_path.write_text(content)
        return True
    return False

def fix_readme_link(file_path: Path) -> bool:
    """Fix README contributing guide link."""
    content = file_path.read_text()
    original = content

    content = content.replace(
        './docs/development/contributing.md',
        './docs/development/contributing-guide.md'
    )

    if content != original:
        file_path.write_text(content)
        return True
    return False

def main():
    """Run all documentation fixes."""
    docs_dir = Path('/REDACTED_ABS_PATH')
    root_dir = Path('/REDACTED_ABS_PATH')

    print("=" * 60)
    print("Fixing Documentation Issues")
    print("=" * 60)

    # Fix Certificate.from_pem() usage
    print("\n1. Fixing Certificate.from_pem() usage with file:// URIs...")
    cert_files = [
        docs_dir / 'guide/security/mtls.md',
        docs_dir / 'guide/security/certificates.md',
        docs_dir / 'guide/security/certificate-reference.md',
    ]

    for file_path in cert_files:
        if file_path.exists():
            if fix_certificate_from_pem_in_file(file_path):
                print(f"   ✓ Fixed {file_path.relative_to(root_dir)}")
            else:
                print(f"   - No changes needed for {file_path.relative_to(root_dir)}")

    # Fix README link
    print("\n2. Fixing README contributing guide link...")
    readme_path = root_dir / 'README.md'
    if fix_readme_link(readme_path):
        print(f"   ✓ Fixed README.md")
    else:
        print(f"   - No changes needed for README.md")

    # Add disclaimers to non-existent modules
    print("\n3. Adding disclaimers to non-existent module references...")
    module_files = [
        docs_dir / 'guide/security/magic-cookies.md',
        docs_dir / 'guide/security/process-isolation.md',
    ]

    for file_path in module_files:
        if file_path.exists():
            if add_disclaimer_to_nonexistent_modules(file_path):
                print(f"   ✓ Added disclaimer to {file_path.relative_to(root_dir)}")
            else:
                print(f"   - No changes needed for {file_path.relative_to(root_dir)}")

    print("\n" + "=" * 60)
    print("Documentation fixes complete!")
    print("=" * 60)
    print("\nNOTE: Factory function parameter removal requires manual review")
    print("      due to complexity of code examples. See:")
    print("      - docs/guide/security/mtls.md (lines 28-84)")
    print("      - docs/guide/best-practices.md")
    print("      - docs/guide/security/certificate-reference.md")

if __name__ == '__main__':
    main()
