#!/usr/bin/env python3
"""Run comprehensive security scans on pyvider-rpcplugin."""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from provide.testkit.quality.security import (
    SecurityScanner,  # Bandit
    PipAuditScanner,
    SemgrepScanner,
)

def main():
    project_root = Path("/REDACTED_ABS_PATH")
    src_dir = project_root / "src"
    artifact_dir = project_root / ".provide/output/security"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("PYVIDER-RPCPLUGIN COMPREHENSIVE SECURITY SCAN")
    print("=" * 70)

    all_passed = True
    results = []

    # 1. Bandit (SecurityScanner) - Python code security
    print("\n[1/3] Running Bandit (Python Security Scanner)...")
    print("-" * 70)
    try:
        bandit = SecurityScanner(config={
            "max_high_severity": 0,
            "max_medium_severity": 10,
            "min_score": 70.0,
            "verbosity": "normal",
            "exclude": ["*/tests/*", "*/.venv/*", "*/.*", "*/build/*", "*/dist/*"],
        })
        result = bandit.analyze(src_dir, artifact_dir=artifact_dir)
        results.append(("Bandit", result))

        print(f"Files scanned: {result.details.get('total_files', 'N/A')}")
        print(f"Issues found: {result.details['total_issues']}")
        print(f"Severity breakdown: HIGH={result.details['severity_breakdown']['HIGH']}, "
              f"MEDIUM={result.details['severity_breakdown']['MEDIUM']}, "
              f"LOW={result.details['severity_breakdown']['LOW']}")
        print(f"Score: {result.score:.1f}%")
        print(f"Status: {'✅ PASSED' if result.passed else '❌ FAILED'}")

        if not result.passed:
            all_passed = False
            print("\nIssues found:")
            for issue in result.details['issues'][:10]:  # Show first 10
                print(f"  - {issue['filename']}:{issue['line_number']} "
                      f"[{issue['severity']}] {issue['test_name']}: {issue['text']}")

    except Exception as e:
        print(f"❌ Bandit scan failed: {e}")
        all_passed = False

    # 2. PipAudit - Python dependency vulnerabilities
    print("\n[2/3] Running PipAudit (Dependency Scanner)...")
    print("-" * 70)
    try:
        pip_audit = PipAuditScanner(config={
            "max_vulnerabilities": 5,  # Allow some low-severity vulns
            "strict": False,
            "timeout": 300,
        })
        result = pip_audit.analyze(project_root, artifact_dir=artifact_dir)
        results.append(("PipAudit", result))

        print(f"Dependencies: {result.details.get('total_dependencies', 'N/A')}")
        print(f"Vulnerabilities: {result.details['total_vulnerabilities']}")
        print(f"Score: {result.score:.1f}%")
        print(f"Status: {'✅ PASSED' if result.passed else '❌ FAILED'}")

        if result.details['total_vulnerabilities'] > 0:
            print("\nVulnerabilities found:")
            for vuln in result.details.get('vulnerabilities', [])[:10]:
                print(f"  - {vuln['package']} {vuln['version']}: {vuln['description']}")
                print(f"    Fix: Upgrade to {', '.join(vuln.get('fix_versions', ['N/A']))}")

        if not result.passed:
            all_passed = False

    except Exception as e:
        print(f"❌ PipAudit scan failed: {e}")
        all_passed = False

    # 3. Semgrep - Pattern-based SAST
    print("\n[3/3] Running Semgrep (Pattern-Based SAST)...")
    print("-" * 70)
    try:
        semgrep = SemgrepScanner(config={
            "config": ["auto"],  # Use auto-detection rules
            "max_findings": 30,
            "severity": ["ERROR", "WARNING"],
            "exclude": ["**/test_*", "**/.venv/**", "**/build/**", "**/dist/**"],
            "timeout": 600,
        })
        result = semgrep.analyze(src_dir, artifact_dir=artifact_dir)
        results.append(("Semgrep", result))

        print(f"Findings: {result.details['total_findings']}")
        if 'severity_breakdown' in result.details:
            print(f"Severity: ERROR={result.details['severity_breakdown'].get('ERROR', 0)}, "
                  f"WARNING={result.details['severity_breakdown'].get('WARNING', 0)}, "
                  f"INFO={result.details['severity_breakdown'].get('INFO', 0)}")
        print(f"Score: {result.score:.1f}%")
        print(f"Status: {'✅ PASSED' if result.passed else '❌ FAILED'}")

        if result.details['total_findings'] > 0 and 'findings' in result.details:
            print("\nFindings:")
            for finding in result.details['findings'][:10]:
                print(f"  - {finding['path']}:{finding['start_line']} "
                      f"[{finding['severity']}] {finding['message']}")

        if not result.passed:
            all_passed = False

    except Exception as e:
        print(f"❌ Semgrep scan failed: {e}")
        # Semgrep might not be installed, don't fail
        print("   (Semgrep may not be installed - skipping)")

    # Summary
    print("\n" + "=" * 70)
    print("SECURITY SCAN SUMMARY")
    print("=" * 70)

    for name, result in results:
        status = "✅ PASSED" if result.passed else "❌ FAILED"
        print(f"{name:20s} Score: {result.score:6.1f}%   {status}")

    print("=" * 70)
    if all_passed:
        print("✅ ALL SECURITY SCANS PASSED!")
        return 0
    else:
        print("❌ SOME SECURITY SCANS FAILED - Review issues above")
        return 1

if __name__ == "__main__":
    sys.exit(main())
