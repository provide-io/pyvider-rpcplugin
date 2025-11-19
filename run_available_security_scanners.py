#!/usr/bin/env python3
"""Run all AVAILABLE security scanners (skip unavailable tools)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

def main():
    """Run all available security scanners."""
    project_root = Path("/REDACTED_ABS_PATH")
    src_dir = project_root / "src"
    artifact_dir = project_root / ".provide/output/security"
    artifact_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 80)
    print("COMPREHENSIVE SECURITY SCAN - ALL AVAILABLE TOOLS")
    print("=" * 80)

    # Try to import scanners - skip if not available
    scanners = []

    # Bandit (always available)
    try:
        from provide.testkit.quality.security import SecurityScanner
        scanners.append(("Bandit", SecurityScanner, {
            "max_high_severity": 0,
            "max_medium_severity": 10,
            "min_score": 70.0,
            "verbosity": "quiet",
        }, src_dir))
    except Exception as e:
        print(f"⏭️  Bandit not available: {e}")

    # PipAudit
    try:
        from provide.testkit.quality.security import PipAuditScanner
        scanners.append(("PipAudit", PipAuditScanner, {
            "max_vulnerabilities": 5,
        }, project_root))
    except Exception as e:
        print(f"⏭️  PipAudit not available: {e}")

    # Semgrep
    try:
        from provide.testkit.quality.security import SemgrepScanner
        scanners.append(("Semgrep", SemgrepScanner, {
            "config": ["auto"],
            "max_findings": 30,
        }, src_dir))
    except Exception as e:
        print(f"⏭️  Semgrep not available: {e}")

    # Safety
    try:
        from provide.testkit.quality.security import SafetyScanner
        scanners.append(("Safety", SafetyScanner, {
            "max_vulnerabilities": 5,
        }, project_root))
    except Exception as e:
        print(f"⏭️  Safety not available: {e}")

    # GitLeaks (requires external binary)
    try:
        from provide.testkit.quality.security import GitLeaksScanner
        scanner = GitLeaksScanner({"max_secrets": 0})
        scanners.append(("GitLeaks", lambda cfg: scanner, {}, project_root))
    except Exception as e:
        print(f"⏭️  GitLeaks not available: {e}")

    # TruffleHog (requires external binary)
    try:
        from provide.testkit.quality.security import TruffleHogScanner
        scanner = TruffleHogScanner({"max_secrets": 0})
        scanners.append(("TruffleHog", lambda cfg: scanner, {}, project_root))
    except Exception as e:
        print(f"⏭️  TruffleHog not available: {e}")

    if not scanners:
        print("❌ No security scanners available!")
        return 1

    results = []
    passed = 0
    failed = 0

    for i, (name, scanner_class, config, path) in enumerate(scanners, 1):
        print(f"\n[{i}/{len(scanners)}] Running {name}...")
        print("-" * 80)

        try:
            scanner = scanner_class(config)
            result = scanner.analyze(path, artifact_dir=artifact_dir)
            results.append((name, result))

            # Display results
            print(f"Score: {result.score:.1f}%")
            print(f"Status: {'✅ PASSED' if result.passed else '❌ FAILED'}")

            # Show details
            if name == "Bandit":
                print(f"Issues: {result.details['total_issues']} "
                      f"(HIGH: {result.details['severity_breakdown']['HIGH']}, "
                      f"MEDIUM: {result.details['severity_breakdown']['MEDIUM']}, "
                      f"LOW: {result.details['severity_breakdown']['LOW']})")
                if not result.passed:
                    for issue in result.details['issues'][:5]:
                        print(f"  • {issue['filename']}:{issue['line_number']} "
                              f"[{issue['severity']}] {issue['test_name']}")
            elif name == "PipAudit":
                print(f"Vulnerabilities: {result.details['total_vulnerabilities']}")
                if result.details['total_vulnerabilities'] > 0:
                    for vuln in result.details.get('vulnerabilities', [])[:5]:
                        print(f"  • {vuln['package']} {vuln['version']}: {vuln['id']}")
            elif name == "Semgrep":
                print(f"Findings: {result.details['total_findings']}")
                if 'severity_breakdown' in result.details:
                    print(f"  ERROR: {result.details['severity_breakdown'].get('ERROR', 0)}, "
                          f"WARNING: {result.details['severity_breakdown'].get('WARNING', 0)}")
            elif name in ["GitLeaks", "TruffleHog"]:
                print(f"Secrets: {result.details['total_secrets']}")
                if result.details.get('verified_secrets', 0) > 0:
                    print(f"⚠️  VERIFIED (ACTIVE) SECRETS: {result.details['verified_secrets']}")
            elif name == "Safety":
                print(f"Vulnerabilities: {result.details['total_vulnerabilities']}")

            if result.passed:
                passed += 1
            else:
                failed += 1

        except Exception as e:
            print(f"❌ ERROR: {e}")
            failed += 1

    # Summary
    print("\n" + "=" * 80)
    print("SECURITY SCAN SUMMARY")
    print("=" * 80)

    for name, result in results:
        status = "✅ PASSED" if result.passed else "❌ FAILED"
        print(f"{name:15s} Score: {result.score:6.1f}%   {status}")

    print("=" * 80)
    print(f"Passed:  {passed}/{len(scanners)}")
    print(f"Failed:  {failed}/{len(scanners)}")
    print(f"Total:   {len(scanners)} scanners run")
    print("=" * 80)

    if failed == 0:
        print("✅ ALL AVAILABLE SECURITY SCANS PASSED!")
        print("\nSecurity Posture: EXCELLENT")
        print(f"  • {len(scanners)} security scanners executed")
        print(f"  • {passed} scanners passed")
        print(f"  • 0 critical issues found")
        return 0
    else:
        print(f"❌ {failed} SECURITY SCAN(S) FAILED")
        print("\nReview the failed scans above and address issues.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
